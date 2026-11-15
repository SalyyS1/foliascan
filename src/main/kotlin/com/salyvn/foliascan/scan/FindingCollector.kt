package com.salyvn.foliascan.scan

import com.salyvn.foliascan.model.CodeLocation
import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.rules.CallRule
import com.salyvn.foliascan.rules.PackageRule
import com.salyvn.foliascan.rules.Rule
import com.salyvn.foliascan.rules.RuleCatalog
import com.salyvn.foliascan.rules.SupertypeRule
import org.objectweb.asm.Opcodes

/** Applies the rule catalog to one already-parsed jar. */
class FindingCollector(
    private val jarName: String,
    private val jar: JarClasses,
    private val offRegion: OffRegionContexts,
    private val descriptor: PluginDescriptor?,
    private val disabledRules: Set<String> = emptySet(),
    /**
     * Classes that may appear in the report. Everything else is still analysed - for supertype
     * resolution and off-region taint - but never blamed.
     */
    private val reportable: Set<String> = jar.classes.keys,
    /** Set when a Folia patcher's marker classes were found in the jar. */
    private val patched: Pair<PatcherSignature, String>? = null,
    /** Code only reachable behind a runtime Folia check, and where that check is. */
    private val guards: GuardIndex = GuardIndex.EMPTY,
) {
    var foliaApiUsages: Int = 0
        private set

    private val out = mutableListOf<Finding>()

    /** Per class: the distinct internal types it reaches, plus where it was first seen. */
    private val internalsByClass = LinkedHashMap<String, MutableSet<String>>()
    private val internalsFirstSite = mutableMapOf<String, CodeLocation>()

    fun collect(): List<Finding> {
        collectManifest()
        collectPatcher()
        val (unsyncFields, unsyncGetters) = discoverUnsyncStaticCollections()
        val parallelRegionTasks = discoverParallelRegionTasks()
        for (model in jar.classes.values) {
            val blamed = model.internalName in reportable
            if (blamed) collectSupertypes(model)
            for (method in model.methods) {
                val methodKey = MethodKey(model.internalName, method.id)
                val context = offRegion.originOf(methodKey)
                for (insn in method.instructions) {
                    // Counted across the whole jar: a relocated Folia shim is still evidence
                    // that the artifact does the region-aware thing somewhere.
                    countFoliaApi(insn)
                    if (!blamed) continue
                    when (insn.kind) {
                        InsnKind.CALL -> {
                            collectCalls(model, method, insn, context)
                            noteInternals(model, method, insn)
                        }
                        InsnKind.TYPE_REF, InsnKind.FIELD -> noteInternals(model, method, insn)
                        InsnKind.INDY, InsnKind.LDC_STRING, InsnKind.MONITOR, InsnKind.NULL_CONST, InsnKind.STACK_POP, InsnKind.VAR -> Unit
                    }
                }
                if (blamed) {
                    collectUnsyncStaticMutations(
                        model = model,
                        method = method,
                        context = context,
                        parallelOrigin = parallelRegionTasks[methodKey],
                        unsyncFields = unsyncFields,
                        unsyncGetters = unsyncGetters,
                    )
                    collectLifecycleAndTeleportRules(
                        model = model,
                        method = method,
                        context = context,
                    )
                    collectAsyncChunkGenerationRules(
                        model = model,
                        method = method,
                        context = context,
                    )
                }
            }
        }
        collectCapturedBlockEntityTasks()
        collectInternals()
        return dedupe(out)
    }

    private fun enabled(rule: Rule): Boolean = rule.id !in disabledRules

    private fun collectManifest() {
        val rule = RuleCatalog.foliaSupportFlag
        // A jar with no descriptor is not a plugin, so the load-time flag does not apply.
        if (descriptor == null || descriptor.foliaSupported || !enabled(rule)) return
        out += finding(
            rule = rule,
            evidence = "${descriptor.source} has no `$FOLIA_KEY: true`",
            why = rule.why,
            location = CodeLocation(jar = jarName, className = descriptor.source),
        )
    }

    private fun collectPatcher() {
        val rule = RuleCatalog.patchedByTool
        val (signature, marker) = patched ?: return
        if (!enabled(rule)) return
        out += finding(
            rule = rule,
            evidence = "${signature.tool} runtime class present: $marker",
            why = "${rule.why}\n${signature.behaviour} See ${signature.url}.",
            location = CodeLocation(jar = jarName, className = marker.removeSuffix(".class")),
        )
    }

    private fun collectSupertypes(model: ClassModel) {
        for (rule in RuleCatalog.supertypeRules) {
            if (!enabled(rule)) continue
            val hit = rule.supertypes.firstOrNull { jar.extends(model.internalName, it) } ?: continue
            out += finding(
                rule = rule,
                evidence = "extends ${hit.substringAfterLast('/')}",
                why = rule.why,
                location = CodeLocation(
                    jar = jarName,
                    className = model.binaryName,
                    sourceFile = model.sourceFile,
                ),
            )
        }
    }

    private fun collectCalls(
        model: ClassModel,
        method: MethodModel,
        insn: Insn,
        context: OffRegionOrigin?,
    ) {
        for (rule in RuleCatalog.callRules) {
            if (!enabled(rule) || !rule.matches(insn.owner, insn.name)) continue
            if (rule.contextual && context == null) continue
            if (rule.contextual && context?.isGlobalTick == true && (rule.id == "FS050" || rule.id == "FS064" || rule.id == "FS094" || rule.id == "FS095" || rule.id == "FS096" || rule.id == "FS097" || rule.id == "FS099")) continue
            val (sinkHops, chainLocations) = buildSinkChain(model, method, insn, context?.takeIf { rule.contextual })
            out += finding(
                rule = rule,
                evidence = "${insn.owner.substringAfterLast('/')}.${insn.name}()",
                why = rule.why,
                location = location(model, method, insn),
                contextual = rule.contextual,
                context = context?.takeIf { rule.contextual }?.let { origin ->
                    val chainSuffix = if (sinkHops.size > 1) {
                        "; call chain: ${sinkHops.joinToString(" -> ") { it.renderShort() }}"
                    } else {
                        ""
                    }
                    "reached off-region: ${origin.reason} (entry point ${shortKey(origin.entryPoint)}, " +
                        "${origin.depth} call(s) deep$chainSuffix)"
                },
                callChain = chainLocations,
            )
        }
    }

    private fun buildSinkChain(
        model: ClassModel,
        method: MethodModel,
        insn: Insn,
        origin: OffRegionOrigin?,
    ): Pair<List<TaintHop>, List<CodeLocation>> {
        val sinkHops = origin?.let {
            if (it.hops.isNotEmpty()) {
                val last = it.hops.last()
                it.hops.dropLast(1) + last.copy(line = insn.line ?: last.line)
            } else {
                listOf(TaintHop(MethodKey(model.internalName, method.id), insn.line, model.sourceFile))
            }
        }.orEmpty()
        val chainLocations = hopsToLocations(sinkHops)
        return sinkHops to chainLocations
    }

    private fun hopsToLocations(hops: List<TaintHop>): List<CodeLocation> = hops.map { hop ->
        CodeLocation(
            jar = jarName,
            className = hop.method.owner.replace('/', '.'),
            method = hop.method.method.name,
            line = hop.line,
            sourceFile = hop.sourceFile,
        )
    }

    /**
     * Records internals access per class instead of per call site. A model engine or NMS adapter
     * touches server internals thousands of times by design; enumerating each one buries every
     * other finding, so one finding per class carries the count instead.
     */
    private fun noteInternals(model: ClassModel, method: MethodModel, insn: Insn) {
        for (rule in RuleCatalog.packageRules) {
            if (!enabled(rule) || !rule.matches(insn.owner)) continue
            val seen = internalsByClass.getOrPut(model.internalName) { linkedSetOf() }
            if (seen.isEmpty()) {
                internalsFirstSite[model.internalName] = location(model, method, insn)
            }
            seen += insn.owner
        }
    }

    private fun collectInternals() {
        val rule = RuleCatalog.packageRules.firstOrNull() ?: return
        if (!enabled(rule)) return
        for ((className, owners) in internalsByClass) {
            val location = internalsFirstSite[className] ?: continue
            val sample = owners.take(3).joinToString(", ") { it.replace('/', '.') }
            val more = if (owners.size > 3) ", +${owners.size - 3} more" else ""
            out += finding(
                rule = rule,
                evidence = "${owners.size} internal type(s): $sample$more",
                why = rule.why,
                location = location,
            )
        }
    }

    private fun countFoliaApi(insn: Insn) {
        val owner = insn.owner
        val name = insn.name
        val isFolia = owner.startsWith(RuleCatalog.FOLIA_SCHEDULER_PACKAGE) ||
            name in FOLIA_GETTERS ||
            (owner == "org/bukkit/World" && (name == "getChunkAtAsync" || name == "getChunkAtAsyncUrgently")) ||
            (owner.startsWith("org/bukkit/entity/") && (name == "getScheduler" || name == "teleportAsync"))
        if (isFolia) foliaApiUsages++
    }

    private fun location(model: ClassModel, method: MethodModel, insn: Insn) = CodeLocation(
        jar = jarName,
        className = model.binaryName,
        method = method.id.name,
        line = insn.line,
        sourceFile = model.sourceFile,
    )

    private fun finding(
        rule: Rule,
        evidence: String,
        why: String,
        location: CodeLocation,
        contextual: Boolean = false,
        context: String? = null,
        callChain: List<CodeLocation> = emptyList(),
    ): Finding {
        // Code only reachable behind a runtime Folia check cannot run on Folia, so its legacy
        // calls are the correct non-Folia branch rather than a defect.
        val internalName = location.className.replace('.', '/')
        val guard = guards.guardFor(internalName, location.method)
        val downgrade = guard != null && rule.severity == Severity.CRITICAL
        // Not provable, so it stays critical; the reader is told what to check instead.
        val suspicion = if (guard == null && rule.severity == Severity.CRITICAL) {
            guards.suspicionFor(internalName)
        } else {
            null
        }
        return Finding(
            ruleId = rule.id,
            severity = if (downgrade) Severity.INFO else rule.severity,
            title = rule.title,
            evidence = evidence,
            why = why,
            fix = rule.fix,
            location = location,
            provenance = rule.provenance.render(),
            contextual = contextual,
            context = guard ?: suspicion ?: context,
            callChain = if (guard == null && suspicion == null) callChain else emptyList(),
        )
    }

    /**
     * A chained statement like `Bukkit.getScheduler().runTaskTimer(...)` matches several rules
     * on one line. Collapse per source line and keep the most severe, lowest-numbered rule so
     * the report reads as one problem per place in the code. Findings with no line number
     * (class-level and manifest-level) keep their own identity.
     */
    private fun dedupe(findings: List<Finding>): List<Finding> = findings
        .groupBy { f ->
            if (f.location.line != null) {
                listOf(f.location.className, f.location.method, f.location.line.toString())
            } else {
                listOf(f.location.className, f.location.method, f.evidence, f.ruleId)
            }
        }
        .values
        .map { group ->
            group.sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.ruleId })
                .first()
        }
        .sortedWith(
            compareByDescending<Finding> { it.severity.rank }
                .thenBy { it.location.className }
                .thenBy { it.location.line ?: 0 },
        )

    private fun discoverUnsyncStaticCollections(): Pair<
        Map<Pair<String, String>, String>,
        Map<Pair<String, String>, Pair<Pair<String, String>, String>>,
        > {
        val fields = mutableMapOf<Pair<String, String>, String>()
        for (model in jar.classes.values) {
            val clinit = model.methods.firstOrNull { it.id.name == "<clinit>" } ?: continue
            var lastAlloc: String? = null
            for (insn in clinit.instructions) {
                when (insn.kind) {
                    InsnKind.TYPE_REF -> if (insn.name == "new") {
                        lastAlloc = when {
                            insn.owner in UNSYNC_COLLECTION_TYPES -> insn.owner.substringAfterLast('/')
                            insn.owner.startsWith("java/util/concurrent/") -> null
                            else -> lastAlloc
                        }
                    }

                    InsnKind.CALL -> when {
                        insn.owner in KOTLIN_COLLECTION_FACTORIES && insn.name in KOTLIN_MUTABLE_FACTORIES ->
                            lastAlloc = insn.name

                        insn.owner == "java/util/Collections" && (
                            insn.name.startsWith("synchronized") ||
                                insn.name.startsWith("unmodifiable") ||
                                insn.name.startsWith("empty") ||
                                insn.name.startsWith("singleton")
                            ) -> lastAlloc = null

                        insn.owner.startsWith("java/util/concurrent/") -> lastAlloc = null
                    }

                    InsnKind.FIELD -> if (insn.opcode == Opcodes.PUTSTATIC) {
                        if (lastAlloc != null) {
                            fields[insn.owner to insn.name] = lastAlloc
                        }
                        lastAlloc = null
                    }

                    else -> Unit
                }
            }
        }

        val getters = mutableMapOf<Pair<String, String>, Pair<Pair<String, String>, String>>()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                if (!method.id.desc.startsWith("()")) continue
                if ((method.access and Opcodes.ACC_SYNCHRONIZED) != 0) continue
                if (method.instructions.any { it.kind == InsnKind.MONITOR }) continue
                val staticReads = method.instructions.filter {
                    it.kind == InsnKind.FIELD && it.opcode == Opcodes.GETSTATIC && (it.owner to it.name) in fields
                }
                if (staticReads.size == 1) {
                    val read = staticReads.single()
                    val fKey = read.owner to read.name
                    fields[fKey]?.let { kind ->
                        getters[model.internalName to method.id.name] = fKey to kind
                    }
                }
            }
        }
        return fields to getters
    }

    private fun discoverParallelRegionTasks(): Map<MethodKey, OffRegionOrigin> {
        val out = mutableMapOf<MethodKey, OffRegionOrigin>()
        val queue = ArrayDeque<MethodKey>()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                val callerKey = MethodKey(model.internalName, method.id)
                val firstLine = method.instructions.firstNotNullOfOrNull { it.line }
                method.instructions.forEachIndexed { idx, insn ->
                    if (insn.kind == InsnKind.CALL && insn.name in PARALLEL_REGION_SUBMITTERS &&
                        PARALLEL_REGION_OWNERS.any { insn.owner.endsWith(it) }
                    ) {
                        val reason = "submitted via ${insn.owner.substringAfterLast('/')}.${insn.name}"
                        for ((resolvedTarget, _) in resolveSubmittedTasks(method, idx)) {
                            val targetClass = jar.get(resolvedTarget.owner)
                            val targetFirstLine = targetClass?.method(resolvedTarget.method)?.instructions
                                ?.firstNotNullOfOrNull { it.line }
                            val hops = if (callerKey == resolvedTarget) {
                                listOf(TaintHop(callerKey, insn.line ?: firstLine, model.sourceFile))
                            } else {
                                listOf(
                                    TaintHop(callerKey, insn.line ?: firstLine, model.sourceFile),
                                    TaintHop(resolvedTarget, targetFirstLine, targetClass?.sourceFile),
                                )
                            }
                            val origin = OffRegionOrigin(
                                entryPoint = callerKey,
                                reason = reason,
                                depth = 0,
                                hops = hops,
                            )
                            if (out.putIfAbsent(resolvedTarget, origin) == null) {
                                queue.addLast(resolvedTarget)
                            }
                        }
                    }
                }
            }
        }
        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            val origin = out[cur] ?: continue
            val curModel = jar.get(cur.owner) ?: continue
            val body = curModel.method(cur.method) ?: continue
            for (insn in body.instructions) {
                val next = when {
                    insn.kind == InsnKind.CALL && jar.contains(insn.owner) ->
                        MethodKey(insn.owner, MethodId(insn.name, insn.desc))
                    insn.kind == InsnKind.INDY && insn.lambdaTarget != null &&
                        jar.contains(insn.lambdaTarget.owner) -> insn.lambdaTarget
                    else -> null
                } ?: continue
                if (out.containsKey(next)) continue
                val nextClass = jar.get(next.owner) ?: continue
                val nextBody = nextClass.method(next.method) ?: continue
                val updatedPrefix = if (origin.hops.isNotEmpty()) {
                    val last = origin.hops.last()
                    origin.hops.dropLast(1) + last.copy(line = insn.line ?: last.line)
                } else {
                    listOf(TaintHop(cur, insn.line, curModel.sourceFile))
                }
                val nextFirstLine = nextBody.instructions.firstNotNullOfOrNull { it.line }
                out[next] = origin.copy(
                    depth = origin.depth + 1,
                    hops = updatedPrefix + TaintHop(next, nextFirstLine, nextClass.sourceFile),
                )
                queue.addLast(next)
            }
        }
        return out
    }

    /**
     * Resolves all lambda synthetic methods (unwrapping Kotlin 2.x two-stage FunctionN SAM bridges)
     * or Runnable subclasses pushed onto the stack for the scheduler call at [callIndex] (covering
     * both primary `task` and `EntityScheduler` `retired` callbacks).
     */
    private fun resolveSubmittedTasks(method: MethodModel, callIndex: Int): List<Pair<MethodKey, Boolean>> {
        val found = mutableListOf<Pair<MethodKey, Boolean>>()
        var j = callIndex - 1
        while (j >= 0) {
            val prev = method.instructions[j]
            if (prev.kind == InsnKind.INDY && prev.lambdaTarget != null) {
                if (prev.desc.startsWith("(Lkotlin/jvm/functions/Function") && j > 0 &&
                    method.instructions[j - 1].kind == InsnKind.INDY &&
                    method.instructions[j - 1].lambdaTarget != null &&
                    method.instructions[j - 1].desc.contains(")Lkotlin/jvm/functions/Function")
                ) {
                    found += method.instructions[j - 1].lambdaTarget!! to true
                    j -= 2
                    continue
                }
                found += prev.lambdaTarget to true
                j -= 1
                continue
            }
            if (prev.kind == InsnKind.TYPE_REF && prev.name == "new") {
                val candidate = jar.get(prev.owner)
                val entry = candidate?.methods?.firstOrNull { it.id == RUN_METHOD }
                    ?: candidate?.methods?.firstOrNull {
                        (it.id.name == "accept" || it.id.name == "invoke") && (it.access and Opcodes.ACC_BRIDGE) == 0
                    }
                if (candidate != null && entry != null) {
                    found += MethodKey(candidate.internalName, entry.id) to false
                }
            }
            if (prev.kind == InsnKind.CALL && prev.name != "<init>") break
            j -= 1
        }
        return found
    }

    private fun collectUnsyncStaticMutations(
        model: ClassModel,
        method: MethodModel,
        context: OffRegionOrigin?,
        parallelOrigin: OffRegionOrigin?,
        unsyncFields: Map<Pair<String, String>, String>,
        unsyncGetters: Map<Pair<String, String>, Pair<Pair<String, String>, String>>,
    ) {
        val rule = RuleCatalog.unsynchronizedStaticCollection
        if (!enabled(rule) || unsyncFields.isEmpty()) return
        if ((method.access and Opcodes.ACC_SYNCHRONIZED) != 0) return
        if (method.instructions.any { it.kind == InsnKind.MONITOR }) return

        val effectiveOrigin = context ?: parallelOrigin ?: return
        var pending: Pair<Pair<String, String>, String>? = null

        for (insn in method.instructions) {
            when (insn.kind) {
                InsnKind.FIELD -> if (insn.opcode == Opcodes.GETSTATIC) {
                    val fKey = insn.owner to insn.name
                    val alloc = unsyncFields[fKey]
                    if (alloc != null) {
                        pending = fKey to alloc
                    } else if (insn.desc.startsWith("Ljava/util/concurrent/")) {
                        pending = null
                    }
                }

                InsnKind.CALL -> {
                    val getterHit = unsyncGetters[insn.owner to insn.name]
                    if (getterHit != null) {
                        pending = getterHit
                    } else if (pending != null &&
                        insn.owner in MUTABLE_COLLECTION_OWNERS &&
                        insn.name in COLLECTION_MUTATORS
                    ) {
                        val (fieldKey, allocKind) = pending
                        val (sinkHops, chainLocations) = buildSinkChain(model, method, insn, effectiveOrigin)
                        val chainSuffix = if (sinkHops.size > 1) {
                            "; call chain: ${sinkHops.joinToString(" -> ") { it.renderShort() }}"
                        } else {
                            ""
                        }
                        out += finding(
                            rule = rule,
                            evidence = "${fieldKey.first.substringAfterLast('/')}.${fieldKey.second} " +
                                "($allocKind) mutated via ${insn.name}()",
                            why = rule.why,
                            location = location(model, method, insn),
                            contextual = true,
                            context = "concurrent task mutation: ${effectiveOrigin.reason}$chainSuffix",
                            callChain = chainLocations,
                        )
                        pending = null
                    } else if (insn.owner.startsWith("java/util/concurrent/")) {
                        pending = null
                    }
                }

                else -> Unit
            }
        }
    }

    private fun collectLifecycleAndTeleportRules(
        model: ClassModel,
        method: MethodModel,
        context: OffRegionOrigin?,
    ) {
        val instructions = method.instructions
        for (i in instructions.indices) {
            val insn = instructions[i]

            // FS083: EntityScheduler lifecycle race when submitted with null retired callback on delayed/repeating task
            if (insn.kind == InsnKind.CALL &&
                insn.owner == "io/papermc/paper/threadedregions/scheduler/EntityScheduler" &&
                (insn.name == "runDelayed" || insn.name == "runAtFixedRate")
            ) {
                val rule = RuleCatalog.entitySchedulerLifecycle
                if (enabled(rule)) {
                    val hasNullRetired = (i > 0 && instructions[i - 1].kind == InsnKind.NULL_CONST) ||
                        (i > 1 && instructions[i - 2].kind == InsnKind.NULL_CONST) ||
                        (i > 2 && instructions[i - 3].kind == InsnKind.NULL_CONST)
                    if (hasNullRetired) {
                        val (_, chainLocations) = buildSinkChain(model, method, insn, context)
                        out += finding(
                            rule = rule,
                            evidence = "EntityScheduler.${insn.name}() called with null retired callback",
                            why = rule.why,
                            location = location(model, method, insn),
                            contextual = context != null,
                            context = context?.let { "entity lifecycle risk: ${it.reason}" },
                            callChain = chainLocations,
                        )
                    }
                }
            }

            // FS084: teleportAsync with discarded CompletableFuture followed by immediate post-teleport entity call
            if (insn.kind == InsnKind.CALL &&
                insn.name == "teleportAsync" &&
                insn.owner.startsWith("org/bukkit/entity/")
            ) {
                val rule = RuleCatalog.unchainedTeleportAsync
                if (enabled(rule)) {
                    val discarded = (i + 1 < instructions.size && instructions[i + 1].kind == InsnKind.STACK_POP)
                    val hasSubsequentEntityCall = instructions.subList(i + 1, instructions.size).any {
                        it.kind == InsnKind.CALL && it.owner.startsWith("org/bukkit/entity/") &&
                            it.name !in setOf("getScheduler", "teleportAsync", "values", "valueOf", "name", "ordinal")
                    }
                    if (discarded && hasSubsequentEntityCall) {
                        val (_, chainLocations) = buildSinkChain(model, method, insn, context)
                        out += finding(
                            rule = rule,
                            evidence = "${insn.owner.substringAfterLast('/')}.teleportAsync() future discarded before subsequent entity access",
                            why = rule.why,
                            location = location(model, method, insn),
                            contextual = context != null,
                            context = context?.let { "asynchronous teleport risk: ${it.reason}" },
                            callChain = chainLocations,
                        )
                    }
                }
            }
        }
    }

    /**
     * Collects FS087 (blocking join/get on getChunkAtAsync* or teleportAsync futures) and FS088
     * (live World escapes inside Moonrise parallel async ChunkGenerator or BlockPopulator paths).
     */
    private fun collectAsyncChunkGenerationRules(
        model: ClassModel,
        method: MethodModel,
        context: OffRegionOrigin?,
    ) {
        val blockingRule = RuleCatalog.blockingAsyncFuture
        if (enabled(blockingRule)) {
            var pendingRegionFuture: String? = null
            val regionFutureSlots = mutableMapOf<Int, String>()
            for (insn in method.flowInstructions) {
                when (insn.kind) {
                    InsnKind.CALL -> {
                        val isRegionFutureSource =
                            (insn.owner == "org/bukkit/World" &&
                                (insn.name == "getChunkAtAsync" || insn.name == "getChunkAtAsyncUrgently")) ||
                                (insn.owner.startsWith("org/bukkit/entity/") && insn.name == "teleportAsync")
                        if (isRegionFutureSource) {
                            pendingRegionFuture = "${insn.owner.substringAfterLast('/')}.${insn.name}()"
                        } else if (insn.owner in COMPLETABLE_FUTURE_OWNERS && insn.name in BLOCKING_FUTURE_CALLS) {
                            val source = pendingRegionFuture
                            if (source != null) {
                                val (sinkHops, chainLocations) = buildSinkChain(model, method, insn, context)
                                val chainSuffix = if (sinkHops.size > 1) {
                                    "; call chain: ${sinkHops.joinToString(" -> ") { it.renderShort() }}"
                                } else {
                                    ""
                                }
                                out += finding(
                                    rule = blockingRule,
                                    evidence = "$source blocked via CompletableFuture.${insn.name}()",
                                    why = blockingRule.why,
                                    location = location(model, method, insn),
                                    contextual = context != null,
                                    context = context?.let { "blocking region-completed future (${it.reason}$chainSuffix)" },
                                    callChain = chainLocations,
                                )
                                pendingRegionFuture = null
                            }
                        } else if (insn.owner !in BOXING_OWNERS) {
                            pendingRegionFuture = null
                        }
                    }

                    InsnKind.VAR -> {
                        val slot = insn.name.toIntOrNull()
                        if (slot != null) {
                            if (insn.opcode == Opcodes.ASTORE) {
                                val cur = pendingRegionFuture
                                if (cur != null) regionFutureSlots[slot] = cur else regionFutureSlots.remove(slot)
                                pendingRegionFuture = null
                            } else if (insn.opcode == Opcodes.ALOAD) {
                                regionFutureSlots[slot]?.let { pendingRegionFuture = it }
                            }
                        }
                    }

                    InsnKind.STACK_POP -> pendingRegionFuture = null

                    else -> Unit
                }
            }
        }

        val chunkGenRule = RuleCatalog.asyncChunkGeneratorWorldEscape
        if (enabled(chunkGenRule) && context?.isChunkGeneration == true) {
            for (insn in method.instructions) {
                val escapeEvidence = when {
                    insn.kind == InsnKind.TYPE_REF &&
                        insn.opcode == Opcodes.CHECKCAST &&
                        insn.owner == "org/bukkit/World" ->
                        "cast to org.bukkit.World inside async chunk generation"

                    insn.kind == InsnKind.CALL &&
                        insn.owner in setOf("org/bukkit/Bukkit", "org/bukkit/Server") &&
                        insn.name in setOf("getWorld", "getWorlds") ->
                        "${insn.owner.substringAfterLast('/')}.${insn.name}() live world lookup"

                    insn.kind == InsnKind.CALL &&
                        insn.owner == "org/bukkit/World" &&
                        insn.name == "getBlockAt" ->
                        "World.getBlockAt() live block access outside ChunkData/LimitedRegion"

                    else -> null
                } ?: continue
                val (sinkHops, chainLocations) = buildSinkChain(model, method, insn, context)
                val chainSuffix = if (sinkHops.size > 1) {
                    "; call chain: ${sinkHops.joinToString(" -> ") { it.renderShort() }}"
                } else {
                    ""
                }
                out += finding(
                    rule = chunkGenRule,
                    evidence = escapeEvidence,
                    why = chunkGenRule.why,
                    location = location(model, method, insn),
                    contextual = true,
                    context = "reached off-region: ${context.reason} (entry point ${shortKey(context.entryPoint)}, " +
                        "${context.depth} call(s) deep$chainSuffix)",
                    callChain = chainLocations,
                )
            }
        }
    }

    /**
     * Collects FS090: pre-fetched BlockState / TileState snapshots captured into delayed/repeating
     * RegionScheduler tasks or cross-region EntityScheduler callbacks.
     */
    private fun collectCapturedBlockEntityTasks() {
        val rule = RuleCatalog.capturedBlockEntityAcrossTicks
        if (!enabled(rule)) return

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val callerKey = MethodKey(model.internalName, method.id)
                val callerFirstLine = method.instructions.firstNotNullOfOrNull { it.line }
                method.instructions.forEachIndexed { idx, insn ->
                    if (insn.kind != InsnKind.CALL) return@forEachIndexed
                    val isDelayedRegionSubmit =
                        insn.owner.endsWith("/RegionScheduler") &&
                            (insn.name == "runDelayed" || insn.name == "runAtFixedRate")
                    val isEntitySubmit =
                        insn.owner.endsWith("/EntityScheduler") &&
                            insn.name in PARALLEL_REGION_SUBMITTERS
                    if (!isDelayedRegionSubmit && !isEntitySubmit) return@forEachIndexed

                    for ((targetKey, isLambda) in resolveSubmittedTasks(method, idx)) {
                        val targetClass = jar.get(targetKey.owner) ?: continue
                        val targetMethod = targetClass.method(targetKey.method) ?: continue

                        val capturesBlockEntity = if (isLambda) {
                            descriptorCapturesBlockEntity(targetKey.method.desc)
                        } else {
                            targetClass.fields.any { descriptorCapturesBlockEntity(it.desc) }
                        }
                        if (!capturesBlockEntity) continue

                        val sinkHit = findBlockEntitySink(targetClass, targetMethod) ?: continue
                        val (sinkClass, sinkMethod, sinkInsn, midHop) = sinkHit
                        if (sinkClass.internalName !in reportable) continue

                        val callerHop = TaintHop(callerKey, insn.line ?: callerFirstLine, model.sourceFile)
                        val sinkKey = MethodKey(sinkClass.internalName, sinkMethod.id)
                        val sinkHop = TaintHop(sinkKey, sinkInsn.line, sinkClass.sourceFile)
                        val hops = buildList {
                            add(callerHop)
                            if (midHop != null && midHop.method != callerKey && midHop.method != sinkKey) {
                                add(midHop)
                            }
                            if (callerKey != sinkKey) add(sinkHop)
                        }
                        val chainSuffix = if (hops.size > 1) {
                            "; call chain: ${hops.joinToString(" -> ") { it.renderShort() }}"
                        } else {
                            ""
                        }
                        val schedulerLabel = "${insn.owner.substringAfterLast('/')}.${insn.name}"
                        out += finding(
                            rule = rule,
                            evidence = "${sinkInsn.owner.substringAfterLast('/')}.${sinkInsn.name}() on captured block-entity state",
                            why = rule.why,
                            location = location(sinkClass, sinkMethod, sinkInsn),
                            contextual = true,
                            context = "captured across ticks/regions via $schedulerLabel " +
                                "(entry point ${shortKey(callerKey)}$chainSuffix)",
                            callChain = hopsToLocations(hops),
                        )
                    }
                }
            }
        }
    }

    private data class BlockEntitySinkHit(
        val sinkClass: ClassModel,
        val sinkMethod: MethodModel,
        val sinkInsn: Insn,
        val intermediateHop: TaintHop? = null,
    )

    private fun findBlockEntitySink(
        taskClass: ClassModel,
        taskMethod: MethodModel,
    ): BlockEntitySinkHit? {
        for (insn in taskMethod.instructions) {
            if (isBlockEntityStateCall(insn)) {
                return BlockEntitySinkHit(taskClass, taskMethod, insn)
            }
        }
        val taskKey = MethodKey(taskClass.internalName, taskMethod.id)
        for (insn in taskMethod.instructions) {
            val helperKey = when {
                insn.kind == InsnKind.CALL && jar.contains(insn.owner) ->
                    MethodKey(insn.owner, MethodId(insn.name, insn.desc))
                insn.kind == InsnKind.INDY && insn.lambdaTarget != null && jar.contains(insn.lambdaTarget.owner) ->
                    insn.lambdaTarget
                else -> null
            } ?: continue
            val helperClass = jar.get(helperKey.owner) ?: continue
            val helperMethod = helperClass.method(helperKey.method) ?: continue
            val hit = helperMethod.instructions.firstOrNull(::isBlockEntityStateCall) ?: continue
            val midHop = TaintHop(taskKey, insn.line, taskClass.sourceFile)
            return BlockEntitySinkHit(helperClass, helperMethod, hit, midHop)
        }
        return null
    }

    private fun isBlockEntityStateCall(insn: Insn): Boolean =
        insn.kind == InsnKind.CALL &&
            (insn.owner == "org/bukkit/block/BlockState" || insn.owner in RuleCatalog.TILE_ENTITY_OWNERS) &&
            insn.name !in ENUM_METHODS

    private fun descriptorCapturesBlockEntity(desc: String): Boolean {
        val paramsSection = if (desc.startsWith("(")) desc.substringBefore(')') else desc
        return CAPTURED_BLOCK_STATE_DESCRIPTORS.any { paramsSection.contains(it) }
    }

    private fun shortKey(key: MethodKey): String =
        "${key.owner.substringAfterLast('/')}.${key.method.name}"

    private companion object {
        const val FOLIA_KEY = "folia-supported"
        val FOLIA_GETTERS = setOf(
            "getGlobalRegionScheduler", "getRegionScheduler", "getAsyncScheduler",
            "isGlobalTickThread", "isOwnedByCurrentRegion", "getRegionTPS",
        )
        val UNSYNC_COLLECTION_TYPES = setOf(
            "java/util/HashMap", "java/util/LinkedHashMap", "java/util/TreeMap",
            "java/util/ArrayList", "java/util/LinkedList",
            "java/util/HashSet", "java/util/LinkedHashSet", "java/util/TreeSet",
        )
        val KOTLIN_COLLECTION_FACTORIES = setOf(
            "kotlin/collections/MapsKt", "kotlin/collections/MapsKt__MapsKt",
            "kotlin/collections/CollectionsKt", "kotlin/collections/CollectionsKt__CollectionsKt",
            "kotlin/collections/SetsKt", "kotlin/collections/SetsKt__SetsKt",
        )
        val KOTLIN_MUTABLE_FACTORIES = setOf(
            "mutableMapOf", "hashMapOf", "linkedMapOf",
            "mutableListOf", "arrayListOf",
            "mutableSetOf", "hashSetOf", "linkedSetOf",
        )
        val MUTABLE_COLLECTION_OWNERS = UNSYNC_COLLECTION_TYPES + setOf(
            "java/util/Map", "java/util/List", "java/util/Set", "java/util/Collection",
        )
        val COLLECTION_MUTATORS = setOf(
            "put", "putAll", "putIfAbsent", "remove", "clear",
            "compute", "computeIfAbsent", "computeIfPresent", "merge",
            "replace", "replaceAll",
            "add", "addAll", "removeAll", "retainAll", "removeIf", "set", "sort",
        )
        val PARALLEL_REGION_OWNERS = setOf("/RegionScheduler", "/EntityScheduler")
        val PARALLEL_REGION_SUBMITTERS = setOf("run", "execute", "runDelayed", "runAtFixedRate")
        val RUN_METHOD = MethodId("run", "()V")
        val COMPLETABLE_FUTURE_OWNERS = setOf(
            "java/util/concurrent/CompletableFuture",
            "java/util/concurrent/Future",
        )
        val BLOCKING_FUTURE_CALLS = setOf("join", "get", "resultNow")
        val BOXING_OWNERS = setOf(
            "java/lang/Long", "java/lang/Integer", "java/lang/Boolean", "java/lang/Double",
            "kotlin/jvm/internal/Intrinsics",
        )
        val ENUM_METHODS = setOf("values", "valueOf", "name", "ordinal")
        val CAPTURED_BLOCK_STATE_DESCRIPTORS: Set<String> =
            (RuleCatalog.TILE_ENTITY_OWNERS + "org/bukkit/block/BlockState")
                .mapTo(mutableSetOf()) { "L$it;" }
    }
}
