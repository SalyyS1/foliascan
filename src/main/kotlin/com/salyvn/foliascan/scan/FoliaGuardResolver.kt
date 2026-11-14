package com.salyvn.foliascan.scan

import org.objectweb.asm.Opcodes

/**
 * Finds code whose legacy calls are only reachable when the server is *not* Folia.
 *
 * Reporting those as critical would flag every correctly written dual-platform plugin, so this
 * resolver looks for the guard. Real plugins write the guard in one of two shapes and both are
 * recognised here.
 *
 * **Per method** - one class, a `isFolia`-style flag, and a branch in every method:
 *
 * ```
 * fun runGlobal(task: Runnable) =
 *     if (isFolia) Bukkit.getGlobalRegionScheduler().run(plugin) { task.run() }
 *     else Bukkit.getScheduler().runTask(plugin, task)
 * ```
 *
 * A method qualifies when it both tests for Folia *and* contains a region-scheduler call. The
 * second half is what keeps this from muting everything: a method that calls the legacy
 * scheduler unconditionally has no region-API call to pair with the test. Lambda bodies created
 * inside a guarded method inherit the guard, because a task built in the legacy branch compiles
 * into a separate synthetic method that would otherwise look unguarded on its own.
 *
 * **Per class** - one interface, two implementations, the choice made once at startup:
 *
 * ```
 * val scheduler = if (IS_FOLIA) PaperScheduler() else BukkitScheduler()
 * ```
 *
 * `BukkitScheduler` there contains no region call at all, so the per-method shape cannot see it.
 * It is treated as guarded when **every** `new` of it in the jar sits in a method that tests for
 * Folia.
 *
 * What counts as testing for Folia: reading or calling any member whose name mentions Folia
 * (`isFolia`, `IS_FOLIA`, `getIS_FOLIA`), or calling Paper's `isBrandCompatible`. Deliberately
 * *not* included is the mere presence of a region-scheduler call, which is the thing being paired
 * against rather than evidence on its own.
 *
 * Limits, stated rather than hidden: a class instantiated reflectively, through a service loader,
 * or by a dependency-injection container has no visible `new`, so the per-class shape will not
 * recognise it; and neither shape does control-flow analysis, so a method that tests for Folia
 * and *also* calls the legacy scheduler outside the branch is treated as guarded. The first errs
 * toward reporting, the second away from it.
 */
object FoliaGuardResolver {

    private val REGION_GETTERS = setOf(
        "getRegionScheduler", "getAsyncScheduler", "getGlobalRegionScheduler",
    )

    private const val REGION_PACKAGE = "io/papermc/paper/threadedregions/"
    private const val REGION_DOTTED_PREFIX = "io.papermc.paper.threadedregions."
    private const val BRAND_CHECK = "isBrandCompatible"
    private val FOLIA_THREAD_CHECKS = setOf("isGlobalTickThread", "isOwnedByCurrentRegion")
    private val CLASS_LOOKUP_CALLS = setOf("forName", "loadClass")

    private data class ProbeCatalog(
        val fields: Map<Pair<String, String>, String>,
        val methods: Map<Pair<String, String>, String>,
    )

    fun resolve(jar: JarClasses): GuardIndex {
        val probes = discoverIndirectProbes(jar)
        return GuardIndex(
            byClass = guardedClasses(jar, probes),
            byMethod = guardedMethods(jar, probes),
            suspectedByClass = suspectedPlatformAlternates(jar),
        )
    }

    /**
     * Classes that look like one arm of a reflectively chosen platform pair.
     *
     * FoliaLib is the canonical case and it defeats both provable shapes: `FoliaLib.createServerImpl`
     * does `Class.forName(basePackage + implName)`, so `SpigotImplementation` has no `new` anywhere
     * in the jar and no method of it tests for Folia - the test lives in the factory, one indirection
     * away, keyed by a string.
     *
     * What can be seen is the shape: a class that this jar never constructs, sitting next to a
     * sibling implementation of the same interface that does use the region API. That is suggestive,
     * not proof, so it only ever attaches an explanation. Severity is left alone - a wrong all-clear
     * costs more than a wrong warning, and the reader is told exactly what to check.
     */
    private fun suspectedPlatformAlternates(jar: JarClasses): Map<String, String> {
        val constructed = constructionSites(jar).keys
        val regionAware = jar.classes.values
            .filter { model -> model.methods.any { it.instructions.any(::isRegionApi) } }
            .map { it.internalName }
            .toSet()

        val out = mutableMapOf<String, String>()
        for (model in jar.classes.values) {
            if (model.internalName in constructed || model.internalName in regionAware) continue
            if (model.interfaces.isEmpty()) continue
            val sibling = regionAware.firstOrNull { other ->
                other != model.internalName &&
                    jar.get(other)?.interfaces?.any { it in model.interfaces } == true
            } ?: continue
            out[model.internalName] = "never constructed in this jar, and " +
                "${sibling.substringAfterLast('/')} implements the same interface using the region " +
                "API - if a factory picks between them at runtime this branch may be unreachable " +
                "on Folia, which this analysis cannot prove"
        }
        return out
    }

    /** Methods that branch on a Folia test and carry the region-aware path themselves. */
    private fun guardedMethods(jar: JarClasses, probes: ProbeCatalog): Map<Pair<String, String>, String> {
        val out = mutableMapOf<Pair<String, String>, String>()
        val pending = ArrayDeque<Pair<MethodKey, String>>()
        val regionCallTargets = regionAwareMethods(jar)

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val probe = probeIn(method, probes) ?: continue
                val hasRegionBranch = method.instructions.any { insn ->
                    isRegionApi(insn) ||
                        (insn.kind == InsnKind.CALL && (insn.owner to insn.name) in regionCallTargets)
                }
                if (!hasRegionBranch) continue
                val where = MethodKey(model.internalName, method.id)
                val reason = "not reachable on Folia: " +
                    "${where.owner.substringAfterLast('/')}.${method.id.name} picks its path " +
                    "from $probe and has a region-scheduler branch"
                if (out.put(model.internalName to method.id.name, reason) == null) {
                    pending += where to reason
                }
            }
        }

        // A task created in the legacy branch compiles into its own synthetic method. Judged
        // alone it looks like unguarded legacy code, so the guard follows the lambda.
        while (pending.isNotEmpty()) {
            val (where, reason) = pending.removeFirst()
            val body = jar.get(where.owner)?.method(where.method) ?: continue
            for (insn in body.instructions) {
                val target = insn.lambdaTarget?.takeIf { jar.contains(it.owner) } ?: continue
                val key = target.owner to target.method.name
                if (out.put(key, reason) == null) pending += target to reason
            }
        }
        return out
    }

    /**
     * Methods in the jar that directly invoke the Folia region API or delegate to an in-jar
     * scheduler interface/wrapper that does (one wrapper hop, excluding lifecycle methods).
     */
    private fun regionAwareMethods(jar: JarClasses): Set<Pair<String, String>> {
        val out = mutableSetOf<Pair<String, String>>()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                if (method.instructions.any(::isRegionApi)) {
                    out += model.internalName to method.id.name
                    for (iface in model.interfaces) {
                        out += iface to method.id.name
                    }
                }
            }
        }
        val wrapped = out.toSet()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                val name = method.id.name
                if (name == "<init>" || name == "<clinit>" || name == "onEnable") continue
                if (method.instructions.any { it.kind == InsnKind.CALL && (it.owner to it.name) in wrapped }) {
                    out += model.internalName to name
                    for (iface in model.interfaces) {
                        out += iface to name
                    }
                }
            }
        }
        return out
    }

    /**
     * Classes whose every construction site tests for Folia first and pairs this class against a
     * region-aware alternative (or a direct region-API branch) in the same factory method.
     *
     * Requiring the factory method to also construct a region-aware class (or call the region API
     * itself) prevents a plugin's `onEnable()` - which might log `supportsFolia()` once while
     * instantiating all 20 of its normal managers - from exonerating every manager in the jar.
     */
    private fun guardedClasses(jar: JarClasses, probes: ProbeCatalog): Map<String, String> {
        val regionAware = jar.classes.values
            .filter { model -> model.methods.any { it.instructions.any(::isRegionApi) } }
            .map { it.internalName }
            .toSet()
        val sites = constructionSites(jar)
        val out = mutableMapOf<String, String>()
        for ((created, callers) in sites) {
            if (callers.isEmpty()) continue
            val guards = callers.map { guardIn(jar, it, created, regionAware, probes) }
            if (guards.any { it == null }) continue
            out[created] = guards.filterNotNull().distinct().first()
        }
        // Nested / inner classes (e.g. `BukkitScheduler$BukkitTask`) constructed inside a guarded
        // outer class inherit their enclosing class's guard.
        for (name in jar.classes.keys) {
            if (name in out || '$' !in name) continue
            val outer = name.substringBefore('$')
            out[outer]?.let { out[name] = it }
        }
        return out
    }

    /** created class internal name -> the methods that instantiate it. */
    private fun constructionSites(jar: JarClasses): Map<String, List<MethodKey>> {
        val out = mutableMapOf<String, MutableList<MethodKey>>()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                val here = MethodKey(model.internalName, method.id)
                for (insn in method.instructions) {
                    if (insn.kind == InsnKind.TYPE_REF && insn.name == "new" && jar.contains(insn.owner)) {
                        out.getOrPut(insn.owner) { mutableListOf() }.add(here)
                    }
                }
            }
        }
        return out
    }

    /**
     * Returns a description of the Folia test inside [where], or null when there is none.
     *
     * [created] is excluded from the search on purpose. A class called `FoliaScheduler` mentions
     * Folia in its own name, so counting the `new FoliaScheduler` instruction as evidence of a
     * guard would make every such class vacuously guarded - the test has to be independent of
     * the class being tested.
     */
    private fun guardIn(
        jar: JarClasses,
        where: MethodKey,
        created: String,
        regionAware: Set<String>,
        probes: ProbeCatalog,
    ): String? {
        val body = jar.get(where.owner)?.method(where.method) ?: return null
        val createdSimple = created.substringAfterLast('/')
        val visible = body.instructions.filterNot {
            it.owner == created || it.name.contains(createdSimple, ignoreCase = true)
        }
        val probe = probeIn(visible, probes) ?: return null
        val hasRegionAlternative = body.instructions.any(::isRegionApi) ||
            body.instructions.any {
                it.kind == InsnKind.TYPE_REF && it.name == "new" &&
                    it.owner != created && it.owner in regionAware &&
                    sharesTypeWith(jar, created, it.owner)
            }
        if (!hasRegionAlternative) return null
        return "not reachable on Folia: this class is only instantiated where " +
            "${where.owner.substringAfterLast('/')}.${where.method.name} tests $probe"
    }

    private fun sharesTypeWith(jar: JarClasses, a: String, b: String): Boolean {
        val modelA = jar.get(a) ?: return false
        val modelB = jar.get(b) ?: return false
        if (modelA.interfaces.any { it in modelB.interfaces }) return true
        val superA = modelA.superName
        if (superA != null && superA != "java/lang/Object" && superA == modelB.superName) return true
        if (superA == b || modelB.superName == a) return true
        return false
    }

    /**
     * Propagates Folia runtime probes (`Class.forName("io.papermc.paper.threadedregions...")`,
     * `ServerBuildInfo#isBrandCompatible`, `isFolia` flags) through boolean fields initialized in
     * `<clinit>` / `<init>` and boolean-returning helper methods so neutral names such as
     * `HAS_REGIONS` or `supportsThreadedRegions()` are recognised without relying on the identifier
     * spelling "folia".
     */
    private fun discoverIndirectProbes(jar: JarClasses): ProbeCatalog {
        val fields = mutableMapOf<Pair<String, String>, String>()
        val methods = mutableMapOf<Pair<String, String>, String>()

        repeat(3) {
            val current = ProbeCatalog(fields.toMap(), methods.toMap())
            for (model in jar.classes.values) {
                for (method in model.methods) {
                    val directOrKnown = probeIn(method.instructions, current)
                        ?: method.instructions.firstNotNullOfOrNull { insn ->
                            val target = insn.lambdaTarget?.let { jar.get(it.owner)?.method(it.method) }
                            target?.let { probeIn(it.instructions, current) }
                        }
                        ?: continue

                    if (method.id.name == "<clinit>" || method.id.name == "<init>") {
                        for (insn in method.instructions) {
                            if (insn.kind == InsnKind.FIELD &&
                                (insn.opcode == Opcodes.PUTSTATIC || insn.opcode == Opcodes.PUTFIELD) &&
                                insn.desc == "Z"
                            ) {
                                fields.putIfAbsent(insn.owner to insn.name, directOrKnown)
                            }
                        }
                    }
                    if (method.id.desc.endsWith(")Z")) {
                        methods.putIfAbsent(model.internalName to method.id.name, directOrKnown)
                        for (iface in model.interfaces) {
                            methods.putIfAbsent(iface to method.id.name, directOrKnown)
                        }
                    }
                }
            }
        }
        return ProbeCatalog(fields, methods)
    }

    private fun probeIn(method: MethodModel, probes: ProbeCatalog): String? =
        probeIn(method.instructions, probes)

    private fun probeIn(instructions: List<Insn>, probes: ProbeCatalog): String? {
        val threadedRegionLiteral = instructions.firstOrNull { insn ->
            insn.kind == InsnKind.LDC_STRING && (
                insn.name.startsWith(REGION_DOTTED_PREFIX) ||
                    insn.name.startsWith(REGION_PACKAGE) ||
                    insn.name.equals("io.papermc.paper.threadedregions.RegionizedServer", ignoreCase = true)
                )
        }
        if (threadedRegionLiteral != null && instructions.any {
                it.kind == InsnKind.CALL && it.name in CLASS_LOOKUP_CALLS
            }
        ) {
            return "Class.forName(\"${threadedRegionLiteral.name}\")"
        }

        for (insn in instructions) {
            if (insn.kind == InsnKind.INDY || insn.kind == InsnKind.LDC_STRING || insn.kind == InsnKind.MONITOR) {
                continue
            }
            if (insn.name.contains("folia", ignoreCase = true)) return insn.name
            if (insn.kind == InsnKind.CALL && insn.name == BRAND_CHECK) {
                return "ServerBuildInfo.$BRAND_CHECK"
            }
            if (insn.kind == InsnKind.CALL && insn.name in FOLIA_THREAD_CHECKS) {
                return "${insn.owner.substringAfterLast('/')}.${insn.name}"
            }
            if (insn.kind == InsnKind.FIELD &&
                (insn.opcode == Opcodes.GETSTATIC || insn.opcode == Opcodes.GETFIELD)
            ) {
                probes.fields[insn.owner to insn.name]?.let { return "${insn.name} ($it)" }
            }
            if (insn.kind == InsnKind.CALL) {
                probes.methods[insn.owner to insn.name]?.let {
                    return "${insn.owner.substringAfterLast('/')}.${insn.name} ($it)"
                }
            }
        }
        return null
    }

    private fun isRegionApi(insn: Insn): Boolean = when {
        insn.owner.startsWith(REGION_PACKAGE) -> true
        insn.kind != InsnKind.CALL -> false
        insn.name in REGION_GETTERS -> true
        // Entity#getScheduler is the region-aware way to follow one entity around.
        insn.name == "getScheduler" && insn.desc.contains(REGION_PACKAGE) -> true
        else -> false
    }
}

/**
 * Where the Folia guards are, addressable the way a finding is: by class, and by the method the
 * finding sits in.
 */
class GuardIndex internal constructor(
    private val byClass: Map<String, String>,
    private val byMethod: Map<Pair<String, String>, String>,
    private val suspectedByClass: Map<String, String> = emptyMap(),
) {
    val size: Int get() = byClass.size + byMethod.size

    /** A description of the guard covering this location, or null when it is not guarded. */
    fun guardFor(internalName: String, methodName: String?): String? =
        byClass[internalName] ?: byMethod[internalName to (methodName ?: return null)]

    /**
     * An explanation for code that *looks* like a platform alternate without proving it. Never a
     * reason to lower severity - only to tell the reader what to verify.
     */
    fun suspicionFor(internalName: String): String? = suspectedByClass[internalName]

    companion object {
        val EMPTY = GuardIndex(emptyMap(), emptyMap())
    }
}
