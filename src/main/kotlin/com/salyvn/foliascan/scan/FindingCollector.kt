package com.salyvn.foliascan.scan

import com.salyvn.foliascan.model.CodeLocation
import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.rules.CallRule
import com.salyvn.foliascan.rules.PackageRule
import com.salyvn.foliascan.rules.Rule
import com.salyvn.foliascan.rules.RuleCatalog
import com.salyvn.foliascan.rules.SupertypeRule

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
        for (model in jar.classes.values) {
            val blamed = model.internalName in reportable
            if (blamed) collectSupertypes(model)
            for (method in model.methods) {
                val context = offRegion.originOf(MethodKey(model.internalName, method.id))
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
                        InsnKind.INDY -> Unit
                    }
                }
            }
        }
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
            out += finding(
                rule = rule,
                evidence = "${insn.owner.substringAfterLast('/')}.${insn.name}()",
                why = rule.why,
                location = location(model, method, insn),
                contextual = rule.contextual,
                context = context?.takeIf { rule.contextual }?.let {
                    "reached off-region: ${it.reason} (entry point ${shortKey(it.entryPoint)}, " +
                        "${it.depth} call(s) deep)"
                },
            )
        }
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
            (owner.startsWith("org/bukkit/entity/") && name == "getScheduler")
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

    private fun shortKey(key: MethodKey): String =
        "${key.owner.substringAfterLast('/')}.${key.method.name}"

    private companion object {
        const val FOLIA_KEY = "folia-supported"
        val FOLIA_GETTERS = setOf(
            "getGlobalRegionScheduler", "getRegionScheduler", "getAsyncScheduler",
        )
    }
}
