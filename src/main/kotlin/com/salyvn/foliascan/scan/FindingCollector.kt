package com.salyvn.foliascan.scan

import com.salyvn.foliascan.model.CodeLocation
import com.salyvn.foliascan.model.Finding
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
) {
    var foliaApiUsages: Int = 0
        private set

    private val out = mutableListOf<Finding>()
    private val packageRuleSeen = mutableSetOf<String>()

    fun collect(): List<Finding> {
        collectManifest()
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
                            collectPackages(model, method, insn)
                        }
                        InsnKind.TYPE_REF, InsnKind.FIELD -> collectPackages(model, method, insn)
                        InsnKind.INDY -> Unit
                    }
                }
            }
        }
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
                    "${it.reason} (entry point ${shortKey(it.entryPoint)}, " +
                        "${it.depth} call(s) deep)"
                },
            )
        }
    }

    private fun collectPackages(model: ClassModel, method: MethodModel, insn: Insn) {
        for (rule in RuleCatalog.packageRules) {
            if (!enabled(rule) || !rule.matches(insn.owner)) continue
            // One report per class/method/target type; NMS access repeats constantly.
            val key = "${rule.id}|${model.internalName}|${method.id}|${insn.owner}"
            if (!packageRuleSeen.add(key)) continue
            out += finding(
                rule = rule,
                evidence = insn.owner.replace('/', '.'),
                why = rule.why,
                location = location(model, method, insn),
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
    ) = Finding(
        ruleId = rule.id,
        severity = rule.severity,
        title = rule.title,
        evidence = evidence,
        why = why,
        fix = rule.fix,
        location = location,
        provenance = rule.provenance.render(),
        contextual = contextual,
        context = context,
    )

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
