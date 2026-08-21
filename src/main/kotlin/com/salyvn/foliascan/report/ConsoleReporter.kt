package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.JarReport
import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity

/** Human-facing output: grouped by rule so the explanation is printed once, not per call site. */
class ConsoleReporter(
    private val color: Boolean = true,
    private val verbose: Boolean = false,
) {

    fun render(report: ScanReport): String = buildString {
        appendLine(bold("FoliaScan ${report.toolVersion}"))
        report.jars.forEach { appendLine(renderJar(it)) }
        append(renderTotals(report))
    }

    private fun renderJar(jar: JarReport): String = buildString {
        val label = listOfNotNull(jar.pluginName, jar.pluginVersion).joinToString(" ")
        appendLine()
        appendLine(bold(if (label.isBlank()) jar.jar else "$label  (${jar.jar})"))
        appendLine("  main class        ${jar.mainClass ?: "-"}")
        appendLine("  api-version       ${jar.apiVersion ?: "-"}")
        appendLine(
            "  folia-supported   " +
                if (jar.declaresFoliaSupport) green("declared") else red("not declared"),
        )
        appendLine("  classes scanned   ${jar.classesScanned}")
        appendLine(
            "  Folia API usage   ${jar.foliaApiUsages} call site(s) " +
                if (jar.foliaApiUsages == 0) dim("(no migration work detected)") else "",
        )
        jar.notes.forEach { appendLine("  note              ${dim(it)}") }

        if (jar.findings.isEmpty()) {
            appendLine()
            appendLine("  ${green("No findings from the enabled rules.")}")
            return@buildString
        }

        jar.findings
            .groupBy { it.ruleId }
            .entries
            .sortedWith(
                compareByDescending<Map.Entry<String, List<Finding>>> {
                    it.value.first().severity.rank
                }.thenBy { it.key },
            )
            .forEach { (_, group) -> append(renderGroup(group)) }
    }

    private fun renderGroup(group: List<Finding>): String = buildString {
        val first = group.first()
        appendLine()
        appendLine(
            "  ${tag(first.severity)} ${bold(first.ruleId)}  ${first.title}" +
                if (group.size > 1) dim("  (${group.size} sites)") else "",
        )
        val shown = if (verbose) group else group.take(MAX_SITES)
        shown.forEach { f ->
            appendLine("      ${f.location.render()}   ${cyan(f.evidence)}")
            f.context?.let { appendLine("        ${dim("reached off-region: $it")}") }
        }
        if (group.size > shown.size) {
            appendLine("      ${dim("... ${group.size - shown.size} more (use --verbose)")}")
        }
        first.why.lines().forEach { appendLine("    ${dim(it)}") }
        appendLine("    fix: ${first.fix}")
        appendLine("    src: ${dim(first.provenance)}")
    }

    private fun renderTotals(report: ScanReport): String = buildString {
        val all = report.allFindings
        appendLine()
        appendLine(
            "Summary: " + Severity.entries
                .map { s -> "${all.count { it.severity == s }} ${s.label}" }
                .joinToString(", "),
        )
        val verdict = when {
            all.any { it.severity == Severity.BLOCKER } ->
                red("Will not load on Folia.")
            all.any { it.severity == Severity.CRITICAL } ->
                red("Loads on Folia, then throws when the flagged code runs.")
            all.any { it.severity == Severity.WARNING } ->
                yellow("No unconditional failure found; thread-dependent risks remain.")
            all.isEmpty() ->
                green("Nothing flagged. This is not a proof of correctness - see README limits.")
            else ->
                yellow("Informational findings only.")
        }
        appendLine("Verdict: $verdict")
    }

    private fun tag(severity: Severity): String = when (severity) {
        Severity.BLOCKER -> onRed(" BLOCKER  ")
        Severity.CRITICAL -> red("CRITICAL")
        Severity.WARNING -> yellow(" WARNING")
        Severity.INFO -> blue("    INFO")
    }

    /** ASCII escape, built at runtime so no control byte ever sits in this source. */
    private val esc: String = Char(27).toString()

    private fun wrap(code: String, text: String) =
        if (color) "$esc[${code}m$text$esc[0m" else text

    private fun bold(t: String) = wrap("1", t)
    private fun dim(t: String) = wrap("2", t)
    private fun red(t: String) = wrap("31", t)
    private fun green(t: String) = wrap("32", t)
    private fun yellow(t: String) = wrap("33", t)
    private fun blue(t: String) = wrap("36", t)
    private fun cyan(t: String) = wrap("36", t)
    private fun onRed(t: String) = wrap("41;97;1", t)

    private companion object {
        const val MAX_SITES = 8
    }
}
