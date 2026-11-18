package com.salyvn.foliascan

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.versionOption
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.int
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.foliascan.bench.BenchmarkSuite
import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.report.Baseline
import com.salyvn.foliascan.report.ConsoleReporter
import com.salyvn.foliascan.report.JsonReporter
import com.salyvn.foliascan.report.SarifReporter
import com.salyvn.foliascan.rules.RuleCatalog
import com.salyvn.foliascan.scan.JarScanner
import com.salyvn.foliascan.scan.ScanOptions
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile

class FoliaScanCommand : CliktCommand(name = "foliascan") {

    init {
        versionOption(BuildInfo.version)
    }

    override fun help(context: Context) =
        "Report where a Minecraft plugin jar breaks under Folia's regionised threading."

    private val paths by argument(name = "TARGET", help = "Plugin jar(s) or a directory of jars")
        .path(mustExist = true, mustBeReadable = true)
        .multiple()

    private val format by option("--format", help = "Output format")
        .choice("console", "json", "sarif").default("console")

    private val output by option("-o", "--output", help = "Write the report to this file")
        .path()

    private val sarifOut by option(
        "--sarif",
        help = "Write an OASIS SARIF 2.1.0 report to this file (can be combined with console or json output)",
    ).path()

    private val failOn by option(
        "--fail-on",
        help = "Lowest severity that makes the run exit non-zero (default: critical)",
    ).choice("blocker", "critical", "warning", "info", "never").default("critical")

    private val scanAll by option(
        "--all",
        help = "Scan every class, including relocated dependency packages",
    ).flag()

    private val includePackages by option(
        "--include",
        help = "Only scan this package (repeatable), e.g. --include com.example.plugin",
    ).multiple()

    private val excludePackages by option(
        "--exclude",
        help = "Skip this package (repeatable). Relocated dependency folders are skipped already.",
    ).multiple()

    private val disabled by option("--disable", help = "Disable a rule id (repeatable)").multiple()

    private val baselineIn by option("--baseline", help = "Suppress findings listed in this file")
        .path()

    private val baselineOut by option(
        "--write-baseline",
        help = "Write current findings to a baseline file and exit successfully",
    ).path()

    private val noColor by option("--no-color", help = "Disable ANSI colour").flag()

    private val verbose by option("-v", "--verbose", help = "List every call site").flag()

    private val listRules by option("--rules", help = "Print the rule catalog and exit").flag()

    private val benchmark by option(
        "--benchmark",
        help = "Run the synthetic multi-class bytecode benchmark suite and exit",
    ).flag()

    private val benchmarkRuns by option(
        "--benchmark-runs",
        help = "Timed passes for --benchmark (default: 20)",
    ).int().default(20)

    override fun run() {
        if (listRules) {
            echo(renderRules())
            return
        }
        if (benchmark) {
            val metrics = BenchmarkSuite.run(benchmarkRuns)
            val rendered = if (format == "json") {
                BenchmarkSuite.renderJson(metrics)
            } else {
                BenchmarkSuite.renderConsole(metrics)
            }
            output?.let { target ->
                target.parent?.let { Files.createDirectories(it) }
                Files.writeString(target, rendered)
                echo("Wrote benchmark report to $target")
            } ?: echo(rendered)
            if (!metrics.recallComplete) {
                throw ProgramResult(1)
            }
            return
        }
        val jars = expandTargets()
        if (jars.isEmpty()) {
            echo("No .jar files found in the given target(s).", err = true)
            throw ProgramResult(2)
        }

        val scanner = JarScanner(
            ScanOptions(
                scanAllPackages = scanAll,
                includePackages = includePackages.toSet(),
                excludePackages = excludePackages.toSet(),
                disabledRules = disabled.map { it.uppercase() }.toSet(),
            ),
        )
        val raw = ScanReport(toolVersion = BuildInfo.version, jars = jars.map { scanner.scan(it) })

        baselineOut?.let { target ->
            Baseline.write(target, raw)
            echo("Wrote ${raw.allFindings.size} fingerprint(s) to $target")
            return
        }

        val report = Baseline.apply(
            raw,
            baselineIn?.let { Baseline.loadMatcher(it) } ?: com.salyvn.foliascan.report.BaselineMatcher(),
        )
        val sarifRendered by lazy { SarifReporter.render(report) }

        sarifOut?.let { target ->
            target.parent?.let { Files.createDirectories(it) }
            Files.writeString(target, sarifRendered)
            if (format == "sarif" && output == null) {
                echo("Wrote sarif report to $target")
            }
        }

        if (!(format == "sarif" && sarifOut != null && output == null)) {
            val text = when (format) {
                "json" -> JsonReporter.render(report)
                "sarif" -> sarifRendered
                else -> ConsoleReporter(color = !noColor && output == null, verbose = verbose)
                    .render(report)
            }

            output?.let { target ->
                target.parent?.let { Files.createDirectories(it) }
                Files.writeString(target, text)
                echo("Wrote $format report to $target")
            } ?: echo(text)
        }

        if (sarifOut != null && !(format == "sarif" && output == null) && output != null) {
            echo("Wrote sarif report to $sarifOut")
        }

        val threshold = Severity.parse(failOn)
        if (threshold != null && report.worstRank() >= threshold.rank) {
            throw ProgramResult(1)
        }
    }

    private fun expandTargets(): List<Path> = paths.flatMap { target ->
        when {
            target.isDirectory() -> Files.list(target).use { stream ->
                stream.filter { it.isRegularFile() && it.extension.equals("jar", true) }
                    .sorted()
                    .toList()
            }
            else -> listOf(target)
        }
    }.distinct()

    private fun renderRules(): String = buildString {
        appendLine("FoliaScan ${BuildInfo.version} - ${RuleCatalog.all.size} rules")
        RuleCatalog.all.sortedBy { it.id }.forEach { rule ->
            appendLine()
            appendLine("${rule.id}  [${rule.severity.label}]  ${rule.title}")
            appendLine("  why: ${rule.why.replace(Regex("\\s+"), " ").trim()}")
            appendLine("  fix: ${rule.fix.replace(Regex("\\s+"), " ").trim()}")
            appendLine("  src: ${rule.provenance.render()}")
        }
    }
}

fun main(args: Array<String>) = FoliaScanCommand().main(args)
