package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.rules.RuleCatalog
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * SARIF 2.1.0 output so GitHub code scanning (and any other SARIF consumer) can ingest a run.
 *
 * Caveat worth knowing: a jar carries a source *file name* but not a repository path, so the
 * emitted artifact URI is reconstructed from the package plus that file name. It lines up for
 * conventional Maven/Gradle layouts and is best-effort everywhere else; the logical location
 * always carries the exact class and method.
 */
object SarifReporter {

    private const val SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    private const val INFO_URI = "https://github.com/SalyyS1/foliascan"

    private val json = Json { prettyPrint = true }

    fun render(report: ScanReport): String {
        val used = report.allFindings.map { it.ruleId }.distinct().sorted()
        val sarif = buildJsonObject {
            put("\$schema", SCHEMA)
            put("version", "2.1.0")
            putJsonArray("runs") {
                add(
                    buildJsonObject {
                        putJsonObject("tool") {
                            putJsonObject("driver") {
                                put("name", "FoliaScan")
                                put("version", report.toolVersion)
                                put("informationUri", INFO_URI)
                                putJsonArray("rules") { used.forEach { add(ruleObject(it)) } }
                            }
                        }
                        putJsonArray("results") {
                            report.allFindings.forEach { add(resultObject(it)) }
                        }
                    },
                )
            }
        }
        return json.encodeToString(sarif)
    }

    private fun ruleObject(ruleId: String) = buildJsonObject {
        val rule = RuleCatalog.byId(ruleId)
        put("id", ruleId)
        put("name", rule?.title ?: ruleId)
        putJsonObject("shortDescription") { put("text", rule?.title ?: ruleId) }
        putJsonObject("fullDescription") { put("text", rule?.why?.oneLine() ?: "") }
        putJsonObject("help") { put("text", rule?.fix ?: "") }
        putJsonObject("defaultConfiguration") { put("level", level(rule?.severity)) }
        putJsonObject("properties") {
            put("provenance", rule?.provenance?.render() ?: "")
            putJsonArray("tags") {
                add("folia")
                add("minecraft")
                add("concurrency")
            }
        }
    }

    private fun resultObject(finding: Finding) = buildJsonObject {
        put("ruleId", finding.ruleId)
        put("level", level(finding.severity))
        putJsonObject("message") {
            val reached = finding.context?.let { " ${it.replaceFirstChar(Char::uppercaseChar)}." } ?: ""
            put("text", "${finding.title}: ${finding.evidence}.$reached ${finding.why.oneLine()}")
        }
        putJsonArray("locations") {
            add(
                buildJsonObject {
                    putJsonObject("physicalLocation") {
                        putJsonObject("artifactLocation") { put("uri", artifactUri(finding)) }
                        finding.location.line?.let { line ->
                            putJsonObject("region") { put("startLine", line) }
                        }
                    }
                    putJsonArray("logicalLocations") {
                        add(
                            buildJsonObject {
                                put("fullyQualifiedName", finding.location.render())
                                put("kind", if (finding.location.method != null) "function" else "type")
                            },
                        )
                    }
                },
            )
        }
        putJsonObject("partialFingerprints") { put("foliascan/v1", finding.fingerprint()) }
    }

    /** Reconstructs a plausible repository path from the package and the source file name. */
    private fun artifactUri(finding: Finding): String {
        val source = finding.location.sourceFile ?: return finding.location.jar
        val pkg = finding.location.className.substringBeforeLast('.', "")
        val dir = if (pkg.isEmpty()) "" else pkg.replace('.', '/') + "/"
        val root = if (source.endsWith(".kt")) "src/main/kotlin/" else "src/main/java/"
        return "$root$dir$source"
    }

    private fun level(severity: Severity?): String = when (severity) {
        Severity.BLOCKER, Severity.CRITICAL -> "error"
        Severity.WARNING -> "warning"
        else -> "note"
    }

    private fun String.oneLine(): String = replace(Regex("\\s+"), " ").trim()
}
