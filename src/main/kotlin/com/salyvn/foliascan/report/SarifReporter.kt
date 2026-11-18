package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.CodeLocation
import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.rules.RuleCatalog
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * OASIS SARIF v2.1.0 output tailored for GitHub Actions `github/codeql-action/upload-sarif`
 * (Security -> Code scanning) as well as general SARIF 2.1.0 consumers.
 *
 * A compiled plugin JAR carries a class package and `SourceFile` attribute rather than a full
 * repository-relative path, so `artifactLocation.uri` is reconstructed against `%SRCROOT%` for
 * conventional Gradle/Maven source trees while `logicalLocations` always records the exact JVM
 * binary class and method. Contextual findings with multi-hop regional taint also emit SARIF
 * `codeFlows` / `threadFlows` so GitHub Code Scanning renders the step-by-step async call chain.
 */
object SarifReporter {

    const val SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    const val VERSION = "2.1.0"
    const val INFO_URI = "https://github.com/SalyyS1/foliascan"
    private const val RULES_HELP_URI = "$INFO_URI#rules"

    private val json = Json { prettyPrint = true }

    fun render(report: ScanReport): String {
        val used = report.allFindings.map { it.ruleId }.distinct().sorted()
        val ruleIndices = used.withIndex().associate { (idx, id) -> id to idx }
        val sarif = buildJsonObject {
            put("\$schema", SCHEMA)
            put("version", VERSION)
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
                            report.allFindings.forEach { finding ->
                                add(resultObject(finding, ruleIndices[finding.ruleId] ?: 0))
                            }
                        }
                    },
                )
            }
        }
        return json.encodeToString(sarif)
    }

    private fun ruleObject(ruleId: String) = buildJsonObject {
        val rule = RuleCatalog.byId(ruleId)
        val title = rule?.title ?: ruleId
        val whyText = rule?.why?.oneLine() ?: title
        val fixText = rule?.fix?.oneLine() ?: ""
        val provText = rule?.provenance?.render() ?: ""
        val sevLevel = level(rule?.severity)

        put("id", ruleId)
        put("name", pascalIdentifier(title, fallback = ruleId))
        putJsonObject("shortDescription") { put("text", title) }
        putJsonObject("fullDescription") { put("text", whyText) }
        put("helpUri", RULES_HELP_URI)
        putJsonObject("help") {
            put("text", fixText)
            put(
                "markdown",
                buildString {
                    append("**Why this fails on Folia:** ").append(whyText)
                    if (fixText.isNotEmpty()) {
                        append("\n\n**Recommended Fix:** ").append(fixText)
                    }
                    if (provText.isNotEmpty()) {
                        append("\n\n**Folia Patch Provenance:** `").append(provText).append("`")
                    }
                },
            )
        }
        putJsonObject("defaultConfiguration") { put("level", sevLevel) }
        putJsonObject("properties") {
            put("provenance", provText)
            put("problem.severity", sevLevel)
            putJsonArray("tags") {
                add("folia")
                add("minecraft")
                add("concurrency")
                add("thread-safety")
            }
        }
    }

    private fun resultObject(finding: Finding, ruleIndex: Int) = buildJsonObject {
        put("ruleId", finding.ruleId)
        put("ruleIndex", ruleIndex)
        put("level", level(finding.severity))
        putJsonObject("message") {
            val reached = finding.context?.let { " ${it.replaceFirstChar(Char::uppercaseChar)}." } ?: ""
            put("text", "${finding.title}: ${finding.evidence}.$reached ${finding.why.oneLine()}")
        }
        putJsonArray("locations") {
            add(locationObject(finding.location))
        }
        if (finding.callChain.size >= 2) {
            putJsonArray("codeFlows") {
                add(
                    buildJsonObject {
                        putJsonArray("threadFlows") {
                            add(
                                buildJsonObject {
                                    putJsonArray("locations") {
                                        finding.callChain.forEachIndexed { idx, hop ->
                                            val role = flowStepRole(finding, idx, finding.callChain.lastIndex)
                                            add(
                                                buildJsonObject {
                                                    putJsonObject("location") {
                                                        putPhysicalLocation(hop)
                                                        putLogicalLocations(hop)
                                                        putJsonObject("message") {
                                                            put("text", "$role: ${hop.render()}")
                                                        }
                                                    }
                                                },
                                            )
                                        }
                                    }
                                },
                            )
                        }
                    },
                )
            }
        }
        putJsonObject("partialFingerprints") {
            put("foliascan/v1", finding.fingerprint())
            put("foliascan/structuralHash/v2", finding.structuralHash())
        }
    }

    private fun locationObject(loc: CodeLocation) = buildJsonObject {
        putPhysicalLocation(loc)
        putLogicalLocations(loc)
    }

    private fun kotlinx.serialization.json.JsonObjectBuilder.putPhysicalLocation(loc: CodeLocation) {
        putJsonObject("physicalLocation") {
            putJsonObject("artifactLocation") {
                put("uri", artifactUri(loc))
                put("uriBaseId", "%SRCROOT%")
            }
            loc.line?.takeIf { it >= 1 }?.let { line ->
                putJsonObject("region") { put("startLine", line) }
            }
        }
    }

    private fun kotlinx.serialization.json.JsonObjectBuilder.putLogicalLocations(loc: CodeLocation) {
        putJsonArray("logicalLocations") {
            add(
                buildJsonObject {
                    put("fullyQualifiedName", loc.render())
                    put("kind", if (loc.method != null) "function" else "type")
                },
            )
        }
    }

    /** Reconstructs a clean repository-relative path with forward slashes for SARIF consumers. */
    internal fun artifactUri(loc: CodeLocation): String {
        val source = loc.sourceFile
        if (source != null) {
            val pkg = loc.className.substringBeforeLast('.', "")
            val dir = if (pkg.isEmpty()) "" else pkg.replace('.', '/') + "/"
            val root = if (source.endsWith(".kt")) "src/main/kotlin/" else "src/main/java/"
            return "$root$dir$source"
        }
        if (loc.className == "plugin.yml" || loc.className == "paper-plugin.yml") {
            return "src/main/resources/${loc.className}"
        }
        if (loc.className.isNotBlank()) {
            val outer = loc.className.replace('/', '.').substringBefore('$')
            return "src/main/java/${outer.replace('.', '/')}.java"
        }
        return loc.jar.replace('\\', '/').trimStart('/')
    }

    /** Converts a human rule title into a whitespace-free PascalCase SARIF descriptor name. */
    internal fun pascalIdentifier(title: String, fallback: String): String {
        val tokens = title.split(Regex("[^A-Za-z0-9]+")).filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return fallback
        return tokens.joinToString("") { tok ->
            tok.first().uppercaseChar() + tok.drop(1)
        }
    }

    private fun flowStepRole(finding: Finding, idx: Int, lastIdx: Int): String = when {
        idx == 0 -> when (finding.ruleId) {
            "FS081", "FS105" -> "Concurrent scheduler entry"
            "FS088" -> "Async chunk-generation taint entry"
            "FS090" -> "Block-entity snapshot capture and schedule"
            "FS101" -> "Coroutine suspension or async continuation entry"
            "FS106" -> "Location-keyed RegionScheduler closure capture"
            "FS107" -> "Delayed or cross-region Chunk closure capture"
            else -> "Off-region taint entry"
        }
        idx == lastIdx -> when (finding.ruleId) {
            "FS081" -> "Unsynchronized static mutation sink (${finding.evidence})"
            "FS087" -> "Blocking region-future sink (${finding.evidence})"
            "FS088" -> "Live-world escape sink (${finding.evidence})"
            "FS090" -> "Delayed or cross-region block-entity sink (${finding.evidence})"
            "FS101" -> "Unconfined continuation resumption sink (${finding.evidence})"
            "FS105" -> "Unsynchronized instance collection mutation sink (${finding.evidence})"
            "FS106" -> "Unowned captured entity mutation sink (${finding.evidence})"
            "FS107" -> "Captured live Chunk access sink (${finding.evidence})"
            else -> "Region-guarded sink (${finding.evidence})"
        }
        else -> "In-jar call, closure wrapper, or interface dispatch hop $idx"
    }

    private fun level(severity: Severity?): String = when (severity) {
        Severity.BLOCKER, Severity.CRITICAL -> "error"
        Severity.WARNING -> "warning"
        else -> "note"
    }

    private fun String.oneLine(): String = replace(Regex("\\s+"), " ").trim()
}
