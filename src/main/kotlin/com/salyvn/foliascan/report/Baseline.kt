package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.ScanReport
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Known-and-accepted findings, so a large legacy plugin can adopt the scanner in CI without
 * having to fix everything first. Fingerprints exclude line numbers, so unrelated edits do
 * not silently un-suppress a finding.
 */
@Serializable
data class BaselineFile(
    val version: Int = 1,
    val note: String = "Fingerprints accepted for this project. Remove entries as they get fixed.",
    val fingerprints: List<String> = emptyList(),
)

object Baseline {

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    fun load(path: Path): Set<String> {
        if (!Files.exists(path)) return emptySet()
        val text = Files.readString(path)
        return json.decodeFromString<BaselineFile>(text).fingerprints.toSet()
    }

    fun write(path: Path, report: ScanReport) {
        val file = BaselineFile(
            fingerprints = report.allFindings.map { it.fingerprint() }.distinct().sorted(),
        )
        path.parent?.let { Files.createDirectories(it) }
        Files.writeString(path, json.encodeToString(file))
    }

    /** Drops findings whose fingerprint is baselined. */
    fun apply(report: ScanReport, suppressed: Set<String>): ScanReport {
        if (suppressed.isEmpty()) return report
        return report.copy(
            jars = report.jars.map { jar ->
                jar.copy(findings = jar.findings.filter { it.fingerprint() !in suppressed })
            },
        )
    }
}
