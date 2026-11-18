package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.Finding
import com.salyvn.foliascan.model.ScanReport
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class BaselineEntry(
    val fingerprint: String,
    val structuralHash: String,
    val ruleId: String,
    val severity: String,
    val className: String,
    val method: String? = null,
)

/**
 * Known-and-accepted findings, so a large legacy plugin can adopt the scanner in CI without
 * having to fix everything first. Fingerprints exclude line numbers, and v2 structural hashes
 * normalise javac/kotlinc synthetic lambda ordinal suffixes (`lambda$foo$0` -> `lambda$foo$*`),
 * so unrelated edits or new lambdas above a call site do not silently un-suppress a finding.
 */
@Serializable
data class BaselineFile(
    val version: Int = 2,
    val note: String = "Fingerprints accepted for this project. Remove entries as they get fixed.",
    val fingerprints: List<String> = emptyList(),
    val entries: List<BaselineEntry> = emptyList(),
)

data class BaselineMatcher(
    val exactFingerprints: Set<String> = emptySet(),
    val structuralHashes: Set<String> = emptySet(),
) {
    val isEmpty: Boolean get() = exactFingerprints.isEmpty() && structuralHashes.isEmpty()

    fun matches(finding: Finding): Boolean =
        finding.fingerprint() in exactFingerprints || finding.structuralHash() in structuralHashes
}

object Baseline {

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true; encodeDefaults = true }

    fun load(path: Path): Set<String> {
        if (!Files.exists(path)) return emptySet()
        val parsed = json.decodeFromString<BaselineFile>(Files.readString(path))
        val fromEntries = parsed.entries.map { it.fingerprint }
        return (parsed.fingerprints + fromEntries).toSet()
    }

    fun loadMatcher(path: Path): BaselineMatcher {
        if (!Files.exists(path)) return BaselineMatcher()
        val parsed = json.decodeFromString<BaselineFile>(Files.readString(path))
        return BaselineMatcher(
            exactFingerprints = (parsed.fingerprints + parsed.entries.map { it.fingerprint }).toSet(),
            structuralHashes = parsed.entries.map { it.structuralHash }.filter { it.isNotBlank() }.toSet(),
        )
    }

    fun write(path: Path, report: ScanReport) {
        val uniqueByFp = LinkedHashMap<String, Finding>()
        for (f in report.allFindings) {
            uniqueByFp.putIfAbsent(f.fingerprint(), f)
        }
        val sortedFps = uniqueByFp.keys.sorted()
        val entries = sortedFps.map { fp ->
            val f = uniqueByFp.getValue(fp)
            BaselineEntry(
                fingerprint = fp,
                structuralHash = f.structuralHash(),
                ruleId = f.ruleId,
                severity = f.severity.label,
                className = f.location.className,
                method = f.location.method,
            )
        }
        val file = BaselineFile(
            version = 2,
            fingerprints = sortedFps,
            entries = entries,
        )
        path.parent?.let { Files.createDirectories(it) }
        Files.writeString(path, json.encodeToString(file))
    }

    /** Drops findings whose exact fingerprint is baselined. */
    fun apply(report: ScanReport, suppressed: Set<String>): ScanReport {
        if (suppressed.isEmpty()) return report
        return apply(report, BaselineMatcher(exactFingerprints = suppressed))
    }

    /** Drops findings matched by either exact v1 fingerprint or v2 structural hash. */
    fun apply(report: ScanReport, matcher: BaselineMatcher): ScanReport {
        if (matcher.isEmpty) return report
        return report.copy(
            jars = report.jars.map { jar ->
                val kept = mutableListOf<Finding>()
                var suppressedCount = 0
                for (f in jar.findings) {
                    if (matcher.matches(f)) suppressedCount++ else kept += f
                }
                val updatedNotes = if (suppressedCount > 0) {
                    jar.notes + "Suppressed $suppressedCount baselined finding(s)"
                } else {
                    jar.notes
                }
                jar.copy(findings = kept, notes = updatedNotes)
            },
        )
    }
}
