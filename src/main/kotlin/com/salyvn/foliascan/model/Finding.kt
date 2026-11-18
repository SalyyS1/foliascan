package com.salyvn.foliascan.model

import java.security.MessageDigest
import kotlinx.serialization.Serializable

/**
 * How badly a finding hurts.
 *
 * BLOCKER  - the plugin will not even load on Folia.
 * CRITICAL - Folia throws unconditionally when this code path runs.
 * WARNING  - Folia throws or corrupts state depending on the calling thread/region.
 * INFO     - behaviour differs enough to need a human look; no automatic verdict.
 */
@Serializable
enum class Severity(val label: String, val rank: Int) {
    BLOCKER("blocker", 4),
    CRITICAL("critical", 3),
    WARNING("warning", 2),
    INFO("info", 1),
    ;

    companion object {
        fun parse(value: String): Severity? =
            entries.firstOrNull { it.label.equals(value, ignoreCase = true) }
    }
}

/** Where in the scanned artifact a finding sits. */
@Serializable
data class CodeLocation(
    val jar: String,
    /** Binary class name, e.g. `com.example.MyPlugin`. */
    val className: String,
    /** Method the call site sits in, or null for jar/manifest-level findings. */
    val method: String? = null,
    /** Source line from the class file's LineNumberTable, if the jar kept debug info. */
    val line: Int? = null,
    /** Source file name from the class file, if present. */
    val sourceFile: String? = null,
) {
    fun render(): String = buildString {
        append(className)
        method?.let { append("#").append(it) }
        if (sourceFile != null && line != null) {
            append(" (").append(sourceFile).append(":").append(line).append(")")
        } else if (line != null) {
            append(":").append(line)
        }
    }
}

/** One problem found in one place. */
@Serializable
data class Finding(
    val ruleId: String,
    val severity: Severity,
    val title: String,
    /** What was actually seen, e.g. `Bukkit.getScheduler()`. */
    val evidence: String,
    val why: String,
    val fix: String,
    val location: CodeLocation,
    /** Which Folia source artifact backs this rule's claim. */
    val provenance: String,
    /** True when the finding depends on the calling thread rather than being unconditional. */
    val contextual: Boolean = false,
    /** For contextual findings: how this code is reached off-region. */
    val context: String? = null,
    /** Ordered call-chain hops from the off-region entry point down to this sink call site. */
    val callChain: List<CodeLocation> = emptyList(),
) {
    /**
     * Stable identity for baseline suppression. Deliberately excludes the line number so
     * that unrelated edits above a call site do not resurrect a suppressed finding.
     */
    fun fingerprint(): String =
        listOf(ruleId, location.className, location.method ?: "-", evidence).joinToString("|")

    /**
     * Lambda-renumber-resilient SHA-256 structural digest (64-bit hex prefix) for Baseline v2
     * and SARIF partialFingerprints. Normalises javac/kotlinc synthetic lambda suffixes
     * (`lambda$foo$0`, `foo$lambda$2`, `$1`) so adding an unrelated closure earlier in the same
     * class does not invalidate baselined findings.
     */
    fun structuralHash(): String {
        val normClass = normalizeSyntheticClass(location.className)
        val normMethod = location.method?.let(::normalizeSyntheticMethod) ?: "-"
        val chainShape = callChain.joinToString("->") { hop ->
            val cls = normalizeSyntheticClass(hop.className.substringAfterLast('.'))
            val m = hop.method?.let(::normalizeSyntheticMethod) ?: "-"
            "$cls#$m"
        }
        val payload = listOf(ruleId, normClass, normMethod, evidence, chainShape).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(Charsets.UTF_8))
        val hex = buildString(16) {
            for (i in 0 until 8) {
                append(String.format("%02x", digest[i].toInt() and 0xff))
            }
        }
        return "sha256-16:$hex"
    }

    companion object {
        fun normalizeSyntheticMethod(name: String): String {
            val lastDollar = name.lastIndexOf('$')
            if (lastDollar > 0 && lastDollar + 1 < name.length) {
                val suffix = name.substring(lastDollar + 1)
                if (suffix.all { it.isDigit() }) {
                    val prefix = name.substring(0, lastDollar + 1)
                    if (prefix.startsWith("lambda\$") || prefix.endsWith("\$lambda\$")) {
                        return "${prefix}*"
                    }
                }
            }
            return name
        }

        fun normalizeSyntheticClass(className: String): String {
            val lastDollar = className.lastIndexOf('$')
            if (lastDollar > 0 && lastDollar + 1 < className.length) {
                val suffix = className.substring(lastDollar + 1)
                if (suffix.all { it.isDigit() }) {
                    return className.substring(0, lastDollar + 1) + "*"
                }
            }
            return className
        }
    }
}

/** Everything learned about one jar. */
@Serializable
data class JarReport(
    val jar: String,
    val pluginName: String? = null,
    val pluginVersion: String? = null,
    val mainClass: String? = null,
    val apiVersion: String? = null,
    /** False when the jar carries no plugin descriptor at all, i.e. it is a plain library. */
    val hasDescriptor: Boolean = true,
    val declaresFoliaSupport: Boolean = false,
    /** Class count actually analysed (after package filtering). */
    val classesScanned: Int = 0,
    /** Call sites into the Paper threaded-region scheduler API - evidence of migration work. */
    val foliaApiUsages: Int = 0,
    /** Things the operator should know about the scan itself, not about the plugin's code. */
    val notes: List<String> = emptyList(),
    val findings: List<Finding> = emptyList(),
) {
    fun countOf(severity: Severity): Int = findings.count { it.severity == severity }

    val worst: Severity?
        get() = findings.maxByOrNull { it.severity.rank }?.severity
}

/** Everything learned in one run. */
@Serializable
data class ScanReport(
    val toolVersion: String,
    val jars: List<JarReport>,
) {
    val allFindings: List<Finding> get() = jars.flatMap { it.findings }

    fun worstRank(): Int = allFindings.maxOfOrNull { it.severity.rank } ?: 0
}
