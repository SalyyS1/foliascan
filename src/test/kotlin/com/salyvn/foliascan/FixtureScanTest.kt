package com.salyvn.foliascan

import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.scan.JarScanner
import com.salyvn.foliascan.scan.ScanOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FixtureScanTest {

    private val scanner = JarScanner()

    @Test
    fun `legacy fixture reports every unconditional Folia failure`() {
        val report = scanner.scan(FixtureJars.legacy())
        val ids = report.findings.map { it.ruleId }.toSet()

        listOf("FS001", "FS010", "FS011", "FS012", "FS020", "FS030", "FS031", "FS040")
            .forEach { expected ->
                assertTrue(expected in ids) { "expected $expected, got $ids" }
            }
        assertFalse(report.declaresFoliaSupport)
        assertEquals(Severity.BLOCKER, report.worst)
        assertEquals(0, report.foliaApiUsages, "legacy fixture uses none of the Folia API")
    }

    @Test
    fun `findings carry the source line so they are actionable`() {
        val report = scanner.scan(FixtureJars.legacy())
        val located = report.findings.filter { it.location.line != null }
        assertTrue(located.isNotEmpty(), "no finding carried a line number")
        assertTrue(
            located.all { it.location.sourceFile == "LegacyPlugin.kt" },
            "unexpected source files: ${located.map { it.location.sourceFile }.distinct()}",
        )
    }

    @Test
    fun `off-region findings appear inside executor lambdas`() {
        val contextual = scanner.scan(FixtureJars.legacy()).findings.filter { it.contextual }
        val ids = contextual.map { it.ruleId }.toSet()
        assertTrue("FS063" in ids) { "entity API in an executor lambda not flagged: $ids" }
        assertTrue(
            contextual.all { it.context != null },
            "a contextual finding did not explain how the code is reached off-region",
        )
        assertTrue(
            contextual.any { it.context!!.contains("ExecutorService.submit") },
            "executor entry point was not named: ${contextual.map { it.context }.distinct()}",
        )
    }

    @Test
    fun `off-region taint propagates one call deep into a helper`() {
        val report = scanner.scan(FixtureJars.legacy())
        val helper = report.findings.filter { it.location.method == "refreshHelper" }
        assertTrue(helper.isNotEmpty()) {
            "helper called from an executor lambda was not analysed; methods seen: " +
                report.findings.mapNotNull { it.location.method }.distinct()
        }
        assertTrue(helper.all { it.contextual })
    }

    @Test
    fun `region aware fixture produces no hard failures`() {
        val report = scanner.scan(FixtureJars.regionAware())
        val ids = report.findings.map { it.ruleId }.toSet()

        listOf("FS001", "FS010", "FS011", "FS012", "FS020", "FS030", "FS031", "FS040")
            .forEach { unexpected ->
                assertFalse(unexpected in ids) {
                    "false positive $unexpected: " +
                        report.findings.filter { it.ruleId == unexpected }.map { it.location.render() }
                }
            }
        assertTrue(report.declaresFoliaSupport)
        assertTrue(report.foliaApiUsages > 0) { "Folia scheduler usage was not detected" }
    }

    @Test
    fun `a jar without a descriptor is not blamed for the load-time flag`() {
        val report = scanner.scan(FixtureJars.libraryWithoutDescriptor())
        assertFalse(report.findings.any { it.ruleId == "FS001" })
        assertTrue(report.notes.any { it.contains("library") })
    }

    @Test
    fun `disabling a rule removes only that rule`() {
        val report = JarScanner(ScanOptions(disabledRules = setOf("FS030")))
            .scan(FixtureJars.legacy())
        val ids = report.findings.map { it.ruleId }.toSet()
        assertFalse("FS030" in ids)
        assertTrue("FS031" in ids)
    }

    @Test
    fun `fingerprints are stable and line independent`() {
        val first = scanner.scan(FixtureJars.legacy()).findings.map { it.fingerprint() }
        val second = scanner.scan(FixtureJars.legacy()).findings.map { it.fingerprint() }
        assertEquals(first, second)
        assertTrue(
            first.none { it.contains(".kt:") },
            "fingerprint leaked a source line and would break on unrelated edits",
        )
    }
}
