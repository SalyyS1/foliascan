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
    fun `a patcher-declared folia flag is reported instead of trusted`() {
        val report = scanner.scan(FixtureJars.patchedByFoliaPhantom())
        val ids = report.findings.map { it.ruleId }.toSet()

        assertTrue(report.declaresFoliaSupport, "fixture should declare support")
        assertFalse("FS001" in ids, "the load-time flag is present, so FS001 must not fire")
        assertTrue("FS002" in ids) { "patcher marker not detected: $ids" }

        val finding = report.findings.first { it.ruleId == "FS002" }
        assertTrue(finding.evidence.contains("FoliaPhantom"))
        assertTrue(finding.why.contains("unconditionally"))
    }

    @Test
    fun `an unpatched jar is not accused of being patched`() {
        val ids = scanner.scan(FixtureJars.legacy()).findings.map { it.ruleId }.toSet()
        assertFalse("FS002" in ids)
    }

    @Test
    fun `sibling packages are scanned when main sits in a platform subpackage`() {
        val report = scanner.scan(FixtureJars.mainInPlatformSubpackage())
        val classes = report.findings.map { it.location.className }

        assertTrue(
            classes.any { it.startsWith("fixtures.multi.core") },
            "the sibling package next to main was not scanned; findings: $classes",
        )
        assertTrue(report.classesScanned >= 2) { "only ${report.classesScanned} class(es) scanned" }
        assertTrue(
            report.notes.any { it.contains("fixtures.multi") && !it.contains("fixtures.multi.platform") },
            "the widened root was not reported: ${report.notes}",
        )
    }

    @Test
    fun `a legacy branch behind a Folia check is not reported as a hard failure`() {
        val report = scanner.scan(FixtureJars.dualMode())
        val guarded = report.findings.filter { it.location.className.endsWith("LegacyTasks") }

        assertTrue(guarded.isNotEmpty()) {
            "the guarded legacy branch was not analysed at all; classes seen: " +
                report.findings.map { it.location.className }.distinct()
        }
        assertTrue(
            guarded.all { it.severity == Severity.INFO },
            "a provably unreachable branch was still reported as a failure: " +
                guarded.map { "${it.ruleId}=${it.severity}" },
        )
        assertTrue(
            guarded.all { it.context?.contains("not reachable on Folia") == true },
            "the downgrade did not say why: ${guarded.map { it.context }}",
        )
        assertTrue(
            guarded.any { it.context!!.contains("IS_FOLIA", ignoreCase = true) },
            "the guard site was not named: ${guarded.map { it.context }.distinct()}",
        )
    }

    @Test
    fun `a legacy branch inside an otherwise region-aware method is not a hard failure`() {
        val report = scanner.scan(FixtureJars.dualMode())
        val branching = report.findings.filter { it.location.className.endsWith("BranchingTasks") }

        assertTrue(branching.isNotEmpty()) {
            "the branching class was not analysed; classes seen: " +
                report.findings.map { it.location.className }.distinct()
        }
        assertTrue(
            branching.all { it.severity == Severity.INFO },
            "a branch guarded in the same method was still reported as a failure: " +
                branching.map { "${it.location.method}=${it.ruleId}/${it.severity}" },
        )
        assertTrue(
            branching.any { it.location.method?.contains("lambda") == true },
            "the task built inside the legacy branch was not analysed: " +
                branching.map { it.location.method },
        )
    }

    @Test
    fun `the same legacy calls are still reported when nothing guards them`() {
        val report = scanner.scan(FixtureJars.dualMode())
        val unguarded = report.findings.filter { it.location.className.endsWith("UnguardedTasks") }

        assertTrue(unguarded.isNotEmpty()) {
            "control class was not analysed; classes seen: " +
                report.findings.map { it.location.className }.distinct()
        }
        assertTrue(
            unguarded.any { it.severity == Severity.CRITICAL },
            "the guard downgrade leaked onto unguarded code: " +
                unguarded.map { "${it.ruleId}=${it.severity}" },
        )
        assertEquals(Severity.CRITICAL, report.worst)
    }

    @Test
    fun `a library is blamed even when its own name is on the relocated-dependency list`() {
        val report = scanner.scan(FixtureJars.libraryNamedLikeAShadedDependency())

        assertTrue(report.findings.any { it.ruleId == "FS010" }) {
            "the jar under test was mistaken for a relocated dependency; notes: ${report.notes}"
        }
        assertFalse(
            report.notes.any { it.contains("relocated") },
            "nothing was relocated into this jar: ${report.notes}",
        )
    }

    @Test
    fun `a plugin rooted in a library-like package is still blamed`() {
        val report = scanner.scan(FixtureJars.pluginRootedInALibraryName())

        assertTrue(report.findings.any { it.ruleId == "FS010" }) {
            "the plugin's own root was treated as a relocation marker; notes: ${report.notes}"
        }
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
