package com.salyvn.foliascan

import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.report.Baseline
import com.salyvn.foliascan.report.ConsoleReporter
import com.salyvn.foliascan.report.JsonReporter
import com.salyvn.foliascan.report.SarifReporter
import com.salyvn.foliascan.scan.JarScanner
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReportFormatTest {

    private val report: ScanReport = ScanReport(
        toolVersion = "test",
        jars = listOf(JarScanner().scan(FixtureJars.legacy())),
    )

    @Test
    fun `json output round-trips`() {
        val text = JsonReporter.render(report)
        val parsed = Json { ignoreUnknownKeys = true }.decodeFromString<ScanReport>(text)
        assertEquals(report.allFindings.size, parsed.allFindings.size)
        assertEquals(report.jars.single().jar, parsed.jars.single().jar)
    }

    @Test
    fun `sarif output is well formed and maps severities`() {
        val sarif = Json.parseToJsonElement(SarifReporter.render(report)).jsonObject
        assertEquals("2.1.0", sarif["version"]!!.jsonPrimitive.content)

        val run = sarif["runs"]!!.jsonArray.single().jsonObject
        val driver = run["tool"]!!.jsonObject["driver"]!!.jsonObject
        assertEquals("FoliaScan", driver["name"]!!.jsonPrimitive.content)

        val declaredRules = driver["rules"]!!.jsonArray
            .map { it.jsonObject["id"]!!.jsonPrimitive.content }
            .toSet()
        val usedRules = report.allFindings.map { it.ruleId }.toSet()
        assertEquals(usedRules, declaredRules, "every reported rule must be declared")

        val results = run["results"]!!.jsonArray
        assertEquals(report.allFindings.size, results.size)
        val levels = results.map { it.jsonObject["level"]!!.jsonPrimitive.content }.toSet()
        assertTrue(levels.all { it in setOf("error", "warning", "note") }) { "bad levels: $levels" }
        assertTrue("error" in levels, "blocker and critical findings should map to error")

        results.forEach { result ->
            val fingerprints = result.jsonObject["partialFingerprints"]!!.jsonObject
            assertNotNull(fingerprints["foliascan/v1"], "result is missing its fingerprint")
        }
    }

    @Test
    fun `baseline round-trip suppresses everything it recorded`() {
        val file = Files.createTempFile("foliascan-baseline", ".json")
        file.toFile().deleteOnExit()

        Baseline.write(file, report)
        val loaded = Baseline.load(file)
        assertEquals(report.allFindings.map { it.fingerprint() }.distinct().size, loaded.size)

        val suppressed = Baseline.apply(report, loaded)
        assertTrue(suppressed.allFindings.isEmpty()) {
            "left over: ${suppressed.allFindings.map { it.ruleId }}"
        }
        assertEquals(0, suppressed.worstRank())
    }

    @Test
    fun `console output stays plain when colour is disabled`() {
        val text = ConsoleReporter(color = false).render(report)
        assertFalse(text.contains(Char(27)), "ANSI escape leaked into no-colour output")
        assertTrue(text.contains("Verdict:"))
        assertTrue(text.contains("FS001"))
    }

    @Test
    fun `severity parsing accepts the documented labels`() {
        assertEquals(Severity.BLOCKER, Severity.parse("blocker"))
        assertEquals(Severity.CRITICAL, Severity.parse("CRITICAL"))
        assertEquals(null, Severity.parse("never"))
    }
}
