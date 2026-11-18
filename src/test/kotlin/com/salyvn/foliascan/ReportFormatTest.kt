package com.salyvn.foliascan

import com.github.ajalt.clikt.testing.test
import com.salyvn.foliascan.model.CodeLocation
import com.salyvn.foliascan.model.ScanReport
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.report.Baseline
import com.salyvn.foliascan.report.ConsoleReporter
import com.salyvn.foliascan.report.JsonReporter
import com.salyvn.foliascan.report.SarifReporter
import com.salyvn.foliascan.scan.JarScanner
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
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
        toolVersion = "0.3.0",
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
    fun `sarif v2_1_0 schema structure and driver metadata are valid`() {
        val sarif = Json.parseToJsonElement(SarifReporter.render(report)).jsonObject
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", sarif["\$schema"]!!.jsonPrimitive.content)
        assertEquals("2.1.0", sarif["version"]!!.jsonPrimitive.content)

        val run = sarif["runs"]!!.jsonArray.single().jsonObject
        val driver = run["tool"]!!.jsonObject["driver"]!!.jsonObject
        assertEquals("FoliaScan", driver["name"]!!.jsonPrimitive.content)
        assertEquals("0.3.0", driver["version"]!!.jsonPrimitive.content)
        assertEquals("https://github.com/SalyyS1/foliascan", driver["informationUri"]!!.jsonPrimitive.content)

        val rules = driver["rules"]!!.jsonArray
        assertTrue(rules.isNotEmpty())
        rules.forEach { ruleEl ->
            val ruleObj = ruleEl.jsonObject
            val ruleName = ruleObj["name"]!!.jsonPrimitive.content
            assertFalse(ruleName.any { it.isWhitespace() }, "SARIF rule.name must not contain whitespace: $ruleName")
            assertTrue(ruleObj["shortDescription"]!!.jsonObject["text"]!!.jsonPrimitive.content.isNotBlank())
            assertTrue(ruleObj["fullDescription"]!!.jsonObject["text"]!!.jsonPrimitive.content.isNotBlank())
            val helpObj = ruleObj["help"]!!.jsonObject
            assertTrue(helpObj["text"]!!.jsonPrimitive.content.isNotBlank())
            assertTrue(helpObj["markdown"]!!.jsonPrimitive.content.contains("Recommended Fix"))
            assertEquals("https://github.com/SalyyS1/foliascan#rules", ruleObj["helpUri"]!!.jsonPrimitive.content)
        }

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
    fun `sarif deduplicates rules across multiple jars and maps ruleIndex`() {
        val multiJarReport = ScanReport(
            toolVersion = "0.3.0",
            jars = listOf(
                JarScanner().scan(FixtureJars.legacy()),
                JarScanner().scan(FixtureJars.dualMode()),
            ),
        )
        assertTrue(
            multiJarReport.allFindings.size > multiJarReport.allFindings.map { it.ruleId }.distinct().size,
            "expected duplicate rule hits across findings",
        )

        val sarif = Json.parseToJsonElement(SarifReporter.render(multiJarReport)).jsonObject
        val run = sarif["runs"]!!.jsonArray.single().jsonObject
        val rules = run["tool"]!!.jsonObject["driver"]!!.jsonObject["rules"]!!.jsonArray
        val ruleIds = rules.map { it.jsonObject["id"]!!.jsonPrimitive.content }

        assertEquals(ruleIds.distinct(), ruleIds, "driver.rules must not contain duplicate rule IDs")
        assertEquals(ruleIds.sorted(), ruleIds, "driver.rules should be deterministically sorted")
        assertEquals(multiJarReport.allFindings.map { it.ruleId }.toSet(), ruleIds.toSet())

        val results = run["results"]!!.jsonArray
        results.forEach { resEl ->
            val obj = resEl.jsonObject
            val ruleId = obj["ruleId"]!!.jsonPrimitive.content
            val ruleIdx = obj["ruleIndex"]!!.jsonPrimitive.int
            assertEquals(ruleId, ruleIds[ruleIdx], "ruleIndex $ruleIdx did not point to $ruleId")
        }
    }

    @Test
    fun `sarif maps source paths bytecode line numbers and regional taint call chains`() {
        val sarif = Json.parseToJsonElement(SarifReporter.render(report)).jsonObject
        val results = sarif["runs"]!!.jsonArray.single().jsonObject["results"]!!.jsonArray

        // 1. Descriptor finding FS001 maps to src/main/resources/plugin.yml without a leading slash
        val fs001 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS001" }.jsonObject
        val fs001Artifact = fs001["locations"]!!.jsonArray.single().jsonObject["physicalLocation"]!!
            .jsonObject["artifactLocation"]!!.jsonObject
        assertEquals("src/main/resources/plugin.yml", fs001Artifact["uri"]!!.jsonPrimitive.content)
        assertEquals("%SRCROOT%", fs001Artifact["uriBaseId"]!!.jsonPrimitive.content)

        // 2. Bytecode call findings map to src/main/kotlin/fixtures/legacy/LegacyPlugin.kt with exact startLine >= 1
        val expectedHelperFinding = report.allFindings.first { it.location.method == "refreshHelper" }
        assertNotNull(expectedHelperFinding.location.line)
        assertTrue(expectedHelperFinding.callChain.size >= 3, "expected 3-hop taint chain into refreshHelper")

        val helperSarif = results.first { resEl ->
            val loc = resEl.jsonObject["locations"]!!.jsonArray.single().jsonObject
            val logical = loc["logicalLocations"]!!.jsonArray.single().jsonObject["fullyQualifiedName"]!!.jsonPrimitive.content
            logical.contains("#refreshHelper") &&
                resEl.jsonObject["ruleId"]!!.jsonPrimitive.content == expectedHelperFinding.ruleId
        }.jsonObject

        val phys = helperSarif["locations"]!!.jsonArray.single().jsonObject["physicalLocation"]!!.jsonObject
        assertEquals(
            "src/main/kotlin/fixtures/legacy/LegacyPlugin.kt",
            phys["artifactLocation"]!!.jsonObject["uri"]!!.jsonPrimitive.content,
        )
        assertEquals(
            expectedHelperFinding.location.line,
            phys["region"]!!.jsonObject["startLine"]!!.jsonPrimitive.int,
        )

        // 3. Regional taint call-chain appears in both message.text and SARIF codeFlows/threadFlows
        val msgText = helperSarif["message"]!!.jsonObject["text"]!!.jsonPrimitive.content
        assertTrue(msgText.contains("ExecutorService.submit"), "expected async origin in message: $msgText")
        assertTrue(msgText.contains("call chain:") && msgText.contains("refreshHelper"), "expected call chain in message: $msgText")

        val threadFlowLocs = helperSarif["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertEquals(expectedHelperFinding.callChain.size, threadFlowLocs.size)
        val firstStepMsg = threadFlowLocs.first().jsonObject["location"]!!.jsonObject["message"]!!
            .jsonObject["text"]!!.jsonPrimitive.content
        val lastStepMsg = threadFlowLocs.last().jsonObject["location"]!!.jsonObject["message"]!!
            .jsonObject["text"]!!.jsonPrimitive.content
        assertTrue(firstStepMsg.startsWith("Off-region taint entry:"))
        assertTrue(lastStepMsg.contains("Region-guarded sink"))

        // 4. Stripped-sourceFile fallback reconstructs clean relative Java path
        val strippedUri = SarifReporter.artifactUri(
            CodeLocation(jar = "/tmp/Plugin.jar", className = "com.example.MyPlugin\$Worker", method = "run"),
        )
        assertEquals("src/main/java/com/example/MyPlugin.java", strippedUri)
    }

    @Test
    fun `cli --sarif flag writes valid sarif file alongside console output`() {
        val sarifFile = Files.createTempFile("foliascan-cli-", ".sarif")
        sarifFile.toFile().deleteOnExit()

        val result = FoliaScanCommand().test(
            listOf(
                FixtureJars.legacy().toString(),
                "--sarif",
                sarifFile.toString(),
                "--no-color",
                "--fail-on",
                "never",
            ),
        )
        assertEquals(0, result.statusCode, "CLI output: ${result.output}")
        assertTrue(result.stdout.contains("Verdict:"), "expected console report on stdout")

        val sarifJson = Json.parseToJsonElement(Files.readString(sarifFile)).jsonObject
        assertEquals("2.1.0", sarifJson["version"]!!.jsonPrimitive.content)
        val driver = sarifJson["runs"]!!.jsonArray.single().jsonObject["tool"]!!.jsonObject["driver"]!!.jsonObject
        assertEquals("FoliaScan", driver["name"]!!.jsonPrimitive.content)
        assertEquals(BuildInfo.version, driver["version"]!!.jsonPrimitive.content)
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

    @Test
    fun `sarif emits role-specific codeFlows for v060 Moonrise chunk generation and captured block-entity rules`() {
        val v060Report = ScanReport(
            toolVersion = "0.6.0",
            jars = listOf(JarScanner().scan(FixtureJars.v060()), JarScanner().scan(FixtureJars.v040())),
        )
        val sarif = Json.parseToJsonElement(SarifReporter.render(v060Report)).jsonObject
        val results = sarif["runs"]!!.jsonArray.single().jsonObject["results"]!!.jsonArray

        val fs088 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS088" }.jsonObject
        val fs088Locs = fs088["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertTrue(fs088Locs.size >= 2)
        assertTrue(
            fs088Locs.first().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Async chunk-generation taint entry:"),
        )
        assertTrue(
            fs088Locs.last().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Live-world escape sink"),
        )

        val fs090 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS090" }.jsonObject
        val fs090Locs = fs090["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertTrue(fs090Locs.size >= 2)
        assertTrue(
            fs090Locs.first().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Block-entity snapshot capture and schedule:"),
        )
        assertTrue(
            fs090Locs.last().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Delayed or cross-region block-entity sink"),
        )

        val fs081 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS081" }.jsonObject
        val fs081Locs = fs081["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertTrue(fs081Locs.size >= 2)
        assertTrue(
            fs081Locs.first().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Concurrent scheduler entry:"),
        )
    }

    @Test
    fun `baseline v2 structuralHash survives synthetic lambda ordinal renumbering and emits SARIF v2 fingerprint`() {
        val v100Report = ScanReport(
            toolVersion = "1.0.0",
            jars = listOf(JarScanner().scan(FixtureJars.v100())),
        )
        val baselinePath = Files.createTempFile("foliascan-v2-baseline-", ".json")
        baselinePath.toFile().deleteOnExit()

        Baseline.write(baselinePath, v100Report)
        val matcher = Baseline.loadMatcher(baselinePath)
        assertFalse(matcher.structuralHashes.isEmpty(), "expected SHA-256 structural hashes in v2 baseline")

        // Simulate javac/kotlinc renumbering synthetic lambda$0 -> lambda$9 after an unrelated edit earlier in the file
        val originalJar = v100Report.jars.single()
        val renumberedFindings = originalJar.findings.map { f ->
            val m = f.location.method
            val shiftedMethod = when {
                m != null && m.contains("\$lambda\$") -> m.substringBeforeLast('$') + "\$99"
                m != null && m.startsWith("lambda\$") -> m.substringBeforeLast('$') + "\$99"
                else -> m
            }
            val shiftedChain = f.callChain.map { hop ->
                val hm = hop.method
                val newHm = when {
                    hm != null && hm.contains("\$lambda\$") -> hm.substringBeforeLast('$') + "\$99"
                    hm != null && hm.startsWith("lambda\$") -> hm.substringBeforeLast('$') + "\$99"
                    else -> hm
                }
                hop.copy(method = newHm)
            }
            f.copy(
                location = f.location.copy(method = shiftedMethod, line = (f.location.line ?: 10) + 25),
                callChain = shiftedChain,
            )
        }
        assertTrue(
            renumberedFindings.any { it.fingerprint() !in matcher.exactFingerprints },
            "expected at least one lambda finding whose v1 exact fingerprint changed upon ordinal shift",
        )

        val shiftedReport = ScanReport(
            toolVersion = "1.0.0",
            jars = listOf(originalJar.copy(findings = renumberedFindings)),
        )
        val suppressed = Baseline.apply(shiftedReport, matcher)
        assertTrue(suppressed.allFindings.isEmpty()) {
            "v2 structuralHash failed to suppress renumbered lambda findings: ${suppressed.allFindings}"
        }
        assertTrue(
            suppressed.jars.single().notes.any { it.contains("Suppressed ${renumberedFindings.size} baselined finding(s)") },
        )

        val sarif = Json.parseToJsonElement(SarifReporter.render(v100Report)).jsonObject
        val firstResult = sarif["runs"]!!.jsonArray.single().jsonObject["results"]!!.jsonArray.first().jsonObject
        val fps = firstResult["partialFingerprints"]!!.jsonObject
        assertTrue(fps["foliascan/structuralHash/v2"]!!.jsonPrimitive.content.startsWith("sha256-16:"))
    }

    @Test
    fun `sarif emits role-specific codeFlows for v110 DataComponent shared Inventory and parallel Scoreboard rules`() {
        val v110Report = ScanReport(
            toolVersion = "1.1.0",
            jars = listOf(JarScanner().scan(FixtureJars.v110())),
        )
        val sarif = Json.parseToJsonElement(SarifReporter.render(v110Report)).jsonObject
        val results = sarif["runs"]!!.jsonArray.single().jsonObject["results"]!!.jsonArray

        val fs112 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS112" }.jsonObject
        val fs112Locs = fs112["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertTrue(fs112Locs.size >= 3)
        assertTrue(
            fs112Locs.first().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Concurrent scheduler entry:"),
        )
        assertTrue(
            fs112Locs.last().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Concurrent shared Inventory or Merchant mutation sink"),
        )

        val fs114 = results.first { it.jsonObject["ruleId"]!!.jsonPrimitive.content == "FS114" }.jsonObject
        val fs114Locs = fs114["codeFlows"]!!.jsonArray.single().jsonObject["threadFlows"]!!
            .jsonArray.single().jsonObject["locations"]!!.jsonArray
        assertTrue(fs114Locs.size >= 2)
        assertTrue(
            fs114Locs.last().jsonObject["location"]!!.jsonObject["message"]!!
                .jsonObject["text"]!!.jsonPrimitive.content.startsWith("Parallel regional Scoreboard race sink"),
        )
    }
}
