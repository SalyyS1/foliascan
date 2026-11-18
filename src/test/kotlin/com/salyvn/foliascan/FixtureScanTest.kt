package com.salyvn.foliascan

import com.salyvn.foliascan.bench.BenchmarkSuite
import com.salyvn.foliascan.model.Severity
import com.salyvn.foliascan.scan.JarScanner
import com.salyvn.foliascan.scan.ScanOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
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
        listOf("FS050", "FS060", "FS062", "FS063", "FS064").forEach { expected ->
            assertTrue(expected in ids) { "expected contextual rule $expected, got $ids" }
        }
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
    fun `async bukkit event handlers are seeded as off-region entry points`() {
        val report = scanner.scan(FixtureJars.legacy())
        val chatFindings = report.findings.filter { it.location.method == "onAsyncChat" }
        assertTrue(chatFindings.isNotEmpty()) {
            "AsyncPlayerChatEvent handler touching Player was not flagged; methods: " +
                report.findings.mapNotNull { it.location.method }.distinct()
        }
        assertTrue(chatFindings.any { it.ruleId == "FS063" })
        assertTrue(
            chatFindings.all { it.context?.contains("AsyncPlayerChatEvent") == true },
            "async event origin was not named: ${chatFindings.map { it.context }}",
        )
    }

    @Test
    fun `hopping from async context onto entity or region scheduler clears off-region taint`() {
        val report = scanner.scan(FixtureJars.regionAware())
        assertTrue(report.findings.isEmpty()) {
            "region re-entry callback inside async task was falsely flagged: " +
                report.findings.map { "${it.ruleId}@${it.location.render()} (${it.context})" }
        }
    }

    @Test
    fun `global region scheduler flags regional block access while permitting global world state`() {
        val dualReport = scanner.scan(FixtureJars.dualMode())
        val fruitFindings = dualReport.findings.filter { it.location.method == "placeFruitBlock" }
        assertTrue(fruitFindings.any { it.ruleId == "FS062" }) {
            "BlockState#update inside GlobalRegionScheduler callback was not flagged; methods: " +
                dualReport.findings.mapNotNull { it.location.method }.distinct()
        }
        assertTrue(
            fruitFindings.all { it.context?.contains("GlobalRegionScheduler") == true },
            "GlobalRegionScheduler origin was not named: ${fruitFindings.map { it.context }}",
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
        assertTrue(
            branching.any { it.location.method == "submitViaWrapper" && it.severity == Severity.INFO },
            "a branch delegating to an in-jar scheduler wrapper was not downgraded: " +
                branching.map { "${it.location.method}=${it.severity}" },
        )
    }

    @Test
    fun `an unrelated manager constructed in onEnable alongside a Folia check is still reported`() {
        val report = scanner.scan(FixtureJars.dualMode())
        val unrelated = report.findings.filter { it.location.className.endsWith("UnrelatedManager") }

        assertTrue(unrelated.isNotEmpty()) {
            "UnrelatedManager was not analysed; classes seen: " +
                report.findings.map { it.location.className }.distinct()
        }
        assertTrue(
            unrelated.any { it.severity == Severity.CRITICAL },
            "an unrelated manager instantiated in onEnable was falsely treated as a platform alternate: " +
                unrelated.map { "${it.ruleId}=${it.severity}" },
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
    fun `a reflectively chosen platform alternate is explained but still reported`() {
        val report = scanner.scan(FixtureJars.dualMode())
        val reflective = report.findings.filter { it.location.className.endsWith("ReflectiveTasks") }

        assertTrue(reflective.isNotEmpty()) {
            "the never-constructed implementation was not analysed; classes seen: " +
                report.findings.map { it.location.className }.distinct()
        }
        assertTrue(
            reflective.all { it.severity == Severity.CRITICAL },
            "an unprovable guess lowered severity: " +
                reflective.map { "${it.ruleId}=${it.severity}" },
        )
        assertTrue(
            reflective.all { it.context?.contains("never constructed in this jar") == true },
            "the reader was not told what to check: ${reflective.map { it.context }}",
        )
        assertTrue(
            reflective.any { f ->
                // Either region-aware sibling is a correct answer; both implement Tasks.
                listOf("RegionTasks", "BranchingTasks").any { f.context!!.contains(it) }
            },
            "no region-aware sibling was named: ${reflective.map { it.context }.distinct()}",
        )
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

    @Test
    fun `neutral Class_forName RegionizedServer probe downgrades guarded legacy branch`() {
        val report = scanner.scan(FixtureJars.v040())
        val guarded = report.findings.filter { it.location.className.endsWith("NeutralGuardedScheduler") }
        assertTrue(guarded.isNotEmpty()) { "expected findings in NeutralGuardedScheduler, got ${report.findings}" }
        assertTrue(guarded.all { it.severity == Severity.INFO }) {
            "Class.forName RegionizedServer guard was not recognised: " +
                guarded.map { "${it.ruleId}=${it.severity} (${it.context})" }
        }
        assertTrue(guarded.any { it.context?.contains("RegionizedServer") == true }) {
            "Class.forName target was not cited in guard context: ${guarded.map { it.context }}"
        }
    }

    @Test
    fun `ProtocolLib and Netty channel handlers are seeded as off-region entry points`() {
        val report = scanner.scan(FixtureJars.v040())
        val packetHits = report.findings.filter { it.location.className.endsWith("MovementPacketHook") }
        assertTrue(packetHits.any { it.ruleId == "FS063" }) {
            "ProtocolLib onPacketReceiving entity call was not flagged: $packetHits"
        }
        assertTrue(packetHits.all { it.context?.contains("ProtocolLib packet listener") == true })

        val nettyHits = report.findings.filter { it.location.className.endsWith("RawNettyDuplexHook") }
        assertTrue(nettyHits.any { it.ruleId == "FS065" }) {
            "Netty channelRead World#getNearbyEntities was not flagged as FS065: $nettyHits"
        }
        assertTrue(nettyHits.all { it.context?.contains("Netty channel handler") == true })
    }

    @Test
    fun `CompletableFuture thenAccept is tainted after supplyAsync but safe after teleportAsync`() {
        val report = scanner.scan(FixtureJars.v040())
        val v040Hits = report.findings.filter { it.location.className.endsWith("V040Plugin") }

        assertTrue(
            v040Hits.any {
                it.ruleId == "FS063" &&
                    it.context?.contains("CompletableFuture.thenAccept chained onto supplyAsync") == true
            },
        ) {
            "thenAccept chained onto supplyAsync was not tainted: " +
                v040Hits.map { "${it.ruleId}@${it.location.method}: ${it.context}" }
        }

        assertFalse(
            v040Hits.any { it.context?.contains("safeTeleportAsyncChain") == true },
        ) {
            "teleportAsync(...).thenAccept(...) falsely inherited off-region taint: $v040Hits"
        }
    }

    @Test
    fun `FS065 flags Chunk entity inspection from AsyncScheduler`() {
        val report = scanner.scan(FixtureJars.v040())
        assertTrue(
            report.findings.any {
                it.ruleId == "FS065" && it.evidence.contains("Chunk.getEntities()")
            },
        ) {
            "Chunk#getEntities inside AsyncScheduler was not flagged as FS065: ${report.findings}"
        }
    }

    @Test
    fun `FS081 flags unsynchronized static HashMap mutation while sparing ConcurrentHashMap and synchronized blocks`() {
        val report = scanner.scan(FixtureJars.v040())
        val fs081 = report.findings.filter { it.ruleId == "FS081" }
        assertEquals(1, fs081.size) {
            "expected exactly 1 FS081 finding (unsafeCooldowns in RegionScheduler), got: " +
                fs081.map { "${it.evidence} @ ${it.location.method} (${it.context})" }
        }
        val single = fs081.single()
        assertTrue(single.evidence.contains("SharedState.unsafeCooldowns"))
        assertTrue(single.context?.contains("RegionScheduler.execute") == true)
    }

    @Test
    fun `v050 fixture flags FS082 cross-region passenger operations in off-region context`() {
        val report = scanner.scan(FixtureJars.v050())
        val fs082 = report.findings.filter { it.ruleId == "FS082" }
        assertTrue(fs082.isNotEmpty()) { "expected FS082 for vehicle.addPassenger, got: ${report.findings}" }
        assertTrue(fs082.any { it.evidence.contains("Entity.addPassenger()") })
        assertTrue(fs082.all { it.contextual })
    }

    @Test
    fun `v050 fixture flags FS083 EntityScheduler task with null retired callback`() {
        val report = scanner.scan(FixtureJars.v050())
        val fs083 = report.findings.filter { it.ruleId == "FS083" }
        assertEquals(1, fs083.size) { "expected exactly 1 FS083 finding, got: ${fs083.map { it.evidence }}" }
        assertTrue(fs083.single().evidence.contains("EntityScheduler.runDelayed() called with null retired callback"))
    }

    @Test
    fun `v050 fixture flags FS084 unchained teleportAsync discarding CompletableFuture while sparing chained calls`() {
        val report = scanner.scan(FixtureJars.v050())
        val fs084 = report.findings.filter { it.ruleId == "FS084" }
        assertEquals(1, fs084.size) { "expected exactly 1 FS084 finding for unchained teleportAsync, got: ${fs084.map { it.location.method }}" }
        assertEquals("unsafeUnchainedTeleport", fs084.single().location.method)
        assertTrue(fs084.single().evidence.contains("teleportAsync() future discarded"))
    }

    @Test
    fun `v050 fixture flags FS085 getOnlinePlayers in off-region context`() {
        val report = scanner.scan(FixtureJars.v050())
        val fs085 = report.findings.filter { it.ruleId == "FS085" }
        assertTrue(fs085.isNotEmpty()) { "expected FS085 for getOnlinePlayers, got: ${report.findings}" }
        assertTrue(fs085.any { it.evidence.contains("Bukkit.getOnlinePlayers()") })
    }

    @Test
    fun `v050 fixture flags FS086 cross-region openInventory in off-region context`() {
        val report = scanner.scan(FixtureJars.v050())
        val fs086 = report.findings.filter { it.ruleId == "FS086" }
        assertTrue(fs086.isNotEmpty()) { "expected FS086 for openInventory, got: ${report.findings}" }
        assertTrue(fs086.any { it.evidence.contains("Player.openInventory()") })
    }

    @Test
    fun `v060 fixture flags FS087 blocking get and join on region-completed futures while sparing non-blocking and background futures`() {
        val report = scanner.scan(FixtureJars.v060())
        val fs087 = report.findings.filter { it.ruleId == "FS087" }
        assertEquals(2, fs087.size) {
            "expected 2 FS087 findings (getChunkAtAsyncUrgently.get and teleportAsync.join), got: " +
                fs087.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs087.any { it.evidence.contains("World.getChunkAtAsyncUrgently() blocked via CompletableFuture.get()") })
        assertTrue(fs087.any { it.evidence.contains("Player.teleportAsync() blocked via CompletableFuture.join()") })
        assertFalse(fs087.any { it.location.method?.contains("safeNonBlockingChunkAndCpuFuture") == true })
    }

    @Test
    fun `v060 fixture flags FS088 live World escape inside Moonrise async ChunkGenerator helper while sparing ChunkData and LimitedRegion`() {
        val report = scanner.scan(FixtureJars.v060())
        val fs088 = report.findings.filter { it.ruleId == "FS088" }
        assertTrue(fs088.isNotEmpty()) { "expected FS088 in StructureGenHelper, got: ${report.findings}" }
        assertTrue(fs088.all { it.location.className.endsWith("StructureGenHelper") })
        assertTrue(fs088.all { it.context?.contains("Moonrise async ChunkGenerator") == true })
        assertTrue(fs088.all { it.callChain.size >= 2 }) {
            "expected multi-hop taint chain from UnsafeMoonriseChunkGenerator#generateSurface, got: ${fs088.map { it.callChain }}"
        }
        assertFalse(report.findings.any { it.location.className.endsWith("SafeMoonriseChunkGenerator") })
        assertFalse(report.findings.any { it.location.className.endsWith("SafeMoonrisePopulator") })
    }

    @Test
    fun `v060 fixture flags FS089 off-region TileState TrialSpawner access while sparing RegionScheduler execute`() {
        val report = scanner.scan(FixtureJars.v060())
        val fs089 = report.findings.filter { it.ruleId == "FS089" }
        assertEquals(1, fs089.size) {
            "expected 1 FS089 finding in tuneTrialSpawnerHelper, got: ${fs089.map { "${it.location.method}: ${it.evidence}" }}"
        }
        val single = fs089.single()
        assertEquals("tuneTrialSpawnerHelper", single.location.method)
        assertTrue(single.evidence.contains("TrialSpawner.setCooldownLength()"))
        assertTrue(single.callChain.size >= 3) {
            "expected 3-hop async taint chain into tuneTrialSpawnerHelper, got: ${single.callChain}"
        }
    }

    @Test
    fun `v060 fixture flags FS090 captured TileState across delayed RegionScheduler and EntityScheduler while sparing Location refetch`() {
        val report = scanner.scan(FixtureJars.v060())
        val fs090 = report.findings.filter { it.ruleId == "FS090" }
        assertEquals(2, fs090.size) {
            "expected 2 FS090 findings (RegionScheduler.runDelayed and EntityScheduler.run), got: " +
                fs090.map { "${it.location.method}: ${it.context}" }
        }
        assertTrue(fs090.any { it.context?.contains("RegionScheduler.runDelayed") == true && it.callChain.size >= 2 })
        assertTrue(fs090.any { it.context?.contains("EntityScheduler.run") == true && it.callChain.size >= 2 })
        assertFalse(
            report.findings.any {
                it.location.method?.contains("safeRefetchedChestInDelayedTicks") == true ||
                    it.context?.contains("safeRefetchedChestInDelayedTicks") == true
            },
        ) {
            "Location-captured delayed RegionScheduler task re-fetching BlockState was falsely flagged: ${report.findings}"
        }
    }

    @Test
    fun `v070 fixture flags FS091 PDC mutations in off-region context while sparing RegionScheduler execution`() {
        val report = scanner.scan(FixtureJars.v070())
        val fs091 = report.findings.filter { it.ruleId == "FS091" }
        assertEquals(1, fs091.size) { "expected 1 FS091 finding, got: $fs091" }
        val finding = fs091.single()
        assertTrue(finding.location.method?.startsWith("unsafePdcOffRegion") == true)
        assertTrue(finding.evidence.contains("PersistentDataContainer.set()"))
        assertTrue(finding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.location.method?.contains("safePdcOnRegion") == true })
    }

    @Test
    fun `v070 fixture flags FS092 Structure place unconditionally`() {
        val report = scanner.scan(FixtureJars.v070())
        val fs092 = report.findings.filter { it.ruleId == "FS092" }
        assertEquals(1, fs092.size) { "expected 1 FS092 finding, got: $fs092" }
        val finding = fs092.single()
        assertEquals("unsafeStructurePlace", finding.location.method)
        assertTrue(finding.evidence.contains("Structure.place()"))
    }

    @Test
    fun `v070 fixture flags FS093 Bukkit createInventory in off-region context`() {
        val report = scanner.scan(FixtureJars.v070())
        val fs093 = report.findings.filter { it.ruleId == "FS093" }
        assertEquals(1, fs093.size) { "expected 1 FS093 finding, got: $fs093" }
        val finding = fs093.single()
        assertTrue(finding.location.method?.startsWith("unsafeCreateInventoryOffRegion") == true)
        assertTrue(finding.evidence.contains("Bukkit.createInventory()"))
        assertTrue(finding.context?.contains("AsyncScheduler") == true)
    }

    @Test
    fun `v070 fixture flags FS094 BossBar player management off-region while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v070())
        val fs094 = report.findings.filter { it.ruleId == "FS094" }
        assertEquals(1, fs094.size) { "expected 1 FS094 finding, got: $fs094" }
        val finding = fs094.single()
        assertTrue(finding.location.method?.startsWith("unsafeBossBarOffRegion") == true)
        assertTrue(finding.evidence.contains("BossBar.addPlayer()"))
        assertTrue(finding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.location.method?.contains("safeBossBarGlobal") == true })
    }

    @Test
    fun `v070 fixture flags FS095 WorldBorder mutation off-region while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v070())
        val fs095 = report.findings.filter { it.ruleId == "FS095" }
        assertEquals(1, fs095.size) { "expected 1 FS095 finding, got: $fs095" }
        val finding = fs095.single()
        assertTrue(finding.location.method?.startsWith("unsafeWorldBorderOffRegion") == true)
        assertTrue(finding.evidence.contains("WorldBorder.setSize()"))
        assertTrue(finding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.location.method?.contains("safeWorldBorderGlobal") == true })
    }

    @Test
    fun `v080 fixture flags FS096 MapView addRenderer from async while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs096 = report.findings.filter { it.ruleId == "FS096" }
        assertTrue(fs096.isNotEmpty()) { "expected at least 1 FS096 finding, got: $fs096" }
        val addRendererFinding = fs096.firstOrNull { it.location.method?.contains("unsafeMapViewAddRendererAsync") == true }
        assertNotNull(addRendererFinding) { "expected FS096 on unsafeMapViewAddRendererAsync" }
        assertTrue(addRendererFinding!!.evidence.contains("MapView.addRenderer()"))
        assertTrue(addRendererFinding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.ruleId == "FS096" && it.location.method?.contains("safeMapViewGlobal") == true })
    }

    @Test
    fun `v080 fixture flags FS096 MapView setLocked from async`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs096locked = report.findings.filter {
            it.ruleId == "FS096" && it.location.method?.contains("unsafeMapViewSetLockedAsync") == true
        }
        assertTrue(fs096locked.isNotEmpty()) { "expected FS096 on unsafeMapViewSetLockedAsync, got: $fs096locked" }
        assertTrue(fs096locked.first().evidence.contains("MapView.setLocked()"))
    }

    @Test
    fun `v080 fixture flags FS097 broadcastMessage from async while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs097 = report.findings.filter { it.ruleId == "FS097" }
        assertTrue(fs097.size >= 2) { "expected at least 2 FS097 findings (broadcastMessage + broadcast), got: $fs097" }
        val broadcastMsg = fs097.firstOrNull { it.location.method?.contains("unsafeBroadcastMessageAsync") == true }
        assertNotNull(broadcastMsg) { "expected FS097 on unsafeBroadcastMessageAsync" }
        assertTrue(broadcastMsg!!.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.ruleId == "FS097" && it.location.method?.contains("safeBroadcastGlobal") == true })
    }

    @Test
    fun `v080 fixture flags FS098 ServicesManager unregisterAll from async`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs098 = report.findings.filter { it.ruleId == "FS098" }
        assertTrue(fs098.isNotEmpty()) { "expected at least 1 FS098 finding, got: $fs098" }
        val finding = fs098.firstOrNull { it.location.method?.contains("unsafeServicesUnregisterAsync") == true }
        assertNotNull(finding) { "expected FS098 on unsafeServicesUnregisterAsync" }
        assertTrue(finding!!.evidence.contains("ServicesManager.unregisterAll()"))
        assertTrue(finding.context?.contains("AsyncScheduler") == true)
    }

    @Test
    fun `v080 fixture flags FS099 registerEvents from async while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs099 = report.findings.filter { it.ruleId == "FS099" }
        assertTrue(fs099.isNotEmpty()) { "expected at least 1 FS099 finding, got: $fs099" }
        val registerFinding = fs099.firstOrNull { it.location.method?.contains("unsafeRegisterEventsAsync") == true }
        assertNotNull(registerFinding) { "expected FS099 on unsafeRegisterEventsAsync" }
        assertTrue(registerFinding!!.evidence.contains("PluginManager.registerEvents()"))
        assertTrue(registerFinding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.ruleId == "FS099" && it.location.method?.contains("safeRegisterEventsGlobal") == true })
    }

    @Test
    fun `v080 fixture flags FS100 BlockData setWaterlogged from async while sparing region scheduler`() {
        val report = scanner.scan(FixtureJars.v080())
        val fs100 = report.findings.filter { it.ruleId == "FS100" }
        assertTrue(fs100.isNotEmpty()) { "expected at least 1 FS100 finding, got: $fs100" }
        val waterloggedFinding = fs100.firstOrNull { it.location.method?.contains("unsafeBlockDataMutationAsync") == true }
        assertNotNull(waterloggedFinding) { "expected FS100 on unsafeBlockDataMutationAsync" }
        assertTrue(waterloggedFinding!!.evidence.contains("BlockData.setWaterlogged()"))
        assertTrue(waterloggedFinding.context?.contains("AsyncScheduler") == true)
        assertFalse(report.findings.any { it.ruleId == "FS100" && it.location.method?.contains("safeBlockDataOnRegion") == true })
    }

    @Test
    fun `v090 fixture propagates taint across INVOKEINTERFACE into concrete implementation for FS102 and FS103`() {
        val report = scanner.scan(FixtureJars.v090())
        val fs103 = report.findings.filter { it.ruleId == "FS103" }
        assertEquals(1, fs103.size) { "expected 1 FS103 finding, got: $fs103" }
        val invFinding = fs103.single()
        assertTrue(invFinding.location.className.endsWith("DatabaseRewardGateway"))
        assertEquals("grantRewardAndScan", invFinding.location.method)
        assertTrue(invFinding.evidence.contains("PlayerInventory.setItem()"))
        assertTrue(invFinding.callChain.size >= 3) {
            "expected >=3-hop taint chain across INVOKEINTERFACE, got: ${invFinding.callChain}"
        }

        val fs102 = report.findings.filter { it.ruleId == "FS102" }
        assertEquals(1, fs102.size) { "expected 1 FS102 finding, got: $fs102" }
        val selFinding = fs102.single()
        assertTrue(selFinding.location.className.endsWith("DatabaseRewardGateway"))
        assertTrue(selFinding.evidence.contains("Bukkit.selectEntities()"))
        assertTrue(selFinding.callChain.size >= 3)
    }

    @Test
    fun `v090 fixture detects Dispatchers_IO coroutine taint and FS101 unconfined suspension while sparing regionDispatcher`() {
        val report = scanner.scan(FixtureJars.v090())
        val fs101 = report.findings.filter { it.ruleId == "FS101" }
        assertEquals(2, fs101.size) {
            "expected 2 FS101 findings (delay() before loadChunk and off-region Continuation.resumeWith), got: " +
                fs101.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs101.any { it.evidence.contains("DelayKt.delay() resumes before World.loadChunk()") })
        assertTrue(fs101.any { it.evidence.contains("Continuation.resumeWith() invoked off-region") })

        val fs060 = report.findings.filter { it.ruleId == "FS060" }
        assertEquals(1, fs060.size) { "expected FS060 on World.loadChunk inside Dispatchers.IO suspend chain, got: $fs060" }
        assertEquals("suspendRefreshChunk", fs060.single().location.method)
        assertTrue(fs060.single().context?.contains("Dispatchers.IO") == true)

        assertFalse(
            report.findings.any {
                it.location.method?.contains("safeCoroutineHoppingToRegion") == true ||
                    it.context?.contains("safeCoroutineHoppingToRegion") == true
            },
        ) {
            "safe coroutine switching to regionDispatcher + EntityScheduler was falsely flagged: ${report.findings}"
        }
    }

    @Test
    fun `v090 fixture flags FS104 runtime Bukkit reloadData as CRITICAL`() {
        val report = scanner.scan(FixtureJars.v090())
        val fs104 = report.findings.filter { it.ruleId == "FS104" }
        assertEquals(1, fs104.size) { "expected 1 FS104 finding, got: $fs104" }
        assertEquals(Severity.CRITICAL, fs104.single().severity)
        assertEquals("unsafeRuntimeDatapackReload", fs104.single().location.method)
        assertTrue(fs104.single().evidence.contains("Bukkit.reloadData()"))
    }

    @Test
    fun `v090 fixture flags FS105 unsynchronized instance HashMap mutated across RegionScheduler while sparing ConcurrentHashMap and synchronized`() {
        val report = scanner.scan(FixtureJars.v090())
        val fs105 = report.findings.filter { it.ruleId == "FS105" }
        assertEquals(1, fs105.size) {
            "expected 1 FS105 finding on UnsafeInstanceSessionTracker.visits, got: " +
                fs105.map { "${it.location.method}: ${it.evidence}" }
        }
        val hit = fs105.single()
        assertTrue(hit.location.className.endsWith("UnsafeInstanceSessionTracker"))
        assertEquals("recordVisit", hit.location.method)
        assertTrue(hit.evidence.contains("UnsafeInstanceSessionTracker.visits (HashMap) mutated via put()"))
        assertTrue(hit.context?.contains("RegionScheduler.execute") == true)
        assertTrue(hit.callChain.size >= 3)
    }

    @Test
    fun `synthetic benchmark suite achieves complete recall and zero false positives`() {
        val metrics = BenchmarkSuite.run(iterations = 3)
        assertTrue(metrics.recallComplete) {
            "benchmark missed expected rules or triggered false positives: $metrics"
        }
        assertEquals(0, metrics.falsePositivesOnSafeControl)
        assertEquals(0, metrics.falseNegatives)
        assertEquals(1.0, metrics.precision)
        assertEquals(1.0, metrics.recall)
        assertEquals(1.0, metrics.f1Score)
        assertTrue(metrics.classesPerSecond > 0.0)
        val json = BenchmarkSuite.renderJson(metrics)
        assertTrue(json.contains("\"recallComplete\": true"))
        assertTrue(json.contains("\"f1Score\": 1.0"))
        val console = BenchmarkSuite.renderConsole(metrics)
        assertTrue(console.contains("precision=1.0  recall=1.0  F1=1.0"))
    }

    @Test
    fun `v100 fixture propagates INVOKEDYNAMIC closure taint across custom interface and Kotlin higher-order wrappers`() {
        val report = scanner.scan(FixtureJars.v100())

        val fs109 = report.findings.filter { it.ruleId == "FS109" }
        assertEquals(1, fs109.size) { "expected 1 FS109 finding via TaskRouter.runOffRegion closure, got: $fs109" }
        assertTrue(fs109.single().evidence.contains("AdvancementProgress.awardCriteria()"))
        assertTrue(fs109.single().context?.contains("FoliaTaskRouter.runOffRegion") == true) {
            "expected wrapper attribution in context, got: ${fs109.single().context}"
        }
        assertTrue(fs109.single().callChain.size >= 3) {
            "expected >=3-hop inter-procedural closure callChain, got: ${fs109.single().callChain}"
        }

        val fs110 = report.findings.filter { it.ruleId == "FS110" }
        assertEquals(1, fs110.size) { "expected 1 FS110 finding via TaskRouter.runOffRegion closure, got: $fs110" }
        assertTrue(fs110.single().evidence.contains("LootTable.fillInventory()"))

        val fs108 = report.findings.filter { it.ruleId == "FS108" }
        assertEquals(1, fs108.size) {
            "expected 1 FS108 finding via FunctionalPool.supplyInBackground while sparing GlobalRegionScheduler, got: $fs108"
        }
        assertTrue(fs108.single().evidence.contains("Team.addEntry()"))
        assertTrue(fs108.single().context?.contains("FunctionalPool.supplyInBackground") == true)
    }

    @Test
    fun `v100 fixture suppresses false positives when async task re-enters Folia via custom scheduler wrapper`() {
        val report = scanner.scan(FixtureJars.v100())
        val falsePositives = report.findings.filter {
            it.location.method?.contains("safeAsyncHoppingViaCustomRouter") == true ||
                it.context?.contains("safeAsyncHoppingViaCustomRouter") == true
        }
        assertTrue(falsePositives.isEmpty()) {
            "custom Folia region/entity wrapper re-entry falsely flagged: $falsePositives"
        }
    }

    @Test
    fun `v100 fixture flags FS106 unowned entity capture in Location scheduler and FS107 delayed Chunk capture`() {
        val report = scanner.scan(FixtureJars.v100())

        val fs106 = report.findings.filter { it.ruleId == "FS106" }
        assertEquals(1, fs106.size) {
            "expected 1 FS106 finding (sparing isOwnedByCurrentRegion guard), got: " +
                fs106.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs106.single().evidence.contains("Player.setHealth() on captured entity"))
        assertTrue(fs106.single().context?.contains("RegionScheduler.execute") == true)
        assertTrue(fs106.single().callChain.size >= 2)

        val fs107 = report.findings.filter { it.ruleId == "FS107" }
        assertEquals(1, fs107.size) {
            "expected 1 FS107 finding on captured Chunk in runDelayed, got: $fs107"
        }
        assertTrue(fs107.single().evidence.contains("Chunk.getEntities() on captured Chunk reference"))
        assertTrue(fs107.single().context?.contains("RegionScheduler.runDelayed") == true)
    }

    @Test
    fun `v110 fixture flags FS111 off-region DataComponentHolder and live slot CraftItemStack while sparing new and cloned ItemStacks`() {
        val report = scanner.scan(FixtureJars.v110())
        val fs111 = report.findings.filter { it.ruleId == "FS111" }
        assertEquals(2, fs111.size) {
            "expected 2 FS111 findings (DataComponentHolder.setData and live getItemInMainHand -> ItemStack.setData), got: " +
                fs111.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs111.any { it.evidence.contains("DataComponentHolder.setData()") })
        assertTrue(fs111.any { it.evidence.contains("live PlayerInventory.getItemInMainHand() mutated via ItemStack.setData()") })
        assertFalse(
            report.findings.any {
                it.location.method?.contains("safeAsyncDetachedAndClonedItemStack") == true ||
                    it.context?.contains("safeAsyncDetachedAndClonedItemStack") == true
            },
        ) {
            "detached new ItemStack or clone() component mutation was falsely flagged: ${report.findings}"
        }
    }

    @Test
    fun `v110 fixture flags FS112 shared Inventory and Merchant fields across parallel regional schedulers while sparing synchronized`() {
        val report = scanner.scan(FixtureJars.v110())
        val fs112 = report.findings.filter { it.ruleId == "FS112" }
        assertEquals(2, fs112.size) {
            "expected 2 FS112 findings (depositUnsync Inventory.setItem and updateTradesUnsync Merchant.setRecipes), got: " +
                fs112.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs112.any { it.evidence.contains("SharedClanVault.vaultInventory (Inventory) mutated via setItem()") && it.callChain.size >= 3 })
        assertTrue(fs112.any { it.evidence.contains("SharedClanVault.clanMerchant (Merchant) mutated via setRecipes()") && it.callChain.size >= 3 })
        assertFalse(report.findings.any { it.location.method == "depositSynchronized" })
    }

    @Test
    fun `v110 fixture flags FS113 off-region InventoryView mutations while sparing viewing player EntityScheduler`() {
        val report = scanner.scan(FixtureJars.v110())
        val fs113 = report.findings.filter { it.ruleId == "FS113" }
        assertEquals(2, fs113.size) {
            "expected 2 FS113 findings (setCursor and setTitle), got: ${fs113.map { it.evidence }}"
        }
        assertTrue(fs113.any { it.evidence.contains("InventoryView.setCursor()") })
        assertTrue(fs113.any { it.evidence.contains("InventoryView.setTitle()") })
        assertFalse(
            report.findings.any {
                it.location.method?.contains("safePlayerInventoryViewMutation") == true ||
                    it.context?.contains("safePlayerInventoryViewMutation") == true
            },
        )
    }

    @Test
    fun `v110 fixture flags FS114 Scoreboard Team Score and resetScores across parallel regional schedulers while sparing GlobalRegionScheduler`() {
        val report = scanner.scan(FixtureJars.v110())
        val fs114 = report.findings.filter { it.ruleId == "FS114" }
        assertEquals(3, fs114.size) {
            "expected 3 FS114 findings (Team.addEntry, Score.setScore, Scoreboard.resetScores), got: " +
                fs114.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs114.any { it.evidence.contains("Team.addEntry()") && it.context?.contains("RegionScheduler.execute") == true })
        assertTrue(fs114.any { it.evidence.contains("Score.setScore()") && it.context?.contains("EntityScheduler.run") == true })
        assertTrue(fs114.any { it.evidence.contains("Scoreboard.resetScores()") && it.context?.contains("EntityScheduler.run") == true })
        assertFalse(
            report.findings.any {
                it.location.method?.contains("safeGlobalScoreboardMutation") == true ||
                    it.context?.contains("safeGlobalScoreboardMutation") == true
            },
        )
    }

    @Test
    fun `v110 fixture flags FS115 unguarded and async Leashable operations while sparing null detach and isOwnedByCurrentRegion`() {
        val report = scanner.scan(FixtureJars.v110())
        val fs115 = report.findings.filter { it.ruleId == "FS115" }
        assertEquals(2, fs115.size) {
            "expected 2 FS115 findings (unguarded setLeashHolder(player) despite earlier null local, and async getLeashHolder), got: " +
                fs115.map { "${it.location.method}: ${it.evidence}" }
        }
        assertTrue(fs115.any { it.evidence.contains("Leashable.setLeashHolder() without isOwnedByCurrentRegion guard") })
        assertTrue(fs115.any { it.evidence.contains("Leashable.getLeashHolder()") && it.context?.contains("AsyncScheduler") == true })
        assertFalse(
            report.findings.any {
                it.location.method?.contains("safeLeashableOperations") == true ||
                    it.context?.contains("safeLeashableOperations") == true
            },
        )
    }
}
