package com.salyvn.foliascan.bench

import com.salyvn.foliascan.BuildInfo
import com.salyvn.foliascan.scan.JarScanner
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.math.roundToLong

@Serializable
data class BenchmarkMetrics(
    val toolVersion: String,
    val iterations: Int,
    val jarsPerIteration: Int,
    val classesPerIteration: Int,
    val totalClassesScanned: Int,
    val meanIterationMs: Double,
    val p50IterationMs: Double,
    val p95IterationMs: Double,
    val jarsPerSecond: Double,
    val classesPerSecond: Double,
    val expectedHazardRules: List<String>,
    val detectedHazardRules: List<String>,
    val truePositives: Int,
    val falseNegatives: Int,
    val falsePositivesOnSafeControl: Int,
    val trueNegativesOnSafeControl: Int,
    val precision: Double,
    val recall: Double,
    val f1Score: Double,
    val recallComplete: Boolean,
)

/**
 * Deterministic synthetic bytecode benchmark harness for FoliaScan.
 *
 * Generates multi-class plugin JARs using ASM ClassWriter (exercising inter-procedural
 * INVOKEDYNAMIC LambdaMetafactory async & region scheduler wrappers, CHA INVOKEINTERFACE
 * propagation, Kotlin SuspendLambda coroutine suspension boundaries, cross-region entity closure
 * capture, and concurrent instance collection tracking alongside a region-safe control JAR),
 * runs warmup and timed scan passes, and computes exact Precision / Recall / F1 metrics.
 */
object BenchmarkSuite {

    private val json = Json { prettyPrint = true }

    val EXPECTED_RULES: List<String> = listOf(
        "FS060", "FS101", "FS102", "FS103", "FS104", "FS105", "FS106", "FS108",
    )

    fun run(iterations: Int = 20): BenchmarkMetrics {
        val safeIterations = iterations.coerceIn(1, 500)
        val workDir = Files.createTempDirectory("foliascan-bench-")
        try {
            val hazardJar = buildHazardPluginJar(workDir.resolve("hazard-suite.jar"), helperCount = 32)
            val controlJar = buildSafeControlJar(workDir.resolve("safe-control.jar"), helperCount = 36)
            val scanner = JarScanner()

            // Warmup JIT and lazy hierarchy caches
            repeat(3) {
                scanner.scan(hazardJar)
                scanner.scan(controlJar)
            }

            val durationsNs = LongArray(safeIterations)
            var classesPerIter = 0
            var controlClasses = 0
            var detectedRules: Set<String> = emptySet()
            var falsePositives = 0

            for (i in 0 until safeIterations) {
                val t0 = System.nanoTime()
                val hazardReport = scanner.scan(hazardJar)
                val controlReport = scanner.scan(controlJar)
                durationsNs[i] = System.nanoTime() - t0
                if (i == 0) {
                    classesPerIter = hazardReport.classesScanned + controlReport.classesScanned
                    controlClasses = controlReport.classesScanned
                    detectedRules = hazardReport.findings.map { it.ruleId }.toSortedSet()
                    falsePositives = controlReport.findings.size
                }
            }

            val sortedMs = durationsNs.map { it / 1_000_000.0 }.sorted()
            val totalSeconds = durationsNs.sum() / 1_000_000_000.0
            val totalClasses = classesPerIter * safeIterations
            val totalJars = 2 * safeIterations
            val meanMs = sortedMs.average()
            val p50Ms = percentile(sortedMs, 0.50)
            val p95Ms = percentile(sortedMs, 0.95)
            val tp = EXPECTED_RULES.count { it in detectedRules }
            val fn = EXPECTED_RULES.size - tp
            val tn = (controlClasses - falsePositives).coerceAtLeast(0)
            val prec = if (tp + falsePositives > 0) round4(tp.toDouble() / (tp + falsePositives)) else 1.0
            val rec = if (tp + fn > 0) round4(tp.toDouble() / (tp + fn)) else 1.0
            val f1 = if (prec + rec > 0.0) round4(2.0 * prec * rec / (prec + rec)) else 0.0

            return BenchmarkMetrics(
                toolVersion = BuildInfo.version,
                iterations = safeIterations,
                jarsPerIteration = 2,
                classesPerIteration = classesPerIter,
                totalClassesScanned = totalClasses,
                meanIterationMs = round2(meanMs),
                p50IterationMs = round2(p50Ms),
                p95IterationMs = round2(p95Ms),
                jarsPerSecond = if (totalSeconds > 0) round2(totalJars / totalSeconds) else 0.0,
                classesPerSecond = if (totalSeconds > 0) round2(totalClasses / totalSeconds) else 0.0,
                expectedHazardRules = EXPECTED_RULES,
                detectedHazardRules = detectedRules.toList(),
                truePositives = tp,
                falseNegatives = fn,
                falsePositivesOnSafeControl = falsePositives,
                trueNegativesOnSafeControl = tn,
                precision = prec,
                recall = rec,
                f1Score = f1,
                recallComplete = fn == 0 && falsePositives == 0,
            )
        } finally {
            Files.walk(workDir).use { stream ->
                stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    fun renderConsole(m: BenchmarkMetrics): String = buildString {
        appendLine("FoliaScan ${m.toolVersion} Synthetic Bytecode Benchmark")
        appendLine("  iterations:          ${m.iterations} (${m.jarsPerIteration} jars / ${m.classesPerIteration} classes per pass)")
        appendLine("  total classes:       ${m.totalClassesScanned}")
        appendLine("  latency (ms):        mean=${m.meanIterationMs}  p50=${m.p50IterationMs}  p95=${m.p95IterationMs}")
        appendLine("  throughput:          ${m.classesPerSecond} classes/sec  (${m.jarsPerSecond} jars/sec)")
        appendLine("  hazard rules hit:    ${m.detectedHazardRules.joinToString(", ")}")
        appendLine("  confusion matrix:    TP=${m.truePositives}  FN=${m.falseNegatives}  FP=${m.falsePositivesOnSafeControl}  TN=${m.trueNegativesOnSafeControl}")
        appendLine("  precision / recall:  precision=${m.precision}  recall=${m.recall}  F1=${m.f1Score}")
        append("  verification:        ${if (m.recallComplete) "PASS (100% expected recall, 0 false positives)" else "FAIL"}")
    }

    fun renderJson(m: BenchmarkMetrics): String = json.encodeToString(m)

    private fun percentile(sorted: List<Double>, p: Double): Double {
        if (sorted.isEmpty()) return 0.0
        val idx = ((sorted.size - 1) * p).toInt().coerceIn(0, sorted.lastIndex)
        return sorted[idx]
    }

    private fun round2(v: Double): Double = (v * 100.0).roundToLong() / 100.0

    private fun round4(v: Double): Double = (v * 10_000.0).roundToLong() / 10_000.0

    private fun buildHazardPluginJar(path: Path, helperCount: Int): Path {
        val pkg = "bench/hazard"
        val entries = LinkedHashMap<String, ByteArray>()
        entries["$pkg/PlayerSyncService.class"] = emitSyncInterface(pkg)
        entries["$pkg/SqlPlayerSyncService.class"] = emitSyncImpl(pkg)
        entries["$pkg/CooldownRegistry.class"] = emitUnsyncInstanceRegistry(pkg)
        entries["$pkg/AsyncTaskBus.class"] = emitAsyncWrapperBus(pkg)
        entries["$pkg/HazardPlugin\$launchIo\$1.class"] = emitSuspendLambdaClass(pkg)
        entries["$pkg/HazardPlugin.class"] = emitHazardMainPlugin(pkg)
        for (idx in 0 until helperCount) {
            entries["$pkg/DomainService$idx.class"] = emitBenignHelperClass("$pkg/DomainService$idx")
        }
        writeJar(path, "hazard-suite", "bench.hazard.HazardPlugin", entries)
        return path
    }

    private fun buildSafeControlJar(path: Path, helperCount: Int): Path {
        val pkg = "bench/safe"
        val entries = LinkedHashMap<String, ByteArray>()
        entries["$pkg/RegionTaskBus.class"] = emitSafeRegionWrapperBus(pkg)
        entries["$pkg/SafePlugin.class"] = emitSafeMainPlugin(pkg)
        for (idx in 0 until helperCount) {
            entries["$pkg/SafeWorker$idx.class"] = emitBenignHelperClass("$pkg/SafeWorker$idx")
        }
        writeJar(path, "safe-control", "bench.safe.SafePlugin", entries)
        return path
    }

    private fun writeJar(
        target: Path,
        name: String,
        mainClass: String,
        classes: Map<String, ByteArray>,
    ) {
        JarOutputStream(Files.newOutputStream(target)).use { jar ->
            jar.putNextEntry(JarEntry("plugin.yml"))
            val yml = "name: $name\nversion: 1.0.0\nmain: $mainClass\napi-version: '1.21'\nfolia-supported: true\n"
            jar.write(yml.toByteArray())
            jar.closeEntry()
            for ((entryName, bytes) in classes) {
                jar.putNextEntry(JarEntry(entryName))
                jar.write(bytes)
                jar.closeEntry()
            }
        }
    }

    private fun emitSyncInterface(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(
            Opcodes.V21,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_INTERFACE,
            "$pkg/PlayerSyncService",
            null,
            "java/lang/Object",
            null,
        )
        cw.visitSource("PlayerSyncService.kt", null)
        cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
            "syncInventoryAndTarget",
            "(Lorg/bukkit/inventory/PlayerInventory;Ljava/lang/Object;)V",
            null,
            null,
        ).visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitSyncImpl(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(
            Opcodes.V21,
            Opcodes.ACC_PUBLIC,
            "$pkg/SqlPlayerSyncService",
            null,
            "java/lang/Object",
            arrayOf("$pkg/PlayerSyncService"),
        )
        cw.visitSource("SqlPlayerSyncService.kt", null)
        emitDefaultConstructor(cw, "java/lang/Object")

        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC,
            "syncInventoryAndTarget",
            "(Lorg/bukkit/inventory/PlayerInventory;Ljava/lang/Object;)V",
            null,
            null,
        )
        mv.visitCode()
        val l1 = Label()
        mv.visitLabel(l1)
        mv.visitLineNumber(14, l1)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "org/bukkit/inventory/PlayerInventory",
            "clear",
            "()V",
            true,
        )
        val l2 = Label()
        mv.visitLabel(l2)
        mv.visitLineNumber(15, l2)
        mv.visitVarInsn(Opcodes.ALOAD, 2)
        mv.visitLdcInsn("@e[type=zombie]")
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "selectEntities",
            "(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;",
            false,
        )
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(3, 3)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitUnsyncInstanceRegistry(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/CooldownRegistry"
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
        cw.visitSource("CooldownRegistry.kt", null)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_FINAL, "cooldowns", "Ljava/util/Map;", null, null).visitEnd()

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitTypeInsn(Opcodes.NEW, "java/util/HashMap")
        init.visitInsn(Opcodes.DUP)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/HashMap", "<init>", "()V", false)
        init.visitFieldInsn(Opcodes.PUTFIELD, owner, "cooldowns", "Ljava/util/Map;")
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(3, 1)
        init.visitEnd()

        val rec = cw.visitMethod(Opcodes.ACC_PUBLIC, "recordHit", "(Ljava/lang/String;)V", null, null)
        rec.visitCode()
        val l1 = Label()
        rec.visitLabel(l1)
        rec.visitLineNumber(22, l1)
        rec.visitVarInsn(Opcodes.ALOAD, 0)
        rec.visitFieldInsn(Opcodes.GETFIELD, owner, "cooldowns", "Ljava/util/Map;")
        rec.visitVarInsn(Opcodes.ALOAD, 1)
        rec.visitInsn(Opcodes.LCONST_1)
        rec.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        rec.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "java/util/Map",
            "put",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
            true,
        )
        rec.visitInsn(Opcodes.POP)
        rec.visitInsn(Opcodes.RETURN)
        rec.visitMaxs(4, 2)
        rec.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitSuspendLambdaClass(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/HazardPlugin\$launchIo\$1"
        cw.visit(
            Opcodes.V21,
            Opcodes.ACC_FINAL,
            owner,
            null,
            "kotlin/coroutines/jvm/internal/SuspendLambda",
            null,
        )
        cw.visitSource("HazardPlugin.kt", null)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_FINAL, "world", "Lorg/bukkit/World;", null, null).visitEnd()

        val init = cw.visitMethod(
            Opcodes.ACC_PUBLIC,
            "<init>",
            "(Lorg/bukkit/World;Lkotlin/coroutines/Continuation;)V",
            null,
            null,
        )
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitInsn(Opcodes.ICONST_2)
        init.visitVarInsn(Opcodes.ALOAD, 2)
        init.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "kotlin/coroutines/jvm/internal/SuspendLambda",
            "<init>",
            "(ILkotlin/coroutines/Continuation;)V",
            false,
        )
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitVarInsn(Opcodes.ALOAD, 1)
        init.visitFieldInsn(Opcodes.PUTFIELD, owner, "world", "Lorg/bukkit/World;")
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(3, 3)
        init.visitEnd()

        val body = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
            "invokeSuspend",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            null,
            null,
        )
        body.visitCode()
        val l1 = Label()
        body.visitLabel(l1)
        body.visitLineNumber(31, l1)
        body.visitLdcInsn(50L)
        body.visitVarInsn(Opcodes.ALOAD, 0)
        body.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "kotlinx/coroutines/DelayKt",
            "delay",
            "(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;",
            false,
        )
        body.visitInsn(Opcodes.POP)
        val l2 = Label()
        body.visitLabel(l2)
        body.visitLineNumber(32, l2)
        body.visitVarInsn(Opcodes.ALOAD, 0)
        body.visitFieldInsn(Opcodes.GETFIELD, owner, "world", "Lorg/bukkit/World;")
        body.visitInsn(Opcodes.ICONST_0)
        body.visitInsn(Opcodes.ICONST_0)
        body.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "org/bukkit/World",
            "loadChunk",
            "(II)Z",
            true,
        )
        body.visitInsn(Opcodes.POP)
        body.visitInsn(Opcodes.ACONST_NULL)
        body.visitInsn(Opcodes.ARETURN)
        body.visitMaxs(3, 2)
        body.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitHazardMainPlugin(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/HazardPlugin"
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
        cw.visitSource("HazardPlugin.kt", null)
        emitDefaultConstructor(cw, "java/lang/Object")

        // 1. Trigger FS104 (Bukkit.reloadData), async interface dispatch (FS102 + FS103), coroutine (FS101 + FS060), and parallel FS105
        val runAll = cw.visitMethod(
            Opcodes.ACC_PUBLIC,
            "runAll",
            "(L$pkg/PlayerSyncService;L$pkg/CooldownRegistry;Lorg/bukkit/inventory/PlayerInventory;Lorg/bukkit/World;Lorg/bukkit/Location;)V",
            null,
            null,
        )
        runAll.visitCode()
        val l1 = Label()
        runAll.visitLabel(l1)
        runAll.visitLineNumber(40, l1)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "org/bukkit/Bukkit", "reloadData", "()V", false)

        // Submit async lambda -> INVOKEINTERFACE PlayerSyncService.syncInventoryAndTarget
        val l2 = Label()
        runAll.visitLabel(l2)
        runAll.visitLineNumber(42, l2)
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "getAsyncScheduler",
            "()Lio/papermc/paper/threadedregions/scheduler/AsyncScheduler;",
            false,
        )
        runAll.visitVarInsn(Opcodes.ALOAD, 0)
        runAll.visitVarInsn(Opcodes.ALOAD, 1)
        runAll.visitVarInsn(Opcodes.ALOAD, 3)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/LambdaMetafactory",
            "metafactory",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
            false,
        )
        val asyncTarget = Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "lambda\$asyncSync\$0",
            "(L$pkg/PlayerSyncService;Lorg/bukkit/inventory/PlayerInventory;Ljava/lang/Object;)V",
            false,
        )
        runAll.visitInvokeDynamicInsn(
            "accept",
            "(L$pkg/PlayerSyncService;Lorg/bukkit/inventory/PlayerInventory;)Ljava/util/function/Consumer;",
            bsm,
            org.objectweb.asm.Type.getType("(Ljava/lang/Object;)V"),
            asyncTarget,
            org.objectweb.asm.Type.getType("(Ljava/lang/Object;)V"),
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "io/papermc/paper/threadedregions/scheduler/AsyncScheduler",
            "runNow",
            "(Ljava/lang/Object;Ljava/util/function/Consumer;)Lio/papermc/paper/threadedregions/scheduler/ScheduledTask;",
            true,
        )
        runAll.visitInsn(Opcodes.POP)

        // Launch Dispatchers.IO coroutine
        val l3 = Label()
        runAll.visitLabel(l3)
        runAll.visitLineNumber(48, l3)
        runAll.visitFieldInsn(
            Opcodes.GETSTATIC,
            "kotlinx/coroutines/GlobalScope",
            "INSTANCE",
            "Lkotlinx/coroutines/GlobalScope;",
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "kotlinx/coroutines/Dispatchers",
            "getIO",
            "()Ljava/lang/Object;",
            false,
        )
        runAll.visitTypeInsn(Opcodes.NEW, "$pkg/HazardPlugin\$launchIo\$1")
        runAll.visitInsn(Opcodes.DUP)
        runAll.visitVarInsn(Opcodes.ALOAD, 4)
        runAll.visitInsn(Opcodes.ACONST_NULL)
        runAll.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "$pkg/HazardPlugin\$launchIo\$1",
            "<init>",
            "(Lorg/bukkit/World;Lkotlin/coroutines/Continuation;)V",
            false,
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "kotlinx/coroutines/BuildersKt",
            "launch",
            "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
            false,
        )
        runAll.visitInsn(Opcodes.POP)

        // Submit RegionScheduler.execute -> CooldownRegistry.recordHit (FS105) + captured Player.setHealth (FS106)
        // plus inter-procedural AsyncTaskBus.dispatchAsync -> Team.addEntry (FS108)
        val l4 = Label()
        runAll.visitLabel(l4)
        runAll.visitLineNumber(54, l4)
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "getRegionScheduler",
            "()Lio/papermc/paper/threadedregions/scheduler/RegionScheduler;",
            false,
        )
        runAll.visitVarInsn(Opcodes.ALOAD, 0)
        runAll.visitVarInsn(Opcodes.ALOAD, 5)
        runAll.visitVarInsn(Opcodes.ALOAD, 2)
        val regionTarget = Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "lambda\$regionHit\$1",
            "(L$pkg/CooldownRegistry;)V",
            false,
        )
        runAll.visitInvokeDynamicInsn(
            "run",
            "(L$pkg/CooldownRegistry;)Ljava/lang/Runnable;",
            bsm,
            org.objectweb.asm.Type.getType("()V"),
            regionTarget,
            org.objectweb.asm.Type.getType("()V"),
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "io/papermc/paper/threadedregions/scheduler/RegionScheduler",
            "execute",
            "(Ljava/lang/Object;Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            true,
        )

        // FS106: RegionScheduler.execute capturing Player and calling Player.setHealth without isOwnedByCurrentRegion
        val l4b = Label()
        runAll.visitLabel(l4b)
        runAll.visitLineNumber(60, l4b)
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "getRegionScheduler",
            "()Lio/papermc/paper/threadedregions/scheduler/RegionScheduler;",
            false,
        )
        runAll.visitVarInsn(Opcodes.ALOAD, 0)
        runAll.visitVarInsn(Opcodes.ALOAD, 5)
        runAll.visitInsn(Opcodes.ACONST_NULL)
        runAll.visitTypeInsn(Opcodes.CHECKCAST, "org/bukkit/entity/Player")
        val splitTarget = Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "lambda\$splitEntity\$2",
            "(Lorg/bukkit/entity/Player;)V",
            false,
        )
        runAll.visitInvokeDynamicInsn(
            "run",
            "(Lorg/bukkit/entity/Player;)Ljava/lang/Runnable;",
            bsm,
            org.objectweb.asm.Type.getType("()V"),
            splitTarget,
            org.objectweb.asm.Type.getType("()V"),
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "io/papermc/paper/threadedregions/scheduler/RegionScheduler",
            "execute",
            "(Ljava/lang/Object;Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            true,
        )

        // FS108 via inter-procedural INVOKEDYNAMIC wrapper AsyncTaskBus.dispatchAsync(Runnable)
        val l4c = Label()
        runAll.visitLabel(l4c)
        runAll.visitLineNumber(66, l4c)
        runAll.visitInsn(Opcodes.ACONST_NULL)
        runAll.visitTypeInsn(Opcodes.CHECKCAST, "org/bukkit/scoreboard/Team")
        val teamTarget = Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "lambda\$teamUpdate\$3",
            "(Lorg/bukkit/scoreboard/Team;)V",
            false,
        )
        runAll.visitInvokeDynamicInsn(
            "run",
            "(Lorg/bukkit/scoreboard/Team;)Ljava/lang/Runnable;",
            bsm,
            org.objectweb.asm.Type.getType("()V"),
            teamTarget,
            org.objectweb.asm.Type.getType("()V"),
        )
        runAll.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "$pkg/AsyncTaskBus",
            "dispatchAsync",
            "(Ljava/lang/Runnable;)V",
            false,
        )
        runAll.visitInsn(Opcodes.RETURN)
        runAll.visitMaxs(6, 6)
        runAll.visitEnd()

        // Synthetic lambda$asyncSync$0
        val lam0 = cw.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "lambda\$asyncSync\$0",
            "(L$pkg/PlayerSyncService;Lorg/bukkit/inventory/PlayerInventory;Ljava/lang/Object;)V",
            null,
            null,
        )
        lam0.visitCode()
        val l5 = Label()
        lam0.visitLabel(l5)
        lam0.visitLineNumber(43, l5)
        lam0.visitVarInsn(Opcodes.ALOAD, 0)
        lam0.visitVarInsn(Opcodes.ALOAD, 1)
        lam0.visitVarInsn(Opcodes.ALOAD, 2)
        lam0.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "$pkg/PlayerSyncService",
            "syncInventoryAndTarget",
            "(Lorg/bukkit/inventory/PlayerInventory;Ljava/lang/Object;)V",
            true,
        )
        lam0.visitInsn(Opcodes.RETURN)
        lam0.visitMaxs(3, 3)
        lam0.visitEnd()

        // Synthetic lambda$regionHit$1
        val lam1 = cw.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "lambda\$regionHit\$1",
            "(L$pkg/CooldownRegistry;)V",
            null,
            null,
        )
        lam1.visitCode()
        val l6 = Label()
        lam1.visitLabel(l6)
        lam1.visitLineNumber(55, l6)
        lam1.visitVarInsn(Opcodes.ALOAD, 0)
        lam1.visitLdcInsn("player-1")
        lam1.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "$pkg/CooldownRegistry",
            "recordHit",
            "(Ljava/lang/String;)V",
            false,
        )
        lam1.visitInsn(Opcodes.RETURN)
        lam1.visitMaxs(2, 1)
        lam1.visitEnd()

        // Synthetic lambda$splitEntity$2 (FS106)
        val lam2 = cw.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "lambda\$splitEntity\$2",
            "(Lorg/bukkit/entity/Player;)V",
            null,
            null,
        )
        lam2.visitCode()
        val l7 = Label()
        lam2.visitLabel(l7)
        lam2.visitLineNumber(61, l7)
        lam2.visitVarInsn(Opcodes.ALOAD, 0)
        lam2.visitLdcInsn(20.0)
        lam2.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "org/bukkit/entity/Player",
            "setHealth",
            "(D)V",
            true,
        )
        lam2.visitInsn(Opcodes.RETURN)
        lam2.visitMaxs(3, 1)
        lam2.visitEnd()

        // Synthetic lambda$teamUpdate$3 (FS108 via AsyncTaskBus.dispatchAsync)
        val lam3 = cw.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "lambda\$teamUpdate\$3",
            "(Lorg/bukkit/scoreboard/Team;)V",
            null,
            null,
        )
        lam3.visitCode()
        val l8 = Label()
        lam3.visitLabel(l8)
        lam3.visitLineNumber(67, l8)
        lam3.visitVarInsn(Opcodes.ALOAD, 0)
        lam3.visitLdcInsn("Steve")
        lam3.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "org/bukkit/scoreboard/Team",
            "addEntry",
            "(Ljava/lang/String;)V",
            true,
        )
        lam3.visitInsn(Opcodes.RETURN)
        lam3.visitMaxs(2, 1)
        lam3.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitAsyncWrapperBus(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/AsyncTaskBus"
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
        cw.visitSource("AsyncTaskBus.kt", null)
        emitDefaultConstructor(cw, "java/lang/Object")

        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "dispatchAsync",
            "(Ljava/lang/Runnable;)V",
            null,
            null,
        )
        mv.visitCode()
        val l1 = Label()
        mv.visitLabel(l1)
        mv.visitLineNumber(10, l1)
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "java/util/concurrent/CompletableFuture",
            "runAsync",
            "(Ljava/lang/Runnable;)Ljava/util/concurrent/CompletableFuture;",
            false,
        )
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(2, 1)
        mv.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitSafeRegionWrapperBus(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/RegionTaskBus"
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
        cw.visitSource("RegionTaskBus.kt", null)
        emitDefaultConstructor(cw, "java/lang/Object")

        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "runAt",
            "(Ljava/lang/Object;Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            null,
            null,
        )
        mv.visitCode()
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "getRegionScheduler",
            "()Lio/papermc/paper/threadedregions/scheduler/RegionScheduler;",
            false,
        )
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitVarInsn(Opcodes.ALOAD, 2)
        mv.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "io/papermc/paper/threadedregions/scheduler/RegionScheduler",
            "execute",
            "(Ljava/lang/Object;Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            true,
        )
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(4, 3)
        mv.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitSafeMainPlugin(pkg: String): ByteArray {
        val cw = ClassWriter(0)
        val owner = "$pkg/SafePlugin"
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
        cw.visitSource("SafePlugin.kt", null)
        cw.visitField(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_FINAL,
            "safeCache",
            "Ljava/util/concurrent/ConcurrentHashMap;",
            null,
            null,
        ).visitEnd()

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitTypeInsn(Opcodes.NEW, "java/util/concurrent/ConcurrentHashMap")
        init.visitInsn(Opcodes.DUP)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/concurrent/ConcurrentHashMap", "<init>", "()V", false)
        init.visitFieldInsn(Opcodes.PUTFIELD, owner, "safeCache", "Ljava/util/concurrent/ConcurrentHashMap;")
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(3, 1)
        init.visitEnd()

        val safeTick = cw.visitMethod(
            Opcodes.ACC_PUBLIC,
            "scheduleRegionSafe",
            "(Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            null,
            null,
        )
        safeTick.visitCode()
        safeTick.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "org/bukkit/Bukkit",
            "getRegionScheduler",
            "()Lio/papermc/paper/threadedregions/scheduler/RegionScheduler;",
            false,
        )
        safeTick.visitVarInsn(Opcodes.ALOAD, 0)
        safeTick.visitVarInsn(Opcodes.ALOAD, 1)
        safeTick.visitVarInsn(Opcodes.ALOAD, 2)
        safeTick.visitMethodInsn(
            Opcodes.INVOKEINTERFACE,
            "io/papermc/paper/threadedregions/scheduler/RegionScheduler",
            "execute",
            "(Ljava/lang/Object;Lorg/bukkit/Location;Ljava/lang/Runnable;)V",
            true,
        )
        safeTick.visitInsn(Opcodes.RETURN)
        safeTick.visitMaxs(4, 3)
        safeTick.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitBenignHelperClass(internalName: String): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        cw.visitSource("${internalName.substringAfterLast('/')}.kt", null)
        emitDefaultConstructor(cw, "java/lang/Object")
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "computeKey", "(I)I", null, null)
        mv.visitCode()
        mv.visitVarInsn(Opcodes.ILOAD, 1)
        mv.visitIntInsn(Opcodes.BIPUSH, 31)
        mv.visitInsn(Opcodes.IMUL)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitMaxs(2, 2)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitDefaultConstructor(cw: ClassWriter, superInternal: String) {
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, superInternal, "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
    }
}
