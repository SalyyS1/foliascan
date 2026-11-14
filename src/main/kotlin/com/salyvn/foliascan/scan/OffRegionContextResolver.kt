package com.salyvn.foliascan.scan

/** One method hop along an off-region taint call chain. */
data class TaintHop(
    val method: MethodKey,
    val line: Int? = null,
    val sourceFile: String? = null,
) {
    fun renderShort(): String {
        val cls = method.owner.substringAfterLast('/')
        val loc = if (line != null && line >= 1) ":${line}" else ""
        return "${cls}#${method.method.name}${loc}"
    }
}

/** Why a method is treated as running off the region that owns the data it touches. */
data class OffRegionOrigin(
    /** The method where the off-region work is handed off, e.g. the caller of submit(). */
    val entryPoint: MethodKey,
    /** Human-readable reason, e.g. "lambda passed to ExecutorService.submit". */
    val reason: String,
    /** How many in-jar calls away from the entry point this method sits. */
    val depth: Int,
    /**
     * True when the task runs on Folia's GlobalRegionScheduler (`region={null}`).
     * GlobalRegionScheduler owns global server/world state (FS050, FS064), so those rules do not
     * fire, but it owns no chunks, blocks or entities - touching FS060..FS063 from it throws
     * `IllegalStateException: Cannot read world asynchronously`.
     */
    val isGlobalTick: Boolean = false,
    /**
     * True when the entry point is a Moonrise parallel async ChunkGenerator or BlockPopulator
     * callback running on a chunk-generation worker pool thread.
     */
    val isChunkGeneration: Boolean = false,
    /** Ordered method hops from [entryPoint] down to the current tainted method. */
    val hops: List<TaintHop> = emptyList(),
)

/** Methods that are reachable from an off-region entry point, with the shortest reason found. */
class OffRegionContexts(private val methods: Map<MethodKey, OffRegionOrigin>) {
    fun originOf(key: MethodKey): OffRegionOrigin? = methods[key]

    val size: Int get() = methods.size
}

/**
 * Finds the methods that can run away from the region owning the world state they touch.
 *
 * Strategy, in order of confidence:
 *  1. Seed: a lambda or Runnable handed to an async submitter (executor, CompletableFuture
 *     async stage, raw Thread, BukkitScheduler async task, Paper AsyncScheduler).
 *  2. Seed: `run()` of an in-jar class that extends BukkitRunnable and is submitted through
 *     one of the `...Asynchronously` methods.
 *  3. Propagate: breadth-first across calls to methods defined inside the same jar, so a
 *     helper called from an async task is reported too.
 *
 * Deliberate limits, documented rather than hidden: calls that leave the jar are not
 * followed, reflection and dependency-injected executors are invisible, and a helper used
 * from both sync and async callers is reported (it genuinely may run off-region).
 */
object OffRegionContextResolver {

    private val CONCURRENT_SUBMITTERS = setOf(
        "submit", "execute", "schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay",
        "invokeAll", "invokeAny", "supplyAsync", "runAsync", "thenRunAsync", "thenApplyAsync",
        "thenAcceptAsync", "thenComposeAsync", "whenCompleteAsync", "handleAsync",
        "thenCombineAsync", "exceptionallyAsync",
    )

    private val BUKKIT_ASYNC_SUBMITTERS = setOf(
        "runTaskAsynchronously", "runTaskLaterAsynchronously", "runTaskTimerAsynchronously",
    )

    private val PAPER_ASYNC_SCHEDULER = "io/papermc/paper/threadedregions/scheduler/AsyncScheduler"

    private val PAPER_ASYNC_SUBMITTERS = setOf("runNow", "runDelayed", "runAtFixedRate")

    private val REGION_SCHEDULER_SUFFIXES = setOf(
        "/EntityScheduler",
        "/RegionScheduler",
    )

    private const val GLOBAL_REGION_SUFFIX = "/GlobalRegionScheduler"

    private val REGION_REENTRY_SUBMITTERS = setOf(
        "run", "execute", "runDelayed", "runAtFixedRate",
    )

    private val ASYNC_EVENT_TYPES = setOf(
        "org/bukkit/event/player/AsyncPlayerChatEvent",
        "org/bukkit/event/player/AsyncPlayerPreLoginEvent",
        "io/papermc/paper/event/player/AsyncChatEvent",
        "io/papermc/paper/event/player/AsyncChatDecorateEvent",
        "io/papermc/paper/event/player/AsyncChatCommandDecorateEvent",
        "io/papermc/paper/event/connection/configuration/AsyncPlayerConnectionConfigureEvent",
        "com/destroystokyo/paper/event/profile/PreLookupProfileEvent",
        "com/destroystokyo/paper/event/player/PlayerConnectionValidateLoginEvent",
    )

    private val PROTOCOLLIB_SUPERTYPES = setOf(
        "com/comphenix/protocol/events/PacketAdapter",
        "com/comphenix/protocol/events/PacketListener",
    )
    private val PROTOCOLLIB_METHODS = setOf("onPacketReceiving", "onPacketSending")

    private val PACKETEVENTS_SUPERTYPES = setOf(
        "com/github/retrooper/packetevents/event/PacketListener",
        "com/github/retrooper/packetevents/event/PacketListenerAbstract",
        "com/github/retrooper/packetevents/event/SimplePacketListenerAbstract",
        "com/github/retrooper/packetevents/event/PacketListenerCommon",
    )
    private val PACKETEVENTS_METHODS = setOf("onPacketReceive", "onPacketSend")

    private val NETTY_HANDLER_SUPERTYPES = setOf(
        "io/netty/channel/ChannelInboundHandlerAdapter",
        "io/netty/channel/SimpleChannelInboundHandler",
        "io/netty/channel/ChannelDuplexHandler",
        "io/netty/channel/ChannelInboundHandler",
    )
    private val NETTY_HANDLER_METHODS = setOf("channelRead", "channelRead0", "userEventTriggered")

    private val CHUNK_GENERATOR_SUPERTYPES = setOf("org/bukkit/generator/ChunkGenerator")
    private val CHUNK_GENERATOR_METHODS = setOf(
        "generateNoise", "generateSurface", "generateBedrock", "generateCaves",
        "generateChunkData", "getBaseHeight",
        "shouldGenerateNoise", "shouldGenerateSurface", "shouldGenerateBedrock",
        "shouldGenerateCaves", "shouldGenerateDecorations", "shouldGenerateMobs",
        "shouldGenerateStructures",
    )

    private val BLOCK_POPULATOR_SUPERTYPES = setOf("org/bukkit/generator/BlockPopulator")
    private val BLOCK_POPULATOR_METHODS = setOf("populate")

    private val TIMER_SUBMITTERS = setOf("schedule", "scheduleAtFixedRate")

    private val CF_TYPES = setOf(
        "java/util/concurrent/CompletableFuture",
        "java/util/concurrent/CompletionStage",
    )
    private val CF_ASYNC_STAGE_CREATORS = setOf(
        "supplyAsync", "runAsync", "thenRunAsync", "thenApplyAsync",
        "thenAcceptAsync", "thenComposeAsync", "whenCompleteAsync", "handleAsync",
        "thenCombineAsync", "exceptionallyAsync",
    )
    private val CF_SYNC_CONTINUATIONS = setOf(
        "thenAccept", "thenApply", "thenRun", "thenCompose",
        "whenComplete", "handle", "exceptionally",
    )

    private val RUN_METHOD = MethodId("run", "()V")

    fun resolve(jar: JarClasses): OffRegionContexts {
        val seeds = mutableMapOf<MethodKey, OffRegionOrigin>()
        val reentries = mutableSetOf<MethodKey>()

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val here = MethodKey(model.internalName, method.id)
                val firstLine = method.instructions.firstNotNullOfOrNull { it.line }
                val entryReason = asyncEventReason(method.id.desc)
                    ?: packetOrNettyReason(model, method, jar)
                val chunkGenReason = chunkGenerationReason(model, method, jar)
                if (entryReason != null || chunkGenReason != null) {
                    seeds.putIfAbsent(
                        here,
                        OffRegionOrigin(
                            entryPoint = here,
                            reason = entryReason ?: chunkGenReason!!,
                            depth = 0,
                            isChunkGeneration = chunkGenReason != null,
                            hops = listOf(TaintHop(here, firstLine, model.sourceFile)),
                        ),
                    )
                }
                method.instructions.forEachIndexed { index, insn ->
                    if (isRegionReentrySubmitter(insn)) {
                        reentries += tasksHandedTo(method, index, jar)
                    } else if (isGlobalRegionSubmitter(insn)) {
                        taskHandedTo(method, index, jar)?.let { target ->
                            reentries += target
                            seeds.putIfAbsent(
                                target,
                                OffRegionOrigin(
                                    entryPoint = here,
                                    reason = "submitted via GlobalRegionScheduler.${insn.name} (region={null})",
                                    depth = 0,
                                    isGlobalTick = true,
                                    hops = seedHops(here, insn.line ?: firstLine, model.sourceFile, target, jar),
                                ),
                            )
                        }
                    }
                    val reason = submitterReason(insn)
                        ?: chainedAsyncStageReason(method, index)
                        ?: return@forEachIndexed
                    taskHandedTo(method, index, jar)?.let { target ->
                        seeds.putIfAbsent(
                            target,
                            OffRegionOrigin(
                                entryPoint = here,
                                reason = reason,
                                depth = 0,
                                hops = seedHops(here, insn.line ?: firstLine, model.sourceFile, target, jar),
                            ),
                        )
                    }
                }
            }
        }
        return OffRegionContexts(propagate(seeds, reentries, jar))
    }

    private fun seedHops(
        caller: MethodKey,
        callLine: Int?,
        callerSource: String?,
        target: MethodKey,
        jar: JarClasses,
    ): List<TaintHop> {
        val callerHop = TaintHop(caller, callLine, callerSource)
        if (caller == target) return listOf(callerHop)
        val targetClass = jar.get(target.owner)
        val targetLine = targetClass?.method(target.method)?.instructions?.firstNotNullOfOrNull { it.line }
        return listOf(callerHop, TaintHop(target, targetLine, targetClass?.sourceFile))
    }

    /** True when the method signature takes a single Bukkit/Paper async event parameter. */
    private fun asyncEventReason(desc: String): String? {
        if (!desc.startsWith("(L") || !desc.endsWith(";)V")) return null
        val paramInternal = desc.removePrefix("(L").removeSuffix(";)V")
        if (paramInternal !in ASYNC_EVENT_TYPES) return null
        return "async event handler (${simple(paramInternal)})"
    }

    /**
     * True when [method] overrides a ProtocolLib, PacketEvents, or raw Netty channel callback,
     * all of which execute on Netty I/O threads outside every Folia region.
     */
    private fun packetOrNettyReason(model: ClassModel, method: MethodModel, jar: JarClasses): String? {
        val name = method.id.name
        return when {
            name in PROTOCOLLIB_METHODS && jar.inheritsAny(model.internalName, PROTOCOLLIB_SUPERTYPES) ->
                "ProtocolLib packet listener ($name on Netty I/O thread)"

            name in PACKETEVENTS_METHODS && jar.inheritsAny(model.internalName, PACKETEVENTS_SUPERTYPES) ->
                "PacketEvents packet listener ($name on Netty I/O thread)"

            name in NETTY_HANDLER_METHODS && jar.inheritsAny(model.internalName, NETTY_HANDLER_SUPERTYPES) ->
                "Netty channel handler ($name on Netty I/O thread)"

            else -> null
        }
    }

    /**
     * True when [method] overrides a Paper/Folia Moonrise ChunkGenerator or BlockPopulator
     * generation phase, which executes concurrently on chunk worker pool threads outside any
     * owning region TickThread.
     */
    private fun chunkGenerationReason(model: ClassModel, method: MethodModel, jar: JarClasses): String? {
        val name = method.id.name
        return when {
            name in CHUNK_GENERATOR_METHODS && jar.inheritsAny(model.internalName, CHUNK_GENERATOR_SUPERTYPES) ->
                "Moonrise async ChunkGenerator ($name on chunk worker thread)"

            name in BLOCK_POPULATOR_METHODS && jar.inheritsAny(model.internalName, BLOCK_POPULATOR_SUPERTYPES) ->
                "Moonrise async BlockPopulator ($name on chunk worker thread)"

            else -> null
        }
    }

    /**
     * True when this instruction hands a task back onto a region or entity scheduler.
     * A callback scheduled onto a region thread from inside an async task is re-entering
     * region ownership and must not inherit off-region taint from its enclosing method.
     */
    private fun isRegionReentrySubmitter(insn: Insn): Boolean {
        if (insn.kind != InsnKind.CALL) return false
        if (insn.name !in REGION_REENTRY_SUBMITTERS) return false
        return REGION_SCHEDULER_SUFFIXES.any { insn.owner.endsWith(it) }
    }

    /**
     * True when this instruction schedules a task onto Folia's GlobalRegionScheduler.
     * The global tick thread (`region={null}`) owns global server/world state (FS050, FS064)
     * but does NOT own any chunk, block or entity (FS060..FS063).
     */
    private fun isGlobalRegionSubmitter(insn: Insn): Boolean {
        if (insn.kind != InsnKind.CALL) return false
        if (insn.name !in REGION_REENTRY_SUBMITTERS) return false
        return insn.owner.endsWith(GLOBAL_REGION_SUFFIX)
    }

    /** Returns a description when this instruction hands work to another thread. */
    private fun submitterReason(insn: Insn): String? {
        if (insn.kind != InsnKind.CALL) return null
        val owner = insn.owner
        val name = insn.name
        return when {
            owner.startsWith("java/util/concurrent/") && name in CONCURRENT_SUBMITTERS ->
                "handed to ${simple(owner)}.$name"

            owner == "java/lang/Thread" && name == "<init>" -> "handed to a new Thread"

            owner == "java/util/Timer" && name in TIMER_SUBMITTERS ->
                "scheduled on Timer.$name"

            name in BUKKIT_ASYNC_SUBMITTERS -> "submitted via $name"

            (owner == PAPER_ASYNC_SCHEDULER || owner.endsWith("/AsyncScheduler")) &&
                name in PAPER_ASYNC_SUBMITTERS -> "submitted via AsyncScheduler.$name"

            else -> null
        }
    }

    /**
     * Detects non-async CompletableFuture continuations (`thenAccept`, `thenApply`, `thenRun`,
     * etc.) chained onto an async CompletableFuture stage (`supplyAsync`, `runAsync`, `*Async`).
     * Continuations chained onto Folia-safe futures such as `Entity#teleportAsync` or
     * `World#getChunkAtAsync` complete on the owning region thread and are deliberately excluded.
     */
    private fun chainedAsyncStageReason(method: MethodModel, callIndex: Int): String? {
        val insn = method.instructions[callIndex]
        if (insn.kind != InsnKind.CALL || insn.owner !in CF_TYPES || insn.name !in CF_SYNC_CONTINUATIONS) {
            return null
        }
        for (i in callIndex - 1 downTo 0) {
            val prev = method.instructions[i]
            if (prev.kind != InsnKind.CALL || prev.name == "<init>") continue
            val returnsStage = prev.desc.endsWith(")Ljava/util/concurrent/CompletableFuture;") ||
                prev.desc.endsWith(")Ljava/util/concurrent/CompletionStage;")
            if (!returnsStage) continue
            if (prev.owner in CF_TYPES && prev.name in CF_ASYNC_STAGE_CREATORS) {
                return "handed to CompletableFuture.${insn.name} chained onto ${prev.name}"
            }
            if (prev.owner in CF_TYPES && prev.name in CF_SYNC_CONTINUATIONS) {
                continue
            }
            return null
        }
        return null
    }

    /**
     * Finds the task body passed to the submitter at [callIndex]: the closest preceding
     * lambda (unwrapping Kotlin 2.x two-stage FunctionN -> Java SAM `invokedynamic` bridges),
     * or the closest preceding `new` of an in-jar class that has a `run()` method.
     */
    private fun taskHandedTo(method: MethodModel, callIndex: Int, jar: JarClasses): MethodKey? =
        tasksHandedTo(method, callIndex, jar).firstOrNull()

    private fun tasksHandedTo(method: MethodModel, callIndex: Int, jar: JarClasses): List<MethodKey> {
        val out = mutableListOf<MethodKey>()
        var i = callIndex - 1
        while (i >= 0) {
            val prev = method.instructions[i]
            if (prev.kind == InsnKind.INDY && prev.lambdaTarget != null) {
                if (prev.desc.startsWith("(Lkotlin/jvm/functions/Function") && i > 0) {
                    val inner = method.instructions[i - 1]
                    if (inner.kind == InsnKind.INDY && inner.lambdaTarget != null &&
                        inner.desc.contains(")Lkotlin/jvm/functions/Function")
                    ) {
                        out += inner.lambdaTarget
                        i -= 2
                        continue
                    }
                }
                out += prev.lambdaTarget
                i -= 1
                continue
            }
            if (prev.kind == InsnKind.TYPE_REF && prev.name == "new") {
                val candidate = jar.get(prev.owner)
                val run = candidate?.methods?.firstOrNull { it.id == RUN_METHOD }
                if (candidate != null && run != null) out += MethodKey(candidate.internalName, run.id)
            }
            if (prev.kind == InsnKind.CALL && prev.name != "<init>") break
            i -= 1
        }
        return out
    }

    /** Breadth-first taint across in-jar call edges, keeping the shortest path to each method. */
    private fun propagate(
        seeds: Map<MethodKey, OffRegionOrigin>,
        reentries: Set<MethodKey>,
        jar: JarClasses,
    ): Map<MethodKey, OffRegionOrigin> {
        val result = seeds.toMutableMap()
        val queue = ArrayDeque(seeds.keys)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val origin = result[current] ?: continue
            val model = jar.get(current.owner) ?: continue
            val body = model.method(current.method) ?: continue
            for (insn in body.instructions) {
                val next = when {
                    insn.kind == InsnKind.CALL && jar.contains(insn.owner) ->
                        MethodKey(insn.owner, MethodId(insn.name, insn.desc))

                    insn.kind == InsnKind.INDY && insn.lambdaTarget != null &&
                        jar.contains(insn.lambdaTarget.owner) -> insn.lambdaTarget

                    else -> null
                } ?: continue
                if (next in reentries) continue
                if (result.containsKey(next)) continue
                val nextClass = jar.get(next.owner) ?: continue
                val nextBody = nextClass.method(next.method) ?: continue
                val updatedPrefix = if (origin.hops.isNotEmpty()) {
                    val last = origin.hops.last()
                    origin.hops.dropLast(1) + last.copy(line = insn.line ?: last.line)
                } else {
                    listOf(TaintHop(current, insn.line, model.sourceFile))
                }
                val nextFirstLine = nextBody.instructions.firstNotNullOfOrNull { it.line }
                result[next] = origin.copy(
                    depth = origin.depth + 1,
                    hops = updatedPrefix + TaintHop(next, nextFirstLine, nextClass.sourceFile),
                )
                queue.addLast(next)
            }
        }
        return result
    }

    private fun simple(internalName: String): String = internalName.substringAfterLast('/')
}
