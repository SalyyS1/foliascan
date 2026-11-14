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
        "com/destroystokyo/paper/event/profile/PreLookupProfileEvent",
    )

    private val RUN_METHOD = MethodId("run", "()V")

    fun resolve(jar: JarClasses): OffRegionContexts {
        val seeds = mutableMapOf<MethodKey, OffRegionOrigin>()
        val reentries = mutableSetOf<MethodKey>()

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val here = MethodKey(model.internalName, method.id)
                val firstLine = method.instructions.firstNotNullOfOrNull { it.line }
                asyncEventReason(method.id.desc)?.let { reason ->
                    seeds.putIfAbsent(
                        here,
                        OffRegionOrigin(
                            entryPoint = here,
                            reason = reason,
                            depth = 0,
                            hops = listOf(TaintHop(here, firstLine, model.sourceFile)),
                        ),
                    )
                }
                method.instructions.forEachIndexed { index, insn ->
                    if (isRegionReentrySubmitter(insn)) {
                        taskHandedTo(method, index, jar)?.let { reentries += it }
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
                    val reason = submitterReason(insn) ?: return@forEachIndexed
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

            name in BUKKIT_ASYNC_SUBMITTERS -> "submitted via $name"

            (owner == PAPER_ASYNC_SCHEDULER || owner.endsWith("/AsyncScheduler")) &&
                name in PAPER_ASYNC_SUBMITTERS -> "submitted via AsyncScheduler.$name"

            else -> null
        }
    }

    /**
     * Finds the task body passed to the submitter at [callIndex]: the closest preceding
     * lambda, or the closest preceding `new` of an in-jar class that has a `run()` method.
     */
    private fun taskHandedTo(method: MethodModel, callIndex: Int, jar: JarClasses): MethodKey? {
        for (i in callIndex - 1 downTo 0) {
            val prev = method.instructions[i]
            if (prev.kind == InsnKind.INDY && prev.lambdaTarget != null) {
                return prev.lambdaTarget
            }
            if (prev.kind == InsnKind.TYPE_REF && prev.name == "new") {
                val candidate = jar.get(prev.owner) ?: continue
                val run = candidate.methods.firstOrNull { it.id == RUN_METHOD }
                if (run != null) return MethodKey(candidate.internalName, run.id)
                // A BukkitRunnable subclass without its own run() is abstract usage; skip.
            }
            // Another call in between means the stack shape is unclear - stop guessing.
            if (prev.kind == InsnKind.CALL && prev.name != "<init>") return null
        }
        return null
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
