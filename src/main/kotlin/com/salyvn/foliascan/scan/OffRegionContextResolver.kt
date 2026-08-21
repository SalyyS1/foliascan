package com.salyvn.foliascan.scan

/** Why a method is treated as running off the region that owns the data it touches. */
data class OffRegionOrigin(
    /** The method where the off-region work is handed off, e.g. the caller of submit(). */
    val entryPoint: MethodKey,
    /** Human-readable reason, e.g. "lambda passed to ExecutorService.submit". */
    val reason: String,
    /** How many in-jar calls away from the entry point this method sits. */
    val depth: Int,
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

    private val RUN_METHOD = MethodId("run", "()V")

    fun resolve(jar: JarClasses): OffRegionContexts {
        val seeds = mutableMapOf<MethodKey, OffRegionOrigin>()

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val here = MethodKey(model.internalName, method.id)
                method.instructions.forEachIndexed { index, insn ->
                    val reason = submitterReason(insn) ?: return@forEachIndexed
                    taskHandedTo(method, index, jar)?.let { target ->
                        seeds.putIfAbsent(target, OffRegionOrigin(here, reason, 0))
                    }
                }
            }
        }
        return OffRegionContexts(propagate(seeds, jar))
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
                if (result.containsKey(next)) continue
                if (jar.get(next.owner)?.method(next.method) == null) continue
                result[next] = origin.copy(depth = origin.depth + 1)
                queue.addLast(next)
            }
        }
        return result
    }

    private fun simple(internalName: String): String = internalName.substringAfterLast('/')
}
