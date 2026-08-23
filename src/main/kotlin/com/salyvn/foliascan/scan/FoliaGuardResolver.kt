package com.salyvn.foliascan.scan

/**
 * Finds code whose legacy calls are only reachable when the server is *not* Folia.
 *
 * Reporting those as critical would flag every correctly written dual-platform plugin, so this
 * resolver looks for the guard. Real plugins write the guard in one of two shapes and both are
 * recognised here.
 *
 * **Per method** - one class, a `isFolia`-style flag, and a branch in every method:
 *
 * ```
 * fun runGlobal(task: Runnable) =
 *     if (isFolia) Bukkit.getGlobalRegionScheduler().run(plugin) { task.run() }
 *     else Bukkit.getScheduler().runTask(plugin, task)
 * ```
 *
 * A method qualifies when it both tests for Folia *and* contains a region-scheduler call. The
 * second half is what keeps this from muting everything: a method that calls the legacy
 * scheduler unconditionally has no region-API call to pair with the test. Lambda bodies created
 * inside a guarded method inherit the guard, because a task built in the legacy branch compiles
 * into a separate synthetic method that would otherwise look unguarded on its own.
 *
 * **Per class** - one interface, two implementations, the choice made once at startup:
 *
 * ```
 * val scheduler = if (IS_FOLIA) PaperScheduler() else BukkitScheduler()
 * ```
 *
 * `BukkitScheduler` there contains no region call at all, so the per-method shape cannot see it.
 * It is treated as guarded when **every** `new` of it in the jar sits in a method that tests for
 * Folia.
 *
 * What counts as testing for Folia: reading or calling any member whose name mentions Folia
 * (`isFolia`, `IS_FOLIA`, `getIS_FOLIA`), or calling Paper's `isBrandCompatible`. Deliberately
 * *not* included is the mere presence of a region-scheduler call, which is the thing being paired
 * against rather than evidence on its own.
 *
 * Limits, stated rather than hidden: a class instantiated reflectively, through a service loader,
 * or by a dependency-injection container has no visible `new`, so the per-class shape will not
 * recognise it; and neither shape does control-flow analysis, so a method that tests for Folia
 * and *also* calls the legacy scheduler outside the branch is treated as guarded. The first errs
 * toward reporting, the second away from it.
 */
object FoliaGuardResolver {

    private val REGION_GETTERS = setOf(
        "getRegionScheduler", "getAsyncScheduler", "getGlobalRegionScheduler",
    )

    private const val REGION_PACKAGE = "io/papermc/paper/threadedregions/"
    private const val BRAND_CHECK = "isBrandCompatible"

    fun resolve(jar: JarClasses): GuardIndex = GuardIndex(
        byClass = guardedClasses(jar),
        byMethod = guardedMethods(jar),
        suspectedByClass = suspectedPlatformAlternates(jar),
    )

    /**
     * Classes that look like one arm of a reflectively chosen platform pair.
     *
     * FoliaLib is the canonical case and it defeats both provable shapes: `FoliaLib.createServerImpl`
     * does `Class.forName(basePackage + implName)`, so `SpigotImplementation` has no `new` anywhere
     * in the jar and no method of it tests for Folia - the test lives in the factory, one indirection
     * away, keyed by a string.
     *
     * What can be seen is the shape: a class that this jar never constructs, sitting next to a
     * sibling implementation of the same interface that does use the region API. That is suggestive,
     * not proof, so it only ever attaches an explanation. Severity is left alone - a wrong all-clear
     * costs more than a wrong warning, and the reader is told exactly what to check.
     */
    private fun suspectedPlatformAlternates(jar: JarClasses): Map<String, String> {
        val constructed = constructionSites(jar).keys
        val regionAware = jar.classes.values
            .filter { model -> model.methods.any { it.instructions.any(::isRegionApi) } }
            .map { it.internalName }
            .toSet()

        val out = mutableMapOf<String, String>()
        for (model in jar.classes.values) {
            if (model.internalName in constructed || model.internalName in regionAware) continue
            if (model.interfaces.isEmpty()) continue
            val sibling = regionAware.firstOrNull { other ->
                other != model.internalName &&
                    jar.get(other)?.interfaces?.any { it in model.interfaces } == true
            } ?: continue
            out[model.internalName] = "never constructed in this jar, and " +
                "${sibling.substringAfterLast('/')} implements the same interface using the region " +
                "API - if a factory picks between them at runtime this branch may be unreachable " +
                "on Folia, which this analysis cannot prove"
        }
        return out
    }

    /** Methods that branch on a Folia test and carry the region-aware path themselves. */
    private fun guardedMethods(jar: JarClasses): Map<Pair<String, String>, String> {
        val out = mutableMapOf<Pair<String, String>, String>()
        val pending = ArrayDeque<Pair<MethodKey, String>>()

        for (model in jar.classes.values) {
            for (method in model.methods) {
                val probe = probeIn(method) ?: continue
                if (method.instructions.none(::isRegionApi)) continue
                val where = MethodKey(model.internalName, method.id)
                val reason = "not reachable on Folia: " +
                    "${where.owner.substringAfterLast('/')}.${method.id.name} picks its path " +
                    "from $probe and has a region-scheduler branch"
                if (out.put(model.internalName to method.id.name, reason) == null) {
                    pending += where to reason
                }
            }
        }

        // A task created in the legacy branch compiles into its own synthetic method. Judged
        // alone it looks like unguarded legacy code, so the guard follows the lambda.
        while (pending.isNotEmpty()) {
            val (where, reason) = pending.removeFirst()
            val body = jar.get(where.owner)?.method(where.method) ?: continue
            for (insn in body.instructions) {
                val target = insn.lambdaTarget?.takeIf { jar.contains(it.owner) } ?: continue
                val key = target.owner to target.method.name
                if (out.put(key, reason) == null) pending += target to reason
            }
        }
        return out
    }

    /** Classes whose every construction site tests for Folia first. */
    private fun guardedClasses(jar: JarClasses): Map<String, String> {
        val out = mutableMapOf<String, String>()
        for ((created, callers) in constructionSites(jar)) {
            if (callers.isEmpty()) continue
            val guards = callers.map { guardIn(jar, it, created) }
            if (guards.any { it == null }) continue
            out[created] = guards.filterNotNull().distinct().first()
        }
        return out
    }

    /** created class internal name -> the methods that instantiate it. */
    private fun constructionSites(jar: JarClasses): Map<String, List<MethodKey>> {
        val out = mutableMapOf<String, MutableList<MethodKey>>()
        for (model in jar.classes.values) {
            for (method in model.methods) {
                val here = MethodKey(model.internalName, method.id)
                for (insn in method.instructions) {
                    if (insn.kind == InsnKind.TYPE_REF && insn.name == "new" && jar.contains(insn.owner)) {
                        out.getOrPut(insn.owner) { mutableListOf() }.add(here)
                    }
                }
            }
        }
        return out
    }

    /**
     * Returns a description of the Folia test inside [where], or null when there is none.
     *
     * [created] is excluded from the search on purpose. A class called `FoliaScheduler` mentions
     * Folia in its own name, so counting the `new FoliaScheduler` instruction as evidence of a
     * guard would make every such class vacuously guarded - the test has to be independent of
     * the class being tested.
     */
    private fun guardIn(jar: JarClasses, where: MethodKey, created: String): String? {
        val body = jar.get(where.owner)?.method(where.method) ?: return null
        val createdSimple = created.substringAfterLast('/')
        val visible = body.instructions.filterNot {
            it.owner == created || it.name.contains(createdSimple, ignoreCase = true)
        }
        val probe = probeIn(visible) ?: return null
        return "not reachable on Folia: this class is only instantiated where " +
            "${where.owner.substringAfterLast('/')}.${where.method.name} tests $probe"
    }

    private fun probeIn(method: MethodModel): String? = probeIn(method.instructions)

    private fun probeIn(instructions: List<Insn>): String? {
        for (insn in instructions) {
            if (insn.kind == InsnKind.INDY) continue
            if (insn.name.contains("folia", ignoreCase = true)) return insn.name
            if (insn.kind == InsnKind.CALL && insn.name == BRAND_CHECK) {
                return "ServerBuildInfo.$BRAND_CHECK"
            }
        }
        return null
    }

    private fun isRegionApi(insn: Insn): Boolean = when {
        insn.owner.startsWith(REGION_PACKAGE) -> true
        insn.kind != InsnKind.CALL -> false
        insn.name in REGION_GETTERS -> true
        // Entity#getScheduler is the region-aware way to follow one entity around.
        insn.name == "getScheduler" && insn.desc.contains(REGION_PACKAGE) -> true
        else -> false
    }
}

/**
 * Where the Folia guards are, addressable the way a finding is: by class, and by the method the
 * finding sits in.
 */
class GuardIndex internal constructor(
    private val byClass: Map<String, String>,
    private val byMethod: Map<Pair<String, String>, String>,
    private val suspectedByClass: Map<String, String> = emptyMap(),
) {
    val size: Int get() = byClass.size + byMethod.size

    /** A description of the guard covering this location, or null when it is not guarded. */
    fun guardFor(internalName: String, methodName: String?): String? =
        byClass[internalName] ?: byMethod[internalName to (methodName ?: return null)]

    /**
     * An explanation for code that *looks* like a platform alternate without proving it. Never a
     * reason to lower severity - only to tell the reader what to verify.
     */
    fun suspicionFor(internalName: String): String? = suspectedByClass[internalName]

    companion object {
        val EMPTY = GuardIndex(emptyMap(), emptyMap())
    }
}
