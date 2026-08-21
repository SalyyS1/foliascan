package com.salyvn.foliascan.rules

import com.salyvn.foliascan.model.Severity

/**
 * The rule table.
 *
 * Every entry was derived by reading PaperMC/Folia's own patch set, not from blog posts or
 * guesswork. `tools/extract_folia_throws.py` in this repository regenerates the underlying
 * dataset from a Folia checkout so the table can be re-verified when Folia changes.
 *
 * Two classes of rule live here:
 *  - unconditional: Folia throws whenever the code runs, on any thread. Reported always.
 *  - contextual:    Folia throws only when the caller is not the thread owning the region.
 *                   Reported only inside a detected off-region context, because the same
 *                   call is perfectly correct from the owning region.
 */
object RuleCatalog {

    private const val PATCH_FLAG =
        "folia-api/paper-patches/features/0003-Require-plugins-to-be-explicitly-marked-as-Folia-sup.patch"
    private const val PATCH_SCHED_API =
        "folia-api/paper-patches/features/0002-Region-scheduler-API.patch"
    private const val PATCH_SERVER =
        "folia-server/paper-patches/features/0001-Region-Threading-Base.patch"

    private const val SCHEDULER_FIX =
        "Use the Paper threaded-region schedulers, which also work on plain Paper: " +
            "Bukkit.getGlobalRegionScheduler() for global state, Bukkit.getRegionScheduler() " +
            "for work at a Location, entity.getScheduler() for work following an entity, " +
            "Bukkit.getAsyncScheduler() for off-tick work."

    /** Internal name of the scheduler package that signals real Folia migration work. */
    const val FOLIA_SCHEDULER_PACKAGE = "io/papermc/paper/threadedregions/scheduler/"

    val foliaSupportFlag = ManifestRule(
        id = "FS001",
        severity = Severity.BLOCKER,
        title = "Plugin does not declare folia-supported: true",
        why = "Folia refuses to load any plugin whose descriptor lacks this key, so the " +
            "plugin never starts. The flag is read from plugin.yml and paper-plugin.yml alike.",
        fix = "Add `folia-supported: true` to plugin.yml (or paper-plugin.yml) - but only " +
            "after the code below is actually region-safe. The flag is a claim, not a fix.",
        provenance = Provenance(PATCH_FLAG, "PluginDescriptionFile#isFoliaSupported"),
    )

    val patchedByTool = ArtifactRule(
        id = "FS002",
        severity = Severity.WARNING,
        title = "Folia support was declared by a patcher, not by the author",
        why = "This jar carries runtime classes injected by an automated Folia patcher. Those " +
            "tools rewrite scheduler calls and then set `folia-supported: true` in the " +
            "descriptor whether or not the result is region-safe, so the load-time check passes " +
            "on a claim nothing verified. A declared flag from a patched jar says only that a " +
            "machine rewrote the bytecode.",
        fix = "Treat the flag as unproven. Test the plugin under real load on Folia, or ask the " +
            "author for first-party support. Patched bytecode also complicates support requests " +
            "and future updates, since the shipped jar no longer matches the author's build.",
        provenance = Provenance(
            "MARVserver/pasta (FoliaPhantom), MIT",
            "PluginPatcher#modifyPluginDescriptor writes `folia-supported: true` " +
                "unconditionally; PluginPatcher.RUNTIME_CLASSES bundles the marker classes",
        ),
    )

    private val bukkitSchedulerGetter = CallRule(
        id = "FS010",
        severity = Severity.CRITICAL,
        title = "Legacy BukkitScheduler is dead on Folia",
        why = "Folia replaces CraftScheduler#handle with an unconditional " +
            "`if (true) throw new UnsupportedOperationException()`, so every runTask, " +
            "runTaskLater, runTaskTimer and async variant fails at runtime - not just on " +
            "the wrong thread, always. BukkitScheduler itself is marked @Deprecated by Folia.",
        fix = SCHEDULER_FIX,
        provenance = Provenance(PATCH_SERVER, "CraftScheduler#handle"),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("getScheduler"),
    )

    private val bukkitSchedulerUse = CallRule(
        id = "FS011",
        severity = Severity.CRITICAL,
        title = "Call on BukkitScheduler will throw on Folia",
        why = "Task submission routes through CraftScheduler#handle, which Folia makes throw " +
            "unconditionally. Holding the scheduler in a field does not avoid it.",
        fix = SCHEDULER_FIX,
        provenance = Provenance(PATCH_SERVER, "CraftScheduler#handle"),
        owners = setOf("org/bukkit/scheduler/BukkitScheduler"),
    )

    private val bukkitRunnableSubclass = SupertypeRule(
        id = "FS012",
        severity = Severity.CRITICAL,
        title = "Class extends BukkitRunnable",
        why = "Every BukkitRunnable#runTask* path submits through CraftScheduler#handle, " +
            "which Folia makes throw unconditionally.",
        fix = SCHEDULER_FIX + " A BukkitRunnable subclass usually becomes a plain lambda or " +
            "Consumer<ScheduledTask>.",
        provenance = Provenance(PATCH_SCHED_API, "BukkitScheduler @Deprecated"),
        supertypes = setOf("org/bukkit/scheduler/BukkitRunnable"),
    )

    private val syncTeleport = CallRule(
        id = "FS020",
        severity = Severity.CRITICAL,
        title = "Synchronous teleport is rejected under region threading",
        why = "Folia throws UnsupportedOperationException(\"Must use teleportAsync while in " +
            "region threading\") from CraftEntity#teleport0 and CraftPlayer#teleport0, " +
            "because a teleport can move an entity between regions.",
        fix = "Use entity.teleportAsync(location) and continue in the returned " +
            "CompletableFuture<Boolean>.",
        provenance = Provenance(PATCH_SERVER, "CraftEntity#teleport0, CraftPlayer#teleport0"),
        ownerPrefixes = setOf("org/bukkit/entity/"),
        methods = setOf("teleport"),
    )

    private val scoreboardRegistration = CallRule(
        id = "FS030",
        severity = Severity.CRITICAL,
        title = "Scoreboard registration is not implemented on Folia",
        why = "CraftScoreboard#registerNewObjective, #registerNewTeam and #clearSlot all " +
            "begin with `if (true) throw new UnsupportedOperationException()` marked " +
            "\"Folia - not supported yet\". Any scoreboard-driven HUD, stat display or team " +
            "system breaks the first time it runs.",
        fix = "There is no drop-in replacement. Render the same information with packet-level " +
            "sidebars, boss bars, action bar or text displays, or gate the feature off when " +
            "running on Folia.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftScoreboard#registerNewObjective, #registerNewTeam, #clearSlot",
        ),
        owners = setOf("org/bukkit/scoreboard/Scoreboard"),
        methods = setOf("registerNewObjective", "registerNewTeam", "clearSlot"),
    )

    private val scoreboardManager = CallRule(
        id = "FS031",
        severity = Severity.CRITICAL,
        title = "Scoreboard creation and assignment are not implemented on Folia",
        why = "CraftScoreboardManager#getNewScoreboard and #setPlayerBoard - the latter reached " +
            "through Player#setScoreboard - throw unconditionally on Folia.",
        fix = "Same as FS030: replace the scoreboard feature or disable it on Folia.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftScoreboardManager#getNewScoreboard, #setPlayerBoard",
        ),
        owners = setOf("org/bukkit/scoreboard/ScoreboardManager", "org/bukkit/entity/Player"),
        methods = setOf("getNewScoreboard", "setScoreboard"),
    )

    private val worldLifecycle = CallRule(
        id = "FS040",
        severity = Severity.CRITICAL,
        title = "Runtime world creation and unloading are not implemented on Folia",
        why = "CraftServer#createWorld and #unloadWorld throw with the comment " +
            "\"Folia - not implemented properly yet\". Multiverse-style world management " +
            "cannot work.",
        fix = "Pre-create worlds before startup, or gate the feature off on Folia.",
        provenance = Provenance(PATCH_SERVER, "CraftServer#createWorld, #unloadWorld"),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("createWorld", "unloadWorld"),
    )

    private val tickableTileEntityCount = CallRule(
        id = "FS041",
        severity = Severity.CRITICAL,
        title = "World#getTickableTileEntityCount is not implemented on Folia",
        why = "CraftWorld#getTickableTileEntityCount throws unconditionally " +
            "(\"Folia - region threading - TODO fix this?\").",
        fix = "Drop the metric or compute it per region from your own bookkeeping.",
        provenance = Provenance(PATCH_SERVER, "CraftWorld#getTickableTileEntityCount"),
        owners = setOf("org/bukkit/World"),
        methods = setOf("getTickableTileEntityCount"),
    )
    // --- contextual: correct from the owning region, fatal from anywhere else -------------

    private const val REGION_FIX =
        "Hop onto the owning region first: Bukkit.getRegionScheduler().execute(plugin, location) " +
            "for block and world work, entity.getScheduler().run(plugin, task, null) for entity " +
            "work, or Bukkit.getGlobalRegionScheduler() for global server state."

    private val serverMetrics = CallRule(
        id = "FS050",
        severity = Severity.WARNING,
        title = "Server metrics throw when read off-region",
        why = "CraftServer#getTPS and #getAverageTickTime throw " +
            "UnsupportedOperationException(\"Not on any region\") unless the calling thread " +
            "owns a region. Reading them from an async task kills the task.",
        fix = "Read them from a region or global-region task, or use the per-region TPS API.",
        provenance = Provenance(PATCH_SERVER, "CraftServer#getTPS, #getAverageTickTime"),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("getTPS", "getAverageTickTime"),
        contextual = true,
    )

    private val dispatchCommand = CallRule(
        id = "FS051",
        severity = Severity.WARNING,
        title = "dispatchCommand throws for senders outside the current region",
        why = "CraftServer#dispatchCommand is region-guarded and throws " +
            "UnsupportedOperationException(\"Dispatching command for <sender>\") when the " +
            "sender is not owned by the calling thread's region.",
        fix = "Dispatch console commands on the global region scheduler; dispatch player " +
            "commands from that player's entity scheduler.",
        provenance = Provenance(PATCH_SERVER, "CraftServer#dispatchCommand"),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("dispatchCommand"),
        contextual = true,
    )

    private val worldRegionGuarded = CallRule(
        id = "FS060",
        severity = Severity.WARNING,
        title = "World call is region-guarded",
        why = "Folia wraps these CraftWorld methods in TickThread.ensureTickThread, which " +
            "throws when the caller does not own the region for that chunk or location.",
        fix = REGION_FIX,
        provenance = Provenance(
            PATCH_SERVER,
            "CraftWorld ensureTickThread guards: generateTree, getChunkAt, getGameTime, " +
                "getHighestBlockYAt, isChunkGenerated, loadChunk, refreshChunk, sendGameEvent, setBiome",
        ),
        owners = setOf("org/bukkit/World"),
        methods = setOf(
            "generateTree", "getChunkAt", "getGameTime", "getHighestBlockYAt",
            "isChunkGenerated", "loadChunk", "refreshChunk", "sendGameEvent", "setBiome",
        ),
        contextual = true,
    )

    private val blockRegionGuarded = CallRule(
        id = "FS061",
        severity = Severity.WARNING,
        title = "Block call is region-guarded",
        why = "Folia wraps these CraftBlock methods in TickThread.ensureTickThread, which " +
            "throws when the caller does not own the region containing the block.",
        fix = REGION_FIX,
        provenance = Provenance(
            PATCH_SERVER,
            "CraftBlock ensureTickThread guards: applyBoneMeal, breakNaturally, canPlace, " +
                "fluidTick, getBiome, getBlockPower, getBlockState, getComputedBiome, " +
                "isBlockFaceIndirectlyPowered, randomTick, rayTrace, setBiome, setBlockState, tick",
        ),
        owners = setOf("org/bukkit/block/Block"),
        methods = setOf(
            "applyBoneMeal", "breakNaturally", "canPlace", "fluidTick", "getBiome",
            "getBlockPower", "getBlockState", "getComputedBiome",
            "isBlockFaceIndirectlyPowered", "randomTick", "rayTrace", "setBiome",
            "setBlockState", "tick",
        ),
        contextual = true,
    )

    private val blockStateRegionGuarded = CallRule(
        id = "FS062",
        severity = Severity.WARNING,
        title = "BlockState call is region-guarded",
        why = "CraftBlockState#getDrops and #randomTick are wrapped in " +
            "TickThread.ensureTickThread and throw off-region.",
        fix = REGION_FIX,
        provenance = Provenance(PATCH_SERVER, "CraftBlockState#getDrops, #randomTick"),
        owners = setOf("org/bukkit/block/BlockState"),
        methods = setOf("getDrops", "randomTick"),
        contextual = true,
    )

    private val entityFamilyRegionGuarded = CallRule(
        id = "FS063",
        severity = Severity.WARNING,
        title = "Entity API touched from an off-region context",
        why = "Folia adds TickThread.ensureTickThread to CraftEntity#getHandle and to the " +
            "getHandle override of every entity subclass. Because nearly every Bukkit entity " +
            "method dereferences that handle, touching an entity from a thread that does not " +
            "own it throws. A handful of cached accessors may survive in practice; the call " +
            "is still not contractually safe.",
        fix = "entity.getScheduler().run(plugin, task, null) - the entity scheduler follows " +
            "the entity across regions, including mid-teleport.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftEntity#getHandle plus ~170 subclass getHandle overrides",
        ),
        ownerPrefixes = setOf("org/bukkit/entity/"),
        // The entity scheduler and the async teleport are the prescribed Folia APIs; flagging
        // them would contradict FS020 and FS012.
        excludeMethods = setOf("getScheduler", "teleportAsync"),
        contextual = true,
    )

    private val serverInternals = PackageRule(
        id = "FS070",
        severity = Severity.WARNING,
        title = "Direct server-internals access",
        why = "Folia rewrites the tick loop, chunk system and entity storage. Internal classes " +
            "reached through NMS or CraftBukkit carry region-ownership assumptions that no " +
            "longer hold, and Folia's own internals are guarded by TickThread checks.",
        fix = "Move to the public Bukkit/Paper API where possible. Where internals are " +
            "unavoidable, confirm the owning region before touching them and keep the access " +
            "behind a version-specific adapter.",
        provenance = Provenance(PATCH_SERVER, "Region-Threading-Base rewrites server internals"),
        prefixes = setOf("net/minecraft/", "org/bukkit/craftbukkit/"),
    )

    private val primaryThreadCheck = CallRule(
        id = "FS080",
        severity = Severity.INFO,
        title = "isPrimaryThread() used as a safety gate",
        why = "There is no single main thread on Folia. Folia's own patches delete internal " +
            "isPrimaryThread() checks rather than reinterpret them, so plugin logic that " +
            "branches on this value is not a reliable guard for touching world state.",
        fix = "Decide by ownership instead of by thread identity: schedule the work on the " +
            "region, entity or global scheduler that owns the data you are about to touch.",
        provenance = Provenance(PATCH_SERVER, "removal of Bukkit.isPrimaryThread() guards"),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("isPrimaryThread"),
    )

    // --- assembled views -----------------------------------------------------------------

    val manifestRules: List<ManifestRule> = listOf(foliaSupportFlag)

    val artifactRules: List<ArtifactRule> = listOf(patchedByTool)

    val supertypeRules: List<SupertypeRule> = listOf(bukkitRunnableSubclass)

    val packageRules: List<PackageRule> = listOf(serverInternals)

    val callRules: List<CallRule> = listOf(
        bukkitSchedulerGetter, bukkitSchedulerUse, syncTeleport,
        scoreboardRegistration, scoreboardManager, worldLifecycle, tickableTileEntityCount,
        serverMetrics, dispatchCommand, worldRegionGuarded, blockRegionGuarded,
        blockStateRegionGuarded, entityFamilyRegionGuarded, primaryThreadCheck,
    )

    val all: List<Rule> = manifestRules + artifactRules + supertypeRules + packageRules + callRules

    fun byId(id: String): Rule? = all.firstOrNull { it.id.equals(id, ignoreCase = true) }
}
