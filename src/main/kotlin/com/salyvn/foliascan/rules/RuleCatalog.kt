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

    /**
     * Bukkit and Paper 26.3 world-bound block-entity (TileState / Container) interfaces whose
     * backing NMS BlockEntity ticks per-region under RegionizedWorldData#tickBlockEntities.
     * Deliberately excludes org.bukkit.block.data (detached BlockData descriptors) and enums.
     */
    val TILE_ENTITY_OWNERS: Set<String> = setOf(
        "org/bukkit/block/TileState",
        "org/bukkit/block/Container",
        "org/bukkit/block/Lockable",
        "org/bukkit/block/Lidded",
        "org/bukkit/block/Banner",
        "org/bukkit/block/Barrel",
        "org/bukkit/block/Beacon",
        "org/bukkit/block/Bed",
        "org/bukkit/block/Bell",
        "org/bukkit/block/BlastFurnace",
        "org/bukkit/block/BrewingStand",
        "org/bukkit/block/BrushableBlock",
        "org/bukkit/block/CalibratedSculkSensor",
        "org/bukkit/block/Campfire",
        "org/bukkit/block/Chest",
        "org/bukkit/block/ChiseledBookshelf",
        "org/bukkit/block/CommandBlock",
        "org/bukkit/block/Comparator",
        "org/bukkit/block/Conduit",
        "org/bukkit/block/Crafter",
        "org/bukkit/block/CreatureSpawner",
        "org/bukkit/block/DaylightDetector",
        "org/bukkit/block/DecoratedPot",
        "org/bukkit/block/Dispenser",
        "org/bukkit/block/DoubleChest",
        "org/bukkit/block/Dropper",
        "org/bukkit/block/EnchantingTable",
        "org/bukkit/block/EnderChest",
        "org/bukkit/block/EndGateway",
        "org/bukkit/block/Furnace",
        "org/bukkit/block/HangingSign",
        "org/bukkit/block/Hopper",
        "org/bukkit/block/Jigsaw",
        "org/bukkit/block/Jukebox",
        "org/bukkit/block/Lectern",
        "org/bukkit/block/SculkCatalyst",
        "org/bukkit/block/SculkSensor",
        "org/bukkit/block/SculkShrieker",
        "org/bukkit/block/ShulkerBox",
        "org/bukkit/block/Sign",
        "org/bukkit/block/Skull",
        "org/bukkit/block/Smoker",
        "org/bukkit/block/Structure",
        "org/bukkit/block/TestBlock",
        "org/bukkit/block/TestInstanceBlock",
        "org/bukkit/block/TrialSpawner",
        "org/bukkit/block/Vault",
        "org/bukkit/block/sign/SignSide",
        "org/bukkit/inventory/BlockInventoryHolder",
    )

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
            "CraftWorld ensureTickThread guards: createExplosion, generateTree, getChunkAt, " +
                "getGameTime, getHighestBlockYAt, isChunkGenerated, loadChunk, refreshChunk, " +
                "sendGameEvent, setBiome, unloadChunk, unloadChunkRequest",
        ),
        owners = setOf("org/bukkit/World"),
        methods = setOf(
            "createExplosion", "generateTree", "getChunkAt", "getGameTime", "getHighestBlockYAt",
            "isChunkGenerated", "loadChunk", "refreshChunk", "sendGameEvent", "setBiome",
            "unloadChunk", "unloadChunkRequest",
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
            "getBlockData", "getBlockPower", "getBlockState", "getComputedBiome",
            "getDrops", "getState", "getType", "isBlockFaceIndirectlyPowered",
            "isEmpty", "isLiquid", "isPassable", "randomTick", "rayTrace",
            "setBiome", "setBlockData", "setBlockState", "setType", "tick",
        ),
        contextual = true,
    )

    private val blockStateRegionGuarded = CallRule(
        id = "FS062",
        severity = Severity.WARNING,
        title = "BlockState call is region-guarded",
        why = "CraftBlockState#update, #getDrops and #randomTick are wrapped in " +
            "TickThread.ensureTickThread and throw off-region.",
        fix = REGION_FIX,
        provenance = Provenance(PATCH_SERVER, "CraftBlockState#update, #getDrops, #randomTick"),
        owners = setOf("org/bukkit/block/BlockState"),
        methods = setOf("getDrops", "randomTick", "update"),
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
        excludeOwners = setOf(
            "org/bukkit/entity/EntityType",
            "org/bukkit/entity/SpawnCategory",
            "org/bukkit/entity/Pose",
        ),
        // The entity scheduler and the async teleport are the prescribed Folia APIs; flagging
        // them would contradict FS020 and FS012. Enum methods (values, valueOf, name, ordinal)
        // on nested entity enums (Villager$Profession, Horse$Color, etc.) are static constants.
        // Passenger and inventory methods have their own specialized rules (FS082 and FS086).
        excludeMethods = setOf(
            "getScheduler", "teleportAsync", "values", "valueOf", "name", "ordinal",
            "addPassenger", "removePassenger", "setPassenger", "eject", "leaveVehicle",
            "openInventory", "openWorkbench", "openEnchanting", "openMerchant", "closeInventory",
        ),
        contextual = true,
    )

    private val worldGlobalRegionGuarded = CallRule(
        id = "FS064",
        severity = Severity.WARNING,
        title = "World global-state call requires the global region",
        why = "Folia wraps these CraftWorld methods in RegionizedServer.ensureGlobalTickThread, " +
            "which throws IllegalStateException(\"Cannot modify/retrieve ... off of the global " +
            "region\") unless the calling thread owns the global region.",
        fix = "Schedule the call on Bukkit.getGlobalRegionScheduler().execute(plugin, task) or " +
            "GlobalRegionScheduler#run.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftWorld ensureGlobalTickThread guards: getForceLoadedChunks, getMetadata, " +
                "hasMetadata, isChunkForceLoaded, removeMetadata, setChunkForceLoaded, " +
                "setClearWeatherDuration, setFullTime, setGameRule, setGameRuleValue, " +
                "setHardcore, setMetadata, setSpawnLimit, setStorm, setThunderDuration, " +
                "setThundering, setTicksPerSpawns, setTime, setWeatherDuration",
        ),
        owners = setOf("org/bukkit/World"),
        methods = setOf(
            "getForceLoadedChunks", "getMetadata", "hasMetadata", "isChunkForceLoaded",
            "removeMetadata", "setChunkForceLoaded", "setClearWeatherDuration", "setFullTime",
            "setGameRule", "setGameRuleValue", "setHardcore", "setMetadata", "setSpawnLimit",
            "setStorm", "setThunderDuration", "setThundering", "setTicksPerSpawns", "setTime",
            "setWeatherDuration",
        ),
        contextual = true,
    )

    private val chunkAndWorldQueryRegionGuarded = CallRule(
        id = "FS065",
        severity = Severity.WARNING,
        title = "Chunk and world entity-query or spawn calls are region-guarded",
        why = "Folia wraps CraftChunk entity/tile/block accessors and CraftWorld entity queries, " +
            "ray traces, item drops, and entity spawns in TickThread.ensureTickThread. Calling " +
            "them from an async task, packet listener, or GlobalRegionScheduler callback throws " +
            "IllegalStateException off-region.",
        fix = REGION_FIX,
        provenance = Provenance(
            PATCH_SERVER,
            "CraftChunk#getEntities, #getTileEntities, #getBlock, #load, #unload; " +
                "CraftWorld#getEntities, #getLivingEntities, #getNearbyEntities, #rayTrace*, " +
                "#spawnEntity, #spawn, #dropItem*, #strikeLightning*",
        ),
        owners = setOf("org/bukkit/Chunk", "org/bukkit/World"),
        methods = setOf(
            "addPluginChunkTicket", "dropItem", "dropItemNaturally", "getBlock",
            "getChunkSnapshot", "getEntities", "getEntitiesByClass", "getEntitiesByClasses",
            "getLivingEntities", "getNearbyEntities", "getPlayers", "getTileEntities",
            "isEntitiesLoaded", "load", "rayTrace", "rayTraceBlocks", "rayTraceEntities",
            "removePluginChunkTicket", "spawn", "spawnEntity", "strikeLightning",
            "strikeLightningEffect", "unload",
        ),
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

    val unsynchronizedStaticCollection = ConcurrencyRule(
        id = "FS081",
        severity = Severity.WARNING,
        title = "Unsynchronized static collection mutated from concurrent Folia tasks",
        why = "On plain Paper, main-thread tasks never ran in parallel so a static HashMap, " +
            "ArrayList, or HashSet appeared safe. Under Folia, RegionScheduler, EntityScheduler, " +
            "AsyncScheduler, and Netty callbacks execute concurrently across worker threads; " +
            "mutating a non-thread-safe static collection without synchronization risks " +
            "ConcurrentModificationException, lost writes, or corrupted bucket chains.",
        fix = "Replace HashMap / LinkedHashMap with ConcurrentHashMap, HashSet with " +
            "ConcurrentHashMap.newKeySet(), and ArrayList with CopyOnWriteArrayList or guard " +
            "every read and mutation behind an explicit lock.",
        provenance = Provenance(
            PATCH_SCHED_API,
            "RegionScheduler, EntityScheduler, and AsyncScheduler execute concurrently across threads",
        ),
    )

    val crossRegionPassenger = CallRule(
        id = "FS082",
        severity = Severity.WARNING,
        title = "Cross-region passenger attachment or vehicle ejection without region synchronization",
        why = "Under Folia, mounting an entity as a passenger or ejecting passengers " +
            "(addPassenger, removePassenger, setPassenger, eject, leaveVehicle) requires " +
            "both entities to reside in the exact same thread region. When called across " +
            "regional boundaries or from an off-region context, Folia throws IllegalStateException " +
            "or corrupts entity passenger linked lists.",
        fix = "Verify region ownership via isOwnedByCurrentRegion before passenger operations, " +
            "or dispatch via EntityScheduler on both vehicle and passenger before modifying passengers.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftEntity#addPassenger, #removePassenger, #eject, #leaveVehicle region assertions",
        ),
        owners = setOf("org/bukkit/entity/Entity"),
        ownerPrefixes = setOf("org/bukkit/entity/"),
        methods = setOf("addPassenger", "removePassenger", "setPassenger", "eject", "leaveVehicle"),
        contextual = true,
    )

    val entitySchedulerLifecycle = ConcurrencyRule(
        id = "FS083",
        severity = Severity.WARNING,
        title = "EntityScheduler task submitted without handling entity retirement",
        why = "Folia's EntityScheduler executes callbacks on the region owning the entity, but " +
            "if the entity is dead, despawned, or removed from the world before or during execution, " +
            "the task is discarded and only the retired callback runs. Submitting tasks with a null " +
            "retired callback drops critical cleanup logic (such as releasing locks, canceling state, or persisting data).",
        fix = "Provide a non-null retired callback to entity.getScheduler().run(plugin, task, retired) " +
            "or entity.getScheduler().execute(plugin, task, retired, delay) to handle entity despawn, death, or chunk unload gracefully.",
        provenance = Provenance(
            PATCH_SCHED_API,
            "EntityScheduler#run, #execute retired callback for dead/unloaded entities",
        ),
    )

    val unchainedTeleportAsync = ConcurrencyRule(
        id = "FS084",
        severity = Severity.WARNING,
        title = "Unchained teleportAsync invocation discarding future without completion handling",
        why = "Folia's entity.teleportAsync(Location) is asynchronous and transfers the entity to another region thread. " +
            "Discarding the returned CompletableFuture or immediately executing subsequent entity calls without " +
            "chaining off the future causes execution while the entity is in-transit or on another thread, " +
            "throwing IllegalStateException off-region.",
        fix = "Chain subsequent actions onto the returned CompletableFuture via .thenAccept(success -> { ... }) " +
            "or .whenComplete(...) instead of discarding the future or executing synchronously.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftEntity#teleportAsync returns CompletableFuture for cross-region handoff",
        ),
    )

    val onlinePlayersDirectMutation = CallRule(
        id = "FS085",
        severity = Severity.WARNING,
        title = "Direct mutation of Bukkit.getOnlinePlayers() without per-player scheduler dispatch",
        why = "On plain Paper, Bukkit.getOnlinePlayers() was commonly iterated on the main thread " +
            "to broadcast, teleport, or modify all players. On Folia, players are partitioned " +
            "across independent regional threads. Iterating over getOnlinePlayers() and directly " +
            "invoking Player methods off the player's owning region throws IllegalStateException.",
        fix = "Dispatch operations for each player to their individual player.getScheduler().run(plugin, ...) " +
            "or use Bukkit.getGlobalRegionScheduler() strictly for global broadcasts that do not touch individual player state.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftServer#getOnlinePlayers contains players across all Folia regions",
        ),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("getOnlinePlayers"),
        contextual = true,
    )

    val crossRegionInventory = CallRule(
        id = "FS086",
        severity = Severity.WARNING,
        title = "Synchronous cross-region HumanEntity.openInventory() call",
        why = "In Folia, HumanEntity#openInventory(Inventory) and related container opening methods " +
            "require both the player and the inventory holder (tile entity, merchant, or entity) " +
            "to reside in the current thread region. Calling openInventory off-region or across " +
            "different regions throws IllegalStateException under Folia's container threading assertions.",
        fix = "Schedule openInventory on the player's owning region via player.getScheduler().run(plugin, ...) " +
            "and verify that any tile-entity inventory holder resides in the player's current region.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftHumanEntity#openInventory container region ownership checks",
        ),
        owners = setOf("org/bukkit/entity/HumanEntity", "org/bukkit/entity/Player"),
        ownerPrefixes = setOf("org/bukkit/entity/"),
        methods = setOf("openInventory", "openWorkbench", "openEnchanting", "openMerchant", "closeInventory"),
        contextual = true,
    )

    val blockingAsyncFuture = ConcurrencyRule(
        id = "FS087",
        severity = Severity.WARNING,
        title = "Blocking join() or get() on getChunkAtAsync or teleportAsync future risks region deadlock",
        why = "Under Paper and Folia 26.3's Moonrise chunk pipeline, World#getChunkAtAsync, " +
            "World#getChunkAtAsyncUrgently, and Entity#teleportAsync complete their returned " +
            "CompletableFuture on the target region's tick thread after asynchronous chunk generation " +
            "or cross-region entity handoff finishes. Calling join(), get(), or resultNow() synchronously " +
            "blocks the region tick thread while waiting for a callback queued onto that same region " +
            "thread, deadlocking the region or stalling Moonrise region merge/split barriers.",
        fix = "Chain continuation logic non-blockingly via .thenAccept(result -> { ... }), which Folia " +
            "executes directly on the owning region thread once the chunk or teleport completes.",
        provenance = Provenance(
            PATCH_SERVER,
            "Moonrise RegionizedChunkTaskScheduler & CraftWorld#getChunkAtAsync, CraftEntity#teleportAsync",
        ),
    )

    val asyncChunkGeneratorWorldEscape = ConcurrencyRule(
        id = "FS088",
        severity = Severity.WARNING,
        title = "Live World access inside Moonrise parallel async ChunkGenerator or BlockPopulator",
        why = "Paper and Folia 26.3 execute ChunkGenerator phases (generateNoise, generateSurface, " +
            "generateBedrock, generateCaves) and BlockPopulator#populate concurrently across Moonrise " +
            "chunk worker pool threads rather than on an owning region TickThread. Casting WorldInfo " +
            "to World, resolving live worlds via Bukkit.getWorld, or calling World#getBlockAt outside " +
            "the provided ChunkData or LimitedRegion buffer throws IllegalStateException under " +
            "TickThread.ensureTickThread or corrupts ungenerated neighbor chunks.",
        fix = "Restrict ChunkGenerator reads and writes to the passed ChunkGenerator.ChunkData and " +
            "WorldInfo parameters, and restrict BlockPopulator logic to LimitedRegion#isInRegion " +
            "and LimitedRegion block/entity methods.",
        provenance = Provenance(
            PATCH_SERVER,
            "Moonrise ChunkSystem parallel generation worker threads & LimitedRegion cutoff guards",
        ),
    )

    val blockEntityOffRegionAccess = CallRule(
        id = "FS089",
        severity = Severity.WARNING,
        title = "Block entity (TileState / Container) accessed from an off-region context",
        why = "Folia ticks block entities (chests, hoppers, furnaces, signs, spawners, trial spawners, " +
            "vaults, crafters, and PersistentDataContainers) per-region in RegionizedWorldData#tickBlockEntities " +
            "and guards CraftBlockEntityState and CraftContainer#getInventory with TickThread.ensureTickThread. " +
            "Accessing TileState or Container methods from an async task, packet listener, chunk worker, " +
            "or GlobalRegionScheduler races against regional block-entity ticking or throws IllegalStateException.",
        fix = "Hop onto the chunk's owning region via Bukkit.getRegionScheduler().execute(plugin, blockLocation, task) " +
            "and fetch block.getState() inside that regional callback.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftBlockEntityState, CraftContainer#getInventory, and RegionizedWorldData#tickBlockEntities",
        ),
        owners = TILE_ENTITY_OWNERS,
        excludeMethods = setOf("values", "valueOf", "name", "ordinal"),
        contextual = true,
    )

    val capturedBlockEntityAcrossTicks = ConcurrencyRule(
        id = "FS090",
        severity = Severity.WARNING,
        title = "Captured BlockState or TileState snapshot accessed across delayed or entity-bound ticks",
        why = "Capturing a pre-fetched BlockState or TileState (such as Chest, Sign, CreatureSpawner, " +
            "TrialSpawner, Vault, or Crafter) into a RegionScheduler.runDelayed / runAtFixedRate lambda " +
            "or an EntityScheduler callback violates Folia's regional block-entity lifecycle: across " +
            "ticks, regional hoppers/crafters/players mutate the live BlockEntity, chunks unload, " +
            "regions split or merge, and an entity's EntityScheduler thread moves with the entity " +
            "away from the block's owning chunk region.",
        fix = "Capture an immutable Location (or world name + block coordinates) instead of a " +
            "BlockState/TileState instance, schedule on Bukkit.getRegionScheduler() for that Location, " +
            "and re-fetch location.getBlock().getState() fresh inside the scheduled tick.",
        provenance = Provenance(
            PATCH_SERVER,
            "RegionizedWorldData#tickBlockEntities & EntityScheduler vs RegionScheduler chunk ownership",
        ),
    )

    val persistentDataContainerOffRegion = CallRule(
        id = "FS091",
        severity = Severity.WARNING,
        title = "PersistentDataContainer mutation from an off-region or asynchronous context",
        why = "In Paper and Folia, PersistentDataContainer (PDC) instances on Chunk, World, and Entity " +
            "are backed directly by NMS compound tags within live regional chunk and entity data. Calling " +
            "set(), remove(), readFromBytes(), or copyTo() from an async scheduler, packet listener, or " +
            "foreign region races with Moonrise chunk persistence and entity serialization, causing " +
            "ConcurrentModificationException and persistent NBT corruption.",
        fix = "Dispatch PDC mutations through the owning region scheduler: Bukkit.getRegionScheduler().execute(...) " +
            "for chunk/world data, or entity.getScheduler().execute(...) for entity data.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftPersistentDataContainer and RegionizedWorldData chunk/entity NBT compound writes",
        ),
        owners = setOf("org/bukkit/persistence/PersistentDataContainer"),
        methods = setOf("set", "remove", "readFromBytes", "copyTo"),
        contextual = true,
    )

    val multiRegionStructurePlace = CallRule(
        id = "FS092",
        severity = Severity.WARNING,
        title = "Structure.place called across potentially unbounded regional chunk boundaries",
        why = "In Paper and Folia 26.3+, org.bukkit.structure.Structure#place pastes multi-block templates, tile entities, " +
            "and entity palettes synchronously across potentially unbounded chunk coordinates. When placed from a single region " +
            "tick thread or off-region task across chunk region boundaries, Folia throws " +
            "IllegalStateException: Asynchronous chunk access! Region does not own chunk... or deadlocks when neighbor " +
            "chunks belong to a different region thread.",
        fix = "Pre-calculate structure bounding boxes with Structure#getSize(); partition placement into chunk-aligned " +
            "slices and schedule each slice via Bukkit.getRegionScheduler() at the target chunk coordinate.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftStructure#place and RegionizedWorldData chunk bounds check",
        ),
        owners = setOf("org/bukkit/structure/Structure"),
        methods = setOf("place"),
        contextual = false,
    )

    val crossRegionInventoryHolderCreation = CallRule(
        id = "FS093",
        severity = Severity.WARNING,
        title = "Bukkit.createInventory with world-bound TileState or Entity holder creates cross-region viewer hazard",
        why = "Passing a world-bound BlockState, TileState (Chest, Hopper, etc.), or Entity as the InventoryHolder " +
            "to Bukkit.createInventory binds container click and viewer events across players and regions. In Folia, " +
            "when players in separate regions open or click inside this inventory, event dispatches and getHolder() " +
            "invocations trigger cross-region thread safety exceptions.",
        fix = "Pass null or a detached virtual InventoryHolder to Bukkit.createInventory, and synchronize item interactions " +
            "explicitly via Location or Entity schedulers.",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftServer#createInventory and InventoryHolder event dispatch",
        ),
        owners = setOf("org/bukkit/Bukkit", "org/bukkit/Server"),
        methods = setOf("createInventory"),
        contextual = true,
    )

    val bossBarMultiRegionDispatch = CallRule(
        id = "FS094",
        severity = Severity.WARNING,
        title = "BossBar player management from regional context risks cross-region packet contention",
        why = "In Folia, players are distributed across independent region threads. Invoking BossBar#addPlayer, " +
            "removePlayer, or removeAll from a regional tick thread directly touches player packet listeners across " +
            "foreign regions, risking packet reordering and client disconnects.",
        fix = "Manage server-wide BossBars via Bukkit.getGlobalRegionScheduler().execute(plugin, () -> bossBar.addPlayer(player)) " +
            "or player.getScheduler().execute(plugin, () -> bossBar.addPlayer(player), null, 1L).",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftBossBar and ServerCommonPacketListenerImpl packet dispatch",
        ),
        owners = setOf("org/bukkit/boss/BossBar", "org/bukkit/boss/KeyedBossBar"),
        ownerPrefixes = setOf("org/bukkit/boss/"),
        methods = setOf("addPlayer", "removePlayer", "removeAll"),
        contextual = true,
    )

    val worldBorderRegionalMutation = CallRule(
        id = "FS095",
        severity = Severity.WARNING,
        title = "WorldBorder mutation from regional thread risks concurrent border state desync",
        why = "In Folia, a world border encompasses all chunk regions within a World. Calling setCenter(), " +
            "setSize(), or setWarningDistance() on WorldBorder from an arbitrary regional thread races with " +
            "neighbor regions calculating entity collision and border packet updates.",
        fix = "Dispatch WorldBorder configuration changes to Bukkit.getGlobalRegionScheduler().execute(plugin, () -> world.getWorldBorder().setSize(...)).",
        provenance = Provenance(
            PATCH_SERVER,
            "CraftWorldBorder and RegionizedWorldData world-wide border broadcasts",
        ),
        owners = setOf("org/bukkit/WorldBorder"),
        methods = setOf("setCenter", "setSize", "setDamageAmount", "setDamageBuffer", "setWarningDistance", "setWarningTime"),
        contextual = true,
    )

    // --- assembled views -----------------------------------------------------------------

    val manifestRules: List<ManifestRule> = listOf(foliaSupportFlag)

    val artifactRules: List<ArtifactRule> = listOf(patchedByTool)

    val supertypeRules: List<SupertypeRule> = listOf(bukkitRunnableSubclass)

    val packageRules: List<PackageRule> = listOf(serverInternals)

    val concurrencyRules: List<ConcurrencyRule> = listOf(
        unsynchronizedStaticCollection,
        entitySchedulerLifecycle,
        unchainedTeleportAsync,
        blockingAsyncFuture,
        asyncChunkGeneratorWorldEscape,
        capturedBlockEntityAcrossTicks,
    )

    val callRules: List<CallRule> = listOf(
        bukkitSchedulerGetter, bukkitSchedulerUse, syncTeleport,
        scoreboardRegistration, scoreboardManager, worldLifecycle, tickableTileEntityCount,
        serverMetrics, dispatchCommand, worldRegionGuarded, blockRegionGuarded,
        blockStateRegionGuarded, entityFamilyRegionGuarded, worldGlobalRegionGuarded,
        chunkAndWorldQueryRegionGuarded,
        primaryThreadCheck,
        crossRegionPassenger,
        onlinePlayersDirectMutation,
        crossRegionInventory,
        blockEntityOffRegionAccess,
        persistentDataContainerOffRegion,
        multiRegionStructurePlace,
        crossRegionInventoryHolderCreation,
        bossBarMultiRegionDispatch,
        worldBorderRegionalMutation,
    )

    val all: List<Rule> =
        manifestRules + artifactRules + supertypeRules + packageRules + callRules + concurrencyRules

    fun byId(id: String): Rule? = all.firstOrNull { it.id.equals(id, ignoreCase = true) }
}
