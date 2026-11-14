package fixtures.v060

import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.block.Chest
import org.bukkit.block.TrialSpawner
import org.bukkit.entity.Player
import org.bukkit.generator.BlockPopulator
import org.bukkit.generator.ChunkGenerator
import org.bukkit.generator.LimitedRegion
import org.bukkit.generator.WorldInfo
import java.util.Random
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

object StructureGenHelper {
    fun stampLiveBeacon(worldInfo: WorldInfo, x: Int, z: Int) {
        val liveWorld = worldInfo as World
        liveWorld.getBlockAt(x, 64, z)
    }
}

class UnsafeMoonriseChunkGenerator : ChunkGenerator() {
    override fun generateSurface(
        worldInfo: WorldInfo,
        random: Random,
        chunkX: Int,
        chunkZ: Int,
        chunkData: ChunkData,
    ) {
        chunkData.setBlock(0, 64, 0, "STONE")
        StructureGenHelper.stampLiveBeacon(worldInfo, chunkX shl 4, chunkZ shl 4)
    }
}

class SafeMoonriseChunkGenerator : ChunkGenerator() {
    override fun generateSurface(
        worldInfo: WorldInfo,
        random: Random,
        chunkX: Int,
        chunkZ: Int,
        chunkData: ChunkData,
    ) {
        if (worldInfo.getMaxHeight() > 64) {
            chunkData.setBlock(0, 64, 0, "DEEPSLATE")
        }
    }
}

class SafeMoonrisePopulator : BlockPopulator() {
    override fun populate(
        worldInfo: WorldInfo,
        random: Random,
        chunkX: Int,
        chunkZ: Int,
        limitedRegion: LimitedRegion,
    ) {
        val bx = chunkX shl 4
        val bz = chunkZ shl 4
        if (limitedRegion.isInRegion(bx, 65, bz)) {
            limitedRegion.setType(bx, 65, bz, "TORCH")
        }
    }
}

class V060Plugin {

    // FS087: Blocking .join() and local-variable .get() on getChunkAtAsync / getChunkAtAsyncUrgently
    fun unsafeBlockingChunkFuture(world: World): Any {
        val urgent = world.getChunkAtAsyncUrgently(4, 8)
        return urgent.get(5L, TimeUnit.SECONDS)
    }

    fun unsafeBlockingTeleportJoin(player: Player, target: Location): Boolean =
        player.teleportAsync(target).join()

    // Safe non-blocking continuation and unrelated background CompletableFuture
    fun safeNonBlockingChunkAndCpuFuture(world: World) {
        world.getChunkAtAsync(4, 8).thenAccept { chunk ->
            chunk.getEntities()
        }
        val cpuResult = CompletableFuture.supplyAsync { 42 }.join()
        if (cpuResult == 0) return
    }

    // FS089: Off-region TileState / TrialSpawner / Chest access through an async helper hop
    fun unsafeTrialSpawnerOffRegion(spawner: TrialSpawner) {
        Bukkit.getAsyncScheduler().runNow(this) {
            tuneTrialSpawnerHelper(spawner)
        }
    }

    private fun tuneTrialSpawnerHelper(spawner: TrialSpawner) {
        spawner.setCooldownLength(200)
    }

    // Safe TileState access inside owning RegionScheduler
    fun safeTrialSpawnerOnRegion(location: Location, spawner: TrialSpawner) {
        Bukkit.getRegionScheduler().execute(this, location, Runnable {
            spawner.setCooldownLength(100)
        })
    }

    // FS090: Captured Chest TileState snapshot mutated across delayed RegionScheduler ticks
    fun unsafeCapturedChestAcrossDelayedTicks(location: Location, chest: Chest) {
        Bukkit.getRegionScheduler().runDelayed(
            this,
            location,
            { _ ->
                chest.getInventory()
                chest.update(true)
            },
            40L,
        )
    }

    // FS090: Captured Chest TileState mutated inside EntityScheduler (entity may move to another region)
    fun unsafeCapturedChestInEntityScheduler(player: Player, chest: Chest) {
        player.getScheduler().run(
            this,
            { _ -> chest.update(true) },
            Runnable { },
        )
    }

    // Safe Folia pattern: capture Location and re-fetch BlockState fresh inside delayed RegionScheduler tick
    fun safeRefetchedChestInDelayedTicks(location: Location) {
        Bukkit.getRegionScheduler().runDelayed(
            this,
            location,
            { _ ->
                val fresh = location.getBlock().getState() as Chest
                fresh.getInventory()
                fresh.update(true)
            },
            40L,
        )
    }
}
