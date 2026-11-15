// Minimal stand-ins for the Bukkit API, used only so the test fixtures can be compiled to
// real bytecode without pulling the Paper API onto the test classpath. Only shapes the
// scanner looks at matter: type names and method names.
package org.bukkit

import org.bukkit.block.Block
import org.bukkit.entity.Player
import org.bukkit.generator.WorldInfo
import org.bukkit.persistence.PersistentDataContainer
import org.bukkit.scheduler.BukkitScheduler
import org.bukkit.scoreboard.ScoreboardManager
import io.papermc.paper.threadedregions.scheduler.AsyncScheduler
import io.papermc.paper.threadedregions.scheduler.GlobalRegionScheduler
import io.papermc.paper.threadedregions.scheduler.RegionScheduler
import java.util.concurrent.CompletableFuture

class Location(val world: World?, val x: Double, val y: Double, val z: Double) {
    fun getBlock(): Block = throw UnsupportedOperationException()
}

interface WorldBorder {
    fun setCenter(x: Double, z: Double)
    fun setSize(newSize: Double)
    fun setWarningDistance(distance: Int)
}

interface Chunk {
    fun getEntities(): Array<Any>
    fun load(): Boolean
    fun getPersistentDataContainer(): PersistentDataContainer
}

interface World : WorldInfo {
    fun getChunkAt(x: Int, z: Int): Any?
    fun getChunkAtAsync(x: Int, z: Int): CompletableFuture<Chunk>
    fun getChunkAtAsyncUrgently(x: Int, z: Int): CompletableFuture<Chunk>
    fun getBlockAt(x: Int, y: Int, z: Int): Block
    fun loadChunk(x: Int, z: Int): Boolean
    fun unloadChunk(x: Int, z: Int): Boolean
    fun createExplosion(x: Double, y: Double, z: Double, power: Float): Boolean
    fun setTime(time: Long)
    fun setStorm(hasStorm: Boolean)
    fun getTickableTileEntityCount(): Int
    fun getHighestBlockYAt(x: Int, z: Int): Int
    fun getNearbyEntities(location: Location, x: Double, y: Double, z: Double): Collection<Any>
    fun getWorldBorder(): WorldBorder
    fun getPersistentDataContainer(): PersistentDataContainer
}

interface Server {
    fun getScheduler(): BukkitScheduler
    fun createWorld(name: String): World?
    fun getTPS(): DoubleArray
    fun createInventory(owner: Any?, size: Int, title: String): Any
}

@Suppress("unused")
object Bukkit {
    @JvmStatic
    fun getScheduler(): BukkitScheduler = throw UnsupportedOperationException()

    @JvmStatic
    fun getScoreboardManager(): ScoreboardManager = throw UnsupportedOperationException()

    @JvmStatic
    fun getOnlinePlayers(): Collection<Player> = emptyList()

    @JvmStatic
    fun createInventory(owner: Any?, size: Int, title: String): Any = throw UnsupportedOperationException()

    @JvmStatic
    fun createWorld(name: String): World? = null

    @JvmStatic
    fun getWorld(name: String): World? = null

    @JvmStatic
    fun unloadWorld(name: String, save: Boolean): Boolean = false

    @JvmStatic
    fun getTPS(): DoubleArray = doubleArrayOf()

    @JvmStatic
    fun getAverageTickTime(): Double = 0.0

    @JvmStatic
    fun dispatchCommand(sender: Any, command: String): Boolean = false

    @JvmStatic
    fun isPrimaryThread(): Boolean = false

    @JvmStatic
    fun getGlobalRegionScheduler(): GlobalRegionScheduler = throw UnsupportedOperationException()

    @JvmStatic
    fun getRegionScheduler(): RegionScheduler = throw UnsupportedOperationException()

    @JvmStatic
    fun getAsyncScheduler(): AsyncScheduler = throw UnsupportedOperationException()
}
