package fixtures.v040

import com.comphenix.protocol.events.PacketAdapter
import com.comphenix.protocol.events.PacketEvent
import io.netty.channel.ChannelInboundHandlerAdapter
import org.bukkit.Bukkit
import org.bukkit.Chunk
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.entity.Player
import java.util.Collections
import java.util.HashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap

/**
 * Neutral-named runtime check using PaperMC's canonical Class.forName probe without the word
 * "folia" anywhere in the class, field, or method names.
 */
object RuntimeEnv {
    val HAS_REGIONS: Boolean = try {
        Class.forName("io.papermc.paper.threadedregions.RegionizedServer")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    fun supportsRegions(): Boolean = HAS_REGIONS
}

object SharedState {
    val unsafeCooldowns = HashMap<String, Long>()
    val safeCooldowns = ConcurrentHashMap<String, Long>()
    val wrappedSafe: MutableMap<String, Long> = Collections.synchronizedMap(HashMap())
    val monitorLock = Any()
}

class NeutralGuardedScheduler {
    fun runGlobal(task: Runnable) {
        if (RuntimeEnv.supportsRegions()) {
            Bukkit.getGlobalRegionScheduler().execute(this, task)
        } else {
            Bukkit.getScheduler().runTask(this, task)
        }
    }
}

class MovementPacketHook : PacketAdapter() {
    override fun onPacketReceiving(event: PacketEvent) {
        event.player.sendMessage("packet hp=${event.player.getHealth()}")
    }
}

class RawNettyDuplexHook(private val world: World, private val center: Location) : ChannelInboundHandlerAdapter() {
    override fun channelRead(ctx: Any, msg: Any) {
        world.getNearbyEntities(center, 8.0, 8.0, 8.0)
    }
}

class V040Plugin {

    fun unsafeAsyncStageChain(player: Player) {
        CompletableFuture.supplyAsync { "loaded" }
            .thenApply { it.uppercase() }
            .thenAccept { label -> player.sendMessage(label) }
    }

    fun safeTeleportAsyncChain(player: Player, home: Location) {
        player.teleportAsync(home).thenAccept { ok ->
            if (ok) player.sendMessage("arrived")
        }
    }

    fun inspectChunkOffRegion(chunk: Chunk) {
        Bukkit.getAsyncScheduler().runNow(this) {
            chunk.getEntities()
        }
    }

    fun mutateUnsyncMapInRegionTask(location: Location) {
        Bukkit.getRegionScheduler().execute(this, location) {
            SharedState.unsafeCooldowns.put("region", 1L)
            SharedState.safeCooldowns.put("region", 1L)
            SharedState.wrappedSafe.put("region", 1L)
        }
    }

    fun mutateSynchronizedSafely() {
        Bukkit.getAsyncScheduler().runNow(this) {
            lockedRecord()
        }
    }

    private fun lockedRecord() {
        synchronized(SharedState.monitorLock) {
            SharedState.unsafeCooldowns.put("locked", 2L)
        }
    }
}
