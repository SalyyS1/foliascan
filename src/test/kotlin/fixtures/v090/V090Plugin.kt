package fixtures.v090

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.entity.Player
import org.bukkit.inventory.PlayerInventory
import java.util.HashMap
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

interface RewardGateway {
    fun grantRewardAndScan(inventory: PlayerInventory, sender: Any)
}

class DatabaseRewardGateway : RewardGateway {
    override fun grantRewardAndScan(inventory: PlayerInventory, sender: Any) {
        // FS103: PlayerInventory mutation reached via INVOKEINTERFACE from AsyncScheduler
        inventory.setItem(0, "diamond_reward")
        // FS102: Bukkit.selectEntities evaluated off-region via INVOKEINTERFACE taint chain
        Bukkit.selectEntities(sender, "@e[type=zombie,distance=..12]")
    }
}

interface SessionTracker {
    fun recordVisit(playerName: String)
}

class UnsafeInstanceSessionTracker : SessionTracker {
    private val visits = HashMap<String, Long>()
    private val safeVisits = ConcurrentHashMap<String, Long>()
    private val mutex = Any()

    override fun recordVisit(playerName: String) {
        // FS105: Unsynchronized instance HashMap mutated across concurrent RegionScheduler tasks
        visits.put(playerName, 1L)
        safeVisits.put(playerName, 1L)
    }

    fun recordVisitSynchronized(playerName: String) {
        synchronized(mutex) {
            visits.put(playerName, 2L)
        }
    }
}

class V090Plugin {

    // 1. AsyncScheduler -> INVOKEINTERFACE RewardGateway -> DatabaseRewardGateway (FS102 + FS103)
    fun unsafeAsyncInterfaceDispatch(gateway: RewardGateway, inventory: PlayerInventory, sender: Any) {
        Bukkit.getAsyncScheduler().runNow(this) {
            gateway.grantRewardAndScan(inventory, sender)
        }
    }

    // 2. Dispatchers.IO coroutine launching suspend state machine with delay() + World.loadChunk (FS101 + FS060)
    fun unsafeIoCoroutineWithDelay(scope: CoroutineScope, world: World) {
        launch(scope, Dispatchers.IO) {
            suspendRefreshChunk(world)
        }
    }

    suspend fun suspendRefreshChunk(world: World) {
        delay(50L)
        world.loadChunk(4, 8)
    }

    // 3. Explicit off-region Continuation.resumeWith from AsyncScheduler (FS101)
    fun unsafeManualContinuationResume(continuation: Continuation<String>) {
        Bukkit.getAsyncScheduler().runNow(this) {
            continuation.resumeWith(Result.success("off-region-resume"))
        }
    }

    // 4. Safe coroutine switching onto Folia regionDispatcher / EntityScheduler (must NOT fire FS101/FS063/FS103)
    private fun regionDispatcher(location: Location): CoroutineContext = EmptyCoroutineContext

    fun safeCoroutineHoppingToRegion(
        scope: CoroutineScope,
        location: Location,
        player: Player,
        inventory: PlayerInventory,
    ) {
        launch(scope, Dispatchers.IO) {
            withContext(regionDispatcher(location)) {
                player.getScheduler().run(
                    this@V090Plugin,
                    { inventory.setItem(1, "safe_item") },
                    Runnable { },
                )
            }
        }
    }

    // 5. FS104: Unconditional runtime Bukkit.reloadData()
    fun unsafeRuntimeDatapackReload() {
        Bukkit.reloadData()
    }

    // 6. FS105: Concurrent RegionScheduler -> INVOKEINTERFACE SessionTracker -> UnsafeInstanceSessionTracker
    fun concurrentRegionVisitTracking(tracker: SessionTracker, location: Location) {
        Bukkit.getRegionScheduler().execute(this, location) {
            tracker.recordVisit("Alex")
        }
    }

    fun safeSynchronizedInstanceMutation(tracker: UnsafeInstanceSessionTracker, location: Location) {
        Bukkit.getRegionScheduler().execute(this, location) {
            tracker.recordVisitSynchronized("Alex")
        }
    }
}
