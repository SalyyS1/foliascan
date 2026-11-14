package fixtures.v050

import io.papermc.paper.threadedregions.scheduler.ScheduledTask
import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.entity.Entity
import org.bukkit.entity.Player

class V050Plugin {

    // FS082: Cross-region passenger attachment or vehicle ejection in off-region context
    fun unsafePassengerInAsyncTask(vehicle: Entity, passenger: Entity) {
        Bukkit.getAsyncScheduler().runNow(this) {
            vehicle.addPassenger(passenger)
        }
    }

    // FS083: EntityScheduler task submitted with null retired callback
    fun unsafeEntitySchedulerNullRetired(player: Player) {
        player.getScheduler().runDelayed(this, { task -> player.sendMessage("ticked") }, null, 20L)
    }

    // Safe EntityScheduler task with non-null retired handler
    fun safeEntitySchedulerWithRetired(player: Player) {
        player.getScheduler().runDelayed(
            this,
            { task -> player.sendMessage("ticked") },
            Runnable { /* entity died or retired */ },
            20L,
        )
    }

    // FS084: Unchained teleportAsync discarding the returned CompletableFuture followed by entity mutation
    fun unsafeUnchainedTeleport(player: Player, destination: Location) {
        player.teleportAsync(destination)
        player.sendMessage("teleporting...")
    }

    // Safe teleportAsync chained with thenAccept
    fun safeChainedTeleport(player: Player, destination: Location) {
        player.teleportAsync(destination).thenAccept { ok ->
            if (ok) player.sendMessage("teleported successfully")
        }
    }

    // FS085: Bukkit.getOnlinePlayers() in an off-region context
    fun unsafeOnlinePlayersInAsyncTask() {
        Bukkit.getAsyncScheduler().runNow(this) {
            val players = Bukkit.getOnlinePlayers()
        }
    }

    // FS086: Synchronous cross-region openInventory in off-region context
    fun unsafeOpenInventoryInAsyncTask(player: Player, inventory: Any) {
        Bukkit.getAsyncScheduler().runNow(this) {
            player.openInventory(inventory)
        }
    }
}
