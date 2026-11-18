package fixtures.v100

import java.util.Random
import java.util.concurrent.CompletableFuture
import org.bukkit.Bukkit
import org.bukkit.Chunk
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.advancement.AdvancementProgress
import org.bukkit.block.Block
import org.bukkit.entity.Player
import org.bukkit.inventory.Inventory
import org.bukkit.loot.LootTable
import org.bukkit.scoreboard.Team

interface TaskRouter {
    fun runOffRegion(task: Runnable)
    fun runAtLocation(location: Location, task: Runnable)
    fun runOnPlayer(player: Player, task: Runnable)
}

class FoliaTaskRouter(private val plugin: Any) : TaskRouter {
    override fun runOffRegion(task: Runnable) {
        Bukkit.getAsyncScheduler().runNow(plugin) {
            task.run()
        }
    }

    override fun runAtLocation(location: Location, task: Runnable) {
        Bukkit.getRegionScheduler().execute(plugin, location, task)
    }

    override fun runOnPlayer(player: Player, task: Runnable) {
        player.getScheduler().run(plugin, { task.run() }, Runnable { })
    }
}

object FunctionalPool {
    fun <T> supplyInBackground(work: () -> T): CompletableFuture<T> =
        CompletableFuture.supplyAsync { work() }
}

class V100Plugin {

    // 1. Inter-procedural INVOKEDYNAMIC closure taint across custom TaskRouter interface -> FoliaTaskRouter.runOffRegion
    fun unsafeInterproceduralRouterClosure(
        router: TaskRouter,
        progress: AdvancementProgress,
        lootTable: LootTable,
        inventory: Inventory,
    ) {
        router.runOffRegion {
            // FS109: AdvancementProgress criteria mutated off-region via custom async wrapper closure
            progress.awardCriteria("minecraft:story/mine_stone")
            // FS110: LootTable.fillInventory invoked off-region via custom async wrapper closure
            lootTable.fillInventory(inventory, Random(1L), null)
        }
    }

    // 2. Inter-procedural Kotlin Function0 closure passed to FunctionalPool.supplyInBackground -> FS108 Team.addEntry
    fun unsafeKotlinHigherOrderAsyncClosure(team: Team) {
        FunctionalPool.supplyInBackground {
            team.addEntry("Alex")
        }
    }

    // 3. Safe Team mutation on GlobalRegionScheduler (exempted for FS108)
    fun safeTeamUpdateOnGlobalRegion(team: Team) {
        Bukkit.getGlobalRegionScheduler().execute(this) {
            team.addEntry("GlobalSafe")
        }
    }

    // 4. Safe custom Folia region/entity wrapper re-entry inside an async task (must produce ZERO findings!)
    fun safeAsyncHoppingViaCustomRouter(router: TaskRouter, location: Location, block: Block, player: Player) {
        Bukkit.getAsyncScheduler().runNow(this) {
            router.runAtLocation(location) {
                block.breakNaturally()
            }
            router.runOnPlayer(player) {
                player.setHealth(20.0)
            }
        }
    }

    // 5. FS106: Captured Player mutated inside Location-keyed RegionScheduler closure without ownership check
    fun unsafeCapturedPlayerInLocationScheduler(location: Location, player: Player) {
        Bukkit.getRegionScheduler().execute(this, location) {
            player.setHealth(18.0)
        }
    }

    // 6. Safe captured Player guarded by Bukkit.isOwnedByCurrentRegion(player)
    fun safeOwnedPlayerInLocationScheduler(location: Location, player: Player) {
        Bukkit.getRegionScheduler().execute(this, location) {
            if (Bukkit.isOwnedByCurrentRegion(player)) {
                player.setHealth(20.0)
            }
        }
    }

    // 7. FS107: Live Chunk captured across delayed RegionScheduler ticks
    fun unsafeCapturedChunkAcrossDelayedTicks(location: Location, chunk: Chunk) {
        Bukkit.getRegionScheduler().runDelayed(
            this,
            location,
            { _ -> chunk.getEntities() },
            20L,
        )
    }

    // 8. Safe delayed RegionScheduler tick re-acquiring chunk via World (no Chunk captured)
    fun safeCoordDelayedChunkLookup(world: World, location: Location) {
        Bukkit.getRegionScheduler().runDelayed(
            this,
            location,
            { _ -> world.getChunkAt(2, 4) },
            20L,
        )
    }
}
