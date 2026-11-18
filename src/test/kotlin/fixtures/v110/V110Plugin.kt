package fixtures.v110

import io.papermc.paper.datacomponent.DataComponentHolder
import io.papermc.paper.entity.Leashable
import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.Material
import org.bukkit.entity.Player
import org.bukkit.inventory.Inventory
import org.bukkit.inventory.InventoryView
import org.bukkit.inventory.ItemStack
import org.bukkit.inventory.Merchant
import org.bukkit.inventory.PlayerInventory
import org.bukkit.scoreboard.Score
import org.bukkit.scoreboard.Scoreboard
import org.bukkit.scoreboard.Team

class SharedClanVault(
    private val vaultInventory: Inventory,
    private val clanMerchant: Merchant,
    private val lock: Any = Any(),
) {
    fun depositUnsync(slot: Int, stack: ItemStack) {
        // FS112: Shared Inventory field mutated concurrently across RegionScheduler / EntityScheduler
        vaultInventory.setItem(slot, stack)
    }

    fun updateTradesUnsync(trades: List<Any>) {
        // FS112: Shared Merchant field mutated concurrently across schedulers
        clanMerchant.setRecipes(trades)
    }

    fun depositSynchronized(slot: Int, stack: ItemStack) {
        synchronized(lock) {
            vaultInventory.setItem(slot, stack)
        }
    }
}

class V110Plugin {

    // 1. FS111: Paper 26.3 DataComponentHolder & live container ItemStack component mutated off-region
    fun unsafeAsyncDataComponents(holder: DataComponentHolder, playerInv: PlayerInventory) {
        Bukkit.getAsyncScheduler().runNow(this) {
            // Direct DataComponentHolder mutation off-region
            holder.setData("minecraft:custom_name", "Relic")
            // Live slot CraftItemStack dataflow across ALOAD/ASTORE mutated off-region
            val held = playerInv.getItemInMainHand()
            held.setData("minecraft:glint", true)
        }
    }

    // 2. Safe detached ItemStack & cloned ItemStack component mutation off-region (ZERO findings)
    fun safeAsyncDetachedAndClonedItemStack(playerInv: PlayerInventory) {
        Bukkit.getAsyncScheduler().runNow(this) {
            val fresh = ItemStack(Material.STONE, 1)
            fresh.setData("minecraft:custom_name", "DetachedSafe")
            val cloned = playerInv.getItemInMainHand().clone()
            cloned.setData("minecraft:glint", false)
        }
    }

    // 3. FS112: Shared Inventory & Merchant mutated from parallel RegionScheduler and EntityScheduler
    fun unsafeParallelSharedVaultAndMerchant(
        vault: SharedClanVault,
        location: Location,
        player: Player,
        stack: ItemStack,
    ) {
        Bukkit.getRegionScheduler().execute(this, location) {
            vault.depositUnsync(0, stack)
        }
        player.getScheduler().run(this, { vault.updateTradesUnsync(emptyList()) }, Runnable { })
    }

    // 4. Safe synchronized shared Inventory mutation (ZERO findings)
    fun safeSynchronizedVaultMutation(vault: SharedClanVault, location: Location, stack: ItemStack) {
        Bukkit.getRegionScheduler().execute(this, location) {
            vault.depositSynchronized(1, stack)
        }
    }

    // 5. FS113: Open InventoryView mutated from off-region AsyncScheduler
    fun unsafeAsyncInventoryViewMutation(view: InventoryView) {
        Bukkit.getAsyncScheduler().runNow(this) {
            view.setCursor(null)
            view.setTitle("Async Menu")
        }
    }

    // 6. Safe InventoryView mutation on viewing player's EntityScheduler (ZERO findings)
    fun safePlayerInventoryViewMutation(player: Player, view: InventoryView) {
        player.getScheduler().run(this, { view.setCursor(null) }, Runnable { })
    }

    // 7. FS114: Scoreboard Team / Score / resetScores mutated across parallel RegionScheduler & EntityScheduler
    fun unsafeParallelRegionalScoreboard(location: Location, player: Player, team: Team, score: Score, board: Scoreboard) {
        Bukkit.getRegionScheduler().execute(this, location) {
            team.addEntry("RegionalFighter")
        }
        player.getScheduler().run(this, {
            score.setScore(42)
            board.resetScores("OldEntry")
        }, Runnable { })
    }

    // 8. Safe Scoreboard mutation on GlobalRegionScheduler (ZERO findings)
    fun safeGlobalScoreboardMutation(team: Team, score: Score, board: Scoreboard) {
        Bukkit.getGlobalRegionScheduler().execute(this) {
            team.addEntry("GlobalFighter")
            score.setScore(100)
            board.resetScores("OldEntry")
        }
    }

    // 9. FS115: Cross-region Leashable attachment without isOwnedByCurrentRegion & async getLeashHolder
    fun unsafeLeashableAttachment(boat: Leashable, player: Player) {
        val unrelatedLocal: Any? = null
        if (unrelatedLocal == null) {
            boat.setLeashHolder(player)
        }
        Bukkit.getAsyncScheduler().runNow(this) {
            boat.getLeashHolder()
        }
    }

    // 10. Safe Leashable null detach on EntityScheduler & isOwnedByCurrentRegion guarded attach (ZERO findings)
    fun safeLeashableOperations(boat: Leashable, player: Player) {
        boat.getScheduler().run(this, {
            boat.setLeashHolder(null)
            if (Bukkit.isOwnedByCurrentRegion(player)) {
                boat.setLeashHolder(player)
            }
        }, Runnable { })
    }
}
