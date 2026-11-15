package fixtures.v070

import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.WorldBorder
import org.bukkit.boss.BossBar
import org.bukkit.entity.Player
import org.bukkit.persistence.PersistentDataContainer
import org.bukkit.structure.Structure
import java.util.Random

class V070Plugin {

    // FS091: PersistentDataContainer mutation in off-region async scheduler
    fun unsafePdcOffRegion(pdc: PersistentDataContainer) {
        Bukkit.getAsyncScheduler().runNow(this) {
            pdc.set("score", "int", 42)
        }
    }

    // Safe PDC mutation on owning region
    fun safePdcOnRegion(location: Location, pdc: PersistentDataContainer) {
        Bukkit.getRegionScheduler().execute(this, location, Runnable {
            pdc.set("score", "int", 42)
        })
    }

    // FS092: Structure.place across potentially unbounded chunk regions (unconditional)
    fun unsafeStructurePlace(structure: Structure, location: Location) {
        structure.place(location, true, null, null, 0, 1.0f, Random())
    }

    // FS093: Bukkit.createInventory in off-region context
    fun unsafeCreateInventoryOffRegion() {
        Bukkit.getAsyncScheduler().runNow(this) {
            Bukkit.createInventory(null, 27, "Vault")
        }
    }

    // FS094: BossBar player management from off-region context
    fun unsafeBossBarOffRegion(bossBar: BossBar, player: Player) {
        Bukkit.getAsyncScheduler().runNow(this) {
            bossBar.addPlayer(player)
        }
    }

    // Safe BossBar management on global region scheduler
    fun safeBossBarGlobal(bossBar: BossBar, player: Player) {
        Bukkit.getGlobalRegionScheduler().run(this) {
            bossBar.addPlayer(player)
        }
    }

    // FS095: WorldBorder regional mutation in off-region context
    fun unsafeWorldBorderOffRegion(worldBorder: WorldBorder) {
        Bukkit.getAsyncScheduler().runNow(this) {
            worldBorder.setSize(500.0)
        }
    }

    // Safe WorldBorder mutation on global region scheduler
    fun safeWorldBorderGlobal(world: World) {
        Bukkit.getGlobalRegionScheduler().run(this) {
            world.getWorldBorder().setSize(500.0)
        }
    }
}
