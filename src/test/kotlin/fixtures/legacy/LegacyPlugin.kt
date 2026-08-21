// Deliberately Folia-hostile fixture. Every call here is expected to be reported; the test
// asserts on the exact rule ids so a regression in the analyzer fails the build.
package fixtures.legacy

import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.entity.Player
import org.bukkit.scheduler.BukkitRunnable
import java.util.concurrent.Executors

class LegacyPlugin {

    // FS010 in the constructor, then FS011 on every use of the stored reference.
    private val scheduler = Bukkit.getScheduler()

    fun repeatForever() {
        scheduler.runTaskTimer(this, { tickEverything() }, 1L, 20L)
    }

    fun onEnable() {
        // FS010 - legacy scheduler
        Bukkit.getScheduler().runTask(this) { tickEverything() }
        // FS040 - runtime world creation
        Bukkit.createWorld("arena")
        // FS031 then FS030 - scoreboard manager and objective registration
        val board = Bukkit.getScoreboardManager().getNewScoreboard()
        board.registerNewObjective("hud", "dummy", "HUD")
        board.registerNewTeam("red")
    }

    // FS020 - synchronous teleport
    fun teleportHome(player: Player, home: Location) {
        player.teleport(home)
    }

    // FS063 and FS050 inside an executor lambda - contextual findings
    fun collectStatsAsync(player: Player) {
        Executors.newSingleThreadExecutor().submit {
            player.sendMessage("health ${player.getHealth()}")
            reportTps(Bukkit.getTPS())
        }
    }

    // Off-region propagation: the lambda calls a helper, the helper touches the entity API.
    fun refreshAsync(player: Player) {
        Executors.newFixedThreadPool(2).submit { refreshHelper(player) }
    }

    fun refreshHelper(player: Player) {
        player.sendMessage(player.getName())
    }

    private fun reportTps(tps: DoubleArray) = tps.size

    private fun tickEverything() = Unit
}

// FS012 - extends BukkitRunnable
class HeartbeatTask : BukkitRunnable() {
    override fun run() {
        Bukkit.getOnlinePlayers().forEach { it.sendMessage("tick") }
    }
}
