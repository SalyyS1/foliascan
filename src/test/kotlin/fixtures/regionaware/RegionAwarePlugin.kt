// A fixture written the way Folia expects. The test asserts this produces no scheduler,
// teleport or scoreboard findings, which is what keeps the rules from being trivially noisy.
package fixtures.regionaware

import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.entity.Player

class RegionAwarePlugin {

    fun onEnable() {
        Bukkit.getGlobalRegionScheduler().execute(this) { warmCaches() }
    }

    fun teleportHome(player: Player, home: Location) {
        player.teleportAsync(home)
    }

    fun editBlockAt(location: Location) {
        Bukkit.getRegionScheduler().execute(this, location) { placeMarker(location) }
    }

    fun greetLater(player: Player) {
        player.getScheduler().execute(this, Runnable { player.sendMessage(player.getName()) }, null, 1L)
    }

    private fun warmCaches() = Unit

    private fun placeMarker(location: Location) = location.x
}
