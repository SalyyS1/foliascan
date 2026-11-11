// A fixture written the way Folia expects. The test asserts this produces no scheduler,
// teleport or scoreboard findings, which is what keeps the rules from being trivially noisy.
package fixtures.regionaware

import org.bukkit.Bukkit
import org.bukkit.Location
import org.bukkit.World
import org.bukkit.block.BlockState
import org.bukkit.entity.Player
import org.bukkit.event.player.AsyncPlayerChatEvent

class RegionAwarePlugin {

    fun onEnable() {
        Bukkit.getGlobalRegionScheduler().execute(this) { warmCaches() }
    }

    // GlobalRegionScheduler owns global world state (FS064 like setTime), so this must NOT warn.
    fun setGlobalTime(world: World) {
        Bukkit.getGlobalRegionScheduler().execute(this) { world.setTime(6000L) }
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

    // Starts on AsyncScheduler, then hops back onto EntityScheduler and RegionScheduler before
    // touching the entity or block state. Region re-entry must prevent false-positive taint!
    fun asyncFetchThenHopToRegion(player: Player, location: Location, state: BlockState) {
        Bukkit.getAsyncScheduler().runNow(this) {
            player.getScheduler().run(this, { player.sendMessage("hp=${player.getHealth()}") }, null)
            Bukkit.getRegionScheduler().execute(this, location) { state.update(true) }
        }
    }

    // Async chat listener that hops onto EntityScheduler before touching the player.
    fun onAsyncChatSafe(event: AsyncPlayerChatEvent) {
        val player = event.player
        player.getScheduler().run(this, { player.sendMessage("hp=${player.getHealth()}") }, null)
    }

    private fun warmCaches() = Unit

    private fun placeMarker(location: Location) = location.x
}
