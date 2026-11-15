package fixtures.v080

import org.bukkit.Bukkit
import org.bukkit.World
import org.bukkit.block.data.BlockData
import org.bukkit.event.Listener
import org.bukkit.map.MapView
import org.bukkit.map.MapRenderer
import org.bukkit.plugin.PluginManager
import org.bukkit.plugin.ServicesManager
import org.bukkit.plugin.ServicePriority

class V080Plugin {

    // FS096: MapView renderer mutation from async context
    fun unsafeMapViewAddRendererAsync(mapView: MapView, renderer: MapRenderer) {
        Bukkit.getAsyncScheduler().runNow(this) {
            mapView.addRenderer(renderer)
        }
    }

    // FS096: MapView locked mutation from async context
    fun unsafeMapViewSetLockedAsync(mapView: MapView) {
        Bukkit.getAsyncScheduler().runNow(this) {
            mapView.setLocked(true)
        }
    }

    // Safe MapView mutation on global region scheduler
    fun safeMapViewGlobal(mapView: MapView, renderer: MapRenderer) {
        Bukkit.getGlobalRegionScheduler().run(this) {
            mapView.addRenderer(renderer)
        }
    }

    // FS097: broadcastMessage from async context
    fun unsafeBroadcastMessageAsync(message: String) {
        Bukkit.getAsyncScheduler().runNow(this) {
            Bukkit.broadcastMessage(message)
        }
    }

    // FS097: Server#broadcast from async context
    fun unsafeServerBroadcastAsync(message: String) {
        Bukkit.getAsyncScheduler().runNow(this) {
            Bukkit.broadcast(message, "myplugin.broadcast")
        }
    }

    // Safe broadcast on global region scheduler
    fun safeBroadcastGlobal(message: String) {
        Bukkit.getGlobalRegionScheduler().run(this) {
            Bukkit.broadcastMessage(message)
        }
    }

    // FS098: ServicesManager.unregisterAll from async context
    fun unsafeServicesUnregisterAsync(sm: ServicesManager) {
        Bukkit.getAsyncScheduler().runNow(this) {
            sm.unregisterAll(this@V080Plugin)
        }
    }

    // FS099: PluginManager.registerEvents from async context
    fun unsafeRegisterEventsAsync(listener: Listener) {
        Bukkit.getAsyncScheduler().runNow(this) {
            Bukkit.getPluginManager().registerEvents(listener, this@V080Plugin)
        }
    }

    // FS099: PluginManager.unregisterAll from async context
    fun unsafeUnregisterAllAsync() {
        Bukkit.getAsyncScheduler().runNow(this) {
            Bukkit.getPluginManager().unregisterAll()
        }
    }

    // Safe: event registration on global region scheduler
    fun safeRegisterEventsGlobal(listener: Listener) {
        Bukkit.getGlobalRegionScheduler().run(this) {
            Bukkit.getPluginManager().registerEvents(listener, this@V080Plugin)
        }
    }

    // FS100: BlockData setter from async context
    fun unsafeBlockDataMutationAsync(blockData: BlockData) {
        Bukkit.getAsyncScheduler().runNow(this) {
            blockData.setWaterlogged(true)
        }
    }

    // FS100: BlockData setOpen from async context
    fun unsafeBlockDataOpenAsync(blockData: BlockData) {
        Bukkit.getAsyncScheduler().runNow(this) {
            blockData.setOpen(false)
        }
    }

    // Safe: BlockData mutation on region scheduler
    fun safeBlockDataOnRegion(blockData: BlockData, loc: org.bukkit.Location) {
        Bukkit.getRegionScheduler().execute(this, loc) {
            blockData.setWaterlogged(true)
        }
    }
}
