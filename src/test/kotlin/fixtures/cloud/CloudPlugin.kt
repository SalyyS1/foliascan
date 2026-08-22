// Named after a library that plugins really do shade (`cloud` is on the relocated-dependency
// list), but this is the artifact under test rather than something relocated inside a plugin.
// Pointing the scanner at a jar like this used to report nothing at all, because the package name
// alone was taken as proof that someone else's code had been bundled in.
package fixtures.cloud

import org.bukkit.Bukkit

class CloudPlugin {
    fun onEnable() {
        Bukkit.getScheduler().runTask(this) { Unit }
    }
}
