// Sibling of the package holding `main`. The violation here is only found if the scan root was
// widened past main's own package.
package fixtures.multi.core

import org.bukkit.Bukkit

class CoreLogic {
    fun start() {
        Bukkit.getScheduler().runTask(this) { tick() }
    }

    private fun tick() = Unit
}
