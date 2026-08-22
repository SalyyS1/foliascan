// Mirrors the layout that exposed a real blind spot: the plugin's `main` class sits in a
// platform subpackage while actual logic lives in a sibling package. Deriving the scan root
// from main's own package skipped the sibling entirely.
package fixtures.multi.platform

import fixtures.multi.core.CoreLogic

class PlatformEntry {
    private val core = CoreLogic()

    fun onEnable() {
        core.start()
    }
}
