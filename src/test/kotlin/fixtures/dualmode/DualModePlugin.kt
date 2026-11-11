// A dual-platform plugin written the way real ones are: one interface, two implementations, the
// choice made once behind a runtime Folia probe. `LegacyTasks` is full of calls that throw on
// Folia and is correct precisely because it never runs there.
//
// `UnguardedTasks` is the control. It makes the identical calls with no guard anywhere, so the
// test can prove the downgrade discriminates rather than muting every legacy call it finds.
package fixtures.dualmode

import org.bukkit.Bukkit
import org.bukkit.block.BlockState

object Platform {
    val IS_FOLIA: Boolean = runCatching {
        Class.forName("io.papermc.paper.threadedregions.RegionizedServer")
    }.isSuccess
}

interface Tasks {
    fun submit(task: Runnable)
}

class RegionTasks : Tasks {
    override fun submit(task: Runnable) {
        Bukkit.getGlobalRegionScheduler().execute(this, task)
    }
}

class LegacyTasks : Tasks {
    override fun submit(task: Runnable) {
        Bukkit.getScheduler().runTask(this, task)
    }
}

class UnguardedTasks : Tasks {
    override fun submit(task: Runnable) {
        Bukkit.getScheduler().runTask(this, task)
    }
}

/**
 * The other shape real plugins use: one class holding a Folia flag, with the branch inside every
 * method rather than at construction. The legacy half of each branch is unreachable on Folia even
 * though the class as a whole runs on both.
 */
class BranchingTasks : Tasks {

    private val isFolia: Boolean = Platform.IS_FOLIA

    override fun submit(task: Runnable) {
        if (isFolia) {
            Bukkit.getGlobalRegionScheduler().execute(this, task)
        } else {
            Bukkit.getScheduler().runTask(this, task)
        }
    }

    // The legacy branch builds its repeating task as a lambda, so the offending call compiles
    // into a synthetic method that carries no visible guard of its own.
    fun submitRepeating(task: Runnable) {
        if (isFolia) {
            Bukkit.getGlobalRegionScheduler().execute(this, task)
        } else {
            Bukkit.getScheduler().runTaskTimer(
                this,
                { Bukkit.getScheduler().runTask(this, task) },
                1L,
                20L,
            )
        }
    }

    // Branches on `isFolia` and calls an in-jar wrapper around `Tasks` rather than calling
    // `Bukkit.getGlobalRegionScheduler()` directly in this method body.
    fun submitViaWrapper(wrapper: SchedulerWrapper, task: Runnable) {
        if (isFolia) {
            wrapper.execute(task)
        } else {
            Bukkit.getScheduler().runTask(this, task)
        }
    }
}

class SchedulerWrapper(private val delegate: Tasks) {
    fun execute(task: Runnable) = delegate.submit(task)
}

/**
 * Unrelated manager constructed in a startup method that also checks `IS_FOLIA` and constructs
 * `RegionTasks`. Because `UnrelatedManager` does not share a supertype with `RegionTasks`, it must
 * not be mistaken for a non-Folia platform alternate.
 */
class UnrelatedManager {
    fun brokenSchedule(task: Runnable) {
        Bukkit.getScheduler().runTask(this, task)
    }

    // GlobalRegionScheduler ticks with region={null}, so touching a regional BlockState throws
    // `Cannot read world asynchronously` (BreweryTeam/Garden#54 pattern).
    fun touchBlockOnGlobalScheduler(state: BlockState) {
        Bukkit.getGlobalRegionScheduler().execute(this) {
            placeFruitBlock(state)
        }
    }

    fun placeFruitBlock(state: BlockState) {
        state.update(true)
    }
}

/**
 * The shape FoliaLib uses, which defeats both provable guards: the factory does
 * `Class.forName(base + name)`, so nothing in the jar ever writes `new ReflectiveTasks()` and no
 * method here tests for Folia. All that is visible is a sibling of [RegionTasks] that this jar
 * never constructs, which earns an explanation but not a downgrade.
 */
class ReflectiveTasks : Tasks {
    override fun submit(task: Runnable) {
        Bukkit.getScheduler().runTask(this, task)
    }
}

class DualModePlugin {

    fun onEnable() {
        val tasks = pick()
        tasks.submit { Unit }
        alwaysLegacy().submit { Unit }
        val br = branching()
        br.submitRepeating { Unit }
        br.submitViaWrapper(SchedulerWrapper(tasks)) { Unit }
        if (Platform.IS_FOLIA) {
            RegionTasks().submit { Unit }
        }
        UnrelatedManager().brokenSchedule { Unit }
    }

    // The guard for the two-implementation shape. Both are constructed here, so this is the only
    // place the resolver can learn that LegacyTasks is the non-Folia branch.
    private fun pick(): Tasks = if (Platform.IS_FOLIA) RegionTasks() else LegacyTasks()

    // Deliberately kept in its own method: if it shared `pick`, the guard there would cover it
    // too and the control would be worthless.
    private fun alwaysLegacy(): Tasks = UnguardedTasks()

    // Also kept guard-free, so BranchingTasks is only ever recognised by its own method-level
    // branches rather than by where it was built.
    private fun branching(): BranchingTasks = BranchingTasks()
}
