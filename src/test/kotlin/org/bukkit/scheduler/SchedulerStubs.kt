package org.bukkit.scheduler

interface BukkitTask {
    fun cancel()
}

interface BukkitScheduler {
    fun runTask(plugin: Any, task: Runnable): BukkitTask
    fun runTaskLater(plugin: Any, task: Runnable, delay: Long): BukkitTask
    fun runTaskTimer(plugin: Any, task: Runnable, delay: Long, period: Long): BukkitTask
    fun runTaskAsynchronously(plugin: Any, task: Runnable): BukkitTask
}

abstract class BukkitRunnable : Runnable {
    fun runTask(plugin: Any): BukkitTask = throw UnsupportedOperationException()

    fun runTaskTimer(plugin: Any, delay: Long, period: Long): BukkitTask =
        throw UnsupportedOperationException()

    fun runTaskAsynchronously(plugin: Any): BukkitTask = throw UnsupportedOperationException()

    fun cancel() = Unit
}
