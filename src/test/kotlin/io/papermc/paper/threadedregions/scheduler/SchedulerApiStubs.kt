// Stand-ins for the Paper threaded-region scheduler API - the APIs a Folia-ready plugin is
// supposed to use. Present so the "clean" fixture can be compiled and shown to produce no
// scheduler findings.
package io.papermc.paper.threadedregions.scheduler

import org.bukkit.Location

interface ScheduledTask {
    fun cancel()
}

interface GlobalRegionScheduler {
    fun run(plugin: Any, task: (ScheduledTask) -> Unit): ScheduledTask
    fun runAtFixedRate(plugin: Any, task: (ScheduledTask) -> Unit, delay: Long, period: Long): ScheduledTask
    fun execute(plugin: Any, task: Runnable)
}

interface RegionScheduler {
    fun execute(plugin: Any, location: Location, task: Runnable)
    fun run(plugin: Any, location: Location, task: (ScheduledTask) -> Unit): ScheduledTask
}

interface AsyncScheduler {
    fun runNow(plugin: Any, task: (ScheduledTask) -> Unit): ScheduledTask
    fun runDelayed(plugin: Any, task: (ScheduledTask) -> Unit, delay: Long, unit: java.util.concurrent.TimeUnit): ScheduledTask
}

interface EntityScheduler {
    fun run(plugin: Any, task: (ScheduledTask) -> Unit, retired: Runnable?): Boolean
    fun execute(plugin: Any, task: Runnable, retired: Runnable?, delay: Long): Boolean
}
