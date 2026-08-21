package org.bukkit.entity

import org.bukkit.Location
import org.bukkit.scoreboard.Scoreboard
import io.papermc.paper.threadedregions.scheduler.EntityScheduler
import java.util.concurrent.CompletableFuture

interface Entity {
    fun teleport(location: Location): Boolean
    fun teleportAsync(location: Location): CompletableFuture<Boolean>
    fun getScheduler(): EntityScheduler
    fun getName(): String
}

interface LivingEntity : Entity {
    fun getHealth(): Double
}

interface Player : LivingEntity {
    fun setScoreboard(scoreboard: Scoreboard)
    fun sendMessage(message: String)
}
