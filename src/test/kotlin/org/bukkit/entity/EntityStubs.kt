package org.bukkit.entity

import org.bukkit.Location
import org.bukkit.persistence.PersistentDataContainer
import org.bukkit.scoreboard.Scoreboard
import io.papermc.paper.threadedregions.scheduler.EntityScheduler
import java.util.concurrent.CompletableFuture

interface Entity {
    fun teleport(location: Location): Boolean
    fun teleportAsync(location: Location): CompletableFuture<Boolean>
    fun getScheduler(): EntityScheduler
    fun getName(): String
    fun addPassenger(passenger: Entity): Boolean
    fun removePassenger(passenger: Entity): Boolean
    fun eject(): Boolean
    fun leaveVehicle(): Boolean
    fun getPersistentDataContainer(): PersistentDataContainer
    fun setData(type: Any, value: Any)
}

interface LivingEntity : Entity {
    fun getHealth(): Double
    fun setHealth(health: Double)
    fun setLeashHolder(holder: Entity?): Boolean
}

interface Player : LivingEntity {
    fun setScoreboard(scoreboard: Scoreboard)
    fun sendMessage(message: String)
    fun openInventory(inventory: Any): Any?
    fun closeInventory()
}
