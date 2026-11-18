package io.papermc.paper.entity

import org.bukkit.entity.Entity

interface Leashable : Entity {
    fun isLeashed(): Boolean
    fun getLeashHolder(): Entity
    fun setLeashHolder(holder: Entity?): Boolean
}
