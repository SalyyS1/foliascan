package org.bukkit.boss

import org.bukkit.entity.Player

interface BossBar {
    fun addPlayer(player: Player)
    fun removePlayer(player: Player)
    fun removeAll()
}

interface KeyedBossBar : BossBar
