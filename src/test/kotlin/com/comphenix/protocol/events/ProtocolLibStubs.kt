package com.comphenix.protocol.events

import org.bukkit.entity.Player

class PacketEvent(val player: Player)

interface PacketListener {
    fun onPacketReceiving(event: PacketEvent) {}
    fun onPacketSending(event: PacketEvent) {}
}

open class PacketAdapter : PacketListener
