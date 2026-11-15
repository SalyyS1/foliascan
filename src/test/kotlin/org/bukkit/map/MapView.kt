package org.bukkit.map

import org.bukkit.World

interface MapRenderer

interface MapView {
    fun addRenderer(renderer: MapRenderer)
    fun removeRenderer(renderer: MapRenderer)
    fun getRenderers(): List<MapRenderer>
    fun setLocked(locked: Boolean)
    fun setCenterX(x: Int)
    fun setCenterZ(z: Int)
    fun setScale(scale: MapView.Scale)
    fun setWorld(world: World)

    enum class Scale { CLOSEST, CLOSE, NORMAL, FAR, FARTHEST }
}
