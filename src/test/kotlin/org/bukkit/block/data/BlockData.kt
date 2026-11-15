package org.bukkit.block.data

import org.bukkit.Material
import org.bukkit.block.BlockFace

/** Minimal BlockData stub for test fixture compilation. */
interface BlockData {
    fun getMaterial(): Material
    fun getAsString(): String
    fun merge(data: BlockData): BlockData
    fun clone(): BlockData

    fun setWaterlogged(waterlogged: Boolean)
    fun setFacing(facing: BlockFace)
    fun setOpen(open: Boolean)
    fun setPowered(powered: Boolean)
    fun setLit(lit: Boolean)
    fun setEnabled(enabled: Boolean)
    fun setLevel(level: Int)
    fun setLayers(layers: Int)
    fun setSnowy(snowy: Boolean)
    fun setAge(age: Int)
    fun setAttached(attached: Boolean)
    fun setTriggered(triggered: Boolean)
    fun setType(material: Material)
    fun setAxis(axis: Axis)
    fun setInstrument(instrument: Instrument)
    fun setNote(note: Int)

    enum class Axis { X, Y, Z }
    enum class Instrument { BASS_DRUM, BASS_GUITAR, SNARE_DRUM, CLICKS, BASS, FLUTE, BELL, GUITAR, CHIME, XYLOPHONE }
}
