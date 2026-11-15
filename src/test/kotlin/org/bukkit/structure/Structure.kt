package org.bukkit.structure

import org.bukkit.Location
import java.util.Random

interface Structure {
    fun place(
        location: Location,
        includeEntities: Boolean,
        structureRotation: Any?,
        mirror: Any?,
        palette: Int,
        integrity: Float,
        random: Random,
    )
    fun getSize(): Any
}
