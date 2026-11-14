package org.bukkit.generator

import java.util.Random

interface WorldInfo {
    fun getName(): String
    fun getMinHeight(): Int
    fun getMaxHeight(): Int
}

interface LimitedRegion {
    fun isInRegion(x: Int, y: Int, z: Int): Boolean
    fun setType(x: Int, y: Int, z: Int, material: String)
}

abstract class BlockPopulator {
    open fun populate(
        worldInfo: WorldInfo,
        random: Random,
        chunkX: Int,
        chunkZ: Int,
        limitedRegion: LimitedRegion,
    ) {}
}

abstract class ChunkGenerator {
    interface ChunkData {
        fun setBlock(x: Int, y: Int, z: Int, material: String)
    }

    open fun generateSurface(
        worldInfo: WorldInfo,
        random: Random,
        chunkX: Int,
        chunkZ: Int,
        chunkData: ChunkData,
    ) {}
}
