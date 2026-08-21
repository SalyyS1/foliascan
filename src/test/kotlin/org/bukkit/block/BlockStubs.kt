package org.bukkit.block

interface BlockState {
    fun getDrops(): Collection<Any>
    fun update(force: Boolean): Boolean
}

interface Block {
    fun getBlockState(): BlockState
    fun breakNaturally(): Boolean
    fun getBiome(): String
    fun setBlockState(state: BlockState)
    fun getType(): String
}
