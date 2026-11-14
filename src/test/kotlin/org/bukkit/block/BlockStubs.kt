package org.bukkit.block

interface BlockState {
    fun getDrops(): Collection<Any>
    fun update(force: Boolean): Boolean
}

interface TileState : BlockState {
    fun getPersistentDataContainer(): Any
}

interface Container : TileState {
    fun getInventory(): Any
    fun getSnapshotInventory(): Any
}

interface Chest : Container

interface TrialSpawner : TileState {
    fun setCooldownLength(ticks: Int)
    fun isOminous(): Boolean
}

interface Vault : TileState {
    fun setActivationRange(range: Double)
}

interface Crafter : Container {
    fun setCraftingTicks(ticks: Int)
}

interface Sign : TileState {
    fun getLine(index: Int): String
    fun setLine(index: Int, line: String)
}

interface Block {
    fun getBlockState(): BlockState
    fun getState(): BlockState
    fun breakNaturally(): Boolean
    fun getBiome(): String
    fun setBlockState(state: BlockState)
    fun getType(): String
}
