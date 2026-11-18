package org.bukkit.inventory

import io.papermc.paper.datacomponent.DataComponentHolder
import org.bukkit.Material

class ItemStack(val type: Material = Material.STONE, var amountCount: Int = 1) : DataComponentHolder {
    override fun setData(type: Any, value: Any) = Unit
    override fun unsetData(type: Any) = Unit
    override fun resetData(type: Any) = Unit
    override fun copyDataFrom(source: DataComponentHolder, predicate: Any?) = Unit
    fun setItemMeta(meta: Any?): Boolean = true
    fun editMeta(consumer: (Any) -> Unit): Boolean = true
    fun setAmount(amount: Int) {
        amountCount = amount
    }
    fun clone(): ItemStack = ItemStack(type, amountCount)
}

interface Inventory {
    fun getItem(index: Int): ItemStack?
    fun setItem(index: Int, item: Any?)
    fun addItem(vararg items: Any?): Map<Int, Any>
    fun removeItem(vararg items: Any?): Map<Int, Any>
    fun clear()
}

interface PlayerInventory : Inventory {
    fun getItemInMainHand(): ItemStack
    fun setHelmet(helmet: Any?)
    fun setItemInMainHand(item: Any?)
    fun setArmorContents(items: Array<Any?>)
}

interface EntityEquipment {
    fun getItemInMainHand(): ItemStack
    fun setChestplate(chestplate: Any?)
    fun setItemInOffHand(item: Any?)
}

interface InventoryView {
    fun getCursor(): ItemStack
    fun setCursor(item: Any?)
    fun setItem(slot: Int, item: Any?)
    fun setTitle(title: String)
    fun close()
}

interface Merchant {
    fun setRecipes(recipes: List<Any>)
    fun setRecipe(index: Int, recipe: Any)
}
