package org.bukkit.inventory

interface Inventory {
    fun setItem(index: Int, item: Any?)
    fun addItem(vararg items: Any?): Map<Int, Any>
    fun removeItem(vararg items: Any?): Map<Int, Any>
    fun clear()
}

interface PlayerInventory : Inventory {
    fun setHelmet(helmet: Any?)
    fun setItemInMainHand(item: Any?)
    fun setArmorContents(items: Array<Any?>)
}

interface EntityEquipment {
    fun setChestplate(chestplate: Any?)
    fun setItemInOffHand(item: Any?)
}
