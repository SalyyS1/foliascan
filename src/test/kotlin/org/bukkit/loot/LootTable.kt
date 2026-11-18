package org.bukkit.loot

import java.util.Random
import org.bukkit.inventory.Inventory

interface LootTable {
    fun fillInventory(inventory: Inventory, random: Random?, context: Any?)
    fun populateLoot(random: Random?, context: Any?): Collection<Any>
}
