package org.bukkit.persistence

interface PersistentDataContainer {
    fun set(key: Any, type: Any, value: Any)
    fun remove(key: Any)
    fun readFromBytes(bytes: ByteArray, clearExisting: Boolean)
    fun copyTo(target: PersistentDataContainer, replace: Boolean)
}
