package org.bukkit.plugin

import org.bukkit.event.Listener

interface PluginManager {
    fun registerEvents(listener: Listener, plugin: Any)
    fun unregisterEvents(listener: Listener)
    fun unregisterAll()
}

interface ServicesManager {
    fun <T : Any> register(service: Class<T>, provider: T, plugin: Any, priority: ServicePriority)
    fun unregister(service: Class<*>, provider: Any)
    fun unregisterAll(plugin: Any)
}

enum class ServicePriority { LOWEST, LOW, NORMAL, HIGH, HIGHEST }
