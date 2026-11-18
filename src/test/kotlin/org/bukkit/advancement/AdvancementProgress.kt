package org.bukkit.advancement

interface AdvancementProgress {
    fun awardCriteria(criteria: String): Boolean
    fun revokeCriteria(criteria: String): Boolean
}
