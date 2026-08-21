package org.bukkit.scoreboard

interface Objective {
    fun setDisplayName(name: String)
}

interface Team {
    fun addEntry(entry: String)
}

interface Scoreboard {
    fun registerNewObjective(name: String, criteria: String, displayName: String): Objective
    fun registerNewTeam(name: String): Team
    fun clearSlot(slot: String)
}

interface ScoreboardManager {
    fun getNewScoreboard(): Scoreboard
    fun getMainScoreboard(): Scoreboard
}
