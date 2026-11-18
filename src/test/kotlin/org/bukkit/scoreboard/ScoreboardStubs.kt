package org.bukkit.scoreboard

interface Score {
    fun setScore(score: Int)
    fun resetScore()
}

interface Objective {
    fun setDisplayName(name: String)
    fun getScore(entry: String): Score
}

interface Team {
    fun addEntry(entry: String)
    fun removeEntry(entry: String): Boolean
}

interface Scoreboard {
    fun registerNewObjective(name: String, criteria: String, displayName: String): Objective
    fun registerNewTeam(name: String): Team
    fun clearSlot(slot: String)
    fun resetScores(entry: String)
}

interface ScoreboardManager {
    fun getNewScoreboard(): Scoreboard
    fun getMainScoreboard(): Scoreboard
}
