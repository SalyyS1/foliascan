package com.salyvn.foliascan

import java.util.Properties

/** The build stamps the version into a resource; this reads it back. */
object BuildInfo {

    private const val RESOURCE = "/foliascan-version.properties"

    val version: String by lazy {
        val stream = BuildInfo::class.java.getResourceAsStream(RESOURCE) ?: return@lazy "dev"
        runCatching {
            stream.use { Properties().apply { load(it) }.getProperty("version") }
        }.getOrNull()?.takeIf { it.isNotBlank() && !it.startsWith("$") } ?: "dev"
    }
}
