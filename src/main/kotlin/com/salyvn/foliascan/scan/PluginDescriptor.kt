package com.salyvn.foliascan.scan

import java.util.jar.JarFile
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/** The plugin descriptor as Folia and Paper read it. */
data class PluginDescriptor(
    /** Which file it came from: `paper-plugin.yml` wins when both exist, as Paper does. */
    val source: String,
    val name: String?,
    val version: String?,
    val main: String?,
    val apiVersion: String?,
    val foliaSupported: Boolean,
) {
    /**
     * Best guess at the plugin's own package, used to keep shaded third-party code out of the
     * report by default. `com.example.plugin.MyPlugin` yields `com/example/plugin`.
     */
    fun rootPackage(): String? {
        val cls = main?.takeIf { it.contains('.') } ?: return null
        return cls.substringBeforeLast('.').replace('.', '/')
    }
}

object PluginDescriptorReader {

    private const val PAPER_FILE = "paper-plugin.yml"
    private const val BUKKIT_FILE = "plugin.yml"
    private const val FOLIA_KEY = "folia-supported"

    /** Parses the descriptor, or returns null when the jar carries none (e.g. a library jar). */
    fun read(jar: JarFile): PluginDescriptor? =
        parse(jar, PAPER_FILE) ?: parse(jar, BUKKIT_FILE)

    private fun parse(jar: JarFile, entryName: String): PluginDescriptor? {
        val entry = jar.getJarEntry(entryName) ?: return null
        val text = jar.getInputStream(entry).use { it.readBytes().decodeToString() }

        // The YAML comes from an untrusted jar, so no arbitrary type construction, no alias
        // expansion bombs, and a hard size cap.
        val options = LoaderOptions().apply {
            isAllowDuplicateKeys = false
            maxAliasesForCollections = 32
            codePointLimit = 2 * 1024 * 1024
        }
        val loaded = runCatching {
            Yaml(SafeConstructor(options)).load<Any?>(text)
        }.getOrNull()

        val map = loaded as? Map<*, *> ?: return PluginDescriptor(
            source = entryName,
            name = null,
            version = null,
            main = null,
            apiVersion = null,
            foliaSupported = false,
        )

        return PluginDescriptor(
            source = entryName,
            name = map.str("name"),
            version = map.str("version"),
            main = map.str("main"),
            apiVersion = map.str("api-version"),
            // Folia compares the raw value with equalsIgnoreCase("true"), so a YAML boolean
            // and the string "TRUE" both count.
            foliaSupported = map[FOLIA_KEY]?.toString()?.equals("true", ignoreCase = true) == true,
        )
    }

    private fun Map<*, *>.str(key: String): String? = this[key]?.toString()?.takeIf { it.isNotBlank() }
}
