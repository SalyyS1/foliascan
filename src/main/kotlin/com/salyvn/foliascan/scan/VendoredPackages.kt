package com.salyvn.foliascan.scan

/**
 * Recognises dependency code that was relocated inside a plugin's own package.
 *
 * Two signals, both matched on whole path segments:
 *  - [BUILD_SEGMENTS]: folders build tools create when relocating (`libs`, `shaded`, …).
 *  - [KNOWN_LIBRARIES]: leaf names of libraries that are commonly shaded into Minecraft
 *    plugins without any such folder. AuraSkills, for example, relocates Adventure to
 *    `dev.aurelium.auraskills.kyori` - no marker segment at all.
 *
 * Only segments *below* the plugin's own root count. The root itself is never a marker, or
 * pointing the scanner at one of these libraries directly would exonerate the whole jar -
 * scanning `IF-0.12.0.jar` would find nothing, because `inventoryframework` is on the list of
 * things plugins shade.
 *
 * This is a curated list, so it is incomplete by construction. Whatever it matches is always
 * named in the report notes, and `--all` turns it off, so a wrong guess is visible and
 * overridable rather than silent.
 */
object VendoredPackages {

    /** Folder names that mean "a dependency was relocated in here". */
    val BUILD_SEGMENTS = setOf(
        "libs", "lib", "shaded", "shadow", "shadowed", "thirdparty", "third_party",
        "dependencies", "external", "vendor", "vendored", "relocated", "repackaged", "internal",
    )

    /**
     * Library leaf names seen relocated into plugin packages. Grouped by what they are so the
     * list stays reviewable.
     */
    val KNOWN_LIBRARIES = setOf(
        // text, config and serialization
        "kyori", "adventure", "configurate", "gson", "jackson", "snakeyaml", "toml4j",
        "geantyref", "typesafe", "hocon",
        // command frameworks and GUI toolkits
        "acf", "aikar", "cloud", "incendo", "slate", "triumph", "inventoryframework",
        "smartinvs", "fastinv", "guilib",
        // storage and pooling
        "hikari", "zaxxer", "jooq", "flyway", "sqlite", "mariadb", "mysql", "jedis", "mongodb",
        // math, nbt and world formats
        "evalex", "exp4j", "nbtapi", "tr7zw", "querz", "nbt",
        // general utility
        "guava", "commons", "apache", "okhttp", "okio", "retrofit", "netty", "caffeine",
        "reflections", "asm", "bytebuddy", "jetbrains", "intellij", "annotations",
        // metrics and platform glue
        "bstats", "metrics", "papi", "placeholderapi", "protocollib", "packetevents",
        // schedulers and Folia compatibility shims
        "folialib", "foliascheduler", "foliacompat", "scheduling",
    )

    /**
     * True when [internalName] sits inside a relocated dependency tree.
     *
     * [extra] holds user-supplied package prefixes in internal form, matched against the whole
     * name because the user named an absolute package. [roots] are the plugin's own package
     * roots; segments belonging to them are skipped, so only what was relocated *inside* the
     * plugin can match.
     */
    fun isVendored(
        internalName: String,
        extra: Set<String> = emptySet(),
        roots: Set<String> = emptySet(),
    ): Boolean {
        if (extra.any { internalName.startsWith(it) }) return true
        return markerIndex(internalName, roots) >= 0
    }

    /** The relocated subtrees present, for reporting which ones were skipped. */
    fun subtreesIn(
        internalNames: Collection<String>,
        extra: Set<String> = emptySet(),
        roots: Set<String> = emptySet(),
    ): List<String> = internalNames.filter { isVendored(it, extra, roots) }
        .mapNotNull { name ->
            val cut = markerIndex(name, roots)
            if (cut < 0) null else name.split('/').take(cut + 1).joinToString(".")
        }
        .distinct()
        .sorted()

    /** Index of the segment that marks a relocated tree, or -1 when there is none. */
    private fun markerIndex(internalName: String, roots: Set<String>): Int {
        // Drop the class name; only package segments count.
        val segments = internalName.split('/').dropLast(1)
        val owned = roots.filter { internalName.startsWith("$it/") }
            .maxOfOrNull { it.count { c -> c == '/' } + 1 } ?: 0
        for (index in owned until segments.size) {
            val segment = segments[index]
            if (segment in BUILD_SEGMENTS || segment in KNOWN_LIBRARIES) return index
        }
        return -1
    }
}
