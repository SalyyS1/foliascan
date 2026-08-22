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
     * True when [internalName] sits inside a relocated dependency tree. [extra] holds
     * user-supplied package prefixes in internal form.
     */
    fun isVendored(internalName: String, extra: Set<String> = emptySet()): Boolean {
        if (extra.any { internalName.startsWith(it) }) return true
        // Drop the class name; only package segments count.
        val segments = internalName.split('/').dropLast(1)
        return segments.any { it in BUILD_SEGMENTS || it in KNOWN_LIBRARIES }
    }

    /** The relocated subtrees present, for reporting which ones were skipped. */
    fun subtreesIn(internalNames: Collection<String>, extra: Set<String> = emptySet()): List<String> =
        internalNames.filter { isVendored(it, extra) }
            .mapNotNull { name ->
                val segments = name.split('/').dropLast(1)
                val cut = segments.indexOfFirst { it in BUILD_SEGMENTS || it in KNOWN_LIBRARIES }
                if (cut < 0) null else segments.take(cut + 1).joinToString(".")
            }
            .distinct()
            .sorted()
}
