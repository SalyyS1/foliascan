package com.salyvn.foliascan

import com.salyvn.foliascan.scan.VendoredPackages
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The relocation filter decides what never appears in a report, so a wrong answer here is
 * invisible in the output. Each case below is a package layout taken from a real jar.
 *
 * The predicate always needs the plugin's roots to be meaningful. A jar with no descriptor has no
 * root, and skipping the filter entirely for those is [com.salyvn.foliascan.scan.JarScanner]'s
 * job - covered by `FixtureScanTest`.
 */
class VendoredPackagesTest {

    private val roots = setOf("dev/aurelium/auraskills", "io/lumine/mythic/lib")

    @Test
    fun `a relocated library inside the plugin root is vendored`() {
        assertTrue(vendored("dev/aurelium/auraskills/kyori/adventure/text/Component"))
        assertTrue(vendored("dev/aurelium/auraskills/acf/commands/BaseCommand"))
        assertTrue(vendored("io/lumine/mythic/lib/sql/hikari/pool/HikariPool"))
    }

    @Test
    fun `a build-tool relocation folder is vendored`() {
        assertTrue(vendored("com/magecore/libs/kotlin/jvm/internal/Intrinsics", setOf("com/magecore")))
    }

    @Test
    fun `the plugin's own root is never a marker`() {
        // `lib` is a relocation folder name and also the last segment of MythicLib's own package.
        // Treating it as a marker exonerated all 1477 of its classes.
        assertFalse(vendored("io/lumine/mythic/lib/UtilityMethods"))
        assertFalse(vendored("io/lumine/mythic/lib/api/stat/StatMap"))
    }

    @Test
    fun `an adapter package named after a library is the plugin's own code`() {
        assertFalse(vendored("io/lumine/mythic/lib/comp/protocollib/DamageParticleCap"))
        assertFalse(vendored("io/lumine/mythic/lib/comp/adventure/AdventureParser"))
        assertFalse(
            vendored("com/example/plugin/hooks/placeholderapi/Expansion", setOf("com/example/plugin")),
        )
    }

    @Test
    fun `a library relocated below an adapter package is still found`() {
        assertTrue(
            vendored("com/example/plugin/compat/libs/kyori/adventure/Component", setOf("com/example/plugin")),
        )
    }

    @Test
    fun `a domain noun is not a library identity`() {
        // Each of these is a real plugin's own package that a generic list entry used to hide.
        // A Prometheus exporter's entire job is metrics, so `metrics` hid all four of its
        // critical findings including the scheduleSyncRepeatingTask call.
        assertFalse(vendored("de/sldk/mc/metrics/Tps", setOf("de/sldk/mc")))
        assertFalse(vendored("ranet/coretools/data/mysql/MySqlStore", setOf("ranet/coretools")))
        assertFalse(
            vendored("io/lumine/mythiccrucible/skills/mechanics/nbt/SetNbt", setOf("io/lumine/mythiccrucible")),
        )
        assertFalse(vendored("io/lumine/mythic/lib/glow/external/GlowHook"))
    }

    @Test
    fun `an explicit exclusion still matches the whole name`() {
        assertTrue(
            VendoredPackages.isVendored(
                "com/example/plugin/thing/Class",
                extra = setOf("com/example/plugin/thing"),
            ),
        )
    }

    @Test
    fun `the reported subtree stops at the marker`() {
        val subtrees = VendoredPackages.subtreesIn(
            listOf(
                "dev/aurelium/auraskills/kyori/adventure/text/Component",
                "dev/aurelium/auraskills/kyori/adventure/text/Other",
                "dev/aurelium/auraskills/acf/commands/BaseCommand",
            ),
            roots = roots,
        )
        assertEquals(
            listOf("dev.aurelium.auraskills.acf", "dev.aurelium.auraskills.kyori"),
            subtrees,
        )
    }

    private fun vendored(internalName: String, roots: Set<String> = this.roots): Boolean =
        VendoredPackages.isVendored(internalName, roots = roots)
}
