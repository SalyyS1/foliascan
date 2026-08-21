package com.salyvn.foliascan.scan

import com.salyvn.foliascan.model.JarReport
import java.nio.file.Path
import java.util.jar.JarFile

data class ScanOptions(
    /** Scan every class in the jar, including shaded third-party libraries. */
    val scanAllPackages: Boolean = false,
    /** Explicit package filter in dotted form, e.g. `com.example.plugin`. */
    val includePackages: Set<String> = emptySet(),
    /** Extra packages to skip, in dotted form. Added to the built-in shaded-library segments. */
    val excludePackages: Set<String> = emptySet(),
    /** Rule ids to skip, e.g. `FS063`. */
    val disabledRules: Set<String> = emptySet(),
)

/**
 * Reads one plugin jar and produces its report.
 *
 * Two filters keep the report about the plugin's own code:
 *  - only the package tree named by `main` in the descriptor is analysed, and
 *  - relocated dependency trees are skipped, because Shadow-style relocation moves libraries
 *    *inside* that package (`com.example.plugin.libs.folialib`). A compatibility shim such as
 *    FoliaLib deliberately contains a legacy BukkitScheduler implementation, so reporting it
 *    would be noise rather than a defect.
 *
 * `--all` disables both filters. Whatever gets skipped is always counted in the report notes,
 * so the filtering is visible rather than silent.
 */
class JarScanner(private val options: ScanOptions = ScanOptions()) {

    fun scan(path: Path): JarReport {
        val notes = mutableListOf<String>()
        JarFile(path.toFile()).use { jar ->
            val descriptor = PluginDescriptorReader.read(jar)
            if (descriptor == null) {
                notes += "No plugin.yml or paper-plugin.yml found; treating the jar as a library."
            }

            val prefixes = includePrefixes(descriptor, notes)
            val classes = readClasses(jar, prefixes, notes)
            val jarClasses = JarClasses(classes)
            val offRegion = OffRegionContextResolver.resolve(jarClasses)

            // Relocated dependencies stay in the analysis model - they improve supertype
            // resolution and let an async task started inside a shaded library taint the
            // plugin code it calls - but they are not blamed in the report.
            val excluded = excludedSegments()
            val reportable = classes.keys.filterNot { isExcluded(it, excluded) }.toSet()
            val hidden = classes.size - reportable.size
            if (hidden > 0) {
                notes += "$hidden relocated dependency class(es) analysed but not reported; " +
                    "pass --all to report them too."
            }

            val collector = FindingCollector(
                jarName = path.fileName.toString(),
                jar = jarClasses,
                offRegion = offRegion,
                descriptor = descriptor,
                disabledRules = options.disabledRules,
                reportable = reportable,
            )
            val findings = collector.collect()

            if (offRegion.size > 0) {
                notes += "${offRegion.size} method(s) are reachable from an off-region entry point."
            }

            return JarReport(
                jar = path.fileName.toString(),
                pluginName = descriptor?.name,
                pluginVersion = descriptor?.version,
                mainClass = descriptor?.main,
                apiVersion = descriptor?.apiVersion,
                declaresFoliaSupport = descriptor?.foliaSupported == true,
                classesScanned = classes.size,
                foliaApiUsages = collector.foliaApiUsages,
                notes = notes,
                findings = findings,
            )
        }
    }

    /** Empty result means "no filter": analyse everything. */
    private fun includePrefixes(
        descriptor: PluginDescriptor?,
        notes: MutableList<String>,
    ): Set<String> {
        if (options.scanAllPackages) return emptySet()
        if (options.includePackages.isNotEmpty()) {
            return options.includePackages.map { it.replace('.', '/') }.toSet()
        }
        val root = descriptor?.rootPackage()
        if (root == null) {
            notes += "Could not derive the plugin package from the descriptor; scanned every class."
            return emptySet()
        }
        notes += "Scanned package ${root.replace('/', '.')} only; pass --all to include shaded code."
        return setOf(root)
    }

    /** Path segments that mean "a dependency was relocated in here". */
    private fun excludedSegments(): Set<String> {
        if (options.scanAllPackages) return emptySet()
        return RELOCATION_SEGMENTS + options.excludePackages.map { it.replace('.', '/') }
    }

    private fun readClasses(
        jar: JarFile,
        prefixes: Set<String>,
        notes: MutableList<String>,
    ): Map<String, ClassModel> {
        val out = LinkedHashMap<String, ClassModel>()
        var unreadable = 0
        for (entry in jar.entries()) {
            if (entry.isDirectory || !entry.name.endsWith(".class")) continue
            val internalName = entry.name.removeSuffix(".class")
            if (prefixes.isNotEmpty() && prefixes.none { internalName.startsWith(it) }) continue
            val bytes = runCatching { jar.getInputStream(entry).use { it.readBytes() } }.getOrNull()
            if (bytes == null) {
                unreadable++
                continue
            }
            val model = runCatching { ClassAnalyzer.read(bytes) }.getOrNull()
            if (model == null) {
                unreadable++
                continue
            }
            out[model.internalName] = model
        }
        if (unreadable > 0) {
            notes += "$unreadable class entr(ies) could not be parsed and were skipped."
        }
        return out
    }

    private fun isExcluded(internalName: String, excluded: Set<String>): Boolean {
        if (excluded.isEmpty()) return false
        val segments = internalName.split('/')
        return excluded.any { candidate ->
            if ('/' in candidate) {
                internalName.startsWith(candidate)
            } else {
                // Match a whole path segment, so `lib` never swallows `library`.
                segments.dropLast(1).contains(candidate)
            }
        }
    }

    private companion object {
        /**
         * Directory names build tools use when relocating dependencies. Matched as whole path
         * segments only.
         */
        val RELOCATION_SEGMENTS = setOf(
            "libs", "lib", "shaded", "shadow", "shadowed", "thirdparty", "third_party",
            "dependencies", "external", "vendor", "relocated", "repackaged",
        )
    }
}
