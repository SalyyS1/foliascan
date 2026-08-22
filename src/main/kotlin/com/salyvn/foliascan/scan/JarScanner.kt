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
            val entryNames = jar.entries().asSequence().map { it.name }.toSet()
            val descriptor = PluginDescriptorReader.read(jar)
            if (descriptor == null) {
                notes += "No plugin.yml or paper-plugin.yml found; treating the jar as a library."
            }

            val classNames = entryNames.filter { it.endsWith(".class") }.map { it.removeSuffix(".class") }
            val prefixes = includePrefixes(descriptor, classNames, notes)
            val classes = readClasses(jar, prefixes, notes)
            val jarClasses = JarClasses(classes)
            val offRegion = OffRegionContextResolver.resolve(jarClasses)

            // Patcher markers sit outside the plugin's own package, so they are looked for in
            // the raw entry list rather than in the parsed classes.
            val patched = PatcherDetector.detect(entryNames)

            // Relocated dependencies stay in the analysis model - they improve supertype
            // resolution and let an async task started inside a shaded library taint the
            // plugin code it calls - but they are not blamed in the report.
            val extraExcludes = options.excludePackages.map { it.replace('.', '/') }.toSet()
            val vendored = if (options.scanAllPackages) {
                emptySet()
            } else {
                classes.keys.filter { VendoredPackages.isVendored(it, extraExcludes) }.toSet()
            }
            val reportable = classes.keys - vendored
            if (vendored.isNotEmpty()) {
                val subtrees = VendoredPackages.subtreesIn(vendored, extraExcludes)
                notes += "${vendored.size} class(es) treated as relocated dependencies and not " +
                    "blamed: ${subtrees.joinToString(", ")}. Pass --all to report them."
            }

            val collector = FindingCollector(
                jarName = path.fileName.toString(),
                jar = jarClasses,
                offRegion = offRegion,
                descriptor = descriptor,
                disabledRules = options.disabledRules,
                reportable = reportable,
                patched = patched,
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
                hasDescriptor = descriptor != null,
                declaresFoliaSupport = descriptor?.foliaSupported == true,
                classesScanned = classes.size,
                foliaApiUsages = collector.foliaApiUsages,
                notes = notes,
                findings = findings,
            )
        }
    }

    /**
     * The package tree(s) to analyse. Empty means "no filter".
     *
     * The plugin's `main` class is often parked in a platform subpackage - AuraSkills declares
     * `dev.aurelium.auraskills.bukkit.AuraSkills` while most of its code lives in the sibling
     * `common` and `api` packages - so using main's own package as the root silently skipped the
     * majority of the plugin. The root is therefore widened to the longest package prefix shared
     * by every class in the jar, as far as that prefix still lies on main's package path.
     */
    private fun includePrefixes(
        descriptor: PluginDescriptor?,
        classNames: List<String>,
        notes: MutableList<String>,
    ): Set<String> {
        if (options.scanAllPackages) return emptySet()
        if (options.includePackages.isNotEmpty()) {
            return options.includePackages.map { it.replace('.', '/') }.toSet()
        }
        val mainPackage = descriptor?.rootPackage()
        if (mainPackage == null) {
            notes += "Could not derive the plugin package from the descriptor; scanned every class."
            return emptySet()
        }
        val root = widenRoot(mainPackage, classNames)
        notes += "Scanned package ${root.replace('/', '.')} " +
            "(${classNames.count { it.startsWith("$root/") }} of ${classNames.size} classes in the jar)."
        return setOf(root)
    }

    /** Walks main's package upward while every class in the jar still shares the prefix. */
    private fun widenRoot(mainPackage: String, classNames: List<String>): String {
        val mainSegments = mainPackage.split('/')
        val shared = commonPackagePrefix(classNames)
            .zip(mainSegments)
            .takeWhile { (fromJar, fromMain) -> fromJar == fromMain }
            .map { it.first }
        // Two segments is the floor; `com` or `dev` alone would be meaningless as a root.
        return if (shared.size >= 2) shared.joinToString("/") else mainPackage
    }

    private fun commonPackagePrefix(classNames: List<String>): List<String> {
        val packages = classNames.asSequence()
            .filterNot { it.startsWith("META-INF/") }
            .map { it.split('/').dropLast(1) }
            .toList()
        if (packages.isEmpty()) return emptyList()
        return packages.reduce { acc, next ->
            acc.zip(next).takeWhile { it.first == it.second }.map { it.first }
        }
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
}
