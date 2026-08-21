package com.salyvn.foliascan

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

/**
 * Packs the compiled test fixtures into throwaway plugin jars.
 *
 * The fixtures are compiled by the normal Kotlin test compilation, so these jars contain real
 * javac/kotlinc bytecode rather than hand-assembled class files - which is the whole point:
 * the analyzer is exercised against the same instruction shapes a real plugin produces.
 */
object FixtureJars {

    fun legacy(): Path = build(
        jarName = "legacy-plugin",
        packagePath = "fixtures/legacy/",
        main = "fixtures.legacy.LegacyPlugin",
        foliaSupported = false,
    )

    fun regionAware(): Path = build(
        jarName = "region-aware-plugin",
        packagePath = "fixtures/regionaware/",
        main = "fixtures.regionaware.RegionAwarePlugin",
        foliaSupported = true,
    )

    /** A jar with classes but no descriptor, i.e. a plain library. */
    fun libraryWithoutDescriptor(): Path = build(
        jarName = "library",
        packagePath = "fixtures/legacy/",
        main = null,
        foliaSupported = false,
    )

    /**
     * A jar that declares Folia support and carries FoliaPhantom's injected runtime class, i.e.
     * the flag came from a patcher rather than from the author.
     */
    fun patchedByFoliaPhantom(): Path = build(
        jarName = "patched-plugin",
        packagePath = "fixtures/legacy/",
        main = "fixtures.legacy.LegacyPlugin",
        foliaSupported = true,
        extraEntries = mapOf(
            "com/patch/foliaphantom/patcher/FoliaPatcher.class" to
                readResource("fixtures/legacy/HeartbeatTask.class"),
        ),
    )

    private fun build(
        jarName: String,
        packagePath: String,
        main: String?,
        foliaSupported: Boolean,
        extraEntries: Map<String, ByteArray> = emptyMap(),
    ): Path {
        val target = Files.createTempFile(jarName, ".jar")
        JarOutputStream(Files.newOutputStream(target)).use { out ->
            if (main != null) {
                out.putNextEntry(JarEntry("plugin.yml"))
                out.write(descriptor(jarName, main, foliaSupported).toByteArray())
                out.closeEntry()
            }
            for (resource in classResources(packagePath)) {
                out.putNextEntry(JarEntry(resource))
                out.write(readResource(resource))
                out.closeEntry()
            }
            for ((name, bytes) in extraEntries) {
                out.putNextEntry(JarEntry(name))
                out.write(bytes)
                out.closeEntry()
            }
        }
        target.toFile().deleteOnExit()
        return target
    }

    private fun descriptor(name: String, main: String, foliaSupported: Boolean): String =
        buildString {
            appendLine("name: $name")
            appendLine("version: 1.0.0")
            appendLine("main: $main")
            appendLine("api-version: '1.21'")
            if (foliaSupported) appendLine("folia-supported: true")
        }

    private fun classResources(packagePath: String): List<String> {
        val url = requireNotNull(javaClass.classLoader.getResource(packagePath)) {
            "Fixture package $packagePath is not on the test classpath"
        }
        val dir = Paths.get(url.toURI())
        return Files.list(dir).use { stream ->
            stream.map { it.fileName.toString() }
                .filter { it.endsWith(".class") }
                .sorted()
                .toList()
                .map { packagePath + it }
        }
    }

    private fun readResource(name: String): ByteArray =
        requireNotNull(javaClass.classLoader.getResourceAsStream(name)) {
            "Missing compiled fixture $name"
        }.use { it.readBytes() }
}
