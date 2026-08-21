package com.salyvn.foliascan.scan

/**
 * A tool that rewrites plugin jars for Folia and leaves identifiable classes behind.
 *
 * This matters because a patcher can declare `folia-supported: true` on the author's behalf.
 * Once that key is present the load-time check passes, so a server owner reading "declared"
 * has no way to tell an author's considered claim from a machine's assumption.
 */
data class PatcherSignature(
    val tool: String,
    val url: String,
    /** Jar entries that only exist because the patcher put them there. */
    val markers: Set<String>,
    /** What the patcher does to the descriptor, stated factually. */
    val behaviour: String,
) {
    fun matchedBy(entryNames: Set<String>): String? = markers.firstOrNull { it in entryNames }
}

object PatcherDetector {

    /**
     * Signatures verified by reading each tool's source. Adding one requires the same: name the
     * file and line that injects the marker, and quote what it does to the descriptor.
     */
    private val known = listOf(
        PatcherSignature(
            tool = "FoliaPhantom (pasta)",
            url = "https://github.com/MARVserver/pasta",
            // PluginPatcher.RUNTIME_CLASSES, bundled into every patched jar at fixed paths.
            markers = setOf(
                "com/patch/foliaphantom/patcher/FoliaPatcher.class",
                "com/patch/foliaphantom/patcher/FoliaPatcher\$TaskSchedulerFactory.class",
                "com/patch/foliaphantom/patcher/FoliaPatcher\$ScheduledTaskStub.class",
            ),
            behaviour = "PluginPatcher#modifyPluginDescriptor appends or rewrites " +
                "`folia-supported: true` unconditionally, without analysing whether the plugin " +
                "is region-safe. Its own README disclaims thread-safety guarantees.",
        ),
    )

    fun detect(entryNames: Set<String>): Pair<PatcherSignature, String>? {
        for (signature in known) {
            val marker = signature.matchedBy(entryNames) ?: continue
            return signature to marker
        }
        return null
    }
}
