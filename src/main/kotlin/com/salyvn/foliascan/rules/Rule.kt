package com.salyvn.foliascan.rules

import com.salyvn.foliascan.model.Severity

/**
 * Why a rule is allowed to make its claim.
 *
 * Every rule in this tool points at a concrete artifact in PaperMC/Folia's own source so a
 * finding can be audited instead of trusted. [source] is the patch file inside the Folia
 * repository; [detail] is the class and member the guard or throw was found in.
 */
data class Provenance(val source: String, val detail: String) {
    fun render(): String = "$source :: $detail"
}

sealed interface Rule {
    val id: String
    val severity: Severity
    val title: String

    /** What Folia actually does when this code runs. Stated as fact, no speculation. */
    val why: String

    /** The concrete replacement. */
    val fix: String
    val provenance: Provenance
}

/**
 * Matches a method invocation by the declared owner type plus the method name.
 *
 * [owners] holds exact JVM internal names (`org/bukkit/Bukkit`); [ownerPrefixes] matches a
 * whole type family (`org/bukkit/entity/`) which is how the entity API is covered without
 * enumerating ~170 interfaces. [methods] holds simple method names; an empty set matches
 * every method on those owners.
 *
 * When [contextual] is true the call is legal on Folia as long as it happens on the thread
 * that owns the relevant region, so it is only reported inside a detected off-region
 * context. When false, Folia throws no matter which thread calls it.
 */
data class CallRule(
    override val id: String,
    override val severity: Severity,
    override val title: String,
    override val why: String,
    override val fix: String,
    override val provenance: Provenance,
    val owners: Set<String> = emptySet(),
    val ownerPrefixes: Set<String> = emptySet(),
    val excludeOwners: Set<String> = emptySet(),
    val methods: Set<String> = emptySet(),
    /** Methods that must never match, used to keep the correct Folia API out of the report. */
    val excludeMethods: Set<String> = emptySet(),
    val contextual: Boolean = false,
) : Rule {
    fun matches(owner: String, method: String): Boolean {
        if (owner in excludeOwners || method in excludeMethods) return false
        val ownerHit = owner in owners || ownerPrefixes.any { owner.startsWith(it) }
        return ownerHit && (methods.isEmpty() || method in methods)
    }
}

/** Matches any reference to a type whose internal name starts with one of [prefixes]. */
data class PackageRule(
    override val id: String,
    override val severity: Severity,
    override val title: String,
    override val why: String,
    override val fix: String,
    override val provenance: Provenance,
    val prefixes: Set<String>,
    /** Internal-name prefixes that are explicitly allowed despite matching. */
    val allow: Set<String> = emptySet(),
) : Rule {
    fun matches(internalName: String): Boolean =
        prefixes.any { internalName.startsWith(it) } && allow.none { internalName.startsWith(it) }
}

/** Matches a class by its direct supertype, e.g. anything extending BukkitRunnable. */
data class SupertypeRule(
    override val id: String,
    override val severity: Severity,
    override val title: String,
    override val why: String,
    override val fix: String,
    override val provenance: Provenance,
    val supertypes: Set<String>,
) : Rule

/** Checked against the plugin descriptor rather than bytecode. */
data class ManifestRule(
    override val id: String,
    override val severity: Severity,
    override val title: String,
    override val why: String,
    override val fix: String,
    override val provenance: Provenance,
) : Rule

/**
 * Checked against what the jar contains rather than what its code does - used for facts about
 * the artifact's origin, such as having been rewritten by a patcher.
 */
data class ArtifactRule(
    override val id: String,
    override val severity: Severity,
    override val title: String,
    override val why: String,
    override val fix: String,
    override val provenance: Provenance,
) : Rule
