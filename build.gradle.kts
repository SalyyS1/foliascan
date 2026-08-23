plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.4.10"
    id("com.gradleup.shadow") version "9.6.1"
    application
}

group = "com.salyvn.foliascan"
version = "0.1.7"

repositories {
    mavenCentral()
}

dependencies {
    // Bytecode reading. We only ever READ class files - no writing, no agents.
    implementation("org.ow2.asm:asm:9.10.1")
    // plugin.yml / paper-plugin.yml parsing. Loaded with SafeConstructor only,
    // because the YAML comes from an untrusted jar.
    implementation("org.yaml:snakeyaml:2.6")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("com.github.ajalt.clikt:clikt:5.1.0")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "com.salyvn.foliascan.MainKt"
    applicationName = "foliascan"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}

// Single source of truth for the version: the build writes it into a resource that the CLI
// reads back, so the number cannot drift between build.gradle.kts and the Kotlin source.
tasks.processResources {
    inputs.property("version", project.version.toString())
    filesMatching("foliascan-version.properties") {
        expand("version" to project.version.toString())
    }
}

// The plain jar gets a classifier so it cannot overwrite the shaded CLI artifact, which is
// what users download and what the release checksums cover.
tasks.jar {
    archiveClassifier = "thin"
}

tasks.shadowJar {
    archiveClassifier = ""
    archiveBaseName = "foliascan"
    manifest {
        attributes["Main-Class"] = "com.salyvn.foliascan.MainKt"
        attributes["Implementation-Version"] = project.version.toString()
    }
    // Reproducible-ish output so release checksums are stable.
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
