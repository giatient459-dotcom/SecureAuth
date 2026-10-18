plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    compileOnly("net.md-5:bungeecord-api:1.21-R0.3")
    implementation("org.bstats:bstats-bungeecord:3.2.1")
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

tasks.processResources {
    filesMatching("bungee.yml") {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    archiveFileName.set("SecureAuthBungee-${project.version}.jar")
    archiveClassifier.set("")
    relocate("org.bstats", "dev.tienday.secureauth.libs.bstats")
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
