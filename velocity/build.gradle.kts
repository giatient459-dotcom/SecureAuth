plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    compileOnly("com.velocitypowered:velocity-api:3.5.1")
    annotationProcessor("com.velocitypowered:velocity-api:3.5.1")
    implementation("com.google.code.gson:gson:2.14.0")
    implementation("org.bstats:bstats-velocity:3.2.1")
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

tasks.processResources {
    filesMatching("velocity-plugin.json") {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    archiveFileName.set("SecureAuthVelocity-${project.version}.jar")
    archiveClassifier.set("")
    relocate("org.bstats", "dev.tienday.secureauth.libs.bstats")
    relocate("com.google.gson", "dev.tienday.secureauth.libs.gson")
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
