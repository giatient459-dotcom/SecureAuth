plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    compileOnly("io.papermc.paper:paper-api:1.21.4-R0.1-SNAPSHOT")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.xerial:sqlite-jdbc:3.53.4.0")
    implementation("org.bstats:bstats-bukkit:3.2.1")
}

tasks.processResources {
    filesMatching("plugin.yml") {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    archiveFileName.set("SecureAuth-${project.version}.jar")
    archiveClassifier.set("")
    relocate("org.bouncycastle", "dev.tienday.secureauth.libs.bouncycastle")
    relocate("org.bstats", "dev.tienday.secureauth.libs.bstats")
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
