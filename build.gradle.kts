plugins {
    java
    id("com.gradleup.shadow") version "8.3.5"
}

group = "dev.tienday"
version = "1.0.4"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly("io.papermc.paper:paper-api:1.21.4-R0.1-SNAPSHOT")

    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.xerial:sqlite-jdbc:3.45.3.0")
}

tasks.processResources {
    val props = mapOf("version" to version)
    inputs.properties(props)
    filteringCharset = "UTF-8"
    filesMatching("plugin.yml") {
        expand(props)
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    archiveFileName.set("\( {project.name}- \){project.version}.jar")

    relocate("org.bouncycastle", "dev.tienday.secureauth.libs.bouncycastle")
    // org.sqlite KHÔNG relocate

    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    exclude("META-INF/MANIFEST.MF", "META-INF/LICENSE*", "META-INF/NOTICE*")
    exclude("module-info.class")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.jar {
    enabled = false
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.release.set(21)
}
