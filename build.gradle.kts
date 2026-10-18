import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension

plugins {
    id("com.gradleup.shadow") version "8.3.6" apply false
    id("org.owasp.dependencycheck") version "12.1.0"
}

group = "dev.tienday"
version = "1.0.3"

allprojects {
    group = rootProject.group
    version = rootProject.version
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "com.gradleup.shadow")

    extensions.configure<JavaPluginExtension> {
        toolchain.languageVersion.set(JavaLanguageVersion.of(if (name == "paper") 21 else 17))
        withSourcesJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
    }

    tasks.withType<ProcessResources>().configureEach {
        filteringCharset = "UTF-8"
    }
}

dependencies {
    // The aggregate task inspects dependency graphs across all subprojects.
}

configure<DependencyCheckExtension> {
    failBuildOnCVSS = 7.0F
    formats = listOf("HTML", "JSON")
    outputDirectory = layout.buildDirectory.dir("reports/dependency-check").get().asFile
    nvd.apiKey = System.getenv("NVD_API_KEY") ?: ""
}
