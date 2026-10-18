pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://oss.sonatype.org/content/groups/public/")
        maven("https://repo.md-5.net/content/groups/public/")
        maven("https://repo.opencollab.dev/main/")
    }
}

rootProject.name = "SecureAuth"
include("paper", "velocity", "bungee")
