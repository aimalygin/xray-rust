buildscript {
    dependencies {
        // AGP applies built-in Kotlin; pin its compiler without applying the legacy plugin.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21")
    }
}

plugins {
    id("com.android.application") version "9.5.0" apply false
    id("com.android.library") version "9.5.0" apply false
}
