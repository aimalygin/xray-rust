plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.xrayrust.devicehost"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.xrayrust.devicehost"
        minSdk = 24
        targetSdk = 35
        manifestPlaceholders["deviceProbePackage"] = "org.xrayrust.deviceprobe"
        versionCode = 1
        versionName = "0.5.0-device-gate"
    }

    buildTypes {
        getByName("debug") {
            // Isolate physical campaigns from an existing device profile store.
            providers.gradleProperty("deviceGateApplicationIdSuffix").orNull?.let { suffix ->
                require(Regex("\\.[a-z][a-z0-9_]*").matches(suffix)) {
                    "deviceGateApplicationIdSuffix must be one lowercase package component"
                }
                applicationIdSuffix = suffix
                manifestPlaceholders["deviceProbePackage"] = "org.xrayrust.deviceprobe$suffix"
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
    }
}

dependencies {
    implementation(project(":xraymobile"))
    testImplementation("junit:junit:4.13.2")
}
