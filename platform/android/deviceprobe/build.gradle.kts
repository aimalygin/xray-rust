plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.xrayrust.deviceprobe"
    compileSdk = 35
    ndkVersion = "26.3.11579264"
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt") } }

    defaultConfig {
        applicationId = "org.xrayrust.deviceprobe"
        minSdk = 24
        targetSdk = 35
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
    testImplementation("junit:junit:4.13.2")
}
