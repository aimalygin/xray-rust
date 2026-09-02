plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.xrayrust.deviceprobe"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.xrayrust.deviceprobe"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.5.0-device-gate"
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
