plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val discoveredNdkVersion = providers.environmentVariable("ANDROID_NDK_HOME")
    .orElse(providers.environmentVariable("ANDROID_NDK_ROOT"))
    .map { it.substringAfterLast("/") }
    .orElse("26.3.11579264")

android {
    namespace = "org.xrayrust.mobile"
    compileSdk = 35
    ndkVersion = discoveredNdkVersion.get()

    defaultConfig {
        minSdk = 24

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs(
                "src/main/jniLibs",
                "../../../target/mobile/android/jniLibs"
            )
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
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
