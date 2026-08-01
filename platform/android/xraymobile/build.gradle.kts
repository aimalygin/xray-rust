plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val xrayFfiAndroidDir = providers.environmentVariable("XRAY_FFI_ANDROID_DIR")
    .getOrElse("../../../target/mobile/android")

android {
    namespace = "org.xrayrust.mobile"
    compileSdk = 35
    ndkVersion = "26.3.11579264"

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
            jniLibs.srcDir(file("$xrayFfiAndroidDir/jniLibs"))
        }
    }

    packaging {
        jniLibs {
            keepDebugSymbols += "**/libxray_ffi.so"
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

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
