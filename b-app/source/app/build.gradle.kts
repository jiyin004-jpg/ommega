plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// 版本号唯一来源 = 仓库根的 VERSION（A 模块 / B 模块 / b-app / 服务端 四端一致）。
val ommegaVersion = file("$rootDir/../../VERSION").readText().trim()

// versionCode 由版本号推出：major*1000000 + minor*1000 + patch（1.5.0 -> 1500000），
// 与 A/B 模块的 build.py 用同一套算法。
val ommegaVersionCode = ommegaVersion.split(".").let { (major, minor, patch) ->
    major.toInt() * 1_000_000 + minor.toInt() * 1_000 + patch.toInt()
}

android {
    namespace = "org.ommega.deviceb"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.ommega.deviceb"
        minSdk = 26
        targetSdk = 36
        versionCode = ommegaVersionCode
        versionName = ommegaVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            val ks = file("../debug.keystore")
            if (ks.exists()) {
                storeFile = ks
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfigs.findByName("release")?.let {
                if (it.storeFile?.exists() == true) {
                    signingConfig = it
                }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
