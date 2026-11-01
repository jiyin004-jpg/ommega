plugins {
    id("com.android.application")
}

android {
    namespace = "aprobes"
    compileSdk = 37

    defaultConfig {
        applicationId = "aprobes.agap"
        minSdk = 31
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
    }


    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
    }
}
