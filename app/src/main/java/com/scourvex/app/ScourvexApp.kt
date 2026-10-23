package com.scourvex.app

import android.app.Application
import com.scourvex.app.core.CrashGuard

class ScourvexApp : Application() {
    override fun onCreate() {
        super.onCreate()
        instance = this
        CrashGuard.install(this)
    }

    companion object {
        lateinit var instance: ScourvexApp
            private set
    }
}
