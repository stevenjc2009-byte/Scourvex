package com.scourvex.app

import android.app.Application

class ScourvexApp : Application() {
    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    companion object {
        lateinit var instance: ScourvexApp
            private set
    }
}
