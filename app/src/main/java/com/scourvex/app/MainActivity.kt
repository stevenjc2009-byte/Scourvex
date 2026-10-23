package com.scourvex.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.ScourvexAppUi
import com.scourvex.app.ui.theme.ScourvexTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        Shell.init()
        // The running-scan notification needs this on Android 13+; scans still work if it is refused.
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7)
        setContent { ScourvexTheme { ScourvexAppUi() } }
    }
}
