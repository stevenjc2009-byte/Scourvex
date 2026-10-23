package com.scourvex.app

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
        setContent { ScourvexTheme { ScourvexAppUi() } }
    }
}
