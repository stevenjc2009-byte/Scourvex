package com.scourvex.app.ui

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.theme.Neon
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * Usage access for an app installed from a downloaded APK is a "restricted setting" on Android 13+:
 * the Grant switch is greyed out until the user allows it in App info → ⋮ → Allow restricted settings.
 * With Shizuku running, Scourvex grants it itself through `appops` (the shell user may set app-ops).
 */
object UsageAccess {

    /** True while the how-to dialog is open. */
    val help = MutableStateFlow(false)

    private var tried = false

    /** Grants usage access through Shizuku. True when it is granted afterwards. */
    suspend fun grantWithShizuku(ctx: Context): Boolean {
        val r = Shell.exec("appops set ${ctx.packageName} GET_USAGE_STATS allow") ?: return false
        return r.first == 0 && Perms.usage(ctx)
    }

    /** Once per launch: with Shizuku ready and usage access missing, grant it without asking the user to dig. */
    suspend fun autoGrant(ctx: Context): Boolean {
        if (tried || Perms.usage(ctx) || !Shell.ready) return false
        tried = true
        return grantWithShizuku(ctx)
    }
}

@Composable
fun UsageHelpDialog(onGranted: () -> Unit) {
    val open by UsageAccess.help.collectAsStateWithLifecycle()
    if (!open) return
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val shizuku by Shell.state.collectAsStateWithLifecycle()
    val close = { UsageAccess.help.value = false }
    AlertDialog(
        onDismissRequest = close,
        containerColor = Neon.Surface,
        title = { Text("Usage access", color = Neon.Text) },
        text = {
            Column {
                Text("Android blocks this switch for apps installed from a downloaded file (\"restricted setting\"). " +
                    "It is safe to allow: Scourvex only reads app sizes and battery use, and nothing leaves the phone.", color = Neon.Dim)
                Text("\nEasiest: start Shizuku and tap Grant with Shizuku.\n\nWithout Shizuku:\n" +
                    "1. Tap Open App info.\n2. Tap ⋮ (top right) → Allow restricted settings, confirm.\n" +
                    "3. Come back and tap Open usage access, then turn Scourvex on.\n\n" +
                    "If ⋮ has no such option, first tap Open usage access and try the switch once — Android only shows the option after that.",
                    color = Neon.Dim)
            }
        },
        confirmButton = {
            if (shizuku == Shell.State.READY) TextButton({
                scope.launch {
                    if (UsageAccess.grantWithShizuku(ctx)) { close(); onGranted() }
                    else Perms.openUsageSettings(ctx)
                }
            }) { Text("Grant with Shizuku", color = Neon.Lime) }
            else TextButton({ close(); Perms.openUsageSettings(ctx) }) { Text("Open usage access", color = Neon.Lime) }
        },
        dismissButton = {
            TextButton({
                close()
                Perms.openAppInfo(ctx, ctx.packageName)
            }) { Text("Open App info", color = Neon.Cyan) }
        },
    )
}
