package com.scourvex.app.ui

import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.BuildConfig
import com.scourvex.app.core.Files
import com.scourvex.app.core.Prefs
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.theme.Neon
import com.scourvex.app.update.Updater

@Composable
fun SettingsScreen(vm: MainViewModel, access: Access) {
    val ctx = LocalContext.current
    val skip by Prefs.skip.collectAsStateWithLifecycle()
    val upd by vm.updater.collectAsStateWithLifecycle()
    var manual by remember { mutableStateOf("") }
    var key by remember { mutableStateOf(Prefs.mbzKey) }
    var auto by remember { mutableStateOf(Prefs.autoUpdateCheck) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        uri?.let { treeToPath(it) }?.let { Prefs.addSkip(it) }
    }
    val field = OutlinedTextFieldDefaults.colors(focusedBorderColor = Neon.Cyan, unfocusedBorderColor = Neon.Surface2,
        focusedTextColor = Neon.Text, unfocusedTextColor = Neon.Text, cursorColor = Neon.Cyan)

    Page {
        item { SectionTitle("Skip these folders") }
        item {
            Text("Scans and cleaning never touch these folders or anything inside them.", color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
            Gap()
        }
        if (skip.isEmpty()) item { Text("Nothing skipped — every folder is scanned.", color = Neon.Lime); Gap() }
        items(skip, key = { it }) { p ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(p, Modifier.weight(1f), color = Neon.Text, style = MaterialTheme.typography.bodyMedium)
                IconButton({ Prefs.removeSkip(p) }) { Icon(Icons.Rounded.Close, "Remove", tint = Neon.Red) }
            }
        }
        item {
            Gap()
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                GhostButton("Pick folder") { picker.launch(null) }
            }
            Gap()
            OutlinedTextField(manual, { manual = it }, Modifier.fillMaxWidth(), singleLine = true, colors = field,
                label = { Text("Or type a path, e.g. ${Files.primary}/DCIM/Camera") })
            Gap(6)
            GhostButton("Add path") {
                val p = manual.trim().trimEnd('/')
                if (p.startsWith("/")) { Prefs.addSkip(p); manual = "" } else vm.toast.value = "Paths start with /"
            }
        }

        item { SectionTitle("MalwareBazaar live lookups") }
        item {
            Text("Optional. With a free abuse.ch Auth-Key, suspicious files are also checked online against MalwareBazaar. Only file hashes are sent, never the files.",
                color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
            Gap()
            OutlinedTextField(key, { key = it }, Modifier.fillMaxWidth(), singleLine = true, colors = field,
                visualTransformation = PasswordVisualTransformation(), label = { Text("abuse.ch Auth-Key") })
            Gap(6)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                GhostButton("Save key") { Prefs.mbzKey = key.trim(); vm.toast.value = if (key.isBlank()) "Key removed" else "Key saved" }
                GhostButton("Get a key", color = Neon.Dim) { Perms.openUrl(ctx, "https://auth.abuse.ch/") }
            }
        }

        item { SectionTitle("Updates") }
        item {
            GlowCard(glow = Neon.Lime) {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Scourvex ${BuildConfig.VERSION_NAME}", color = Neon.Text, style = MaterialTheme.typography.titleMedium)
                            Text(updateText(upd), color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    Gap(6)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Check automatically", Modifier.weight(1f), color = Neon.Text)
                        Switch(auto, { auto = it; Prefs.autoUpdateCheck = it },
                            colors = SwitchDefaults.colors(checkedTrackColor = Neon.Lime, checkedThumbColor = Neon.Bg))
                    }
                    Gap(6)
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        GhostButton("Check now") { vm.checkUpdate() }
                        (upd as? Updater.State.Available)?.let { a -> GhostButton("Install ${a.r.version}", color = Neon.Lime) { vm.installUpdate(a.r) } }
                    }
                }
            }
        }

        item { SectionTitle("Shizuku") }
        item {
            Text(when (access.shizuku) {
                Shell.State.READY -> "Connected. Scourvex can clean Android/data, every app cache and read real battery stats."
                Shell.State.NO_PERMISSION -> "Running, but Scourvex has not been allowed yet."
                Shell.State.NOT_RUNNING -> "Not running. Install Shizuku from the Play Store, turn on Wireless debugging in Developer options, " +
                    "then press Start in Shizuku. It must be started again after every reboot."
            }, color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
            Gap(6)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                GhostButton("Open Shizuku") { Perms.openShizuku(ctx) }
                if (access.shizuku == Shell.State.NO_PERMISSION) GhostButton("Allow", color = Neon.Lime) { Shell.requestPermission() }
            }
        }

        item { SectionTitle("About") }
        item {
            Text(
                "Virus signatures: ClamAV (Cisco Talos), GPL-2.0, rebuilt daily into the Scourvex signature pack.\n" +
                    "Stalkerware indicators: Echap stalkerware-indicators, CC BY 4.0.\n" +
                    "Hash intelligence: abuse.ch MalwareBazaar.\n" +
                    "Junk locations informed by SD Maid SE's open filter research.\n" +
                    "Source: github.com/${BuildConfig.GITHUB_REPO}",
                color = Neon.Dim, style = MaterialTheme.typography.bodyMedium,
            )
            Gap(6)
            GhostButton("Open on GitHub", color = Neon.Dim) { Perms.openUrl(ctx, "https://github.com/${BuildConfig.GITHUB_REPO}") }
        }
    }
}

private fun updateText(s: Updater.State) = when (s) {
    Updater.State.Idle -> "Not checked yet"
    Updater.State.Checking -> "Checking…"
    Updater.State.UpToDate -> "Up to date"
    is Updater.State.Available -> "${s.r.version} available"
    is Updater.State.Downloading -> if (s.total > 0) "Downloading ${s.done * 100 / s.total}%" else "Downloading…"
    Updater.State.Installing -> "Installing…"
    is Updater.State.Failed -> "Update failed: ${s.why}"
}

/** Converts a SAF tree URI ("primary:DCIM/Camera", "1A2B-3C4D:Music") to a filesystem path. */
internal fun treeToPath(uri: Uri): String? {
    val id = runCatching { DocumentsContract.getTreeDocumentId(uri) }.getOrNull() ?: return null
    val vol = id.substringBefore(':')
    val rel = id.substringAfter(':', "").trimEnd('/')
    val base = if (vol.equals("primary", true)) Files.primary else "/storage/$vol"
    return if (rel.isEmpty()) base else "$base/$rel"
}
