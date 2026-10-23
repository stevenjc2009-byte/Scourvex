package com.scourvex.app.ui

import android.content.Context
import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.unit.dp
import com.scourvex.app.security.DeviceFinding
import com.scourvex.app.security.SensorUse
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.theme.Neon

/** "Phone settings": settings that weaken security, and user-added CA certificates. */
fun LazyListScope.deviceSection(findings: List<DeviceFinding>, ctx: Context) {
    item { SectionTitle("Phone settings") }
    if (findings.isEmpty()) {
        item { Text("Nothing risky found in your settings.", color = Neon.Lime); Gap() }
        return
    }
    items(findings.sortedBy { it.level }, key = { "dev:" + it.title }) { f ->
        val color = when (f.level) {
            DeviceFinding.Level.HIGH -> Neon.Red
            DeviceFinding.Level.MEDIUM -> Neon.Amber
            DeviceFinding.Level.INFO -> Neon.Cyan
        }
        GlowCard(glow = color) {
            Column {
                Text(f.title, style = MaterialTheme.typography.titleMedium, color = Neon.Text)
                Text(f.detail, color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
                f.action?.let { a -> Gap(8); GhostButton("Open settings", color = color) { Perms.openAction(ctx, a, f.pkg) } }
            }
        }
        Gap()
    }
}

/** "Camera, mic & location use": recent use per app; background use first. Needs Shizuku. */
fun LazyListScope.sensorSection(apps: List<SensorUse.AppUse>?, ctx: Context) {
    item { SectionTitle("Camera, mic & location use") }
    if (apps == null) {
        item { Banner("Start Shizuku to see which apps used the camera, mic and location", Neon.Amber); Gap() }
        return
    }
    if (apps.isEmpty()) {
        item { Text("No app has used the camera, mic or location recently.", color = Neon.Lime); Gap() }
        return
    }
    items(apps, key = { "sensor:" + it.pkg }) { a ->
        val bg = a.background.isNotEmpty()
        GlowCard(glow = if (bg) Neon.Red else Neon.Violet) {
            Column {
                Text(a.label, style = MaterialTheme.typography.titleMedium, color = Neon.Text)
                if (bg) Text("Used ${a.background.joinToString { it.label.lowercase() }} while in the background",
                    color = Neon.Red, style = MaterialTheme.typography.bodyMedium)
                for ((kind, t) in a.last.entries.sortedBy { it.key }) {
                    Text("${kind.label}: ${DateUtils.getRelativeTimeSpanString(t)}", color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
                }
                Gap(8)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    GhostButton("Permissions") { Perms.openAppInfo(ctx, a.pkg) }
                    GhostButton("Uninstall", color = Neon.Red) { Perms.uninstall(ctx, a.pkg) }
                }
            }
        }
        Gap()
    }
}
