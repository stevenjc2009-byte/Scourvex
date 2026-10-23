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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.scourvex.app.core.formatBytes
import com.scourvex.app.storage.UnusedApp
import com.scourvex.app.storage.UnusedApps
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.theme.Neon

/** Storage → Unused: apps not opened for 30+ days, biggest first. */
fun LazyListScope.unusedApps(apps: List<UnusedApp>?, vm: MainViewModel, ctx: Context) {
    if (apps == null) {
        item { Banner("Grant usage access to find apps you no longer use", Neon.Amber, "Grant") { Perms.openUsage(ctx) } }
        return
    }
    item {
        Text(if (apps.isEmpty()) "Every app was opened in the last ${UnusedApps.DAYS} days."
            else "${apps.size} app${if (apps.size == 1) "" else "s"} not opened for ${UnusedApps.DAYS}+ days · ${formatBytes(apps.sumOf { it.size.total })}. " +
                "Archive removes the app but keeps its data; tap it in the app drawer to get it back.",
            color = if (apps.isEmpty()) Neon.Lime else Neon.Dim, style = MaterialTheme.typography.bodyMedium)
        Gap()
    }
    items(apps, key = { "unused:" + it.pkg }) { a ->
        GlowCard(glow = Neon.Violet) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(a.label, color = Neon.Text, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(if (a.lastUsed > 0) "Last opened ${DateUtils.getRelativeTimeSpanString(a.lastUsed)}" else "No record of it being opened",
                            color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
                    }
                    Text(formatBytes(a.size.total), color = Neon.Violet, style = MaterialTheme.typography.labelLarge)
                }
                Gap(8)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (UnusedApps.canArchive) GhostButton("Archive · ${formatBytes(a.size.app + a.size.cache)}", color = Neon.Cyan) { vm.archiveApp(a.pkg) }
                    GhostButton("Uninstall", color = Neon.Red) { Perms.uninstall(ctx, a.pkg) }
                }
            }
        }
        Gap()
    }
}
