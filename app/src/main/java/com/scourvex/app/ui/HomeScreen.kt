package com.scourvex.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.clean.Cleaner
import com.scourvex.app.core.formatBytes
import com.scourvex.app.security.Sigs
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.NeonButton
import com.scourvex.app.ui.components.ScanOrb
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.components.Stat
import com.scourvex.app.ui.theme.Neon
import com.scourvex.app.update.Updater

@Composable
fun HomeScreen(vm: MainViewModel, access: Access, go: (Tab) -> Unit) {
    val ctx = LocalContext.current
    val total = remember(access) { Cleaner.totalBytes() }
    val free = remember(access) { Cleaner.freeBytes() }
    val used = (total - free).coerceAtLeast(0)
    val junk by vm.junk.collectAsStateWithLifecycle()
    val sec by vm.sec.collectAsStateWithLifecycle()
    val upd by vm.updater.collectAsStateWithLifecycle()
    val sigs by Sigs.info.collectAsStateWithLifecycle()

    Page {
        item {
            Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                ScanOrb(
                    title = if (total > 0) "${used * 100 / total}%" else "—",
                    subtitle = "${formatBytes(used)} of ${formatBytes(total)} used",
                    active = vm.busy, progress = if (total > 0) used.toFloat() / total else null,
                )
            }
        }
        item {
            NeonButton("Scan for junk", Modifier.fillMaxWidth()) { vm.scanJunk(); go(Tab.CLEAN) }
            Spacer(Modifier.height(12.dp))
        }
        (upd as? Updater.State.Available)?.let { a ->
            item { Banner("Scourvex ${a.r.version} is available", Neon.Lime, "Install") { vm.installUpdate(a.r) }; Gap() }
        }
        item { AccessCards(access, ctx) }
        item { SectionTitle("At a glance") }
        item {
            GlowCard(glow = Neon.Violet) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    val j = junk
                    Stat(
                        when (j) {
                            is MainViewModel.Junk.Found -> formatBytes(j.result.items.sumOf { it.size })
                            is MainViewModel.Junk.Cleaned -> formatBytes(j.report.freed) + " freed"
                            else -> "—"
                        }, "junk", Neon.Cyan,
                    )
                    val s = sec
                    Stat(if (s is MainViewModel.Sec.Done) "${s.report.threats.size}" else "—", "threats",
                        if (s is MainViewModel.Sec.Done && s.report.threats.isNotEmpty()) Neon.Red else Neon.Lime)
                    Stat(sigs?.let { "%,d".format(it.md5 + it.body) } ?: "none", "signatures", Neon.Magenta)
                }
            }
        }
        item { SectionTitle("Tools") }
        item {
            ToolCard("Security scan", "ClamAV + stalkerware + permission audit, every app and file", Neon.Red) { go(Tab.SECURITY) }
            ToolCard("Storage killers", "Biggest files, folders, apps and duplicates", Neon.Amber) { go(Tab.STORAGE) }
            ToolCard("Battery drainers", "Apps using the most power since the last charge", Neon.Lime) { go(Tab.BATTERY) }
        }
    }
}

@Composable
private fun AccessCards(a: Access, ctx: android.content.Context) {
    Column {
        when (a.shizuku) {
            Shell.State.READY -> Banner("Shizuku connected — deep clean of Android/data, all app caches, battery stats", Neon.Lime)
            Shell.State.NO_PERMISSION -> Banner("Shizuku is running — allow Scourvex to use it", Neon.Amber, "Allow") { Shell.requestPermission() }
            Shell.State.NOT_RUNNING -> Banner("Shizuku not running — basic mode. Start it for deep cleaning (needed again after every reboot).", Neon.Amber, "Open") { Perms.openShizuku(ctx) }
        }
        Gap()
        if (!a.allFiles) { Banner("All-files access is needed to scan storage", Neon.Red, "Grant") { Perms.openAllFiles(ctx) }; Gap() }
        if (!a.usage) { Banner("Usage access lets Scourvex size app caches and rank battery use", Neon.Amber, "Grant") { Perms.openUsage(ctx) }; Gap() }
    }
}

@Composable
private fun ToolCard(title: String, detail: String, color: Color, onClick: () -> Unit) {
    GlowCard(glow = color, onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(12.dp).padding(0.dp)) { androidx.compose.foundation.Canvas(Modifier.size(12.dp)) { drawCircle(color) } }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = Neon.Text)
                Text(detail, style = MaterialTheme.typography.bodyMedium, color = Neon.Dim)
            }
            Icon(Icons.Rounded.ChevronRight, null, tint = color)
        }
    }
    Gap()
}

@Composable
fun Gap(h: Int = 10) = Spacer(Modifier.height(h.dp))
