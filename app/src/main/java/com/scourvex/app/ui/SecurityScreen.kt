package com.scourvex.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.core.formatBytes
import com.scourvex.app.security.AppRisk
import com.scourvex.app.security.Sigs
import com.scourvex.app.security.Threat
import com.scourvex.app.ui.MainViewModel.Sec
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.NeonButton
import com.scourvex.app.ui.components.ScanBar
import com.scourvex.app.ui.components.ScanOrb
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.components.Stat
import com.scourvex.app.ui.theme.Neon

@Composable
fun SecurityScreen(vm: MainViewModel, access: Access) {
    val ctx = LocalContext.current
    val state by vm.sec.collectAsStateWithLifecycle()
    val info by Sigs.info.collectAsStateWithLifecycle()
    val sigMsg by vm.sigUpdate.collectAsStateWithLifecycle()
    var deleting by remember { mutableStateOf<Threat?>(null) }

    Page {
        item {
            Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                when (val s = state) {
                    Sec.Idle -> ScanOrb("Shield", "Real signature scan of every app and file", false, null, accent = Neon.Magenta)
                    is Sec.Scanning -> ScanOrb(
                        if (s.p.total > 0) "${s.p.done * 100 / s.p.total}%" else "…",
                        "${s.p.phase}: ${s.p.current.takeLast(48)}", true,
                        if (s.p.total > 0) s.p.done.toFloat() / s.p.total else null, accent = Neon.Magenta,
                    )
                    is Sec.Done -> if (s.report.threats.isEmpty()) ScanOrb("Clean", "No known malware found", false, 1f, accent = Neon.Lime)
                    else ScanOrb("${s.report.threats.size}", "threats found", false, 1f, accent = Neon.Red)
                    is Sec.Failed -> ScanOrb("Error", s.why, false, null, accent = Neon.Red)
                }
            }
        }
        item {
            (state as? Sec.Scanning)?.p?.let { p ->
                ScanBar(if (p.total > 0) "${p.phase} · ${p.done} of ${p.total}" else "${p.phase} · ${p.current.takeLast(48)}",
                    if (p.total > 0) p.done.toFloat() / p.total else null, accent = Neon.Magenta)
                Gap(10)
            }
            if (state is Sec.Scanning) GhostButton("Stop", Modifier.fillMaxWidth(), Neon.Red) { vm.cancel() }
            else NeonButton("Full scan", Modifier.fillMaxWidth(), enabled = info != null || sigMsg == null) { vm.scanThreats() }
            Gap(14)
        }
        if (!access.allFiles) item { Banner("Grant all-files access so files can be scanned", Neon.Red, "Grant") { Perms.openAllFiles(ctx) }; Gap() }
        item { SignatureCard(info, sigMsg) { vm.updateSignatures() } }

        val s = state as? Sec.Done ?: return@Page
        val r = s.report
        item {
            Gap()
            GlowCard(glow = Neon.Violet) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Stat("${r.appsScanned}", "apps", Neon.Cyan)
                    Stat("%,d".format(r.filesSeen), "files seen", Neon.Cyan)
                    Stat("%,d".format(r.filesInspected), "inspected", Neon.Magenta)
                    Stat(formatBytes(r.bytesRead), "read", Neon.Violet)
                }
            }
            if (!r.privileged) { Gap(); Banner("Android/data and obb were not scanned — start Shizuku for full coverage", Neon.Amber) }
        }
        if (r.threats.isNotEmpty()) {
            item { SectionTitle("Threats") }
            items(r.threats, key = { it.target + it.detection }) { t ->
                ThreatCard(t,
                    remove = if (!t.removable) null else { { if (t.isApp) Perms.uninstall(ctx, t.target) else deleting = t } },
                    ignore = { vm.ignoreThreat(t) })
            }
        }
        if (r.risks.isNotEmpty()) {
            item { SectionTitle("Risky apps — not malware, worth a look") }
            items(r.risks, key = { "risk:" + it.pkg }) { a -> RiskCard(a, { Perms.openAppInfo(ctx, a.pkg) }, { Perms.uninstall(ctx, a.pkg) }) }
        }
        deviceSection(r.device, ctx)
        sensorSection(r.sensors, ctx)
    }

    deleting?.let { t ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            containerColor = Neon.Surface2,
            title = { Text("Delete infected file?") },
            text = { Text("${t.target}\n\n${t.detection}") },
            confirmButton = { TextButton({ deleting = null; vm.deleteFile(t.target) }) { Text("DELETE", color = Neon.Red) } },
            dismissButton = { TextButton({ deleting = null }) { Text("CANCEL", color = Neon.Dim) } },
        )
    }
}

@Composable
private fun SignatureCard(info: Sigs.Info?, msg: String?, update: () -> Unit) {
    GlowCard(glow = Neon.Cyan) {
        Column {
            Text("Virus database", style = MaterialTheme.typography.titleMedium, color = Neon.Text)
            if (info == null) Text("Not downloaded yet", color = Neon.Amber, style = MaterialTheme.typography.bodyMedium)
            else {
                Text("ClamAV daily ${info.clamDaily} · main ${info.clamMain} · built ${info.built}", color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
                Text("%,d hashes · %,d body sigs · %,d stalkerware · %,d spyware IOCs".format(info.md5, info.body, info.stalkerware, info.spyware),
                    color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
            }
            if (msg != null && msg.contains("failed")) Text(msg, color = Neon.Red, style = MaterialTheme.typography.bodyMedium)
            else if (msg != null) { Gap(6); ScanBar(msg, Regex("(\\d+)%").find(msg)?.groupValues?.get(1)?.toFloat()?.div(100f)) }
            Gap(8)
            GhostButton("Update signatures", onClick = update)
        }
    }
}

@Composable
private fun ThreatCard(t: Threat, remove: (() -> Unit)?, ignore: () -> Unit) {
    GlowCard(glow = if (t.pua) Neon.Amber else Neon.Red) {
        Column {
            Text(t.label, style = MaterialTheme.typography.titleMedium, color = Neon.Text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(t.detection, color = if (t.pua) Neon.Amber else Neon.Red, style = MaterialTheme.typography.bodyMedium)
            Text("${t.source}${if (t.size > 0) " · " + formatBytes(t.size) else ""}", color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
            Text(t.target, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 2, overflow = TextOverflow.StartEllipsis)
            Gap(8)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (remove != null) GhostButton(if (t.isApp) "Uninstall" else "Delete", color = Neon.Red, onClick = remove)
                GhostButton("Ignore", color = Neon.Dim, onClick = ignore)
            }
        }
    }
    Gap()
}

@Composable
private fun RiskCard(a: AppRisk, info: () -> Unit, uninstall: () -> Unit) {
    GlowCard(glow = Neon.Amber) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(a.label, style = MaterialTheme.typography.titleMedium, color = Neon.Text)
                    Text(a.pkg + (a.installer?.let { " · from $it" } ?: ""), color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
                }
                Text("risk ${a.score}", color = Neon.Amber, style = MaterialTheme.typography.labelLarge)
            }
            a.reasons.forEach { Text("• $it", color = Neon.Text, style = MaterialTheme.typography.bodyMedium) }
            Gap(8)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                GhostButton("App info", onClick = info)
                GhostButton("Uninstall", color = Neon.Red, onClick = uninstall)
            }
        }
    }
    Gap()
}
