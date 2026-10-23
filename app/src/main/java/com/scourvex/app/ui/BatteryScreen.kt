package com.scourvex.app.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.battery.PowerUse
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.NeonBar
import com.scourvex.app.ui.components.NeonButton
import com.scourvex.app.ui.components.ScanBar
import com.scourvex.app.ui.components.ScanOrb
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.theme.Neon

@Composable
fun BatteryScreen(vm: MainViewModel, access: Access) {
    val ctx = LocalContext.current
    val report by vm.battery.collectAsStateWithLifecycle()
    val loading by vm.batteryLoading.collectAsStateWithLifecycle()
    LaunchedEffect(access.shizuku, access.usage) { vm.scanBattery() }

    Page {
        val r = report
        item {
            Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                ScanOrb(r?.apps?.size?.toString() ?: "…", if (r == null) "Reading battery stats" else "apps drawing power", r == null, null, accent = Neon.Lime)
            }
            if (loading) { ScanBar("Reading battery stats", null, accent = Neon.Lime); Gap(10) }
            NeonButton("Refresh", Modifier.fillMaxWidth(), brush = Neon.Safe, enabled = !loading) { vm.scanBattery() }
            Gap(14)
        }
        if (access.shizuku != Shell.State.READY) item {
            Banner("Without Shizuku only screen-on time is shown. Start Shizuku for real mAh drain.", Neon.Amber, "Open") { Perms.openShizuku(ctx) }; Gap()
        }
        if (!access.usage && access.shizuku != Shell.State.READY) item {
            Banner("Grant usage access to rank apps", Neon.Red, "Grant") { Perms.openUsage(ctx) }; Gap()
        }
        if (r == null) return@Page
        item { SectionTitle(r.source) }
        val top = r.apps.firstOrNull()
        itemsIndexed(r.apps.take(60)) { i, a -> PowerRow(i + 1, a, top, { a.pkg?.let { Perms.openAppInfo(ctx, it) } }) }
    }
}

@Composable
private fun PowerRow(rank: Int, a: PowerUse, top: PowerUse?, open: () -> Unit) {
    val mAhMode = !a.mAh.isNaN()
    val share = when {
        top == null -> 0f
        mAhMode -> if (top.mAh > 0) (a.mAh / top.mAh).toFloat() else 0f
        else -> if (top.foregroundMs > 0) a.foregroundMs.toFloat() / top.foregroundMs else 0f
    }
    GlowCard(glow = if (rank <= 3) Neon.Red else Neon.Lime, onClick = if (a.pkg != null) open else null) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("#$rank", color = if (rank <= 3) Neon.Red else Neon.Dim, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(a.label, color = Neon.Text, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (a.parts.isNotEmpty()) Text(a.parts, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text(if (mAhMode) (if (a.mAh < 0.05) "<0.1 mAh" else "%.1f mAh".format(a.mAh)) else duration(a.foregroundMs), color = Neon.Text, style = MaterialTheme.typography.labelLarge)
            }
            Gap(8)
            NeonBar(share, brush = if (rank <= 3) Neon.Danger else Neon.Safe, height = 6.dp)
        }
    }
    Gap()
}

private fun duration(ms: Long): String {
    val m = ms / 60_000
    return if (m >= 60) "${m / 60}h ${m % 60}m" else "${m}m"
}
