package com.scourvex.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.core.Entry
import com.scourvex.app.core.formatBytes
import com.scourvex.app.ui.MainViewModel.Dupes
import com.scourvex.app.ui.MainViewModel.Store
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.NeonBar
import com.scourvex.app.ui.components.NeonButton
import com.scourvex.app.ui.components.ScanBar
import com.scourvex.app.ui.components.ScanOrb
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.theme.Neon

private enum class View(val label: String) { TYPES("Types"), FILES("Files"), FOLDERS("Folders"), APPS("Apps"), UNUSED("Unused"), DUPES("Duplicates") }

@Composable
fun StorageScreen(vm: MainViewModel, access: Access) {
    val ctx = LocalContext.current
    val state by vm.store.collectAsStateWithLifecycle()
    val dupes by vm.dupes.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val mine = running == MainViewModel.STORAGE || running == MainViewModel.DUPES || running == MainViewModel.DELETING
    var view by rememberSaveable { mutableStateOf(View.TYPES) }
    // Duplicates: every copy except the one to keep is pre-ticked.
    val ticked = remember(state, dupes) {
        mutableStateListOf<String>().apply {
            (dupes as? Dupes.Done)?.let { d -> addAll(d.groups.flatMap { g -> g.files.filter { it != g.keep }.map { it.path } }) }
        }
    }
    val tickedFiles = remember(state) { mutableStateListOf<String>() }
    // The selection the confirm dialog will delete; null when no dialog is open.
    var confirm by remember { mutableStateOf<List<String>?>(null) }

    Page {
        item {
            Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                when (val s = state) {
                    Store.Idle -> ScanOrb("Map", "Find what is eating your storage", false, null, accent = Neon.Amber)
                    is Store.Scanning -> ScanOrb("%,d".format(s.count), s.path.takeLast(60), true, null, accent = Neon.Amber)
                    is Store.Done -> ScanOrb(formatBytes(s.report.entries.sumOf { it.size }), "in %,d files".format(s.report.entries.size), false, null, accent = Neon.Amber)
                }
            }
            (state as? Store.Scanning)?.let { s -> ScanBar("Measuring files · ${"%,d".format(s.count)} so far", null, accent = Neon.Amber); Gap(10) }
            if (mine) GhostButton("Stop", Modifier.fillMaxWidth(), Neon.Red) { vm.cancel() }
            else NeonButton(if (state is Store.Done) "Rescan" else "Analyse storage", Modifier.fillMaxWidth(), enabled = running == null) { vm.scanStorage() }
            Gap(14)
        }
        if (!access.allFiles) item { Banner("Grant all-files access first", Neon.Red, "Grant") { Perms.openAllFiles(ctx) }; Gap() }
        val r = (state as? Store.Done)?.report ?: return@Page
        if (!r.privileged) item { Banner("Android/data and obb not counted — start Shizuku to include them", Neon.Amber); Gap() }
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                View.entries.forEach { v ->
                    Text(v.label.uppercase(), Modifier.clip(RoundedCornerShape(50))
                        .background(if (v == view) Neon.Cyan else Neon.Surface2).clickable { view = v }
                        .padding(horizontal = 14.dp, vertical = 8.dp),
                        color = if (v == view) Neon.Bg else Neon.Dim, style = MaterialTheme.typography.labelLarge)
                }
            }
            Gap()
        }
        when (view) {
            View.TYPES -> {
                val max = r.byType.values.maxOrNull() ?: 1L
                items(r.byType.entries.sortedByDescending { it.value }.toList()) { (k, v) ->
                    GlowCard(glow = Neon.Amber) {
                        Column {
                            Row { Text(k, Modifier.weight(1f), color = Neon.Text, style = MaterialTheme.typography.titleMedium); Text(formatBytes(v), color = Neon.Text) }
                            Gap(6); NeonBar(v.toFloat() / max, height = 6.dp)
                        }
                    }
                    Gap()
                }
            }
            View.FILES -> {
                items(r.biggestFiles, key = { it.path }) { e -> FileLine(e, tickedFiles) }
                item { DeleteBar(r.biggestFiles, tickedFiles, vm.busy) { confirm = tickedFiles.toList() } }
            }
            View.FOLDERS -> items(r.biggestFolders, key = { it.path }) { f ->
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(f.path.substringAfterLast('/'), color = Neon.Text, style = MaterialTheme.typography.titleMedium)
                        Text(f.path, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.StartEllipsis)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(formatBytes(f.size), color = Neon.Amber, style = MaterialTheme.typography.labelLarge)
                        Text(if (f.files == 1) "1 file" else "%,d files".format(f.files), color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            View.APPS -> {
                val apps = r.apps
                if (apps == null) item { Banner("Grant usage access to see app sizes", Neon.Amber, "Grant") { Perms.openUsage(ctx) } }
                else items(apps.take(100), key = { it.pkg }) { a ->
                    GlowCard(glow = Neon.Violet, onClick = { Perms.openAppInfo(ctx, a.pkg) }) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(a.label, color = Neon.Text, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("app ${formatBytes(a.app)} · data ${formatBytes(a.data)} · cache ${formatBytes(a.cache)}", color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
                            }
                            Text(formatBytes(a.total), color = Neon.Violet, style = MaterialTheme.typography.labelLarge)
                        }
                    }
                    Gap()
                }
            }
            View.UNUSED -> unusedApps(r.unused, vm, ctx)
            View.DUPES -> when (val d = dupes) {
                Dupes.Idle -> item { NeonButton("Find duplicates", Modifier.fillMaxWidth(), enabled = !vm.busy) { vm.findDuplicates() } }
                is Dupes.Hashing -> item {
                    Text("Comparing ${d.done} / ${d.total} candidates…", color = Neon.Cyan)
                    Gap(6); ScanBar("Same-size files are being compared byte for byte", if (d.total > 0) d.done.toFloat() / d.total else null)
                }
                is Dupes.Done -> {
                    item { Text("${d.groups.size} group${if (d.groups.size == 1) "" else "s"} · ${formatBytes(d.groups.sumOf { it.wasted })} wasted. The oldest copy is kept unticked.", color = Neon.Dim) }
                    d.groups.take(300).forEach { g ->
                        item(key = "g" + g.files.first().path) { SectionTitle("${g.files.size} × ${formatBytes(g.size)}") }
                        items(g.files, key = { "d" + it.path }) { e -> FileLine(e, ticked, keep = e == g.keep) }
                    }
                    item { DeleteBar(d.groups.flatMap { it.files }, ticked, vm.busy) { confirm = ticked.toList() } }
                }
            }
        }
    }

    confirm?.let { paths ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            containerColor = Neon.Surface2,
            title = { Text("Delete ${paths.size} files?") },
            text = { Text("They will be permanently removed. This cannot be undone.") },
            confirmButton = { TextButton({ confirm = null; vm.deleteMany(paths) }) { Text("DELETE", color = Neon.Red) } },
            dismissButton = { TextButton({ confirm = null }) { Text("CANCEL", color = Neon.Dim) } },
        )
    }
}

@Composable
private fun FileLine(e: Entry, ticked: MutableList<String>, keep: Boolean = false) {
    val toggle = { if (e.path in ticked) ticked.remove(e.path) else ticked.add(e.path); Unit }
    Row(Modifier.fillMaxWidth().clickable { toggle() }.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(e.path in ticked, { toggle() }, colors = CheckboxDefaults.colors(checkedColor = Neon.Red, checkmarkColor = Neon.Bg))
        Column(Modifier.weight(1f)) {
            Text(e.name + if (keep) "  · KEEP" else "", color = if (keep) Neon.Lime else Neon.Text, style = MaterialTheme.typography.bodyMedium,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(e.path, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.StartEllipsis)
        }
        Text(formatBytes(e.size), color = Neon.Amber, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun DeleteBar(all: List<Entry>, ticked: List<String>, busy: Boolean, onDelete: () -> Unit) {
    val set = ticked.toSet()
    val size = all.filter { it.path in set }.sumOf { it.size }
    Gap()
    NeonButton("Delete ${ticked.size} selected · ${formatBytes(size)}", Modifier.fillMaxWidth(), brush = Neon.Danger,
        enabled = ticked.isNotEmpty() && !busy, onClick = onDelete)
}
