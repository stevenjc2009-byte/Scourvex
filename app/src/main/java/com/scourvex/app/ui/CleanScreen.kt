package com.scourvex.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scourvex.app.clean.JunkCategory
import com.scourvex.app.clean.JunkItem
import com.scourvex.app.clean.JunkResult
import com.scourvex.app.core.formatBytes
import com.scourvex.app.ui.components.Banner
import com.scourvex.app.ui.components.GhostButton
import com.scourvex.app.ui.components.GlowCard
import com.scourvex.app.ui.components.NeonButton
import com.scourvex.app.ui.components.ScanBar
import com.scourvex.app.ui.components.ScanOrb
import com.scourvex.app.ui.components.SectionTitle
import com.scourvex.app.ui.theme.Neon
import com.scourvex.app.ui.MainViewModel.Junk

@Composable
fun CleanScreen(vm: MainViewModel, access: Access) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val state by vm.junk.collectAsStateWithLifecycle()
    val result: JunkResult? = when (val s = state) {
        is Junk.Found -> s.result
        is Junk.Cleaned -> s.result
        else -> null
    }
    // Review items the user ticked; reset whenever a new result arrives.
    val ticked = remember(result) { mutableStateListOf<String>() }
    var open by remember { mutableStateOf<JunkCategory?>(null) }
    var confirm by remember { mutableStateOf(false) }

    Page {
        item {
            Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                when (val s = state) {
                    Junk.Idle -> ScanOrb("Ready", "Scan every folder for caches, temp files, thumbnails and bins", false, null)
                    is Junk.Scanning -> ScanOrb("%,d".format(s.count), s.path.ifEmpty { "Starting…" }.takeLast(60), true, null)
                    is Junk.Cleaning -> ScanOrb("${s.done}/${s.total}", "Cleaning…", true, if (s.total > 0) s.done.toFloat() / s.total else null, accent = Neon.Lime)
                    is Junk.Found -> ScanOrb(formatBytes(s.result.items.sumOf { it.size }), "junk · ${"%,d".format(s.result.filesScanned)} files scanned", false, null, accent = Neon.Magenta)
                    is Junk.Cleaned -> ScanOrb(formatBytes(s.report.freed), "freed · ${s.report.deleted} item${if (s.report.deleted == 1) "" else "s"} removed", false, 1f, accent = Neon.Lime)
                }
            }
        }
        item {
            when (val s = state) {
                is Junk.Scanning -> { ScanBar("Checking folders · ${"%,d".format(s.count)} files so far", null); Gap(10) }
                is Junk.Cleaning -> { ScanBar("Deleting ${s.done} of ${s.total}", if (s.total > 0) s.done.toFloat() / s.total else null, accent = Neon.Lime); Gap(10) }
                else -> {}
            }
            when (state) {
                is Junk.Scanning, is Junk.Cleaning -> GhostButton("Stop", Modifier.fillMaxWidth(), Neon.Red) { vm.cancel() }
                else -> NeonButton(if (result == null) "Scan" else "Scan again", Modifier.fillMaxWidth()) { vm.scanJunk() }
            }
            Gap(14)
        }
        if (!access.allFiles) item { Banner("Grant all-files access first", Neon.Red, "Grant") { Perms.openAllFiles(ctx) }; Gap() }
        (state as? Junk.Cleaned)?.report?.let { r ->
            if (r.cacheNote != null) item { Banner(r.cacheNote, Neon.Amber); Gap() }
            if (r.failed.isNotEmpty()) item { FailedList(r.failed, access); Gap() }
        }
        if (result == null) return@Page
        if (!result.privileged) item { Banner("Android/data and obb skipped — start Shizuku to clean them", Neon.Amber); Gap() }
        if (!result.appStatsAvailable) item { Banner("Grant usage access to size internal app caches", Neon.Amber, "Grant") { Perms.openUsage(ctx) }; Gap() }

        val byCat = result.byCategory()
        val autoItems = result.items.filter { it.category.auto }
        item { SectionTitle("Safe to clean — one tap") }
        items(JunkCategory.entries.filter { it.auto }) { c -> CategoryRow(c, byCat[c].orEmpty(), open == c, null) { open = if (open == c) null else c } }
        item {
            Gap(4)
            NeonButton("Clean ${formatBytes(autoItems.sumOf { it.size })}", Modifier.fillMaxWidth(), brush = Neon.Safe,
                enabled = autoItems.isNotEmpty() && !vm.busy) { vm.clean(autoItems) }
        }
        item { SectionTitle("Review first — tick what to delete") }
        items(JunkCategory.entries.filter { !it.auto }) { c ->
            CategoryRow(c, byCat[c].orEmpty(), open == c, ticked) { open = if (open == c) null else c }
        }
        item {
            val sel = result.items.filter { it.path in ticked }
            Gap(4)
            NeonButton("Delete ${sel.size} selected · ${formatBytes(sel.sumOf { it.size })}", Modifier.fillMaxWidth(), brush = Neon.Danger,
                enabled = sel.isNotEmpty() && !vm.busy) { confirm = true }
        }
    }

    if (confirm && result != null) {
        val sel = result.items.filter { it.path in ticked }
        AlertDialog(
            onDismissRequest = { confirm = false },
            containerColor = Neon.Surface2,
            title = { Text("Delete ${sel.size} items?") },
            text = { Text("${formatBytes(sel.sumOf { it.size })} will be permanently removed. This cannot be undone.") },
            confirmButton = { TextButton({ confirm = false; vm.clean(sel) }) { Text("DELETE", color = Neon.Red) } },
            dismissButton = { TextButton({ confirm = false }) { Text("CANCEL", color = Neon.Dim) } },
        )
    }
}

@Composable
private fun CategoryRow(c: JunkCategory, items: List<JunkItem>, expanded: Boolean, ticked: MutableList<String>?, toggle: () -> Unit) {
    val size = items.sumOf { it.size }
    GlowCard(glow = if (c.auto) Neon.Cyan else Neon.Amber, onClick = if (items.isNotEmpty()) toggle else null) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (ticked != null && items.isNotEmpty()) {
                    val all = items.all { it.path in ticked }
                    Checkbox(all, { on -> if (on) ticked.addAll(items.map { it.path }.filter { it !in ticked }) else ticked.removeAll(items.map { it.path }) },
                        colors = CheckboxDefaults.colors(checkedColor = Neon.Amber, checkmarkColor = Neon.Bg))
                }
                Column(Modifier.weight(1f)) {
                    Text(c.label, style = MaterialTheme.typography.titleMedium, color = Neon.Text)
                    Text(c.detail, style = MaterialTheme.typography.bodyMedium, color = Neon.Dim)
                }
                Spacer(Modifier.width(8.dp))
                Column(horizontalAlignment = Alignment.End) {
                    Text(if (items.isEmpty()) "clean" else formatBytes(size), color = if (items.isEmpty()) Neon.Lime else Neon.Text,
                        style = MaterialTheme.typography.titleMedium)
                    if (items.isNotEmpty()) Text(if (c == JunkCategory.EMPTY_FOLDERS) plural(items.size, "folder") else plural(items.sumOf { it.files }, "file"), color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
                }
            }
            if (expanded) {
                Gap(6)
                items.sortedByDescending { it.size }.take(MAX_SHOWN).forEach { i -> ItemLine(i, ticked) }
                if (items.size > MAX_SHOWN) Text("+ ${items.size - MAX_SHOWN} more", color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
    Gap()
}

@Composable
private fun ItemLine(i: JunkItem, ticked: MutableList<String>?) {
    val toggle = { if (ticked != null) { if (i.path in ticked) ticked.remove(i.path) else ticked.add(i.path) } }
    Row(Modifier.fillMaxWidth().clickable(enabled = ticked != null) { toggle() }.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
        if (ticked != null) Checkbox(i.path in ticked, { toggle() }, colors = CheckboxDefaults.colors(checkedColor = Neon.Amber, checkmarkColor = Neon.Bg))
        Column(Modifier.weight(1f)) {
            Text(i.label, color = Neon.Text, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(i.path, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.StartEllipsis)
        }
        Text(formatBytes(i.size), color = Neon.Dim, style = MaterialTheme.typography.labelSmall)
    }
}

private const val MAX_SHOWN = 60

private fun plural(n: Int, word: String) = if (n == 1) "1 $word" else "%,d ${word}s".format(n)

/** Which items were not deleted and why, so "could not be deleted" is never a mystery. Tap to show the list. */
@Composable
private fun FailedList(failed: List<String>, access: Access) {
    var open by remember { mutableStateOf(false) }
    val locked = failed.count { com.scourvex.app.core.Files.isRestricted(it) || it.startsWith("/data/") }
    val head = "${failed.size} item${if (failed.size == 1) "" else "s"} not deleted" + when {
        locked > 0 && access.shizuku != com.scourvex.app.shizuku.Shell.State.READY -> " — $locked need Shizuku (Android/data is locked to other apps)"
        else -> " — in use by an app or protected by Android"
    }
    Banner(head, Neon.Amber, if (open) "Hide" else "Show") { open = !open }
    if (open) failed.forEach { p ->
        val why = if (com.scourvex.app.core.Files.isRestricted(p) || p.startsWith("/data/")) "needs Shizuku" else "in use or protected"
        Text("• ${p.removePrefix("/storage/emulated/0")}  ($why)", color = Neon.Dim, style = MaterialTheme.typography.labelSmall,
            maxLines = 2, overflow = TextOverflow.StartEllipsis)
    }
}
