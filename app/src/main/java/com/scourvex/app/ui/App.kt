package com.scourvex.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BatteryChargingFull
import androidx.compose.material.icons.rounded.CleaningServices
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.TextButton
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.scourvex.app.shizuku.Shell
import com.scourvex.app.ui.theme.Neon

enum class Tab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Rounded.Home),
    CLEAN("Clean", Icons.Rounded.CleaningServices),
    SECURITY("Security", Icons.Rounded.Security),
    STORAGE("Storage", Icons.Rounded.Storage),
    BATTERY("Battery", Icons.Rounded.BatteryChargingFull),
}

/** Bumped on every resume so screens re-read permissions granted in system settings. */
class Access(val allFiles: Boolean, val usage: Boolean, val shizuku: Shell.State)

@Composable
fun ScourvexAppUi(vm: MainViewModel = viewModel()) {
    var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
    var settings by rememberSaveable { mutableStateOf(false) }
    // Back closes Settings, then returns to Home; only Back on Home leaves the app.
    androidx.activity.compose.BackHandler(enabled = settings || tab != Tab.HOME) { if (settings) settings = false else tab = Tab.HOME }
    val ctx = androidx.compose.ui.platform.LocalContext.current
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) { Shell.refresh(); resumes++; onPauseOrDispose { } }
    val shizuku by Shell.state.collectAsStateWithLifecycle()
    val access = remember(resumes, shizuku) { Access(Perms.allFiles(), Perms.usage(ctx), shizuku) }

    val snack = remember { SnackbarHostState() }
    val toast by vm.toast.collectAsStateWithLifecycle()
    LaunchedEffect(toast) {
        toast?.let { snack.showSnackbar(it); vm.toast.value = null }
    }

    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Neon.Bg, androidx.compose.ui.graphics.Color(0xFF0B0820))))) {
        Column(Modifier.fillMaxSize()) {
            Header(if (settings) "Settings" else tab.label, settings) { settings = !settings }
            Box(Modifier.weight(1f)) {
                AnimatedContent(if (settings) null else tab, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "tab") { t ->
                    when (t) {
                        null -> SettingsScreen(vm, access)
                        Tab.HOME -> HomeScreen(vm, access) { tab = it }
                        Tab.CLEAN -> CleanScreen(vm, access)
                        Tab.SECURITY -> SecurityScreen(vm, access)
                        Tab.STORAGE -> StorageScreen(vm, access)
                        Tab.BATTERY -> BatteryScreen(vm, access)
                    }
                }
            }
            NavigationBar(containerColor = Neon.Surface, tonalElevation = 0.dp, modifier = Modifier.navigationBarsPadding()) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = !settings && tab == t,
                        onClick = { tab = t; settings = false },
                        icon = { Icon(t.icon, t.label) },
                        label = { Text(t.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Neon.Bg, indicatorColor = Neon.Cyan,
                            unselectedIconColor = Neon.Dim, selectedTextColor = Neon.Cyan, unselectedTextColor = Neon.Dim,
                        ),
                    )
                }
            }
        }
        SnackbarHost(snack, Modifier.align(Alignment.BottomCenter).padding(bottom = 96.dp))
    }
    RecoveryDialog(vm) { tab = it; settings = false }
}

/** After a crash, or when Android closed the app mid-scan: say so and offer to run the scan again. */
@Composable
private fun RecoveryDialog(vm: MainViewModel, show: (Tab) -> Unit) {
    val n by vm.notice.collectAsStateWithLifecycle()
    val notice = n ?: return
    val clip = androidx.compose.ui.platform.LocalClipboardManager.current
    val what = notice.scan
    AlertDialog(
        onDismissRequest = { vm.notice.value = null },
        containerColor = Neon.Surface,
        title = { Text(if (notice.crashed) "Scourvex closed unexpectedly" else "${what ?: "A scan"} did not finish", color = Neon.Text) },
        text = {
            Text(when {
                notice.crashed && what != null -> "It stopped during: $what. Nothing was lost; results from that run were not saved."
                notice.crashed -> "Nothing was lost. If it keeps happening, copy the details and report it on GitHub."
                else -> "Android closed Scourvex while it was running (low memory or battery saver). Nothing was lost."
            }, color = Neon.Dim)
        },
        confirmButton = {
            if (what != null) TextButton({
                // Open the screen the scan belongs to, so its progress is visible.
                show(when (what) {
                    MainViewModel.SECURITY -> Tab.SECURITY
                    MainViewModel.STORAGE, MainViewModel.DUPES, MainViewModel.DELETING -> Tab.STORAGE
                    else -> Tab.CLEAN
                })
                vm.rerun(what)
            }) { Text("Run it again", color = Neon.Lime) }
            else TextButton({ vm.notice.value = null }) { Text("OK", color = Neon.Cyan) }
        },
        dismissButton = {
            Row {
                notice.trace?.let { t -> TextButton({ clip.setText(androidx.compose.ui.text.AnnotatedString(t)); vm.toast.value = "Details copied" }) { Text("Copy details", color = Neon.Dim) } }
                if (what != null) TextButton({ vm.notice.value = null }) { Text("Not now", color = Neon.Dim) }
            }
        },
    )
}

@Composable
private fun Header(title: String, inSettings: Boolean, onGear: () -> Unit) {
    Row(Modifier.fillMaxWidth().statusBarsPadding().padding(start = 20.dp, end = 8.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("SCOURVEX", style = MaterialTheme.typography.labelLarge, color = Neon.Magenta)
            Text(title, style = MaterialTheme.typography.headlineMedium, color = Neon.Text)
        }
        IconButton(onClick = onGear) {
            Icon(Icons.Rounded.Settings, "Settings", tint = if (inSettings) Neon.Cyan else Neon.Dim)
        }
        Spacer(Modifier.width(4.dp))
    }
}

/** Shared scrolling page with the standard gutters. */
@Composable
fun Page(content: LazyListScope.() -> Unit) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp), content = content)
}
