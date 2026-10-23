package com.scourvex.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.scourvex.app.ScourvexApp
import com.scourvex.app.battery.BatteryAnalyzer
import com.scourvex.app.battery.BatteryReport
import com.scourvex.app.clean.CleanReport
import com.scourvex.app.clean.Cleaner
import com.scourvex.app.clean.JunkItem
import com.scourvex.app.clean.JunkResult
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.CrashGuard
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Prefs
import com.scourvex.app.core.ScanKeeper
import com.scourvex.app.core.SkipGuard
import com.scourvex.app.security.Sigs
import com.scourvex.app.security.Threat
import com.scourvex.app.security.ThreatProgress
import com.scourvex.app.security.ThreatReport
import com.scourvex.app.security.ThreatScanner
import com.scourvex.app.storage.DuplicateGroup
import com.scourvex.app.storage.Duplicates
import com.scourvex.app.storage.StorageAnalyzer
import com.scourvex.app.storage.StorageReport
import com.scourvex.app.storage.UnusedApps
import com.scourvex.app.update.Updater
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Long-running scans live here so they survive screen changes and rotation. */
class MainViewModel : ViewModel() {

    sealed interface Junk {
        object Idle : Junk
        data class Scanning(val path: String, val count: Int) : Junk
        data class Found(val result: JunkResult) : Junk
        data class Cleaning(val done: Int, val total: Int) : Junk
        data class Cleaned(val report: CleanReport, val result: JunkResult) : Junk
    }

    sealed interface Sec {
        object Idle : Sec
        data class Scanning(val p: ThreatProgress) : Sec
        data class Done(val report: ThreatReport) : Sec
        data class Failed(val why: String) : Sec
    }

    sealed interface Store {
        object Idle : Store
        data class Scanning(val path: String, val count: Int) : Store
        data class Done(val report: StorageReport) : Store
    }

    sealed interface Dupes {
        object Idle : Dupes
        data class Hashing(val done: Int, val total: Int) : Dupes
        data class Done(val groups: List<DuplicateGroup>) : Dupes
    }

    val junk = MutableStateFlow<Junk>(Junk.Idle)
    val sec = MutableStateFlow<Sec>(Sec.Idle)
    val store = MutableStateFlow<Store>(Store.Idle)
    val dupes = MutableStateFlow<Dupes>(Dupes.Idle)
    val battery = MutableStateFlow<BatteryReport?>(null)
    val batteryLoading = MutableStateFlow(false)
    val sigUpdate = MutableStateFlow<String?>(null)      // progress / error text while updating
    val toast = MutableStateFlow<String?>(null)
    val updater: StateFlow<Updater.State> = Updater.state
    /** Shown once after a crash, or after Android killed the app mid-scan. */
    val notice = MutableStateFlow(CrashGuard.takeNotice())

    private var job: Job? = null

    init {
        viewModelScope.launch {
            Sigs.get()
            if (!Sigs.installed) updateSignatures()
            Updater.checkIfDue()
        }
        viewModelScope.launch {
            // The Shizuku walker got the skip list when it started; stop rather than let it read a folder added since.
            Prefs.skip.drop(1).collect {
                if (busy) { cancel(); toast.value = "Scan stopped because the skip list changed. Run it again." }
            }
        }
        viewModelScope.launch {
            UnusedApps.results.collect { (pkg, error) ->
                if (error != null) { toast.value = "Could not archive: $error"; return@collect }
                val s = store.value as? Store.Done ?: return@collect
                val name = s.report.unused?.firstOrNull { it.pkg == pkg }?.label ?: pkg
                toast.value = "Archived $name"
                store.value = Store.Done(s.report.copy(unused = s.report.unused?.filter { it.pkg != pkg }))
            }
        }
    }

    fun archiveApp(pkg: String) = viewModelScope.launch { UnusedApps.archive(pkg) }

    val busy: Boolean get() = job?.isActive == true

    /** Name of the scan running now (null when idle), so each screen shows Stop only for its own scan. */
    val running = MutableStateFlow<String?>(null)

    fun cancel() { job?.cancel() }

    /** Runs one scan at a time; [what] names it in the notification and in the after-crash notice. */
    private fun run(what: String, block: suspend () -> Unit) {
        if (busy) { toast.value = "Another scan is running"; return }
        running.value = what
        job = viewModelScope.launch {
            ScanKeeper.begin(what)
            CrashGuard.scanStarted(what)
            val ticker = launch { while (true) { status()?.let { (t, p) -> ScanKeeper.update(t, p) }; delay(500) } }
            try { block() } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) {
                toast.value = e.message ?: e.toString()
            } finally {
                ticker.cancel()
                ScanKeeper.end()
                CrashGuard.scanEnded()
                running.value = null
            }
        }
    }

    /** Notification line + bar for whatever is running now. */
    private fun status(): Pair<String, Float?>? {
        fun frac(d: Int, t: Int) = if (t > 0) d.toFloat() / t else null
        (junk.value as? Junk.Scanning)?.let { return "%,d files checked".format(it.count) to null }
        (junk.value as? Junk.Cleaning)?.let { return "Cleaning ${it.done} of ${it.total}" to frac(it.done, it.total) }
        (sec.value as? Sec.Scanning)?.p?.let { return "${it.phase}: ${it.done} of ${it.total}" to frac(it.done, it.total) }
        (dupes.value as? Dupes.Hashing)?.let { return "Comparing ${it.done} of ${it.total}" to frac(it.done, it.total) }
        (store.value as? Store.Scanning)?.let { return "%,d files measured".format(it.count) to null }
        return null
    }

    /** Re-runs the scan named in [CrashGuard.Notice.scan]. */
    fun rerun(what: String?) {
        notice.value = null
        when (what) {
            JUNK, CLEANING -> scanJunk()
            SECURITY -> scanThreats()
            STORAGE, DELETING -> scanStorage()
            DUPES -> findDuplicates()
        }
    }

    fun scanJunk() = run(JUNK) {
        junk.value = Junk.Scanning("", 0)
        try {
            val r = JunkScanner.scan { p, n -> junk.value = Junk.Scanning(p, n) }
            junk.value = Junk.Found(r)
        } catch (e: kotlinx.coroutines.CancellationException) {
            junk.value = Junk.Idle; throw e
        }
    }

    /** Cleans [items] (the caller decides: auto categories, or the user's ticked review items). */
    fun clean(items: List<JunkItem>) = run(CLEANING) {
        val before = (junk.value as? Junk.Found)?.result ?: (junk.value as? Junk.Cleaned)?.result ?: return@run
        junk.value = Junk.Cleaning(0, items.size)
        val report = Cleaner.clean(items) { d, t -> junk.value = Junk.Cleaning(d, t) }
        val gone = items.map { it.path }.toSet() - report.failed.toSet()
        val left = before.copy(items = before.items.filter { it.path !in gone || (it.path.startsWith("app:") && report.cacheNote != null) })
        junk.value = Junk.Cleaned(report, left)
    }

    fun scanThreats() = run(SECURITY) {
        if (Sigs.get() == null) updateSignaturesNow()
        sec.value = Sec.Scanning(ThreatProgress("Starting", "", 0, 0, 0))
        try {
            sec.value = Sec.Done(ThreatScanner.scan { sec.value = Sec.Scanning(it) })
        } catch (e: kotlinx.coroutines.CancellationException) {
            sec.value = Sec.Idle; throw e
        } catch (e: Exception) {
            sec.value = Sec.Failed(e.message ?: e.toString())
        }
    }

    fun ignoreThreat(t: Threat) {
        Prefs.ignoredThreats = Prefs.ignoredThreats + t.ignoreKey
        dropThreat(t.target)
    }

    fun dropThreat(target: String) {
        val s = sec.value as? Sec.Done ?: return
        sec.value = Sec.Done(s.report.copy(
            threats = s.report.threats.filter { it.target != target },
            risks = s.report.risks.filter { it.pkg != target },
        ))
    }

    fun deleteFile(path: String, after: () -> Unit = {}) = viewModelScope.launch {
        val r = Files.delete(path)
        val name = path.substringAfterLast('/')
        toast.value = when {
            r >= 0 -> "Deleted $name"
            SkipGuard.isSkipped(path) -> "Not deleted: $name is on your skip list"
            else -> "Could not delete $name"
        }
        if (r >= 0) { dropThreat(path); after() }
    }

    fun updateSignatures() = viewModelScope.launch { updateSignaturesNow() }

    private suspend fun updateSignaturesNow() {
        sigUpdate.value = "Connecting…"
        try {
            Sigs.update { d, t ->
                sigUpdate.value = if (t > 0) "Downloading ${d * 100 / t}%" else "Downloading ${d / 1_048_576} MB"
            }
            sigUpdate.value = null
        } catch (e: Exception) {
            sigUpdate.value = "Signature update failed: ${e.message}"
        }
    }

    fun scanStorage() = run(STORAGE) {
        store.value = Store.Scanning("", 0)
        dupes.value = Dupes.Idle
        try {
            store.value = Store.Done(StorageAnalyzer.scan { p, n -> store.value = Store.Scanning(p, n) })
        } catch (e: kotlinx.coroutines.CancellationException) {
            store.value = Store.Idle; throw e
        }
    }

    fun findDuplicates() = run(DUPES) {
        val entries: List<Entry> = (store.value as? Store.Done)?.report?.entries ?: kotlin.run {
            val r = StorageAnalyzer.scan { p, n -> store.value = Store.Scanning(p, n) }
            store.value = Store.Done(r)
            r.entries
        }
        dupes.value = Dupes.Hashing(0, 0)
        try {
            dupes.value = Dupes.Done(Duplicates.find(entries) { d, t -> dupes.value = Dupes.Hashing(d, t) })
        } catch (e: kotlinx.coroutines.CancellationException) {
            dupes.value = Dupes.Idle; throw e
        }
    }

    fun deleteMany(paths: List<String>) = run(DELETING) {
        var ok = 0
        var freed = 0L
        val gone = HashSet<String>()
        for (p in paths) { val r = Files.delete(p); if (r >= 0) { ok++; freed += r; gone += p } }   // refused/failed stay listed
        toast.value = "Deleted $ok of ${paths.size} (${com.scourvex.app.core.formatBytes(freed)})"
        (dupes.value as? Dupes.Done)?.let { d ->
            dupes.value = Dupes.Done(d.groups.map { g -> g.copy(files = g.files.filter { it.path !in gone }) }.filter { it.files.size > 1 })
        }
        (store.value as? Store.Done)?.let { s ->
            store.value = Store.Done(s.report.copy(biggestFiles = s.report.biggestFiles.filter { it.path !in gone },
                entries = s.report.entries.filter { it.path !in gone }))
        }
    }

    fun scanBattery() = viewModelScope.launch {
        if (batteryLoading.value) return@launch
        batteryLoading.value = true
        try {
            battery.value = runCatching { BatteryAnalyzer.scan() }.getOrElse {
                if (it is kotlinx.coroutines.CancellationException) throw it
                toast.value = it.message; battery.value
            }
        } finally { batteryLoading.value = false }
    }

    fun checkUpdate() = viewModelScope.launch { Updater.check() }

    fun installUpdate(r: Updater.Release) {
        val ctx = ScourvexApp.instance
        if (!com.scourvex.app.shizuku.Shell.ready && !Perms.installs(ctx)) {
            toast.value = "Allow Scourvex to install updates, then tap Install again"
            Perms.openInstalls(ctx)
            return
        }
        viewModelScope.launch { Updater.downloadAndInstall(r) }
    }

    companion object {
        const val JUNK = "Junk scan"
        const val CLEANING = "Cleaning"
        const val SECURITY = "Security scan"
        const val STORAGE = "Storage scan"
        const val DUPES = "Duplicate search"
        const val DELETING = "Deleting files"
    }
}
