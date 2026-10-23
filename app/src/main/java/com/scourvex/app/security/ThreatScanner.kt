package com.scourvex.app.security

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.Files
import com.scourvex.app.core.Perf
import com.scourvex.app.core.Prefs
import com.scourvex.app.core.SkipGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

data class Threat(
    val target: String,        // file path, or package name when [isApp]
    val isApp: Boolean,
    val label: String,
    val detection: String,
    val source: String,        // "ClamAV", "Stalkerware IOC", "Spyware IOC (MVT)"
    val size: Long,
    val removable: Boolean = true, // false for traces like a system property: nothing to delete
) {
    val pua: Boolean get() = detection.startsWith("PUA.")
    /** What "Ignore" stores: this detection on this target only. */
    val ignoreKey: String get() = "$target\t$detection"
}

data class ThreatProgress(val phase: String, val current: String, val done: Int, val total: Int, val found: Int)

data class ThreatReport(
    val threats: List<Threat>,
    val risks: List<AppRisk>,
    val filesSeen: Int,
    val filesInspected: Int,
    val bytesRead: Long,
    val appsScanned: Int,
    val privileged: Boolean,
    val signatures: Sigs.Info?,
    val device: List<DeviceFinding>,
    val sensors: List<SensorUse.AppUse>?, // null without Shizuku
)

/** The real security scan: installed apps and every file on storage, inspected by one shared worker pool. */
object ThreatScanner {

    /** One thing to inspect: a file, or an installed APK ([app] set). */
    private class Work(val path: String, val size: Long, val name: String, val app: ApplicationInfo?)

    /**
     * Four inspectors hold about 128 MB of buffers (two 16 MB arrays each, a third when a zip nests: up to ~192 MB),
     * so four run only when that much heap is free; otherwise two, as before.
     */
    private fun workerCount(): Int {
        val rt = Runtime.getRuntime()
        val free = rt.maxMemory() - (rt.totalMemory() - rt.freeMemory())
        return if (free >= (300L shl 20)) 4 else 2
    }

    suspend fun scan(progress: (ThreatProgress) -> Unit): ThreatReport {
        var seen = 0
        return Perf.time("ThreatScanner.scan", { "files=$seen" }) { scanTimed(progress).also { seen = it.filesSeen } }
    }

    private suspend fun scanTimed(progress: (ThreatProgress) -> Unit): ThreatReport = withContext(Dispatchers.IO) {
        val pack = Sigs.get() ?: error("Virus signatures are not downloaded yet. Tap Update signatures.")
        val ctx = ScourvexApp.instance
        val pm = ctx.packageManager
        val ignored = Prefs.ignoredThreats
        val threats = ArrayList<Threat>()
        val risks = ArrayList<AppRisk>()
        val lock = Any()
        var bytes = 0L
        val workers = workerCount()
        val seen = AtomicInteger(0)
        val total = AtomicInteger(0)     // 0 (unknown) while the walk runs, the listed count after
        val done = AtomicInteger(0)
        val inspected = AtomicInteger(0)
        val apkAcc = Perf.Acc("ThreatScanner.apkInspect")
        val inspectAcc = Perf.Acc("ThreatScanner.inspectCalls")
        val t0All = System.nanoTime()
        var pkgCount = 0
        var privileged = true

        val device: List<DeviceFinding>
        val sensors: List<SensorUse.AppUse>?
        coroutineScope {
            // The device checks are shell calls: start them first so they overlap the whole scan.
            val spy = async { Perf.time("SpywareCheck.run") { SpywareCheck.run(pack.spyware) } }
            val dev = async { Perf.time("DeviceAudit.run") { DeviceAudit.run(ctx) } }
            val sen = async { Perf.time("SensorUse.read") { SensorUse.read() } }

            val queue = Channel<Work>(Channel.UNLIMITED)
            val pool = List(workers) {
                launch {
                    val ins = FileInspector(pack)
                    for (w in queue) {
                        currentCoroutineContext().ensureActive()
                        val app = w.app
                        val t0 = System.nanoTime()
                        val v = runCatching { ins.inspect(w.path, w.size) { Files.open(w.path) } }.getOrNull()
                        if (app != null) {
                            apkAcc.add(t0, w.size)
                            if (v == null) continue
                            if (v.detections.isNotEmpty()) {
                                val label = JunkScanner.appLabel(app, app.packageName)   // only a hit needs the name
                                synchronized(lock) { v.detections.forEach { threats += Threat(app.packageName, true, label, it, source(it), w.size) } }
                            }
                        } else {
                            if (v == null) { inspectAcc.add(t0); continue }
                            inspectAcc.add(t0, if (v.inspected) w.size else 0)
                            if (v.inspected) inspected.incrementAndGet()
                            if (v.detections.isNotEmpty()) synchronized(lock) {
                                v.detections.forEach { threats += Threat(w.path, false, w.name, it, source(it), w.size) }
                            }
                            val d = done.incrementAndGet()
                            if (d % 200 == 0) progress(ThreatProgress("Files", w.path, d, total.get(), synchronized(lock) { threats.size }))
                        }
                    }
                    synchronized(lock) { bytes += ins.bytesRead }
                }
            }

            // ---- Installed apps: checks here, APK contents go to the pool while the file walk runs ----
            val appsJob = launch {
                val flags = PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_PERMISSIONS
                @Suppress("DEPRECATION") val pkgs = pm.getInstalledPackages(flags)
                pkgCount = pkgs.size
                val audit = AppAudit(ctx)
                val appsT0 = System.nanoTime()
                pkgs.forEachIndexed { i, info ->
                    currentCoroutineContext().ensureActive()
                    val app = info.applicationInfo ?: return@forEachIndexed
                    progress(ThreatProgress("Apps", info.packageName, i + 1, pkgs.size, synchronized(lock) { threats.size }))
                    // The label is looked up only for an app that is reported (a hit or a risk).
                    val label by lazy { JunkScanner.appLabel(app, info.packageName) }
                    fun hit(det: String, src: String) {
                        val l = label
                        synchronized(lock) { threats += Threat(info.packageName, true, l, det, src, 0) }
                    }
                    pack.stalkerPkgs[info.packageName]?.let { hit("Stalkerware.$it", "Stalkerware IOC") }
                    val certs = certs(info)
                    for (cert in certs) pack.stalkerCerts[cert]?.let { hit("Stalkerware.$it (signing key)", "Stalkerware IOC") }
                    pack.spyware.pkgs[info.packageName]?.let { hit(it, SpywareCheck.SOURCE) }
                    for (cert in certs) pack.spyware.certs[cert]?.let { hit("$it (signing key)", SpywareCheck.SOURCE) }
                    audit.audit(info) { label }?.let { risks += it }

                    val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0 && app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
                    if (!system) {
                        for (apk in listOfNotNull(app.sourceDir) + (app.splitSourceDirs ?: emptyArray())) {
                            if (!SkipGuard.allows(apk)) continue   // skip list wins even for installed APKs
                            queue.trySend(Work(apk, File(apk).length(), apk.substringAfterLast('/'), app))
                        }
                    }
                }
                Perf.log("ThreatScanner.apps", (System.nanoTime() - appsT0) / 1_000_000, "pkgs=${pkgs.size}")
            }

            // ---- Every file: queued as it is found, so inspection runs during the walk ----
            progress(ThreatProgress("Files", "Listing storage…", 0, 0, 0))
            privileged = Perf.time("ThreatScanner.listing", { "files=${seen.get()}" }) {
                Files.walkAll { e -> if (!e.isDir) { seen.incrementAndGet(); queue.trySend(Work(e.path, e.size, e.name, null)) } }
            }
            total.set(seen.get())
            appsJob.join()
            queue.close()
            progress(ThreatProgress("Device", "Checking settings and spyware traces…", 0, 0, synchronized(lock) { threats.size }))
            pool.joinAll()
            Perf.log("ThreatScanner.inspect", (System.nanoTime() - t0All) / 1_000_000,
                "files=${seen.get()} inspected=${inspected.get()} bytesRead=$bytes workers=$workers")
            apkAcc.flush()
            inspectAcc.flush()
            threats += spy.await()
            device = dev.await()
            sensors = sen.await()
        }

        // Ignore is per detection: ignoring one finding never hides a different one on the same app or file.
        val visible = threats.filter { it.ignoreKey !in ignored }.distinctBy { it.target to it.detection }
        val ignoredTargets = ignored.map { it.substringBefore('\t') }.toSet()
        ThreatReport(
            visible, risks.filter { it.pkg !in ignoredTargets }.sortedByDescending { it.score },
            seen.get(), inspected.get(), bytes, pkgCount, privileged, Sigs.info.value, device, sensors,
        )
    }

    /** Hash detections from the MVT indicators are named Spyware.* / Stalkerware.* by the pack builder. */
    private fun source(det: String) =
        if (det.startsWith("Spyware.") || det.startsWith("Stalkerware.")) SpywareCheck.SOURCE else "ClamAV"

    /** SHA-1 and SHA-256 of every signing cert, lowercase hex. */
    private fun certs(info: PackageInfo): List<String> {
        val si = info.signingInfo ?: return emptyList()
        val certs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        return certs.orEmpty().flatMap { c ->
            listOf("SHA-1", "SHA-256").map { FileInspector.hex(MessageDigest.getInstance(it).digest(c.toByteArray())) }
        }
    }
}
