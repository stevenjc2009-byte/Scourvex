package com.scourvex.app.security

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Perf
import com.scourvex.app.core.Prefs
import com.scourvex.app.core.SkipGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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

/** The real security scan: installed apps, then every file on storage. */
object ThreatScanner {

    private const val WORKERS = 2

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
        var bytes = 0L

        // ---- Installed apps ----
        val flags = PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_PERMISSIONS
        @Suppress("DEPRECATION") val pkgs = pm.getInstalledPackages(flags)
        val audit = AppAudit(ctx)
        val inspector = FileInspector(pack)
        val apkAcc = Perf.Acc("ThreatScanner.apkInspect")
        val appsT0 = System.nanoTime()
        pkgs.forEachIndexed { i, info ->
            currentCoroutineContext().ensureActive()
            val app = info.applicationInfo ?: return@forEachIndexed
            val label = JunkScanner.appLabel(app, info.packageName)
            progress(ThreatProgress("Apps", label, i + 1, pkgs.size, threats.size))
            fun hit(det: String, src: String, size: Long = 0) {
                threats += Threat(info.packageName, true, label, det, src, size)
            }
            pack.stalkerPkgs[info.packageName]?.let { hit("Stalkerware.$it", "Stalkerware IOC") }
            val certs = certs(info)
            for (cert in certs) pack.stalkerCerts[cert]?.let { hit("Stalkerware.$it (signing key)", "Stalkerware IOC") }
            pack.spyware.pkgs[info.packageName]?.let { hit(it, SpywareCheck.SOURCE) }
            for (cert in certs) pack.spyware.certs[cert]?.let { hit("$it (signing key)", SpywareCheck.SOURCE) }
            audit.audit(info, label)?.let { risks += it }

            val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0 && app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
            if (!system) {
                for (apk in listOfNotNull(app.sourceDir) + (app.splitSourceDirs ?: emptyArray())) {
                    if (!SkipGuard.allows(apk)) continue   // skip list wins even for installed APKs
                    val f = File(apk)
                    val t0 = System.nanoTime()
                    val v = inspector.inspect(apk, f.length()) { Files.open(apk) }
                    apkAcc.add(t0, f.length())
                    v.detections.forEach { hit(it, source(it), f.length()) }
                }
            }
        }
        bytes += inspector.bytesRead
        apkAcc.flush()
        Perf.log("ThreatScanner.apps", (System.nanoTime() - appsT0) / 1_000_000, "pkgs=${pkgs.size} apkBytes=${inspector.bytesRead}")

        // ---- Every file ----
        progress(ThreatProgress("Files", "Listing storage…", 0, 0, threats.size))
        val entries = ArrayList<Entry>()
        val privileged = Perf.time("ThreatScanner.listing", { "files=${entries.size}" }) { Files.walkAll { e -> if (!e.isDir) entries += e } }
        val next = AtomicInteger(0)
        val inspected = AtomicInteger(0)
        val lock = Any()
        val inspectAcc = Perf.Acc("ThreatScanner.inspectCalls")
        val inspectT0 = System.nanoTime()
        coroutineScope {
            repeat(WORKERS) {
                launch {
                    val ins = FileInspector(pack)
                    while (true) {
                        val idx = next.getAndIncrement()
                        if (idx >= entries.size) break
                        currentCoroutineContext().ensureActive()
                        val e = entries[idx]
                        if (idx % 200 == 0) progress(ThreatProgress("Files", e.path, idx, entries.size, threats.size))
                        val t0 = System.nanoTime()
                        val v = runCatching { ins.inspect(e.path, e.size) { Files.open(e.path) } }.getOrNull()
                        if (v == null) { inspectAcc.add(t0); continue }
                        inspectAcc.add(t0, if (v.inspected) e.size else 0)
                        if (v.inspected) inspected.incrementAndGet()
                        synchronized(lock) {
                            v.detections.forEach { d -> threats += Threat(e.path, false, e.name, d, source(d), e.size) }
                        }
                    }
                    synchronized(lock) { bytes += ins.bytesRead }
                }
            }
        }

        Perf.log("ThreatScanner.inspect", (System.nanoTime() - inspectT0) / 1_000_000,
            "files=${entries.size} inspected=${inspected.get()} bytesRead=$bytes workers=$WORKERS")
        inspectAcc.flush()

        progress(ThreatProgress("Device", "Checking settings and spyware traces…", 0, 0, threats.size))
        threats += Perf.time("SpywareCheck.run") { SpywareCheck.run(pack.spyware) }
        val device = Perf.time("DeviceAudit.run") { DeviceAudit.run(ctx) }
        val sensors = Perf.time("SensorUse.read") { SensorUse.read() }

        // Ignore is per detection: ignoring one finding never hides a different one on the same app or file.
        val visible = threats.filter { it.ignoreKey !in ignored }.distinctBy { it.target to it.detection }
        val ignoredTargets = ignored.map { it.substringBefore('	') }.toSet()
        ThreatReport(
            visible, risks.filter { it.pkg !in ignoredTargets }.sortedByDescending { it.score },
            entries.size, inspected.get(), bytes, pkgs.size, privileged, Sigs.info.value, device, sensors,
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
