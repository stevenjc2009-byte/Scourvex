package com.scourvex.app.security

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

data class Threat(
    val target: String,        // file path, or package name when [isApp]
    val isApp: Boolean,
    val label: String,
    val detection: String,
    val source: String,        // "ClamAV", "Stalkerware IOC"
    val size: Long,
) {
    val pua: Boolean get() = detection.startsWith("PUA.")
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
)

/** The real security scan: installed apps, then every file on storage. */
object ThreatScanner {

    private const val WORKERS = 2

    suspend fun scan(progress: (ThreatProgress) -> Unit): ThreatReport = withContext(Dispatchers.IO) {
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
        pkgs.forEachIndexed { i, info ->
            currentCoroutineContext().ensureActive()
            val app = info.applicationInfo ?: return@forEachIndexed
            val label = JunkScanner.appLabel(app, info.packageName)
            progress(ThreatProgress("Apps", label, i + 1, pkgs.size, threats.size))
            fun hit(det: String, src: String, size: Long = 0) {
                threats += Threat(info.packageName, true, label, det, src, size)
            }
            pack.stalkerPkgs[info.packageName]?.let { hit("Stalkerware.$it", "Stalkerware IOC") }
            for (cert in certSha1s(info)) pack.stalkerCerts[cert]?.let { hit("Stalkerware.$it (signing key)", "Stalkerware IOC") }
            audit.audit(info, label)?.let { risks += it }

            val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0 && app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
            if (!system) {
                for (apk in listOfNotNull(app.sourceDir) + (app.splitSourceDirs ?: emptyArray())) {
                    val f = File(apk)
                    val v = inspector.inspect(apk, f.length()) { runCatching { FileInputStream(f) }.getOrNull() }
                    v.detections.forEach { hit(it, "ClamAV", f.length()) }
                }
            }
        }
        bytes += inspector.bytesRead

        // ---- Every file ----
        progress(ThreatProgress("Files", "Listing storage…", 0, 0, threats.size))
        val entries = ArrayList<Entry>()
        val privileged = Files.walkAll(Prefs.skip.value) { e -> if (!e.isDir) entries += e }
        val next = AtomicInteger(0)
        val inspected = AtomicInteger(0)
        val lock = Any()
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
                        val v = runCatching { ins.inspect(e.path, e.size) { Files.open(e.path) } }.getOrNull() ?: continue
                        if (v.inspected) inspected.incrementAndGet()
                        synchronized(lock) {
                            v.detections.forEach { d -> threats += Threat(e.path, false, e.name, d, "ClamAV", e.size) }
                        }
                    }
                    synchronized(lock) { bytes += ins.bytesRead }
                }
            }
        }

        val visible = threats.filter { it.target !in ignored }.distinctBy { it.target to it.detection }
        ThreatReport(
            visible, risks.filter { it.pkg !in ignored }.sortedByDescending { it.score },
            entries.size, inspected.get(), bytes, pkgs.size, privileged, Sigs.info.value,
        )
    }

    private fun certSha1s(info: PackageInfo): List<String> {
        val si = info.signingInfo ?: return emptyList()
        val certs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        return certs.orEmpty().map { FileInspector.hex(MessageDigest.getInstance("SHA-1").digest(it.toByteArray())) }
    }
}
