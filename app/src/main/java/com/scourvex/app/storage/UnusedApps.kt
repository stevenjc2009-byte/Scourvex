package com.scourvex.app.storage

import android.app.PendingIntent
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.os.Build
import android.os.Process
import com.scourvex.app.ScourvexApp
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow

/** An installed app not opened for [UnusedApps.DAYS] days. [lastUsed] is 0 when Android has no record of it being opened. */
data class UnusedApp(val pkg: String, val label: String, val lastUsed: Long, val size: AppSize)

/** Apps you no longer open, biggest first, with archive (keep data, drop the APK) and uninstall. */
object UnusedApps {

    const val DAYS = 30
    private const val DAY = 86_400_000L

    /** (package, error message or null on success) for every archive attempt. */
    private val _results = MutableSharedFlow<Pair<String, String?>>(extraBufferCapacity = 8)
    val results: SharedFlow<Pair<String, String?>> = _results

    /** Needs usage access, like [sizes]; null without it. */
    fun find(sizes: List<AppSize>?): List<UnusedApp>? {
        sizes ?: return null
        val ctx = ScourvexApp.instance
        val pm = ctx.packageManager
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val now = System.currentTimeMillis()
        // Android keeps yearly buckets for about two years, so this reaches back as far as records go.
        val usage = usm.queryAndAggregateUsageStats(now - 730 * DAY, now)
        val cutoff = now - DAYS * DAY
        return sizes.mapNotNull { s ->
            if (s.pkg == ctx.packageName || pm.getLaunchIntentForPackage(s.pkg) == null) return@mapNotNull null
            val info = runCatching { pm.getPackageInfo(s.pkg, 0) }.getOrNull() ?: return@mapNotNull null
            val app = info.applicationInfo ?: return@mapNotNull null
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0 || info.firstInstallTime > cutoff) return@mapNotNull null
            val u = usage[s.pkg]
            val last = maxOf(u?.lastTimeUsed ?: 0, u?.lastTimeVisible ?: 0)
            if (last > cutoff) null else UnusedApp(s.pkg, s.label, last, s)
        }.sortedByDescending { it.size.total }
    }

    /** Archiving needs Shizuku, or Android 15+ (where the system asks the user to confirm). */
    val canArchive: Boolean get() = Shell.ready || Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM

    /** Result arrives on [results]. Fails for apps whose store does not support archiving (most sideloaded apps). */
    suspend fun archive(pkg: String) {
        if (Shell.ready) {
            val user = Process.myUserHandle().hashCode()
            val r = Shell.exec("pm archive --user $user '$pkg' 2>&1")
            val out = r?.second?.trim().orEmpty()
            _results.emit(pkg to if (r != null && r.first == 0 && !out.contains("Failure", true) && !out.contains("Error", true)) null
                else out.ifEmpty { "Archive failed" })
            return
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) { _results.emit(pkg to "Archiving needs Android 15 or Shizuku"); return }
        val ctx = ScourvexApp.instance
        val intent = Intent(ctx, ArchiveReceiver::class.java).putExtra(ArchiveReceiver.PKG, pkg)
        val pi = PendingIntent.getBroadcast(ctx, pkg.hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
        try {
            ctx.packageManager.packageInstaller.requestArchive(pkg, pi.intentSender)
        } catch (e: Exception) {
            _results.emit(pkg to (e.message ?: "Archive failed"))
        }
    }

    internal fun onResult(pkg: String, error: String?) { _results.tryEmit(pkg to error) }
}

/** Receives archive results; shows the system confirm screen when it asks for one. */
class ArchiveReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.getStringExtra(PKG) ?: return
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            PackageInstaller.STATUS_SUCCESS -> UnusedApps.onResult(pkg, null)
            else -> UnusedApps.onResult(pkg, intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "Archive failed ($status)")
        }
    }

    companion object { const val PKG = "pkg" }
}
