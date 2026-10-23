package com.scourvex.app.update

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import com.scourvex.app.BuildConfig
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.Net
import com.scourvex.app.core.Prefs
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Self-update from GitHub Releases of [BuildConfig.GITHUB_REPO]: reads releases/latest
 * (the "sigpack" prerelease is never "latest"), downloads the APK and installs it —
 * silently through Shizuku when it's running, otherwise via the system installer prompt.
 */
object Updater {

    data class Release(val version: String, val notes: String, val apkUrl: String, val size: Long)

    sealed interface State {
        object Idle : State
        object Checking : State
        object UpToDate : State
        data class Available(val r: Release) : State
        data class Downloading(val done: Long, val total: Long) : State
        object Installing : State
        data class Failed(val why: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state

    /** Compares dotted versions numerically ("1.10.0" > "1.9.3"). */
    fun newer(remote: String, local: String): Boolean {
        val a = remote.trimStart('v', 'V').split('.', '-').map { it.toIntOrNull() ?: 0 }
        val b = local.trimStart('v', 'V').split('.', '-').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    suspend fun check(): State {
        _state.value = State.Checking
        val s = try {
            val j = JSONObject(Net.getText("https://api.github.com/repos/${BuildConfig.GITHUB_REPO}/releases/latest",
                mapOf("Accept" to "application/vnd.github+json")))
            val tag = j.getString("tag_name")
            val assets = j.getJSONArray("assets")
            val apk = (0 until assets.length()).map { assets.getJSONObject(it) }.firstOrNull { it.getString("name").endsWith(".apk") }
            Prefs.lastUpdateCheck = System.currentTimeMillis()
            when {
                apk == null -> State.Failed("Release $tag has no APK attached")
                newer(tag, BuildConfig.VERSION_NAME) ->
                    State.Available(Release(tag.trimStart('v'), j.optString("body"), apk.getString("browser_download_url"), apk.getLong("size")))
                else -> State.UpToDate
            }
        } catch (e: Exception) {
            State.Failed(e.message ?: "Update check failed")
        }
        _state.value = s
        return s
    }

    /** Checks at most every 6 hours when auto-check is on. */
    suspend fun checkIfDue() {
        if (Prefs.autoUpdateCheck && System.currentTimeMillis() - Prefs.lastUpdateCheck > 6 * 3600_000L) check()
    }

    suspend fun downloadAndInstall(r: Release) {
        val ctx = ScourvexApp.instance
        try {
            val dir = File(ctx.getExternalFilesDir(null), "updates").apply { mkdirs() }
            dir.listFiles()?.forEach { it.delete() }
            val apk = File(dir, "Scourvex-${r.version}.apk")
            Net.download(r.apkUrl, apk) { d, t -> _state.value = State.Downloading(d, if (t > 0) t else r.size) }
            _state.value = State.Installing
            if (!installWithShizuku(apk)) installWithPrompt(ctx, apk)
        } catch (e: Exception) {
            _state.value = State.Failed(e.message ?: "Update failed")
        }
    }

    private suspend fun installWithShizuku(apk: File): Boolean {
        if (!Shell.ready) return false
        // system_server can't open files on /sdcard (SELinux fuse denial), so stream the APK through stdin.
        val r = Shell.exec("cat '${apk.absolutePath}' | pm install -r -t -i ${BuildConfig.APPLICATION_ID} -S ${apk.length()}") ?: return false
        // On success the process is killed by the update; reaching here with an error means fall back.
        return r.first == 0 && r.second.contains("Success")
    }

    private suspend fun installWithPrompt(ctx: Context, apk: File) = withContext(Dispatchers.IO) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(BuildConfig.APPLICATION_ID)
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val intent = Intent(ctx, InstallReceiver::class.java)
            val pi = PendingIntent.getBroadcast(ctx, id, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
            session.commit(pi.intentSender)
        }
    }

    internal fun onInstallStatus(status: Int, message: String?) {
        _state.value = if (status == PackageInstaller.STATUS_SUCCESS) State.UpToDate
        else State.Failed(message ?: "Install failed ($status)")
    }
}

/** Receives PackageInstaller results; shows the system confirm screen when it asks for one. */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            else -> Updater.onInstallStatus(status, intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE))
        }
    }
}
