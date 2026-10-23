package com.scourvex.app.security

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.shizuku.Shell
import java.security.KeyStore
import java.security.cert.X509Certificate

data class DeviceFinding(
    val title: String,
    val detail: String,
    val level: Level,
    val action: String?,   // settings screen that fixes it
    val pkg: String? = null,
) {
    enum class Level { HIGH, MEDIUM, INFO }
}

/** Phone settings that weaken security, and certificates the user (or an app) added to the trust store. */
object DeviceAudit {

    private const val DEV = Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS
    private const val TRUSTED_CREDS = "com.android.settings.TRUSTED_CREDENTIALS_USER"

    suspend fun run(ctx: Context): List<DeviceFinding> {
        val out = ArrayList<DeviceFinding>()
        val fetched = prefetch()
        fun g(key: String) = fetched["global:$key"]
        fun sec(key: String) = fetched["secure:$key"]
        val H = DeviceFinding.Level.HIGH
        val M = DeviceFinding.Level.MEDIUM
        val I = DeviceFinding.Level.INFO

        if (!ctx.getSystemService(KeyguardManager::class.java).isDeviceSecure)
            out += DeviceFinding("No screen lock", "Anyone who picks up the phone can open it and every app on it.", H, Settings.ACTION_SECURITY_SETTINGS)
        // The Play Protect switch writes package_verifier_user_consent=-1 (checked on Android 16); older builds used package_verifier_enable=0.
        if (g("package_verifier_user_consent") == "-1" || g("package_verifier_enable") == "0")
            out += DeviceFinding("Play Protect app scanning is off", "Google no longer checks installed apps for harmful behaviour.", H, Settings.ACTION_SECURITY_SETTINGS)
        if (g("verifier_verify_adb_installs") == "0")
            out += DeviceFinding("Apps installed over USB are not checked", "\"Verify apps over USB\" is off in Developer options.", M, DEV)
        if (g(Settings.Global.ADB_ENABLED) == "1")
            out += DeviceFinding("USB debugging is on", "A computer you plug into can install apps and read data once you accept its key.", M, DEV)
        if (g("adb_wifi_enabled") == "1")
            out += DeviceFinding("Wireless debugging is on", "Shizuku needs it to start; turn it off when you are not starting Shizuku.", I, DEV)
        if (g(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == "1")
            out += DeviceFinding("Developer options are on", "Fine if you use Shizuku; otherwise turn them off.", I, DEV)

        try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val proxy = cm.defaultProxy?.let { "${it.host}:${it.port}" } ?: g(Settings.Global.HTTP_PROXY)?.takeIf { it.isNotBlank() && it != ":0" }
            if (proxy != null)
                out += DeviceFinding("Network proxy set: $proxy", "Web traffic goes through this server. Remove it unless you set it up.", H, Settings.ACTION_WIRELESS_SETTINGS)
            val vpnApp = sec("always_on_vpn_app")?.takeIf { it.isNotBlank() }
            val vpnOn = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            if (vpnApp != null || vpnOn)
                out += DeviceFinding("VPN active" + (vpnApp?.let { ": " + appName(ctx, it) + " (always on)" } ?: ""),
                    "All traffic goes through this VPN. Fine if you installed it on purpose.", I, Settings.ACTION_VPN_SETTINGS)
            val dns = cm.activeNetwork?.let { cm.getLinkProperties(it) }?.privateDnsServerName
            if (dns != null)
                out += DeviceFinding("Private DNS: $dns", "Website lookups go to this server. Fine if you chose it.", I, Settings.ACTION_WIRELESS_SETTINGS)
        } catch (e: Exception) {
            out += DeviceFinding("Could not check network settings", e.message ?: e.toString(), I, null)
        }

        for ((alias, cert) in userCerts())
            out += DeviceFinding("Extra trusted certificate: ${commonName(cert)}",
                "Added by you or an app ($alias). It can let someone read encrypted traffic. Remove it unless you know why it is there.", H, TRUSTED_CREDS)

        out += installers(ctx).map { (pkg, label) ->
            DeviceFinding("$label can install apps", "It is allowed to install other apps. Turn it off unless you need it.", M,
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkg)
        }
        return out
    }

    /** User-added CA certificates ("user:" aliases in the Android CA store). */
    fun userCerts(): List<Pair<String, X509Certificate>> = runCatching {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        ks.aliases().toList().filter { it.startsWith("user:") }.mapNotNull { a -> (ks.getCertificate(a) as? X509Certificate)?.let { a to it } }
    }.getOrDefault(emptyList())

    private fun commonName(c: X509Certificate): String {
        val dn = c.subjectX500Principal.name
        return Regex("(?:^|,)CN=([^,]+)").find(dn)?.groupValues?.get(1) ?: dn
    }

    /** Non-system apps (other than app stores and Scourvex) currently allowed to install apps. */
    private fun installers(ctx: Context): List<Pair<String, String>> {
        val pm = ctx.packageManager
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        @Suppress("DEPRECATION") val pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        return pkgs.mapNotNull { p ->
            val app = p.applicationInfo ?: return@mapNotNull null
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0 || p.packageName == ctx.packageName || p.packageName in AppAudit.STORES) return@mapNotNull null
            if (p.requestedPermissions?.contains("android.permission.REQUEST_INSTALL_PACKAGES") != true) return@mapNotNull null
            val mode = ops.unsafeCheckOpNoThrow("android:request_install_packages", app.uid, p.packageName)
            if (mode != AppOpsManager.MODE_ALLOWED) return@mapNotNull null
            p.packageName to JunkScanner.appLabel(app, p.packageName)
        }
    }

    private fun appName(ctx: Context, pkg: String) = runCatching {
        JunkScanner.appLabel(ctx.packageManager.getApplicationInfo(pkg, 0), pkg)
    }.getOrDefault(pkg)

    private val KEYS = listOf(
        "global" to "package_verifier_user_consent", "global" to "package_verifier_enable",
        "global" to "verifier_verify_adb_installs", "global" to Settings.Global.ADB_ENABLED,
        "global" to "adb_wifi_enabled", "global" to Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
        "global" to Settings.Global.HTTP_PROXY, "secure" to "always_on_vpn_app",
    )

    /**
     * Reads every setting the audit looks at once. Hidden keys can throw SecurityException for apps; those
     * are fetched together with a single shell call (the shell user may read them) instead of one exec each.
     */
    private suspend fun prefetch(): Map<String, String?> {
        val cr = com.scourvex.app.ScourvexApp.instance.contentResolver
        val out = HashMap<String, String?>()
        val denied = ArrayList<Pair<String, String>>()
        for ((table, key) in KEYS) {
            try {
                out["$table:$key"] = if (table == "global") Settings.Global.getString(cr, key) else Settings.Secure.getString(cr, key)
            } catch (_: SecurityException) {
                denied += table to key
            }
        }
        if (denied.isNotEmpty() && Shell.ready) {
            val script = denied.joinToString("; ") { (t, k) -> "echo \"$t:$k=\$(settings get $t $k)\"" }
            val text = Shell.exec(script)?.second.orEmpty()
            for (ln in text.lineSequence()) {
                val eq = ln.indexOf('=')
                if (eq < 0) continue
                val v = ln.substring(eq + 1).trim()
                out[ln.substring(0, eq)] = v.takeIf { it.isNotEmpty() && it != "null" }
            }
        }
        return out
    }
}
