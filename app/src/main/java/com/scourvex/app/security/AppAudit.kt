package com.scourvex.app.security

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.provider.Settings
import android.provider.Telephony

/** A risk finding for an installed app. Not a virus verdict: a list of reasons to look closer. */
data class AppRisk(
    val pkg: String,
    val label: String,
    val score: Int,
    val reasons: List<String>,
    val installer: String?,
)

/**
 * Permission / behaviour audit of user-installed apps, the checks stalkerware and banking
 * trojans trip: sideloaded + accessibility + SMS + hidden icon + device admin, and so on.
 */
class AppAudit(private val ctx: Context) {

    private val pm = ctx.packageManager
    private val accessibility = secureList("enabled_accessibility_services")
    private val listeners = secureList("enabled_notification_listeners")
    private val admins = runCatching {
        ctx.getSystemService(DevicePolicyManager::class.java).activeAdmins?.map { it.packageName }?.toSet()
    }.getOrNull() ?: emptySet()
    private val smsApp = runCatching { Telephony.Sms.getDefaultSmsPackage(ctx) }.getOrNull()
    private val launchable: Set<String> = pm.queryIntentActivities(
        Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), PackageManager.MATCH_ALL,
    ).map { it.activityInfo.packageName }.toSet()

    private fun secureList(key: String): Set<String> =
        (Settings.Secure.getString(ctx.contentResolver, key) ?: "").split(':')
            .mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }.toSet()

    fun audit(info: PackageInfo, label: () -> String): AppRisk? {
        val app = info.applicationInfo ?: return null
        val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
        if (system && app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0) return null
        val pkg = info.packageName
        if (pkg == ctx.packageName) return null

        val granted = HashSet<String>()
        info.requestedPermissions?.forEachIndexed { i, p ->
            val f = info.requestedPermissionsFlags?.getOrNull(i) ?: 0
            if (f and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) granted += p
        }
        val requested = info.requestedPermissions?.toSet() ?: emptySet()

        val installer = runCatching { pm.getInstallSourceInfo(pkg).installingPackageName }.getOrNull()
        // An updated system app shipped with the phone; its update source says nothing about origin.
        val sideloaded = !system && installer !in STORES

        var score = 0
        val why = ArrayList<String>()
        fun add(points: Int, reason: String) { score += points; why += reason }

        if (sideloaded) add(1, "Installed from outside an app store" + (installer?.let { " ($it)" } ?: ""))
        if (pkg in accessibility) add(if (sideloaded) 4 else 2, "Accessibility service is ON (can read and tap the screen)")
        if (pkg in admins) add(3, "Is an active device administrator")
        if (pkg in listeners) add(1, "Reads all notifications")
        if (pkg !in launchable) add(if (sideloaded) 3 else 1, "Has no app icon (hidden from the launcher)")
        val sms = granted.intersect(SMS)
        if (sms.isNotEmpty() && pkg != smsApp) add(3, "Can read or send SMS without being the SMS app")
        if (Manifest.permission.READ_CALL_LOG in granted) add(2, "Can read the call log")
        if (Manifest.permission.RECORD_AUDIO in granted && Manifest.permission.ACCESS_BACKGROUND_LOCATION in granted)
            add(2, "Microphone + background location")
        if (Manifest.permission.SYSTEM_ALERT_WINDOW in requested && pkg in accessibility) add(2, "Can draw over other apps while controlling the screen")
        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in requested && sideloaded) add(1, "Can install other apps")
        if (app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) add(1, "Debug build")

        return if (score >= THRESHOLD) AppRisk(pkg, label(), score, why, installer) else null
    }

    companion object {
        const val THRESHOLD = 4
        val STORES = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.google.android.feedback", "com.amazon.venezia")
        private val SMS = setOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS)
    }
}
