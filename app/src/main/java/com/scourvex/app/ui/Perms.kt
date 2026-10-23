package com.scourvex.app.ui

import android.app.AppOpsManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.os.Process
import android.provider.Settings

/** The special accesses Scourvex needs, and the system screens that grant them. */
object Perms {

    fun allFiles(): Boolean = Environment.isExternalStorageManager()

    fun usage(ctx: Context): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName) == AppOpsManager.MODE_ALLOWED
    }

    fun installs(ctx: Context): Boolean = ctx.packageManager.canRequestPackageInstalls()

    fun openAllFiles(ctx: Context) = open(ctx,
        Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${ctx.packageName}")),
        Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))

    fun openUsage(ctx: Context) = open(ctx,
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:${ctx.packageName}")),
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))

    fun openInstalls(ctx: Context) = open(ctx,
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}")))

    fun openAppInfo(ctx: Context, pkg: String) = open(ctx,
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))

    fun uninstall(ctx: Context, pkg: String) = open(ctx, Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))

    /** Opens Shizuku if installed, otherwise its Play Store page. */
    fun openShizuku(ctx: Context) {
        val launch = ctx.packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
        open(ctx, launch ?: Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=moe.shizuku.privileged.api")))
    }

    fun openUrl(ctx: Context, url: String) = open(ctx, Intent(Intent.ACTION_VIEW, Uri.parse(url)))

    private fun open(ctx: Context, vararg intents: Intent?) {
        for (i in intents) {
            if (i == null) continue
            try {
                ctx.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return
            } catch (_: ActivityNotFoundException) {
            } catch (_: SecurityException) {
            }
        }
    }
}
