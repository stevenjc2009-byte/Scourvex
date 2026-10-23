package com.scourvex.app.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.PowerManager
import com.scourvex.app.MainActivity
import com.scourvex.app.R
import com.scourvex.app.ScourvexApp

/**
 * Keeps a scan running when the screen turns off or the app is left: a foreground service (so Android
 * does not kill the process) plus a partial wake lock (so the CPU does not sleep). Started by [begin],
 * stopped by [end]; [update] refreshes the notification text and bar.
 */
object ScanKeeper {

    private const val CHANNEL = "scans"
    internal const val ID = 41

    @Volatile var title = ""; private set
    @Volatile var text = ""; private set
    @Volatile var progress: Float? = null; private set
    @Volatile var running = false; private set
    private var lastPost = 0L

    fun begin(what: String) {
        title = what; text = "Starting…"; progress = null; running = true
        val ctx = ScourvexApp.instance
        // Throws only when the app is in the background; scans are always started from a tap.
        runCatching { ctx.startForegroundService(Intent(ctx, ScanService::class.java)) }
    }

    /** Throttled to two posts a second: notification updates are rate-limited by Android. */
    fun update(text: String, progress: Float?) {
        this.text = text; this.progress = progress
        val now = System.currentTimeMillis()
        if (!running || now - lastPost < 500) return
        lastPost = now
        val ctx = ScourvexApp.instance
        runCatching { ctx.getSystemService(NotificationManager::class.java).notify(ID, build(ctx)) }
    }

    fun end() {
        if (!running) return
        running = false
        val ctx = ScourvexApp.instance
        runCatching { ctx.stopService(Intent(ctx, ScanService::class.java)) }
    }

    internal fun build(ctx: Context): Notification {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Running scans", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val p = progress
        return Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_scan)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(1000, ((p ?: 0f) * 1000).toInt(), p == null)
            .build()
    }
}

class ScanService : Service() {

    private var lock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        lock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "scourvex:scan")
            // Safety cap: a scan that somehow never ends still lets the phone sleep after 3 hours.
            .apply { acquire(3 * 60 * 60 * 1000L) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(ScanKeeper.ID, ScanKeeper.build(this), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        // If the scan already finished before Android got here, stop straight away.
        if (!ScanKeeper.running) stopSelf()
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        lock?.takeIf { it.isHeld }?.release()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
