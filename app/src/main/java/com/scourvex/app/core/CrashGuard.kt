package com.scourvex.app.core

import android.content.Context
import java.io.File

/**
 * Crash and interruption recovery. A crash is written to crash.txt (stack trace only, no file names
 * from the user's storage beyond what the trace holds) and the next launch offers to carry on.
 * A scan marked running at launch means the process died mid-scan (crash, or Android killed it).
 */
object CrashGuard {

    private lateinit var dir: File
    private val crashFile get() = File(dir, "crash.txt")
    private val runningFile get() = File(dir, "running.txt")

    fun install(ctx: Context) {
        dir = ctx.filesDir
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            runCatching {
                val what = runCatching { runningFile.readText() }.getOrDefault("")
                crashFile.writeText("${System.currentTimeMillis()}\n$what\n${e.stackTraceToString().take(8000)}")
            }
            previous?.uncaughtException(t, e)
        }
    }

    /** Called when a scan starts / ends, so an unfinished one can be reported after a restart. */
    fun scanStarted(what: String) { runCatching { runningFile.writeText(what) } }
    fun scanEnded() { runningFile.delete() }

    data class Notice(val crashed: Boolean, val scan: String?, val trace: String?)

    /** What happened last time, once: both markers are cleared by reading them. */
    fun takeNotice(): Notice? {
        val crash = runCatching { crashFile.readText() }.getOrNull()
        val scan = runCatching { runningFile.readText() }.getOrNull()
        crashFile.delete(); runningFile.delete()
        if (crash == null && scan == null) return null
        val lines = crash?.lines()
        return Notice(crash != null, scan ?: lines?.getOrNull(1)?.ifEmpty { null }, lines?.drop(2)?.joinToString("\n"))
    }
}
