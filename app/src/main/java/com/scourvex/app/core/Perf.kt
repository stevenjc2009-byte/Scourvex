package com.scourvex.app.core

import android.util.Log
import java.util.concurrent.atomic.AtomicLong

/** Timing logs for scans: `adb logcat -s ScourvexPerf`. Logging never throws (unit tests have no Log). */
object Perf {
    const val TAG = "ScourvexPerf"

    fun log(tag: String, ms: Long, extra: String = "") {
        runCatching { Log.i(TAG, "$tag ms=$ms${if (extra.isEmpty()) "" else " $extra"}") }
    }

    inline fun <T> time(tag: String, extra: () -> String = { "" }, block: () -> T): T {
        val t0 = System.nanoTime()
        try {
            return block()
        } finally {
            log(tag, (System.nanoTime() - t0) / 1_000_000, extra())
        }
    }

    /** Thread-safe accumulator for time spent in a repeated step; [flush] logs and resets it. */
    class Acc(private val tag: String) {
        private val nanos = AtomicLong()
        private val count = AtomicLong()
        private val bytes = AtomicLong()
        fun add(startNanos: Long, byteCount: Long = 0) {
            nanos.addAndGet(System.nanoTime() - startNanos); count.incrementAndGet(); bytes.addAndGet(byteCount)
        }
        fun flush(extra: String = "") {
            log(tag, nanos.getAndSet(0) / 1_000_000, "n=${count.getAndSet(0)} bytes=${bytes.getAndSet(0)} $extra".trim())
        }
    }
}
