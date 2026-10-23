package com.scourvex.app.security

import com.scourvex.app.security.SensorUse.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parser vs. real filtered `dumpsys appops` output from the Android 16 emulator. */
class SensorUseTest {

    @Test fun realDump() {
        val text = javaClass.classLoader!!.getResource("appops_emulator36.txt").readText()
        val r = SensorUse.parse(text)
        // Play services read fine location in the foreground; MONITOR_LOCATION must not count.
        val gms = r.getValue("com.google.android.gms")
        assertTrue(Kind.LOCATION in gms.last)
        assertTrue(gms.background.isEmpty())
        // com.android.phone has FINE_LOCATION allowed but never used.
        assertTrue("com.android.phone" !in r)
        // WAKE_LOCK in the cached state is not a sensor.
        assertTrue("audioserver" !in r)
    }

    @Test fun backgroundAndLatest() {
        val text = """
            |    Package com.spy:
            |      CAMERA (allow):
            |          Access: [fg-s] 2026-10-23 08:00:00.000 (-8h) duration=+5s
            |          Access: [bg-s] 2026-10-23 09:00:00.000 (-7h) duration=+5s
            |      RECORD_AUDIO (allow):
            |          Access: [top-s] 2026-10-23 10:00:00.000 (-6h)
            |      WAKE_LOCK (allow):
            |          Access: [cch-s] 2026-10-23 11:00:00.000 (-5h)
            |    Package com.ok:
            |      COARSE_LOCATION (allow):
            |          Access: [fgsvc-s] 2026-10-22 10:00:00.000 (-30h)
            """.trimMargin()
        val r = SensorUse.parse(text)
        val spy = r.getValue("com.spy")
        assertEquals(setOf(Kind.CAMERA), spy.background)
        assertEquals(setOf(Kind.CAMERA, Kind.MIC), spy.last.keys)
        assertEquals(3_600_000L, spy.last.getValue(Kind.MIC) - spy.last.getValue(Kind.CAMERA))
        assertEquals(setOf(Kind.LOCATION), r.getValue("com.ok").last.keys)
        assertTrue(r.getValue("com.ok").background.isEmpty())
    }
}
