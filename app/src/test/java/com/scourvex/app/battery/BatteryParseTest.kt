package com.scourvex.app.battery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parser vs. real `dumpsys batterystats` output captured from the Android 16 emulator. */
class BatteryParseTest {

    @Test fun uids() {
        assertEquals(10155, BatteryAnalyzer.uidOf("u0a155"))
        assertEquals(1010003, BatteryAnalyzer.uidOf("u10a3"))
        assertEquals(1000, BatteryAnalyzer.uidOf("1000"))
    }

    @Test fun realDump() {
        val text = javaClass.classLoader!!.getResource("batterystats_emulator36.txt").readText()
        val rows = BatteryAnalyzer.parse(text)
        println(rows)
        assertTrue(rows.isNotEmpty())
        assertEquals(10155, rows[0].uid)
        assertTrue(rows[0].parts.startsWith("sensors 100%"))
        assertTrue(rows.zipWithNext().all { (a, b) -> a.mAh >= b.mAh })
    }
}
