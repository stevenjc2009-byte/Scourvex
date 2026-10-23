package com.scourvex.app.security

import org.junit.Assert.assertEquals
import org.junit.Test

class SpywareParsePropsTest {
    @Test fun parsesGetpropOutput() {
        val m = SpywareCheck.parseProps("[ro.build.id]: [TP1A.220624.014]\n[persist.sys.x]: []\nnoise line\n[a.b]: [with: colon]\n")
        assertEquals("TP1A.220624.014", m["ro.build.id"])
        assertEquals("", m["persist.sys.x"])
        assertEquals("with: colon", m["a.b"])
        assertEquals(3, m.size)
    }
}
