package com.scourvex.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Matcher pieces on hand-built inputs (no sig pack needed). */
class EngineTest {

    @Test fun ahoCorasickFindsAllOverlapping() {
        val ac = AhoCorasick(listOf("he".toByteArray(), "she".toByteArray(), "hers".toByteArray()), fold = false)
        val hits = ArrayList<Pair<Int, Int>>()
        val buf = "ushers".toByteArray()
        ac.scan(buf, buf.size) { id, end -> hits += id to end }
        assertEquals(setOf(1 to 4, 0 to 4, 2 to 6), hits.toSet())
    }

    @Test fun ahoCorasickFolded() {
        val ac = AhoCorasick(listOf("evil".toByteArray()), fold = true)
        var n = 0
        val buf = "xxEvILxx".toByteArray()
        ac.scan(buf, buf.size) { _, _ -> n++ }
        assertEquals(1, n)
    }

    @Test fun hexPatternWildcardsAndGaps() {
        val p = HexPattern.parse("6162??64{2-3}(6566|6768)*7a7a")!!
        val ok = "ab_dXXefQQQzz".toByteArray()
        assertTrue(p.matchFrom(ok, ok.size, 0..0))
        val bad = "ab_dXXXXegzz".toByteArray()     // gap of 4 is too long
        assertFalse(p.matchFrom(bad, bad.size, 0..0))
    }

    @Test fun hexPatternWide() {
        val p = HexPattern.parse("616263", wide = true)!!
        val buf = byteArrayOf(0x61, 0, 0x62, 0, 0x63, 0)
        assertTrue(p.matchFrom(buf, buf.size, 0..0))
    }

    @Test fun ldbExpressions() {
        assertTrue(LdbExpr.parse("0&1")!!.eval(intArrayOf(1, 2)).count > 0)
        assertFalse(LdbExpr.parse("0&1")!!.eval(intArrayOf(1, 0)).count > 0)
        assertTrue(LdbExpr.parse("0|1")!!.eval(intArrayOf(0, 1)).count > 0)
        assertTrue(LdbExpr.parse("(0|1)&2=0")!!.eval(intArrayOf(1, 0, 0)).count > 0)
        assertFalse(LdbExpr.parse("(0|1)&2=0")!!.eval(intArrayOf(1, 0, 1)).count > 0)
        assertTrue(LdbExpr.parse("0>2")!!.eval(intArrayOf(3)).count > 0)
        assertFalse(LdbExpr.parse("0>2")!!.eval(intArrayOf(2)).count > 0)
        assertTrue(LdbExpr.parse("(0|1|2)>1,1")!!.eval(intArrayOf(1, 1, 0)).count > 0)
        assertNull(LdbExpr.parse("0&"))
    }

    @Test fun bodySigsNdbAndLdb() {
        val (b, skipped) = BodySigs.parse(sequenceOf(
            "N\tTest.Ndb:0:*:6576696c????636f6465",
            "L\tTest.Ldb;Engine:51-255,Target:0;0&1;6669727374;7365636f6e64::w",
        ))
        assertEquals(0, skipped)
        val a = "....evil__code....".toByteArray()
        assertEquals(listOf("Test.Ndb"), b.match(a, a.size, false))
        val wide = "first".toByteArray() + "second".flatMap { listOf(it.code.toByte(), 0) }.toByteArray()
        assertEquals(listOf("Test.Ldb"), b.match(wide, wide.size, false))
        val half = "first".toByteArray()
        assertTrue(b.match(half, half.size, false).isEmpty())
    }

    @Test fun eicarBuiltIn() {
        assertNotNull(SigPack.EICAR_MD5)
        assertEquals(16, SigPack.EICAR_MD5.size)
    }
}
