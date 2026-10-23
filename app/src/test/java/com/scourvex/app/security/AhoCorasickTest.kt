package com.scourvex.app.security

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Random

/** The automaton (dense + sparse states, breadth-first numbering) against a brute-force matcher. */
class AhoCorasickTest {

    private fun fold(b: Int) = if (b in 0x41..0x5A) b + 0x20 else b

    private fun naive(pats: List<ByteArray>, data: ByteArray, len: Int, fold: Boolean): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>()
        for (end in 1..len) for ((id, p) in pats.withIndex()) {
            val st = end - p.size
            if (st < 0) continue
            var ok = true
            for (k in p.indices) {
                var a = data[st + k].toInt() and 0xFF
                var b = p[k].toInt() and 0xFF
                if (fold) { a = fold(a); b = fold(b) }
                if (a != b) { ok = false; break }
            }
            if (ok) out += id to end
        }
        return out.sortedWith(compareBy({ it.second }, { it.first }))
    }

    private fun scan(ac: AhoCorasick, data: ByteArray, len: Int): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>()
        ac.scan(data, len) { id, end -> out += id to end }
        return out.sortedWith(compareBy({ it.second }, { it.first }))
    }

    private fun check(seed: Long, alphabet: Int, patterns: Int, minLen: Int, maxLen: Int, fold: Boolean) {
        val rnd = Random(seed)
        val base = if (fold) 0x41 else 1
        fun sym() = (base + rnd.nextInt(alphabet)).toByte()
        val pats = List(patterns) { ByteArray(minLen + rnd.nextInt(maxLen - minLen + 1)) { sym() } } + listOf(byteArrayOf(sym()), byteArrayOf(sym(), sym()))
        // Plant some patterns in the data so deep states are really reached, not only the shallow ones.
        val data = ByteArray(40_000) { sym() }
        repeat(300) { val p = pats[rnd.nextInt(pats.size)]; val at = rnd.nextInt(data.size - p.size); System.arraycopy(p, 0, data, at, p.size) }
        if (fold) for (i in data.indices step 7) data[i] = (data[i].toInt() or 0x20).toByte()   // mixed case input
        val ac = AhoCorasick(pats, fold)
        assertEquals("seed=$seed alphabet=$alphabet", naive(pats, data, data.size, fold), scan(ac, data, data.size))
        assertEquals(naive(pats, data, 1234, fold), scan(ac, data, 1234))   // len shorter than the buffer
    }

    @Test fun smallAlphabet() = check(1, alphabet = 3, patterns = 60, minLen = 1, maxLen = 9, fold = false)

    @Test fun wideAlphabetPastTheDenseCap() = check(2, alphabet = 120, patterns = 9000, minLen = 3, maxLen = 7, fold = false)

    @Test fun caseFolded() = check(3, alphabet = 20, patterns = 200, minLen = 2, maxLen = 8, fold = true)

    @Test fun overlappingAndDuplicatePatterns() {
        val pats = listOf("abab", "bab", "ab", "abab", "b").map { it.toByteArray() }
        val data = "xababab".toByteArray()
        assertEquals(naive(pats, data, data.size, false), scan(AhoCorasick(pats, false), data, data.size))
    }
}
