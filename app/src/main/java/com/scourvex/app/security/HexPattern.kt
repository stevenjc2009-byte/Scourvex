package com.scourvex.app.security

/**
 * A ClamAV hex body signature (the subset build_sigpack.py lets through):
 * hex bytes, ?? / a? / ?a nibble wildcards, (aa|bb) equal-length alternatives,
 * {n} {-n} {n-m} [n-m] bounded gaps, and * / {n-} unbounded gaps.
 *
 * The pattern is split at unbounded gaps into [segments]; each segment has bounded length.
 * https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html
 */
class HexPattern private constructor(val segments: List<List<Item>>, val starMin: IntArray, val caseless: Boolean) {

    sealed interface Item
    /** Matches one byte: (b & mask) == value. */
    class B(val value: Int, val mask: Int) : Item
    class Gap(val min: Int, val max: Int) : Item
    class Alt(val options: List<ByteArray>) : Item { val len = options[0].size }

    /** A literal run inside segment [seg] starting [minOff]..[maxOff] bytes after the segment start. */
    class Anchor(val seg: Int, val minOff: Int, val maxOff: Int, val bytes: ByteArray)

    val anchor: Anchor? = pickAnchor()

    /** Tries segment [s] starting exactly at [pos]; returns end position or -1. */
    fun matchSegmentAt(buf: ByteArray, len: Int, s: Int, pos: Int): Int = matchItems(buf, len, segments[s], 0, pos)

    private fun matchItems(buf: ByteArray, len: Int, items: List<Item>, idx: Int, pos: Int): Int {
        var i = idx
        var p = pos
        while (i < items.size) {
            when (val it = items[i]) {
                is B -> {
                    if (p >= len) return -1
                    var b = buf[p].toInt() and 0xFF
                    if (caseless) b = fold(b)
                    if ((b and it.mask) != it.value) return -1
                    p++
                }
                is Alt -> {
                    if (p + it.len > len) return -1
                    if (it.options.none { o -> regionEquals(buf, p, o) }) return -1
                    p += it.len
                }
                is Gap -> {
                    if (it.min == it.max) {
                        p += it.min
                        if (p > len) return -1
                    } else {
                        for (g in it.min..it.max) {
                            if (p + g > len) return -1
                            val r = matchItems(buf, len, items, i + 1, p + g)
                            if (r >= 0) return r
                        }
                        return -1
                    }
                }
            }
            i++
        }
        return p
    }

    private fun regionEquals(buf: ByteArray, p: Int, o: ByteArray): Boolean {
        for (k in o.indices) {
            var b = buf[p + k].toInt() and 0xFF
            if (caseless) b = fold(b)
            if (b != (o[k].toInt() and 0xFF)) return false
        }
        return true
    }

    /** Earliest start >= [from] where segment [s] matches; returns (start, end) or null. */
    fun findSegment(buf: ByteArray, len: Int, s: Int, from: Int): IntArray? {
        var p = from
        while (p < len) {
            val e = matchSegmentAt(buf, len, s, p)
            if (e >= 0) return intArrayOf(p, e)
            p++
        }
        return null
    }

    /** Full match given that segment [s] matched at [start]..[end]. */
    fun verifyAround(buf: ByteArray, len: Int, s: Int, start: Int, end: Int): Boolean {
        // Segments before s must fit, in order, before start; greedy earliest is enough.
        var pos = 0
        for (k in 0 until s) {
            val hit = findSegment(buf, len, k, pos) ?: return false
            pos = hit[1] + starMin[k]
            if (pos > start) return false
        }
        pos = end
        for (k in s + 1 until segments.size) {
            val hit = findSegment(buf, len, k, pos + starMin[k - 1]) ?: return false
            pos = hit[1]
        }
        return true
    }

    /** Whole-buffer match for patterns with a fixed start range (no anchor search needed). */
    fun matchFrom(buf: ByteArray, len: Int, starts: IntRange): Boolean {
        for (st in starts) {
            if (st < 0 || st >= len) continue
            val e = matchSegmentAt(buf, len, 0, st)
            if (e >= 0 && verifyAround(buf, len, 0, st, e)) return true
        }
        return false
    }

    private fun pickAnchor(): Anchor? {
        var best: Anchor? = null
        for ((si, seg) in segments.withIndex()) {
            var lo = 0
            var hi = 0
            var runLo = 0
            var runHi = 0
            val run = ArrayList<Byte>()
            fun close() {
                if (run.size > (best?.bytes?.size ?: 0)) best = Anchor(si, runLo, runHi, run.toByteArray())
                run.clear()
            }
            for (it in seg) {
                if (it is B && it.mask == 0xFF) {
                    if (run.isEmpty()) { runLo = lo; runHi = hi }
                    run.add(it.value.toByte())
                    lo++; hi++
                } else {
                    close()
                    when (it) {
                        is B -> { lo++; hi++ }
                        is Alt -> { lo += it.len; hi += it.len }
                        is Gap -> { lo += it.min; hi += it.max }
                    }
                }
            }
            close()
        }
        return best
    }

    companion object {
        fun fold(b: Int) = if (b in 0x41..0x5A) b + 0x20 else b

        /**
         * Parses [hex]. [wide] turns each literal byte into a UTF-16LE pair (ClamAV ::w),
         * [caseless] folds ASCII case (::i). Returns null for syntax this matcher doesn't implement.
         */
        fun parse(hex: String, wide: Boolean = false, caseless: Boolean = false): HexPattern? {
            val s = hex.lowercase()
            val segments = ArrayList<List<Item>>()
            val stars = ArrayList<Int>()
            var cur = ArrayList<Item>()
            var i = 0
            fun lit(v: Int, m: Int) {
                cur.add(B(if (caseless) fold(v) and m else v and m, m))
                if (wide) cur.add(B(0, 0xFF))
            }
            fun gap(a: Int, b: Int) = cur.add(if (wide) Gap(a * 2, b * 2) else Gap(a, b))
            fun cut(min: Int) { segments.add(cur); stars.add(if (wide) min * 2 else min); cur = ArrayList() }
            while (i < s.length) {
                val c = s[i]
                when {
                    c == '*' -> { cut(0); i++ }
                    c == '{' || c == '[' -> {
                        val close = s.indexOf(if (c == '{') '}' else ']', i)
                        if (close < 0) return null
                        val body = s.substring(i + 1, close)
                        val (a, b) = body.split('-').let { if (it.size == 1) listOf(it[0], it[0]) else it }
                        when {
                            a.isEmpty() -> gap(0, b.toIntOrNull() ?: return null)
                            b.isEmpty() -> cut(a.toIntOrNull() ?: return null)
                            else -> {
                                val lo = a.toIntOrNull() ?: return null
                                val hi = b.toIntOrNull() ?: return null
                                if (hi < lo || hi - lo > 4096) return null
                                gap(lo, hi)
                            }
                        }
                        i = close + 1
                    }
                    c == '(' -> {
                        val close = s.indexOf(')', i)
                        if (close < 0) return null
                        val opts = s.substring(i + 1, close).split('|').map { o ->
                            if (o.length % 2 != 0 || !o.all { it in "0123456789abcdef" }) return null
                            val raw = o.chunked(2).map { it.toInt(16) }.map { if (caseless) fold(it) else it }
                            ByteArray(if (wide) raw.size * 2 else raw.size) { k ->
                                if (wide) (if (k % 2 == 0) raw[k / 2] else 0).toByte() else raw[k].toByte()
                            }
                        }
                        if (opts.size < 2 || opts.map { it.size }.toSet().size != 1) return null
                        cur.add(Alt(opts))
                        i = close + 1
                    }
                    i + 1 < s.length -> {
                        val hi = s[i]
                        val lo = s[i + 1]
                        when {
                            hi == '?' && lo == '?' -> { cur.add(B(0, 0)); if (wide) cur.add(B(0, 0)) }
                            hi == '?' -> lit(Character.digit(lo, 16).takeIf { it >= 0 } ?: return null, 0x0F)
                            lo == '?' -> lit((Character.digit(hi, 16).takeIf { it >= 0 } ?: return null) shl 4, 0xF0)
                            else -> {
                                val v = (s.substring(i, i + 2)).toIntOrNull(16) ?: return null
                                lit(v, 0xFF)
                            }
                        }
                        i += 2
                    }
                    else -> return null
                }
            }
            segments.add(cur)
            if (segments.any { it.isEmpty() }) return null
            return HexPattern(segments, stars.toIntArray(), caseless)
        }
    }
}
