package com.scourvex.app.security

/**
 * Byte-level Aho-Corasick automaton: finds every occurrence of every anchor in one pass.
 * The root has a dense 256-entry table; other states keep sorted sparse edges, so memory
 * stays proportional to the total anchor length (a dense table per state needed >500 MB).
 */
class AhoCorasick(patterns: List<ByteArray>, private val fold: Boolean) {

    private val root = IntArray(256)
    private lateinit var edgeStart: IntArray   // state -> first edge index (CSR)
    private lateinit var edgeChar: IntArray
    private lateinit var edgeTo: IntArray
    private lateinit var fail: IntArray
    private val out = ArrayList<IntArray?>()

    init {
        val children = ArrayList<HashMap<Int, Int>>()
        children.add(HashMap())
        out.add(null)
        patterns.forEachIndexed { id, p ->
            var s = 0
            for (b in p) {
                var c = b.toInt() and 0xFF
                if (fold) c = HexPattern.fold(c)
                s = children[s].getOrPut(c) {
                    children.add(HashMap(4))
                    out.add(null)
                    children.size - 1
                }
            }
            out[s] = (out[s] ?: IntArray(0)) + id
        }
        val n = children.size
        edgeStart = IntArray(n + 1)
        for (s in 0 until n) edgeStart[s + 1] = edgeStart[s] + children[s].size
        edgeChar = IntArray(edgeStart[n])
        edgeTo = IntArray(edgeStart[n])
        for (s in 0 until n) {
            var e = edgeStart[s]
            for ((c, t) in children[s].entries.sortedBy { it.key }) { edgeChar[e] = c; edgeTo[e] = t; e++ }
        }
        for (c in 0 until 256) root[c] = children[0][c] ?: 0

        fail = IntArray(n)
        val queue = ArrayDeque<Int>()
        for (c in 0 until 256) if (root[c] != 0) queue.add(root[c])
        while (queue.isNotEmpty()) {
            val s = queue.removeFirst()
            for (e in edgeStart[s] until edgeStart[s + 1]) {
                val c = edgeChar[e]
                val t = edgeTo[e]
                var f = fail[s]
                var g = goto(f, c)
                while (g < 0) { f = fail[f]; g = goto(f, c) }
                fail[t] = g
                out[g]?.let { inherited -> out[t] = (out[t] ?: IntArray(0)) + inherited }
                queue.add(t)
            }
        }
    }

    /** Edge from [s] on [c], or -1. The root always has a transition (to itself if none). */
    private fun goto(s: Int, c: Int): Int {
        if (s == 0) return root[c]
        for (e in edgeStart[s] until edgeStart[s + 1]) {
            val ch = edgeChar[e]
            if (ch == c) return edgeTo[e]
            if (ch > c) break
        }
        return -1
    }

    /** Calls [hit] with (patternId, endPositionExclusive) for every occurrence. */
    fun scan(buf: ByteArray, len: Int, hit: (Int, Int) -> Unit) {
        var s = 0
        for (i in 0 until len) {
            var c = buf[i].toInt() and 0xFF
            if (fold && c in 0x41..0x5A) c += 0x20
            var g = goto(s, c)
            while (g < 0) { s = fail[s]; g = goto(s, c) }
            s = g
            val o = out[s]
            if (o != null) for (id in o) hit(id, i + 1)
        }
    }
}
