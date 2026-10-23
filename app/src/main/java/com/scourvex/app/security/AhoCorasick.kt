package com.scourvex.app.security

/**
 * Byte-level Aho-Corasick automaton: finds every occurrence of every anchor in one pass.
 * The root and the states one or two bytes deep have a dense 256-entry table with the failure links
 * already folded in (these are the states the scan sits in almost all the time); every other state
 * keeps sorted sparse edges, so memory stays proportional to the total anchor length (a dense table
 * per state needed >500 MB).
 */
class AhoCorasick(patterns: List<ByteArray>, private val fold: Boolean) {

    private val root = IntArray(256)
    private lateinit var edgeStart: IntArray   // state -> first edge index (CSR)
    private lateinit var edgeChar: IntArray
    private lateinit var edgeTo: IntArray
    private lateinit var fail: IntArray
    private lateinit var dense: IntArray   // rows of 256 for states 0 until denseN (flat), failure links folded in
    private var denseN = 0
    private lateinit var hasOut: LongArray // bit per state: it reports at least one pattern
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
        renumberBreadthFirst(children)
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
        val depth = IntArray(n)
        val bfs = ArrayList<Int>()
        val queue = ArrayDeque<Int>()
        for (c in 0 until 256) if (root[c] != 0) { queue.add(root[c]); depth[root[c]] = 1 }
        while (queue.isNotEmpty()) {
            val s = queue.removeFirst()
            bfs.add(s)
            for (e in edgeStart[s] until edgeStart[s + 1]) {
                val c = edgeChar[e]
                val t = edgeTo[e]
                var f = fail[s]
                var g = goto(f, c)
                while (g < 0) { f = fail[f]; g = goto(f, c) }
                fail[t] = g
                out[g]?.let { inherited -> out[t] = (out[t] ?: IntArray(0)) + inherited }
                depth[t] = depth[s] + 1
                queue.add(t)
            }
        }

        // Dense rows for depth 1 and 2 (BFS order: a state's failure target is shallower, so its row exists).
        // States are numbered breadth first, so the dense ones are exactly ids 0 until denseN: one flat table,
        // one compare instead of a pointer lookup, and the states the scan lives in sit together in memory.
        var deep2 = 0
        var last = 0
        for (s in bfs) {
            if (depth[s] > 2 || (depth[s] == 2 && deep2 >= MAX_DENSE_DEPTH2)) break
            if (depth[s] == 2) deep2++
            last = s
        }
        denseN = last + 1
        dense = IntArray(denseN * 256)
        System.arraycopy(root, 0, dense, 0, 256)
        for (s in 1 until denseN) {
            System.arraycopy(dense, fail[s] shl 8, dense, s shl 8, 256)
            for (e in edgeStart[s] until edgeStart[s + 1]) dense[(s shl 8) + edgeChar[e]] = edgeTo[e]
        }
        hasOut = LongArray((n + 63) ushr 6)
        for (s in 0 until n) if (out[s] != null) hasOut[s ushr 6] = hasOut[s ushr 6] or (1L shl (s and 63))
    }

    /** Renames the trie states in breadth-first order (children by byte value); [out] follows. */
    private fun renumberBreadthFirst(children: ArrayList<HashMap<Int, Int>>) {
        val n = children.size
        val order = IntArray(n)
        val newId = IntArray(n)
        var tail = 1
        for (head in 0 until n) {
            val old = order[head]
            newId[old] = head
            for (c in children[old].keys.sorted()) order[tail++] = children[old][c]!!
        }
        val oldOut = ArrayList(out)
        val oldChildren = ArrayList(children)
        for (i in 0 until n) {
            val o = order[i]
            children[i] = HashMap<Int, Int>(oldChildren[o].size * 2).also { m -> for ((c, t) in oldChildren[o]) m[c] = newId[t] }
            out[i] = oldOut[o]
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
        val tab = dense
        val dn = denseN
        for (i in 0 until len) {
            var c = buf[i].toInt() and 0xFF
            if (fold && c in 0x41..0x5A) c += 0x20
            if (s < dn) {
                s = tab[(s shl 8) + c]
            } else {
                while (true) {
                    val g = goto(s, c)
                    if (g >= 0) { s = g; break }
                    s = fail[s]
                    if (s < dn) { s = tab[(s shl 8) + c]; break }
                }
            }
            if (hasOut[s ushr 6] and (1L shl (s and 63)) != 0L) for (id in out[s]!!) hit(id, i + 1)
        }
    }

    private companion object { const val MAX_DENSE_DEPTH2 = 4096 }
}
