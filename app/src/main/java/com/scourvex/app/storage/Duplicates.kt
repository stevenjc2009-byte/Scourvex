package com.scourvex.app.storage

import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.security.MessageDigest

/** A set of byte-identical files. [keep] is the suggested original (oldest, shortest path). */
data class DuplicateGroup(val size: Long, val files: List<Entry>) {
    val keep: Entry get() = files.minWith(compareBy<Entry> { it.mtime }.thenBy { it.path.length })
    val wasted: Long get() = size * (files.size - 1)
}

/**
 * Finds identical files: same size, then same first+last 64 KB, then same full SHA-256.
 * Only files that pass every stage are reported, so nothing is called a duplicate on a guess.
 */
object Duplicates {
    private const val MIN_SIZE = 4096L
    private const val EDGE = 64 * 1024

    suspend fun find(entries: List<Entry>, progress: (Int, Int) -> Unit): List<DuplicateGroup> = withContext(Dispatchers.IO) {
        val bySize = entries.filter { it.size >= MIN_SIZE }.groupBy { it.size }.values.filter { it.size > 1 }
        val total = bySize.sumOf { it.size }
        var done = 0
        val out = ArrayList<DuplicateGroup>()
        for (group in bySize) {
            currentCoroutineContext().ensureActive()
            val byEdge = group.groupBy { e -> hash(e, edgesOnly = true).also { progress(++done, total) } }
                .filterKeys { it != null }.values.filter { it.size > 1 }
            for (cand in byEdge) {
                val full = if (cand[0].size <= 2L * EDGE) mapOf("" to cand)   // edges already covered the whole file
                else cand.groupBy { hash(it, edgesOnly = false) }.filterKeys { it != null }
                full.values.filter { it.size > 1 }.forEach { out += DuplicateGroup(it[0].size, it) }
            }
        }
        out.sortedByDescending { it.wasted }
    }

    private suspend fun hash(e: Entry, edgesOnly: Boolean): String? {
        val md = MessageDigest.getInstance("SHA-256")
        val inp: InputStream = Files.open(e.path) ?: return null
        return runCatching {
            inp.use { s ->
                val buf = ByteArray(EDGE)
                if (edgesOnly) {
                    // First 64 KB, then skip to the last 64 KB (readNBytes/skipNBytes need API 33+).
                    var pos = 0L
                    val skipTo = if (e.size > 2L * EDGE) e.size - EDGE else -1L
                    while (true) {
                        if (pos == EDGE.toLong() && skipTo > 0) {
                            while (pos < skipTo) { val k = s.skip(skipTo - pos); if (k <= 0) break; pos += k }
                        }
                        val want = if (pos < EDGE && skipTo > 0) (EDGE - pos).toInt() else buf.size
                        val r = s.read(buf, 0, want); if (r < 0) break
                        md.update(buf, 0, r); pos += r
                    }
                } else {
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val r = s.read(buf); if (r < 0) break; md.update(buf, 0, r)
                    }
                }
                md.digest().joinToString("") { "%02x".format(it) }
            }
        }.getOrNull()
    }
}
