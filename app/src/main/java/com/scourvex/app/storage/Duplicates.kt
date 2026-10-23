package com.scourvex.app.storage

import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Perf
import com.scourvex.app.security.FileInspector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

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

    suspend fun find(entries: List<Entry>, progress: (Int, Int) -> Unit): List<DuplicateGroup> {
        var groups = 0
        return Perf.time("Duplicates.find", { "entries=${entries.size} groups=$groups" }) { findTimed(entries, progress).also { groups = it.size } }
    }

    private const val WORKERS = 3
    private const val FULL_BUF = 256 * 1024

    private val edgeAcc = Perf.Acc("Duplicates.edge")
    private val fullAcc = Perf.Acc("Duplicates.full")

    private suspend fun findTimed(entries: List<Entry>, progress: (Int, Int) -> Unit): List<DuplicateGroup> = withContext(Dispatchers.IO) {
        val bySize = entries.filter { it.size >= MIN_SIZE }.groupBy { it.size }.values.filter { it.size > 1 }
        val total = bySize.sumOf { it.size }
        val done = AtomicInteger(0)
        val lastTick = AtomicLong(System.nanoTime())
        // Progress is throttled (every 50 files or 100 ms): a callback per file costs more than hashing a small one.
        fun tick() {
            val d = done.incrementAndGet()
            val now = System.nanoTime()
            val last = lastTick.get()
            if (d % 50 == 0 || (now - last >= 100_000_000L && lastTick.compareAndSet(last, now))) progress(d, total)
        }
        // Several size groups are hashed at once; each worker owns its digest and buffers. Results are kept by
        // group index so the output is the same as the sequential walk's.
        val results = arrayOfNulls<List<DuplicateGroup>>(bySize.size)
        val next = AtomicInteger(0)
        coroutineScope {
            repeat(minOf(WORKERS, bySize.size)) {
                launch {
                    val h = Hasher()
                    while (true) {
                        val gi = next.getAndIncrement()
                        if (gi >= bySize.size) break
                        currentCoroutineContext().ensureActive()
                        val group = bySize[gi]
                        val found = ArrayList<DuplicateGroup>()
                        val byEdge = group.groupBy { e -> h.hash(e, edgesOnly = true).also { tick() } }
                            .filterKeys { it != null }.values.filter { it.size > 1 }
                        for (cand in byEdge) {
                            val full = if (cand[0].size <= 2L * EDGE) mapOf("" to cand)   // edges already covered the whole file
                            else cand.groupBy { h.hash(it, edgesOnly = false) }.filterKeys { it != null }
                            full.values.filter { it.size > 1 }.forEach { found += DuplicateGroup(it[0].size, it) }
                        }
                        results[gi] = found
                    }
                }
            }
        }
        progress(done.get(), total)
        edgeAcc.flush(); fullAcc.flush()
        results.filterNotNull().flatten().sortedByDescending { it.wasted }
    }

    /** One worker's SHA-256 digest and read buffers, reused for every file it hashes. */
    private class Hasher {
        private val md = MessageDigest.getInstance("SHA-256")
        private val edgeBuf = ByteArray(EDGE)
        private val fullBuf = ByteArray(FULL_BUF)

        suspend fun hash(e: Entry, edgesOnly: Boolean): String? {
            val t0 = System.nanoTime()
            val r = hashInner(e, edgesOnly)
            (if (edgesOnly) edgeAcc else fullAcc).add(t0, if (r == null) 0 else if (edgesOnly) minOf(e.size, 2L * EDGE) else e.size)
            return r
        }

        private suspend fun hashInner(e: Entry, edgesOnly: Boolean): String? {
            md.reset()
            val inp: InputStream = Files.open(e.path) ?: return null
            return runCatching {
                inp.use { s ->
                    if (edgesOnly) {
                        val buf = edgeBuf
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
                        val buf = fullBuf
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val r = s.read(buf); if (r < 0) break; md.update(buf, 0, r)
                        }
                    }
                    FileInspector.hex(md.digest())
                }
            }.getOrNull()
        }
    }
}
