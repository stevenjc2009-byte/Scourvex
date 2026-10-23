package com.scourvex.app.shizuku

import android.os.ParcelFileDescriptor
import com.scourvex.app.IShellService
import com.scourvex.app.core.GuardedDelete
import com.scourvex.app.core.SkipSet
import java.io.File
import java.io.FileOutputStream
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes
import kotlin.system.exitProcess

/**
 * Runs in Shizuku's process as the shell uid. Shell can read and delete
 * /sdcard/Android/data and /sdcard/Android/obb, which normal apps cannot since Android 11.
 * Must keep a no-arg constructor: Shizuku instantiates it by class name.
 */
class ShellService : IShellService.Stub() {

    override fun destroy() {
        exitProcess(0)
    }

    override fun exec(command: String): String {
        val p = ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start()
        var bytes = ByteArray(0)
        val reader = Thread { bytes = p.inputStream.readBytes() }.apply { start() }
        // Some pm commands never return on some builds (pm clear --cache-only on Android 16): don't hang the app.
        if (!p.waitFor(EXEC_TIMEOUT_S, java.util.concurrent.TimeUnit.SECONDS)) {
            p.destroyForcibly()
            reader.join(2000)
            return "124\nTimed out after ${EXEC_TIMEOUT_S}s: $command"
        }
        reader.join()
        val text = String(bytes.copyOf(minOf(bytes.size, MAX_OUTPUT)))
        return "${p.exitValue()}\n$text"
    }

    override fun walk(root: String, skip: Array<String>, sink: ParcelFileDescriptor) {
        Thread {
            FileOutputStream(sink.fileDescriptor).writer(Charsets.UTF_8).buffered(64 * 1024).use { w ->
                try {
                    walkInto(File(root), SkipSet.of(skip.toList()), w)
                } catch (_: Throwable) {
                    // Pipe closed by the reader (scan cancelled) — stop quietly.
                }
            }
            sink.close()
        }.start()
    }

    private fun walkInto(dir: File, skip: SkipSet, w: java.io.Writer) {
        if (!skip.allows(dir.path)) return
        val stack = ArrayDeque<String>().apply { add(dir.path) }
        while (stack.isNotEmpty()) {
            val dp = stack.removeLast()
            val names = File(dp).list()
            if (names == null) { w.write("0\t0\tu\t$dp\n"); continue }
            val filter = skip.childFilter(dp)
            val pre = if (dp.endsWith("/")) dp else "$dp/"
            for (name in names) {
                val path = pre + name
                // Name check before any stat: a skipped child is never probed.
                if (filter.skips(path, name)) continue
                // One lstat per entry (never follows links: they can loop or escape the tree).
                val a = try {
                    java.nio.file.Files.readAttributes(java.nio.file.Paths.get(path), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                } catch (_: java.io.IOException) { continue }
                if (a.isSymbolicLink) continue
                val mtime = a.lastModifiedTime().toMillis()
                if (a.isDirectory) {
                    w.write("0\t$mtime\td\t$path\n")
                    stack.add(path)
                } else {
                    w.write("${a.size()}\t$mtime\tf\t$path\n")
                }
            }
        }
    }

    override fun open(path: String, skip: Array<String>): ParcelFileDescriptor {
        if (!skipSet(skip).allows(path)) throw SecurityException("skipped")
        if (java.nio.file.Files.isSymbolicLink(java.nio.file.Paths.get(path))) throw SecurityException("symlink")
        return ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    // The app hands over the same skip list on every open(): normalise it once, not once per file.
    @Volatile private var lastSkip: Pair<Array<String>, SkipSet>? = null

    private fun skipSet(skip: Array<String>): SkipSet {
        lastSkip?.let { if (it.first.contentEquals(skip)) return it.second }
        return SkipSet.of(skip.toList()).also { lastSkip = skip to it }
    }

    override fun delete(path: String, skip: Array<String>): Long {
        val g = SkipSet.of(skip.toList())
        return GuardedDelete.delete(path) { g }
    }

    private companion object {
        const val MAX_OUTPUT = 256 * 1024
        const val EXEC_TIMEOUT_S = 180L
    }
}
