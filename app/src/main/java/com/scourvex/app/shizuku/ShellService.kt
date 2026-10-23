package com.scourvex.app.shizuku

import android.os.ParcelFileDescriptor
import com.scourvex.app.IShellService
import com.scourvex.app.core.GuardedDelete
import com.scourvex.app.core.SkipSet
import java.io.File
import java.io.FileOutputStream
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
            FileOutputStream(sink.fileDescriptor).bufferedWriter().use { w ->
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
        val stack = ArrayDeque<File>().apply { add(dir) }
        while (stack.isNotEmpty()) {
            val d = stack.removeLast()
            val children = d.listFiles()
            if (children == null) { w.write("0\t0\tu\t${d.path}\n"); continue }
            for (f in children) {
                val path = f.path
                // Name check before any stat: a skipped child is never probed.
                if (skip.isSkipped(path)) continue
                // Do not follow symlinks: they can loop or escape the tree.
                if (java.nio.file.Files.isSymbolicLink(f.toPath())) continue
                if (f.isDirectory) {
                    w.write("0\t${f.lastModified()}\td\t$path\n")
                    stack.add(f)
                } else {
                    w.write("${f.length()}\t${f.lastModified()}\tf\t$path\n")
                }
            }
        }
    }

    override fun open(path: String, skip: Array<String>): ParcelFileDescriptor {
        if (!SkipSet.of(skip.toList()).allows(path)) throw SecurityException("skipped")
        if (java.nio.file.Files.isSymbolicLink(java.nio.file.Paths.get(path))) throw SecurityException("symlink")
        return ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY)
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
