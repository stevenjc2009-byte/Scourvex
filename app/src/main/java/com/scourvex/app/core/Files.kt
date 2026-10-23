package com.scourvex.app.core

import android.os.Environment
import android.os.ParcelFileDescriptor
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.util.Locale

/** One file or directory found during a walk. */
data class Entry(val path: String, val size: Long, val mtime: Long, val isDir: Boolean) {
    val name: String get() = path.substringAfterLast('/')
}

/**
 * Walks every storage volume. Normal folders are read directly (all-files access);
 * Android/data and Android/obb go through Shizuku because Android blocks apps from them.
 */
object Files {

    val primary: String = Environment.getExternalStorageDirectory().absolutePath

    fun roots(): List<String> {
        val sm = ScourvexApp.instance.getSystemService(StorageManager::class.java)
        return sm.storageVolumes.mapNotNull { it.directory?.absolutePath }.ifEmpty { listOf(primary) }
    }

    /** Folders that only the shell uid can read on Android 11+. */
    fun restricted(root: String) = listOf("$root/Android/data", "$root/Android/obb")

    fun isRestricted(path: String) = roots().any { r -> restricted(r).any { path == it || path.startsWith("$it/") } }

    fun skipped(path: String, skip: List<String>) = skip.any { path == it || path.startsWith("$it/") }

    /**
     * Calls [visit] for every entry under all roots, honouring the skip list.
     * Returns true when Android/data + obb were included (Shizuku ready).
     */
    suspend fun walkAll(skip: List<String>, visit: (Entry) -> Unit): Boolean {
        var privileged = true
        for (root in roots()) {
            val blocked = restricted(root)
            walkDirect(File(root), skip + blocked, visit)
            for (b in blocked) {
                if (skipped(b, skip)) continue
                if (!walkShell(b, skip, visit)) privileged = false
            }
        }
        return privileged
    }

    suspend fun walkDirect(dir: File, skip: List<String>, visit: (Entry) -> Unit) {
        val stack = ArrayDeque<File>().apply { add(dir) }
        while (stack.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            val d = stack.removeLast()
            val children = d.listFiles() ?: continue
            for (f in children) {
                val p = f.absolutePath
                if (skipped(p, skip)) continue
                if (java.nio.file.Files.isSymbolicLink(f.toPath())) continue
                if (f.isDirectory) {
                    visit(Entry(p, 0, f.lastModified(), true))
                    stack.add(f)
                } else {
                    visit(Entry(p, f.length(), f.lastModified(), false))
                }
            }
        }
    }

    /** Walks [root] as shell uid. Returns false when Shizuku is not available. */
    suspend fun walkShell(root: String, skip: List<String>, visit: (Entry) -> Unit): Boolean {
        val pfd = Shell.walkPipe(root, skip) ?: return false
        ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().useLines { lines ->
            for (ln in lines) {
                currentCoroutineContext().ensureActive()
                val a = ln.split('\t', limit = 4)
                if (a.size == 4) visit(Entry(a[3], a[0].toLong(), a[1].toLong(), a[2] == "d"))
            }
        }
        return true
    }

    /** Opens a file for reading, through Shizuku when it lives in a restricted folder. */
    suspend fun open(path: String): InputStream? {
        if (!isRestricted(path)) return runCatching { FileInputStream(path) }.getOrNull()
        val s = Shell.get() ?: return null
        val pfd = runCatching { s.open(path) }.getOrNull() ?: return null
        return ParcelFileDescriptor.AutoCloseInputStream(pfd)
    }

    /** Deletes a file or folder tree. Returns bytes freed (0 if already gone, -1 on failure). */
    suspend fun delete(path: String): Long {
        // /data/... (spyware drop folders like /data/local/tmp) is only reachable as the shell user.
        if (isRestricted(path) || path.startsWith("/data/")) {
            val s = Shell.get() ?: return -1
            return runCatching { s.delete(path) }.getOrDefault(-1)
        }
        val f = File(path)
        if (!f.exists()) return 0
        var freed = 0L
        f.walkBottomUp().forEach { x ->
            val len = if (x.isFile) x.length() else 0
            if (x.delete()) freed += len
        }
        return if (f.exists()) -1 else freed
    }
}

fun formatBytes(b: Long): String {
    if (b < 1024) return "$b B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var v = b / 1024.0
    var i = 0
    while (v >= 1024 && i < units.lastIndex) { v /= 1024; i++ }
    return String.format(Locale.US, if (v >= 100) "%.0f %s" else "%.1f %s", v, units[i])
}
