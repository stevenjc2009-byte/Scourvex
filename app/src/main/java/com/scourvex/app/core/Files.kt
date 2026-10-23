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

/** One file or directory found during a walk. [unreadable]: a folder that could not be listed (second event for the same path). */
data class Entry(val path: String, val size: Long, val mtime: Long, val isDir: Boolean, val unreadable: Boolean = false) {
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

    private fun under(path: String, dirs: List<String>) = dirs.any { path == it || path.startsWith("$it/") }

    /**
     * Calls [visit] for every entry under all roots. The skip list is read live; a skipped path is
     * dropped from its parent's listing before any stat. Returns true when Android/data + obb were
     * included (Shizuku ready).
     */
    suspend fun walkAll(visit: (Entry) -> Unit): Boolean {
        var privileged = true
        for (root in roots()) {
            val blocked = restricted(root)
            walkDirect(File(root), visit, blocked)
            for (b in blocked) {
                if (SkipGuard.isSkipped(b)) continue
                if (!walkShell(b, visit)) privileged = false
            }
        }
        return privileged
    }

    /** Walks [dir] directly; [exclude] folders are left for the shell walker. Unlistable folders are reported [Entry.unreadable]. */
    suspend fun walkDirect(dir: File, visit: (Entry) -> Unit, exclude: List<String> = emptyList()) {
        if (!SkipGuard.allows(dir.path)) return
        val stack = ArrayDeque<File>().apply { add(dir) }
        while (stack.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            val d = stack.removeLast()
            val g = SkipGuard.live()          // re-read per directory: additions mid-scan apply
            if (g.isSkipped(d.path)) continue
            val children = d.listFiles()
            if (children == null) { visit(Entry(d.path, 0, 0, true, unreadable = true)); continue }
            for (f in children) {
                val p = f.path
                // Name check first: no stat, isDirectory or symlink probe ever touches a skipped child.
                if (g.isSkipped(p) || under(p, exclude)) continue
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
    suspend fun walkShell(root: String, visit: (Entry) -> Unit): Boolean {
        if (!SkipGuard.allows(root)) return true
        val pfd = Shell.walkPipe(root, SkipGuard.live().raw) ?: return false
        ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().useLines { lines ->
            for (ln in lines) {
                currentCoroutineContext().ensureActive()
                val a = ln.split('\t', limit = 4)
                // The service got the list at start; entries for paths skipped since are discarded here.
                if (a.size == 4 && !SkipGuard.isSkipped(a[3])) visit(Entry(a[3], a[0].toLong(), a[1].toLong(), a[2] != "f", unreadable = a[2] == "u"))
            }
        }
        return true
    }

    /** Opens a file for reading, through Shizuku when it lives in a restricted folder. Null for skipped paths. */
    suspend fun open(path: String): InputStream? {
        val g = SkipGuard.live()
        if (!g.allows(path)) return null
        if (!isRestricted(path)) {
            // A link planted after the scan could point into a skipped folder: never follow one.
            if (java.nio.file.Files.isSymbolicLink(java.nio.file.Paths.get(path))) return null
            return runCatching { FileInputStream(path) }.getOrNull()
        }
        val s = Shell.get() ?: return null
        val pfd = runCatching { s.open(path, g.raw.toTypedArray()) }.getOrNull() ?: return null
        return ParcelFileDescriptor.AutoCloseInputStream(pfd)
    }

    /**
     * Deletes a file or folder tree, never touching the skip list. Returns bytes freed (0 if already
     * gone, -1 on failure or when [path] is skipped). A folder holding skipped entries stays, minus its other content.
     */
    suspend fun delete(path: String): Long {
        val g = SkipGuard.live()
        if (!g.allows(path)) return -1
        // /data/... (spyware drop folders like /data/local/tmp) is only reachable as the shell user.
        if (isRestricted(path) || path.startsWith("/data/")) {
            val s = Shell.get() ?: return -1
            return runCatching { s.delete(path, g.raw.toTypedArray()) }.getOrDefault(-1)
        }
        return GuardedDelete.delete(path) { SkipGuard.live() }
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
