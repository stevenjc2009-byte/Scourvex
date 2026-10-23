package com.scourvex.app.core

import android.os.Environment
import android.os.ParcelFileDescriptor
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.nio.file.LinkOption
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

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

    /** Volume roots and the restricted folders below them, looked up once (a StorageManager binder call) and reused. */
    private class RootInfo(val roots: List<String>, val restricted: List<String>, val stamp: Long)

    @Volatile private var rootInfo: RootInfo? = null
    private const val ROOT_TTL_NS = 5_000_000_000L

    private fun info(): RootInfo {
        val c = rootInfo
        if (c != null && System.nanoTime() - c.stamp < ROOT_TTL_NS) return c
        val sm = ScourvexApp.instance.getSystemService(StorageManager::class.java)
        val roots = sm.storageVolumes.mapNotNull { it.directory?.absolutePath }.ifEmpty { listOf(primary) }
        return RootInfo(roots, roots.flatMap { restricted(it) }, System.nanoTime()).also { rootInfo = it }
    }

    /** Forget the cached volumes (a card may have been mounted); every walk starts with this. */
    fun refreshRoots() { rootInfo = null }

    fun roots(): List<String> = info().roots

    /** Folders that only the shell uid can read on Android 11+. */
    fun restricted(root: String) = listOf("$root/Android/data", "$root/Android/obb")

    fun isRestricted(path: String): Boolean {
        for (r in info().restricted) {
            if (path.startsWith(r) && (path.length == r.length || path[r.length] == '/')) return true
        }
        return false
    }

    private fun under(path: String, dirs: List<String>) = dirs.any { path == it || path.startsWith("$it/") }

    /**
     * Calls [visit] for every entry under all roots, always from the calling coroutine (never two threads at once).
     * The skip list is read live; a skipped path is dropped from its parent's listing before any stat. The
     * Android/data and obb shell walks run at the same time as the direct walk and are merged in here.
     * Returns true when Android/data + obb were included (Shizuku ready).
     */
    suspend fun walkAll(visit: (Entry) -> Unit): Boolean {
        refreshRoots()
        var n = 0
        var privileged = true
        return Perf.time("Files.walkAll", { "entries=$n privileged=$privileged" }) {
            val counted = { e: Entry -> n++; visit(e) }
            val roots = roots()
            coroutineScope {
                val shellEntries = Channel<Entry>(Channel.UNLIMITED)
                val denied = AtomicBoolean(false)
                val producers = ArrayList<Job>()
                for (root in roots) for (b in restricted(root)) {
                    if (SkipGuard.isSkipped(b)) continue
                    producers += launch(Dispatchers.IO) { if (!walkShell(b) { e -> shellEntries.trySend(e) }) denied.set(true) }
                }
                launch { producers.joinAll(); shellEntries.close() }
                val drain = {
                    while (true) { val e = shellEntries.tryReceive().getOrNull() ?: break; counted(e) }
                }
                for (root in roots) walkDirect(File(root), counted, restricted(root), drain)
                for (e in shellEntries) counted(e)
                privileged = !denied.get()
            }
            privileged
        }
    }

    /**
     * Walks [dir] directly; [exclude] folders are left for the shell walker. Unlistable folders are reported [Entry.unreadable].
     * [onDir] runs before each directory (used to merge the concurrent shell walks).
     */
    suspend fun walkDirect(dir: File, visit: (Entry) -> Unit, exclude: List<String> = emptyList(), onDir: () -> Unit = {}) {
        if (!SkipGuard.allows(dir.path)) return
        var n = 0
        var dirs = 0
        Perf.time("Files.walkDirect", { "root=${dir.path} entries=$n dirs=$dirs" }) {
            val stack = ArrayDeque<String>().apply { add(dir.path) }
            val ctx = currentCoroutineContext()
            while (stack.isNotEmpty()) {
                ctx.ensureActive()
                onDir()
                val dp = stack.removeLast()
                val g = SkipGuard.live()          // re-read per directory: additions mid-scan apply
                if (g.isSkipped(dp)) continue
                dirs++
                val names = File(dp).list()
                if (names == null) { visit(Entry(dp, 0, 0, true, unreadable = true)); continue }
                val filter = g.childFilter(dp)    // skip prefixes prepared once for this directory
                val pre = if (dp.endsWith("/")) dp else "$dp/"
                val insideExcluded = exclude.isNotEmpty() && under(dp, exclude)
                val excluded = if (exclude.isEmpty() || insideExcluded) null else
                    exclude.filter { it.startsWith(pre) && it.indexOf('/', pre.length) < 0 }.map { it.substring(pre.length) }.ifEmpty { null }
                for (name in names) {
                    if (insideExcluded) break
                    val p = pre + name
                    // Name check first: no stat, isDirectory or symlink probe ever touches a skipped child.
                    if (filter.skips(p, name) || (excluded != null && name in excluded)) continue
                    // One lstat per entry; a link is never followed.
                    val a = try {
                        java.nio.file.Files.readAttributes(Paths.get(p), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                    } catch (_: IOException) { continue }
                    if (a.isSymbolicLink) continue
                    n++
                    val mtime = a.lastModifiedTime().toMillis()
                    if (a.isDirectory) {
                        visit(Entry(p, 0, mtime, true))
                        stack.add(p)
                    } else {
                        visit(Entry(p, a.size(), mtime, false))
                    }
                }
            }
        }
    }

    /** Walks [root] as shell uid. Returns false when Shizuku is not available. */
    suspend fun walkShell(root: String, visit: (Entry) -> Unit): Boolean {
        if (!SkipGuard.allows(root)) return true
        var lines = 0
        var visited = 0
        return Perf.time("Files.walkShell", { "root=$root lines=$lines entries=$visited" }) {
            val start = SkipGuard.live()
            val pfd = Shell.walkPipe(root, start.raw) ?: return@time false
            val ctx = currentCoroutineContext()
            ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().useLines { seq ->
                for (ln in seq) {
                    lines++
                    ctx.ensureActive()
                    // size \t mtime \t type \t path (the path may itself hold tabs)
                    val i1 = ln.indexOf('\t')
                    val i2 = if (i1 < 0) -1 else ln.indexOf('\t', i1 + 1)
                    val i3 = if (i2 < 0) -1 else ln.indexOf('\t', i2 + 1)
                    if (i3 < 0) continue
                    val path = ln.substring(i3 + 1)
                    // The service got the list at start and filtered with it; only a list changed since needs a re-check here.
                    val g = SkipGuard.live()
                    if (g !== start && g.isSkipped(path)) continue
                    val type = if (i3 == i2 + 2) ln[i2 + 1] else '?'
                    visited++
                    visit(Entry(path, ln.substring(0, i1).toLong(), ln.substring(i1 + 1, i2).toLong(), type != 'f', unreadable = type == 'u'))
                }
            }
            true
        }
    }

    /** Opens a file for reading, through Shizuku when it lives in a restricted folder. Null for skipped paths. */
    suspend fun open(path: String): InputStream? {
        val g = SkipGuard.live()
        if (!g.allows(path)) return null
        if (!isRestricted(path)) {
            // A link planted after the scan could point into a skipped folder: never follow one.
            if (java.nio.file.Files.isSymbolicLink(Paths.get(path))) return null
            return runCatching { FileInputStream(path) }.getOrNull()
        }
        var s = Shell.get() ?: return null
        val pfd = try {
            s.open(path, g.rawArray)
        } catch (_: android.os.DeadObjectException) {
            Shell.invalidate()                      // the service died: rebind once and retry
            s = Shell.get() ?: return null
            runCatching { s.open(path, g.rawArray) }.getOrNull()
        } catch (_: Exception) {
            null
        } ?: return null
        return ParcelFileDescriptor.AutoCloseInputStream(pfd)
    }

    /**
     * Deletes a file or folder tree, never touching the skip list. Returns bytes freed (0 if already
     * gone, -1 on failure or when [path] is skipped). A folder holding skipped entries stays, minus its other content.
     */
    suspend fun delete(path: String): Long = withContext(Dispatchers.IO) { deleteOnIo(path) }

    private suspend fun deleteOnIo(path: String): Long {
        val g = SkipGuard.live()
        if (!g.allows(path)) return -1
        // /data/... (spyware drop folders like /data/local/tmp) is only reachable as the shell user.
        if (isRestricted(path) || path.startsWith("/data/")) {
            val s = Shell.get() ?: return -1
            return runCatching { s.delete(path, g.rawArray) }.getOrDefault(-1)
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
