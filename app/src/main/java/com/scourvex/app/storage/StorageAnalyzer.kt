package com.scourvex.app.storage

import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.AppStorage
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Perf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.util.PriorityQueue

data class AppSize(val pkg: String, val label: String, val app: Long, val data: Long, val cache: Long) {
    val total: Long get() = app + data + cache
}

data class FolderSize(val path: String, val size: Long, val files: Int)

data class StorageReport(
    val biggestFiles: List<Entry>,
    val biggestFolders: List<FolderSize>,
    val apps: List<AppSize>?,          // null without usage access
    val byType: Map<String, Long>,     // Images / Videos / Audio / Documents / APKs / Archives / Other
    val entries: List<Entry>,          // every file, kept for the duplicate finder
    val privileged: Boolean,
    val unused: List<UnusedApp>?,      // null without usage access
)

/** Biggest storage killers: files, folders, apps and file types, from one walk. */
object StorageAnalyzer {

    suspend fun scan(progress: (String, Int) -> Unit): StorageReport {
        var seen = 0
        return Perf.time("StorageAnalyzer.scan", { "files=$seen" }) { scanTimed(progress).also { seen = it.entries.size } }
    }

    private suspend fun scanTimed(progress: (String, Int) -> Unit): StorageReport = withContext(Dispatchers.IO) {
        coroutineScope {
            // Per-app sizes are binder calls: run them beside the walk.
            val appsJob = async { Perf.time("StorageAnalyzer.apps") { apps() } }

            val files = ArrayList<Entry>()
            val direct = HashMap<String, LongArray>()     // dir -> [bytes, files] of the files directly in it
            val roots = Files.roots()
            val prefixes = roots.map { "$it/" }
            var n = 0
            val privileged = Files.walkAll { e ->
                if (++n % 1000 == 0) progress(e.path, n)
                if (e.isDir) return@walkAll
                files += e
                val prefix = prefixes.firstOrNull { e.path.startsWith(it) } ?: return@walkAll
                val parent = e.path.substringBeforeLast('/')
                if (parent.length < prefix.length) return@walkAll    // directly in a volume root: the root is not listed
                val a = direct.getOrPut(parent) { LongArray(2) }
                a[0] += e.size; a[1]++
            }
            val folder = rollUp(direct, roots)            // counted at every ancestor, once, after the walk

            val top = PriorityQueue<Entry>(compareBy { it.size })
            for (e in files) { top.add(e); if (top.size > 200) top.poll() }

            // Biggest folders. Sorted biggest first, so a parent is listed before its children;
            // skip a child that is nearly all of an already-listed parent (DCIM vs DCIM/Camera).
            val ranked = folder.entries.sortedByDescending { it.value[0] }
            val folders = ArrayList<FolderSize>()
            for ((p, a) in ranked) {
                if (folders.size >= 100) break
                if (folders.any { p.startsWith(it.path + "/") && a[0] > it.size * 0.9 }) continue
                folders += FolderSize(p, a[0], a[1].toInt())
            }

            val byType = HashMap<String, Long>()
            for (e in files) byType.merge(typeOf(e.name), e.size, Long::plus)

            val apps = appsJob.await()
            StorageReport(
                top.sortedByDescending { it.size }, folders.sortedByDescending { it.size },
                apps, byType, files, privileged, Perf.time("UnusedApps.find") { UnusedApps.find(apps) },
            )
        }
    }

    /**
     * Adds every directory's [direct] totals ([bytes, files]) into all of its ancestors that are still below
     * their volume root (the root itself is never listed). Deepest directories go first, so each total is
     * complete before it is passed up: one pass instead of climbing the whole path for every file.
     * Changes and returns [direct].
     */
    internal fun rollUp(direct: HashMap<String, LongArray>, roots: List<String>): HashMap<String, LongArray> {
        val levels = ArrayList<ArrayList<String>>()
        fun level(d: Int): ArrayList<String> {
            while (levels.size <= d) levels.add(ArrayList())
            return levels[d]
        }
        fun depth(p: String): Int { var c = 0; for (ch in p) if (ch == '/') c++; return c }
        for (k in direct.keys) level(depth(k)).add(k)
        for (d in levels.lastIndex downTo 1) {
            for (path in levels[d]) {
                val root = roots.firstOrNull { path.startsWith("$it/") } ?: continue
                val parent = path.substringBeforeLast('/')
                if (parent.length <= root.length) continue
                val src = direct[path]!!
                var dst = direct[parent]
                if (dst == null) { dst = LongArray(2); direct[parent] = dst; level(d - 1).add(parent) }
                dst[0] += src[0]; dst[1] += src[1]
            }
        }
        return direct
    }

    fun typeOf(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
        "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "bmp", "dng", "raw", "avif" -> "Images"
        "mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v", "ts" -> "Videos"
        "mp3", "m4a", "aac", "ogg", "opus", "flac", "wav", "amr" -> "Audio"
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "epub", "odt" -> "Documents"
        "apk", "apks", "xapk", "apkm", "obb" -> "APKs & game data"
        "zip", "rar", "7z", "tar", "gz", "xz" -> "Archives"
        else -> "Other"
    }

    private suspend fun apps(): List<AppSize>? {
        val pm = ScourvexApp.instance.packageManager
        // No GET_META_DATA: nothing here reads the app's meta-data bundle, and loading it costs per app.
        val out = AppStorage.query(pm.getInstalledApplications(0)) { a, st ->
            AppSize(a.packageName, JunkScanner.appLabel(a, a.packageName), st.appBytes, st.dataBytes - st.cacheBytes, st.cacheBytes)
        } ?: return null
        return out.sortedByDescending { it.total }
    }
}
