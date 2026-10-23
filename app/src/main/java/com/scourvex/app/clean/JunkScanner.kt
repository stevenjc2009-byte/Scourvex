package com.scourvex.app.clean

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.AppStorage
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Perf
import com.scourvex.app.core.SkipGuard
import com.scourvex.app.core.SkipSet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

data class JunkItem(
    val path: String,          // file/dir path, or "app:<package>" for internal app cache
    val size: Long,
    val category: JunkCategory,
    val label: String,
    val files: Int = 1,
)

data class JunkResult(
    val items: List<JunkItem>,
    val privileged: Boolean,     // Android/data + obb were scanned (Shizuku ready)
    val appStatsAvailable: Boolean,
    val filesScanned: Int,
) {
    fun byCategory() = items.groupBy { it.category }
    fun total(cat: JunkCategory) = items.filter { it.category == cat }.sumOf { it.size }
}

/** Walks all storage once and sorts every junk hit into a [JunkCategory]. */
object JunkScanner {

    /** A junk folder being summed up; mutable so a file adds to it without copying an item per file. */
    private class Target(val path: String, val category: JunkCategory, val label: String) {
        var size = 0L
        var files = 0
        fun item() = JunkItem(path, size, category, label, files)
    }

    private val extCache = Regex("""/Android/data/[^/]+/cache$""")

    suspend fun scan(progress: (String, Int) -> Unit): JunkResult {
        var scanned = 0
        return Perf.time("JunkScanner.scan", { "files=$scanned" }) { scanTimed(progress).also { scanned = it.filesScanned } }
    }

    private suspend fun scanTimed(progress: (String, Int) -> Unit): JunkResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val pm = ScourvexApp.instance.packageManager
            val installed = pm.getInstalledApplications(PackageManager.MATCH_UNINSTALLED_PACKAGES)
                .associateBy { it.packageName }
            val isInstalled = { p: String -> p in installed }

            // Per-app cache sizes are binder calls: run them beside the walk instead of after it.
            val statsJob = async {
                Perf.time("JunkScanner.appCaches", { "apps=${installed.size}" }) {
                    AppStorage.query(installed.values) { a, st ->
                        if (st.cacheBytes > 0) JunkItem("app:${a.packageName}", st.cacheBytes, JunkCategory.APP_CACHE, appLabel(a, a.packageName)) else null
                    }
                }
            }

            val roots = Files.roots()
            val rootPrefixes = roots.map { "$it/" }
            val ownerOf = HashMap<String, Target>()      // a junk folder, and every folder inside one -> that junk folder
            val targets = ArrayList<Target>()
            val fileHits = ArrayList<JunkItem>()
            val dirs = HashSet<String>()
            val nonEmpty = HashSet<String>()
            var count = 0

            val visitEntry = { e: Entry ->
                count++
                if (count % 500 == 0) progress(e.path, count)
                val prefix = rootPrefixes.firstOrNull { e.path.startsWith(it) }
                if (prefix != null) {
                    val rel = e.path.substring(prefix.length)
                    // A parent is always visited before its children, so its owner is already known: no climbing.
                    val owner = ownerOf[e.path.substring(0, e.path.lastIndexOf('/'))]
                    var isTarget = false
                    if (owner != null) {
                        if (e.isDir) ownerOf[e.path] = owner else { owner.size += e.size; owner.files++ }
                    } else if (e.isDir) {
                        val hit = JunkRules.classifyDir(rel, isInstalled)
                        if (hit != null) {
                            val label = hit.pkg?.let { appLabel(installed[it], it) } ?: rel
                            val t = Target(e.path, hit.category, label)
                            targets += t
                            ownerOf[e.path] = t
                            isTarget = true
                        } else {
                            dirs.add(e.path)
                        }
                    } else {
                        JunkRules.classifyFile(rel)?.let { fileHits.add(JunkItem(e.path, e.size, it, rel)) }
                    }
                    if (!e.isDir || isTarget) markNonEmpty(e.path, nonEmpty)
                }
            }
            val visitAcc = Perf.Acc("JunkScanner.visit")
            val visit = { e: Entry ->
                val t0 = System.nanoTime()
                // A folder that could not be listed may hold anything: never offer it (or its parents) as empty.
                if (e.unreadable) { nonEmpty.add(e.path); markNonEmpty(e.path, nonEmpty) } else visitEntry(e)
                visitAcc.add(t0)
            }
            val privileged = Files.walkAll(visit)
            visitAcc.flush("targets=${targets.size} dirs=${dirs.size}")

            // Junk folders that hold a skipped entry stay in the list (size already excludes the skipped part);
            // deleting them goes through the guarded delete, which removes only the non-skipped content.
            val live = SkipGuard.live()
            val items = ArrayList<JunkItem>()
            items += targets.filter { it.size > 0 || it.category == JunkCategory.LEFTOVERS || it.category == JunkCategory.RECYCLE_BINS }
                .map { it.item() }
            items += fileHits
            items += Perf.time("JunkScanner.emptyFolders", { "dirs=${dirs.size}" }) { emptyFolders(dirs, nonEmpty, rootPrefixes, live) }
            items.removeAll { !it.path.startsWith("app:") && live.isSkipped(it.path) }

            val stats = statsJob.await()
            if (stats != null) {
                // StorageStats cacheBytes already includes Android/data/<pkg>/cache; don't count it twice.
                items.replaceAll { if (it.category == JunkCategory.APP_CACHE && extCache.containsMatchIn(it.path)) it.copy(size = 0) else it }
                items += stats
            }
            JunkResult(items.sortedByDescending { it.size }, privileged, stats != null, count)
        }
    }

    private fun markNonEmpty(path: String, set: HashSet<String>) {
        var cur = path.substringBeforeLast('/', "")
        while (cur.isNotEmpty() && set.add(cur)) cur = cur.substringBeforeLast('/', "")
    }

    private fun emptyFolders(dirs: Set<String>, nonEmpty: Set<String>, rootPrefixes: List<String>, skip: SkipSet): List<JunkItem> {
        // A folder that is a parent of a skip entry is not empty, even though the skipped child was never walked.
        val empty = dirs.filter { it !in nonEmpty && !skip.isAncestorOfSkip(it) }.filter { d ->
            val prefix = rootPrefixes.firstOrNull { d.startsWith(it) } ?: return@filter false
            val rel = d.substring(prefix.length)
            // Leave Android/ alone (apps expect their folders) and the standard top-level folders.
            !rel.startsWith("Android") && rel !in JunkRules.keepEmpty
        }.toSet()
        // Report only the top-most empty folder of each empty subtree.
        return empty.filter { it.substringBeforeLast('/') !in empty }
            .map { JunkItem(it, 0, JunkCategory.EMPTY_FOLDERS, it.substringAfterLast('/'), 0) }
    }

    fun appLabel(info: ApplicationInfo?, pkg: String): String =
        info?.let { runCatching { ScourvexApp.instance.packageManager.getApplicationLabel(it).toString() }.getOrNull() } ?: pkg
}
