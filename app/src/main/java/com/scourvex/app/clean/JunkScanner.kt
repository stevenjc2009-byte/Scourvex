package com.scourvex.app.clean

import android.app.usage.StorageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Prefs

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

    suspend fun scan(progress: (String, Int) -> Unit): JunkResult {
        val ctx = ScourvexApp.instance
        val pm = ctx.packageManager
        val installed = pm.getInstalledApplications(PackageManager.MATCH_UNINSTALLED_PACKAGES)
            .associateBy { it.packageName }
        val isInstalled = { p: String -> p in installed }

        val skip = Prefs.skip.value
        val roots = Files.roots()
        val targets = HashMap<String, JunkItem>()   // junk dir path -> item being summed
        val fileHits = ArrayList<JunkItem>()
        val dirs = HashSet<String>()
        val nonEmpty = HashSet<String>()
        var count = 0

        fun rootOf(p: String) = roots.firstOrNull { p.startsWith("$it/") }
        fun owningTarget(p: String): String? {
            var cur = p.substringBeforeLast('/', "")
            while (cur.isNotEmpty()) {
                if (cur in targets) return cur
                cur = cur.substringBeforeLast('/', "")
            }
            return null
        }

        val visit = { e: Entry ->
            count++
            if (count % 500 == 0) progress(e.path, count)
            val root = rootOf(e.path)
            if (root != null) {
                val rel = e.path.substring(root.length + 1)
                val owner = owningTarget(e.path)
                if (owner != null) {
                    if (!e.isDir) targets[owner] = targets[owner]!!.let { it.copy(size = it.size + e.size, files = it.files + 1) }
                } else if (e.isDir) {
                    val hit = JunkRules.classifyDir(rel, isInstalled)
                    if (hit != null) {
                        val label = hit.pkg?.let { appLabel(installed[it], it) } ?: rel
                        targets[e.path] = JunkItem(e.path, 0, hit.category, label, 0)
                    } else {
                        dirs.add(e.path)
                    }
                } else {
                    JunkRules.classifyFile(rel)?.let { fileHits.add(JunkItem(e.path, e.size, it, rel)) }
                }
                if (!e.isDir) markNonEmpty(e.path, nonEmpty)
                else if (e.path in targets) markNonEmpty(e.path, nonEmpty)
            }
        }
        val privileged = Files.walkAll(skip, visit)

        val items = ArrayList<JunkItem>()
        items += targets.values.filter { it.size > 0 || it.category == JunkCategory.LEFTOVERS || it.category == JunkCategory.RECYCLE_BINS }
        items += fileHits
        items += emptyFolders(dirs, nonEmpty, roots)

        val stats = appCaches(ctx, installed.values)
        if (stats != null) {
            // StorageStats cacheBytes already includes Android/data/<pkg>/cache; don't count it twice.
            val extCache = Regex("""/Android/data/[^/]+/cache$""")
            items.replaceAll { if (it.category == JunkCategory.APP_CACHE && extCache.containsMatchIn(it.path)) it.copy(size = 0) else it }
            items += stats
        }
        return JunkResult(items.sortedByDescending { it.size }, privileged, stats != null, count)
    }

    private fun markNonEmpty(path: String, set: HashSet<String>) {
        var cur = path.substringBeforeLast('/', "")
        while (cur.isNotEmpty() && set.add(cur)) cur = cur.substringBeforeLast('/', "")
    }

    private fun emptyFolders(dirs: Set<String>, nonEmpty: Set<String>, roots: List<String>): List<JunkItem> {
        val empty = dirs.filter { it !in nonEmpty }.filter { d ->
            val root = roots.firstOrNull { d.startsWith("$it/") } ?: return@filter false
            val rel = d.substring(root.length + 1)
            // Leave Android/ alone (apps expect their folders) and the standard top-level folders.
            !rel.startsWith("Android") && rel !in JunkRules.keepEmpty
        }.toSet()
        // Report only the top-most empty folder of each empty subtree.
        return empty.filter { it.substringBeforeLast('/') !in empty }
            .map { JunkItem(it, 0, JunkCategory.EMPTY_FOLDERS, it.substringAfterLast('/'), 0) }
    }

    /** Internal cache size per app from StorageStatsManager (needs usage access). */
    private fun appCaches(ctx: Context, apps: Collection<ApplicationInfo>): List<JunkItem>? {
        val ssm = ctx.getSystemService(StorageStatsManager::class.java)
        val user = Process.myUserHandle()
        val out = ArrayList<JunkItem>()
        for (a in apps) {
            val st = try {
                ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, a.packageName, user)
            } catch (_: SecurityException) {
                return null
            } catch (_: Exception) {
                continue
            }
            if (st.cacheBytes > 0) {
                out += JunkItem("app:${a.packageName}", st.cacheBytes, JunkCategory.APP_CACHE, appLabel(a, a.packageName))
            }
        }
        return out
    }

    fun appLabel(info: ApplicationInfo?, pkg: String): String =
        info?.let { runCatching { ScourvexApp.instance.packageManager.getApplicationLabel(it).toString() }.getOrNull() } ?: pkg
}
