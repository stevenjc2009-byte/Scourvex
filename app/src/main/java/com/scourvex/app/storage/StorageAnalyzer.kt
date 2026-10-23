package com.scourvex.app.storage

import android.app.usage.StorageStatsManager
import android.content.pm.PackageManager
import android.os.Process
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.Entry
import com.scourvex.app.core.Files
import com.scourvex.app.core.Prefs
import kotlinx.coroutines.Dispatchers
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

    suspend fun scan(progress: (String, Int) -> Unit): StorageReport = withContext(Dispatchers.IO) {
        val files = ArrayList<Entry>()
        val folder = HashMap<String, LongArray>()     // dir -> [bytes, files], counted at every ancestor
        val roots = Files.roots()
        var n = 0
        val privileged = Files.walkAll(Prefs.skip.value) { e ->
            if (++n % 1000 == 0) progress(e.path, n)
            if (e.isDir) return@walkAll
            files += e
            val root = roots.firstOrNull { e.path.startsWith("$it/") } ?: return@walkAll
            var d = e.path.substringBeforeLast('/')
            while (d.length > root.length) {
                val a = folder.getOrPut(d) { LongArray(2) }
                a[0] += e.size; a[1]++
                d = d.substringBeforeLast('/')
            }
        }

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

        val apps = apps()
        StorageReport(
            top.sortedByDescending { it.size }, folders.sortedByDescending { it.size },
            apps, byType, files, privileged, UnusedApps.find(apps),
        )
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

    private fun apps(): List<AppSize>? {
        val ctx = ScourvexApp.instance
        val ssm = ctx.getSystemService(StorageStatsManager::class.java)
        val user = Process.myUserHandle()
        val out = ArrayList<AppSize>()
        for (a in ctx.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)) {
            val st = try {
                ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, a.packageName, user)
            } catch (_: SecurityException) {
                return null
            } catch (_: Exception) {
                continue
            }
            out += AppSize(a.packageName, JunkScanner.appLabel(a, a.packageName), st.appBytes, st.dataBytes - st.cacheBytes, st.cacheBytes)
        }
        return out.sortedByDescending { it.total }
    }
}
