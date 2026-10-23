package com.scourvex.app.clean

import android.app.usage.StorageStatsManager
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.Files
import com.scourvex.app.core.SkipGuard
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class CleanReport(val freed: Long, val deleted: Int, val failed: List<String>, val cacheNote: String?)

/**
 * Deletes junk items. Files count the bytes actually deleted; app caches (cleared by the system, sizes unknown)
 * count the real free-space change around that one call — a whole-run free-space delta was skewed by other writes.
 */
object Cleaner {

    suspend fun clean(items: List<JunkItem>, progress: (Int, Int) -> Unit): CleanReport = withContext(Dispatchers.IO) {
        var freed = 0L
        var deleted = 0
        val failed = ArrayList<String>()
        var cacheNote: String? = null

        val appCaches = items.filter { it.path.startsWith("app:") }
        if (appCaches.isNotEmpty()) {
            val before = freeBytes()
            cacheNote = clearAppCaches()
            freed += (freeBytes() - before).coerceAtLeast(0)
            if (cacheNote == null) deleted += appCaches.size
        }
        val files = items.filterNot { it.path.startsWith("app:") }
        files.forEachIndexed { i, item ->
            progress(i + 1, files.size)
            val r = Files.delete(item.path)
            if (r >= 0) { deleted++; freed += r } else failed += item.path
        }
        CleanReport(freed, deleted, failed, cacheNote)
    }

    /**
     * Clears every app's internal + external cache. `pm trim-caches` asks the system to free
     * cache until the requested space is free; asking for far more than the disk holds empties
     * all of them. Returns an error note, or null on success.
     */
    private suspend fun clearAppCaches(): String? {
        // trim-caches empties every Android/data/<pkg>/cache system-wide and cannot exclude one; there is
        // no per-app cache cleaner here, so if the skip list could be hit we clear nothing.
        if (SkipGuard.blocksTrimCaches()) return "App caches skipped because a skip-list folder is inside an app cache"
        val r = Shell.exec("pm trim-caches 4096G") ?: return "Internal app caches need Shizuku (see Settings)"
        return if (r.first == 0) null else "pm trim-caches failed: ${r.second.trim().take(200)}"
    }

    fun freeBytes(): Long {
        val ssm = ScourvexApp.instance.getSystemService(StorageStatsManager::class.java)
        return runCatching { ssm.getFreeBytes(StorageManager.UUID_DEFAULT) }
            .getOrElse { java.io.File(Files.primary).freeSpace }
    }

    fun totalBytes(): Long {
        val ssm = ScourvexApp.instance.getSystemService(StorageStatsManager::class.java)
        return runCatching { ssm.getTotalBytes(StorageManager.UUID_DEFAULT) }
            .getOrElse { java.io.File(Files.primary).totalSpace }
    }
}
