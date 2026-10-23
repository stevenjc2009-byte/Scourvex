package com.scourvex.app.clean

import android.app.usage.StorageStatsManager
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.Files
import com.scourvex.app.shizuku.Shell

data class CleanReport(val freed: Long, val deleted: Int, val failed: List<String>, val cacheNote: String?)

/** Deletes junk items. Measures real free space before/after rather than trusting estimates. */
object Cleaner {

    suspend fun clean(items: List<JunkItem>, progress: (Int, Int) -> Unit): CleanReport {
        val before = freeBytes()
        var deleted = 0
        val failed = ArrayList<String>()
        var cacheNote: String? = null

        val appCaches = items.filter { it.path.startsWith("app:") }
        if (appCaches.isNotEmpty()) {
            cacheNote = clearAppCaches()
            if (cacheNote == null) deleted += appCaches.size
        }
        val files = items.filterNot { it.path.startsWith("app:") }
        files.forEachIndexed { i, item ->
            progress(i + 1, files.size)
            val r = Files.delete(item.path)
            if (r >= 0) deleted++ else failed += item.path
        }
        val freed = (freeBytes() - before).coerceAtLeast(0)
        return CleanReport(freed, deleted, failed, cacheNote)
    }

    /**
     * Clears every app's internal + external cache. `pm trim-caches` asks the system to free
     * cache until the requested space is free; asking for far more than the disk holds empties
     * all of them. Returns an error note, or null on success.
     */
    private suspend fun clearAppCaches(): String? {
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
