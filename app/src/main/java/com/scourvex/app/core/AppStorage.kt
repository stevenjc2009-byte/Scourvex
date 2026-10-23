package com.scourvex.app.core

import android.app.usage.StorageStats
import android.app.usage.StorageStatsManager
import android.content.pm.ApplicationInfo
import android.os.Process
import android.os.storage.StorageManager
import com.scourvex.app.ScourvexApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** `queryStatsForPackage` for many apps with a few calls in flight (each one is a binder round trip). */
object AppStorage {

    private const val PARALLEL = 4

    /**
     * Runs [transform] on every app that has stats, in app order, on up to [PARALLEL] threads; apps whose
     * query fails are left out and a null from [transform] drops the app. Null result: usage access is missing
     * (SecurityException), like the sequential loops this replaces.
     */
    suspend fun <T : Any> query(apps: Collection<ApplicationInfo>, transform: (ApplicationInfo, StorageStats) -> T?): List<T>? = coroutineScope {
        val ssm = ScourvexApp.instance.getSystemService(StorageStatsManager::class.java)
        val user = Process.myUserHandle()
        val list = apps.toList()
        val results = arrayOfNulls<Any>(list.size)
        val next = AtomicInteger()
        val denied = AtomicBoolean(false)
        repeat(minOf(PARALLEL, list.size)) {
            launch(Dispatchers.IO) {
                while (!denied.get()) {
                    val i = next.getAndIncrement()
                    if (i >= list.size) break
                    val a = list[i]
                    val st = try {
                        ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, a.packageName, user)
                    } catch (_: SecurityException) {
                        denied.set(true); break
                    } catch (_: Exception) {
                        continue
                    }
                    results[i] = transform(a, st)
                }
            }
        }
        // coroutineScope returns after every worker finished, so the array writes are visible here.
        if (denied.get()) null else {
            @Suppress("UNCHECKED_CAST")
            results.filterNotNull() as List<T>
        }
    }
}
