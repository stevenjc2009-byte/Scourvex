package com.scourvex.app.core

import com.scourvex.app.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Minimal HTTP helpers (no extra dependencies). */
object Net {
    private const val UA = "Scourvex/${BuildConfig.VERSION_NAME} (+https://github.com/${BuildConfig.GITHUB_REPO})"

    private fun open(url: String, headers: Map<String, String>): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 15_000
        c.readTimeout = 60_000
        c.instanceFollowRedirects = true
        c.setRequestProperty("User-Agent", UA)
        headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
        return c
    }

    suspend fun getText(url: String, headers: Map<String, String> = emptyMap()): String = withContext(Dispatchers.IO) {
        val c = open(url, headers)
        try {
            if (c.responseCode !in 200..299) throw IOException("HTTP ${c.responseCode} for $url")
            c.inputStream.bufferedReader().readText()
        } finally {
            c.disconnect()
        }
    }

    suspend fun postForm(url: String, form: Map<String, String>, headers: Map<String, String> = emptyMap()): Pair<Int, String> =
        withContext(Dispatchers.IO) {
            val c = open(url, headers)
            try {
                c.requestMethod = "POST"
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                val body = form.entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
                c.outputStream.use { it.write(body.toByteArray()) }
                val code = c.responseCode
                val text = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: ""
                code to text
            } finally {
                c.disconnect()
            }
        }

    /** Downloads to a temp file next to [dest], then renames. Calls [progress] with (done, total or -1). */
    suspend fun download(url: String, dest: File, progress: (Long, Long) -> Unit = { _, _ -> }) = withContext(Dispatchers.IO) {
        val tmp = File(dest.parentFile, dest.name + ".part")
        val c = open(url, mapOf("Accept" to "application/octet-stream"))
        try {
            if (c.responseCode !in 200..299) throw IOException("HTTP ${c.responseCode} for $url")
            val total = c.contentLengthLong
            var done = 0L
            c.inputStream.use { inp ->
                tmp.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val n = inp.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        done += n
                        progress(done, total)
                    }
                }
            }
            if (total > 0 && done != total) throw IOException("Download cut short ($done of $total bytes)")
            dest.delete()
            if (!tmp.renameTo(dest)) throw IOException("Could not save ${dest.name}")
        } finally {
            c.disconnect()
            tmp.delete()
        }
    }
}
