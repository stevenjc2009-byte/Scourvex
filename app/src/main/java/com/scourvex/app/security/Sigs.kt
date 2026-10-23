package com.scourvex.app.security

import com.scourvex.app.BuildConfig
import com.scourvex.app.ScourvexApp
import com.scourvex.app.core.Net
import com.scourvex.app.core.Perf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.nio.file.StandardCopyOption

/**
 * Owns the on-device signature pack: downloads it from the repo's "sigpack" release
 * (rebuilt daily from ClamAV by .github/workflows/sigpack.yml) and keeps it loaded.
 */
object Sigs {

    data class Info(val clamDaily: Int, val clamMain: Int, val built: String, val md5: Int, val body: Int, val stalkerware: Int, val spyware: Int)

    private val file get() = File(ScourvexApp.instance.filesDir, "sigpack.zip")
    private const val URL = "https://github.com/${BuildConfig.GITHUB_REPO}/releases/download/sigpack/sigpack.zip"

    private val lock = Mutex()
    @Volatile var pack: SigPack? = null
        private set

    private val _info = MutableStateFlow<Info?>(null)
    val info: StateFlow<Info?> = _info

    val installed: Boolean get() = file.exists()

    /** Loads the pack from disk if present. Returns null when none has been downloaded yet. */
    suspend fun get(): SigPack? = lock.withLock {
        pack ?: withContext(Dispatchers.IO) {
            if (!file.exists()) null else runCatching { Perf.time("Sigs.coldLoad", { "bytes=${file.length()}" }) { SigPack.load(file) } }.getOrNull()?.also { setLoaded(it) }
        }
    }

    /** Downloads the newest pack and loads it. Throws with a readable message on failure. */
    suspend fun update(progress: (Long, Long) -> Unit): Info = lock.withLock {
        withContext(Dispatchers.IO) {
            val fresh = File(file.parentFile, "sigpack.new.zip")
            Net.download(URL, fresh, progress)
            val p = try {
                SigPack.load(fresh)
            } catch (e: Exception) {
                fresh.delete()
                throw IllegalStateException("Downloaded signatures are damaged: ${e.message}")
            }
            // One atomic rename replaces the old pack: there is never a moment with no pack on disk.
            java.nio.file.Files.move(fresh.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            setLoaded(p)
            _info.value!!
        }
    }

    private fun setLoaded(p: SigPack) {
        pack = p
        val m = JSONObject(p.manifest)
        val c = m.getJSONObject("counts")
        val cl = m.getJSONObject("clamav")
        _info.value = Info(
            clamDaily = cl.getJSONObject("daily").getInt("version"),
            clamMain = cl.getJSONObject("main").getInt("version"),
            built = m.getString("built"),
            md5 = c.getInt("md5") + c.getInt("sha"),
            body = c.getInt("body"),
            stalkerware = c.getInt("stalkerware"),
            spyware = c.optInt("spyware"),
        )
    }
}
