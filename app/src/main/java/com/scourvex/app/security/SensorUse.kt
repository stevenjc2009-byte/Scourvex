package com.scourvex.app.security

import android.content.pm.ApplicationInfo
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.shizuku.Shell
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Which apps used the camera, microphone or location, when, and whether any of it happened
 * while the app was in the background. Read from `dumpsys appops`, so it needs Shizuku.
 */
object SensorUse {

    enum class Kind(val label: String) { CAMERA("Camera"), MIC("Microphone"), LOCATION("Location") }

    /** Last use per sensor (epoch ms) and which sensors were used from the background. */
    data class Raw(val last: Map<Kind, Long>, val background: Set<Kind>)

    data class AppUse(val pkg: String, val label: String, val last: Map<Kind, Long>, val background: Set<Kind>) {
        val newest: Long get() = last.values.maxOrNull() ?: 0
    }

    private val OPS = mapOf("CAMERA" to Kind.CAMERA, "RECORD_AUDIO" to Kind.MIC,
        "FINE_LOCATION" to Kind.LOCATION, "COARSE_LOCATION" to Kind.LOCATION)

    // Full dumpsys appops is ~800 KB, past the shell's output cap; keep only the lines parse() reads.
    private const val CMD = "dumpsys appops | grep -E '^    Package |^      [A-Z_]+ \\(|Access:'"
    private const val LIMIT = 50

    suspend fun read(): List<AppUse>? {
        if (!Shell.ready) return null
        val text = Shell.exec(CMD)?.second ?: return null
        val pm = ScourvexApp.instance.packageManager
        val self = ScourvexApp.instance.packageName
        return parse(text).mapNotNull { (pkg, raw) ->
            if (pkg == self) return@mapNotNull null
            val app = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() ?: return@mapNotNull null
            // Pure system components (phone, camera app, location services) would bury everything else.
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0 && app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0) return@mapNotNull null
            AppUse(pkg, JunkScanner.appLabel(app, pkg), raw.last, raw.background)
        }.sortedWith(compareByDescending<AppUse> { it.background.isNotEmpty() }.thenByDescending { it.newest }).take(LIMIT)
    }

    /**
     * Parses filtered `dumpsys appops` output:
     * ```
     *     Package com.example:
     *       CAMERA (allow):
     *           Access: [bg-s] 2026-10-23 08:52:36.318 (-7h3m6s16ms) duration=+5s
     * ```
     * State `bg` (background) and `cch` (cached) count as background use.
     */
    fun parse(text: String): Map<String, Raw> {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
        val last = HashMap<String, HashMap<Kind, Long>>()
        val bg = HashMap<String, HashSet<Kind>>()
        var pkg: String? = null
        var kind: Kind? = null
        val access = Regex("""Access: \[([a-z]+)[^\]]*] (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})""")
        for (raw in text.lineSequence()) {
            val line = raw.trimEnd()
            when {
                line.startsWith("    Package ") -> { pkg = line.removePrefix("    Package ").trimEnd(':', ' '); kind = null }
                line.startsWith("      ") && !line.startsWith("       ") && line.contains(" (") ->
                    kind = OPS[line.trim().substringBefore(' ')]
                else -> {
                    val p = pkg ?: continue
                    val k = kind ?: continue
                    val m = access.find(line) ?: continue
                    val t = runCatching { fmt.parse(m.groupValues[2])?.time }.getOrNull() ?: continue
                    val map = last.getOrPut(p) { HashMap() }
                    if (t > (map[k] ?: 0)) map[k] = t
                    if (m.groupValues[1] == "bg" || m.groupValues[1] == "cch") bg.getOrPut(p) { HashSet() } += k
                }
            }
        }
        return last.mapValues { (p, m) -> Raw(m, bg[p].orEmpty()) }
    }
}
