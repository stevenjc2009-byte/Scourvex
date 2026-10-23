package com.scourvex.app.security

import com.scourvex.app.shizuku.Shell

/**
 * Device-level spyware traces from the MVT indicators: system properties some mercenary
 * spyware sets, and files it leaves where only the shell user can look (/data/local/tmp).
 */
object SpywareCheck {

    const val SOURCE = "Spyware IOC (MVT)"

    /** Threats for properties that exist and, with Shizuku, files that exist. */
    suspend fun run(spy: SigPack.Spyware): List<Threat> {
        val out = ArrayList<Threat>()
        for ((prop, label) in spy.props) {
            if (getprop(prop).isNotEmpty()) out += Threat("prop:$prop", false, prop, "$label (system property)", SOURCE, 0, removable = false)
        }
        if (spy.paths.isNotEmpty() && Shell.ready) {
            val quoted = spy.paths.keys.joinToString(" ") { "'" + it.replace("'", "") + "'" }
            val found = Shell.exec("for p in $quoted; do [ -e \"\$p\" ] && echo \"\$p\"; done")?.second.orEmpty()
            for (path in found.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
                val label = spy.paths[path] ?: continue
                out += Threat(path, false, path.trimEnd('/').substringAfterLast('/'), "$label (file)", SOURCE, 0)
            }
        }
        return out
    }

    private fun getprop(name: String): String = runCatching {
        val p = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText().trim().also { p.waitFor() }
    }.getOrDefault("")
}
