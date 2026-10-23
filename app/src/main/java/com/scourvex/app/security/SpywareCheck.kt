package com.scourvex.app.security

import com.scourvex.app.core.SkipGuard
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
        val props = if (spy.props.isEmpty()) emptyMap() else allProps()
        for ((prop, label) in spy.props) {
            if (!props[prop].isNullOrEmpty()) out += Threat("prop:$prop", false, prop, "$label (system property)", SOURCE, 0, removable = false)
        }
        if (spy.paths.isNotEmpty() && Shell.ready) {
            // Skipped IOC paths are never handed to the shell (it would stat them); filter the sanitised form.
            val safe = spy.paths.keys.map { it.replace("'", "") }.filter { SkipGuard.allows(it) }
            val quoted = safe.joinToString(" ") { "'$it'" }
            val found = Shell.exec("for p in $quoted; do [ -e \"\$p\" ] && echo \"\$p\"; done")?.second.orEmpty()
            for (path in found.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
                val label = spy.paths[path] ?: continue
                out += Threat(path, false, path.trimEnd('/').substringAfterLast('/'), "$label (file)", SOURCE, 0)
            }
        }
        return out
    }

    /** Every system property from one `getprop` call (a process per IOC property was the slow part). */
    private fun allProps(): Map<String, String> = runCatching {
        val p = ProcessBuilder("getprop").redirectErrorStream(true).start()
        parseProps(p.inputStream.bufferedReader().readText()).also { p.waitFor() }
    }.getOrDefault(emptyMap())

    /** Parses `getprop` output: `[name]: [value]`; a value that spans lines counts as non-empty. */
    fun parseProps(text: String): Map<String, String> {
        val m = HashMap<String, String>()
        for (ln in text.lineSequence()) {
            if (!ln.startsWith("[")) continue
            val k = ln.indexOf("]: [")
            if (k < 0) continue
            val v = ln.substring(k + 4).removeSuffix("]").trim()
            m[ln.substring(1, k)] = v
        }
        return m
    }
}
