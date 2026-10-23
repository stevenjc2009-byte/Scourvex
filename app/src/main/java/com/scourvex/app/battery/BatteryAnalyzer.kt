package com.scourvex.app.battery

import android.app.usage.UsageStatsManager
import android.content.Context
import com.scourvex.app.ScourvexApp
import com.scourvex.app.clean.JunkScanner
import com.scourvex.app.core.Perf
import com.scourvex.app.shizuku.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class PowerUse(
    val label: String,
    val pkg: String?,
    val mAh: Double,            // estimated drain since last full charge; NaN in usage-time mode
    val foregroundMs: Long,
    val parts: String,          // e.g. "cpu 41%, screen 30%, wifi 12%"
)

data class BatteryReport(val apps: List<PowerUse>, val source: String)

/**
 * Most power-hungry apps. With Shizuku: Android's own per-app power model
 * (`dumpsys batterystats`, mAh since last full charge). Without: screen-on time per app
 * over the last 24 h from usage access, which is a weaker signal and labelled as such.
 */
object BatteryAnalyzer {

    suspend fun scan(): BatteryReport {
        var n = 0
        return Perf.time("BatteryAnalyzer.scan", { "rows=$n" }) { scanTimed().also { n = it.apps.size } }
    }

    private val headRe = Regex("""^\s+UID (\S+): ([0-9.eE-]+)""")
    private val compRe = Regex("""(?<![\w:])(\w+)=([0-9.eE-]+)""")   // skips "sensors:bg=" foreground/background splits
    private val userAppRe = Regex("""u(\d+)a(\d+)""")
    private val userSharedRe = Regex("""u(\d+)s(\d+)""")

    private suspend fun scanTimed(): BatteryReport = withContext(Dispatchers.IO) {
        val ctx = ScourvexApp.instance
        // Only the power section: the full dump can be megabytes, over the shell service's output cap.
        val out = Perf.time("BatteryAnalyzer.dumpsys") { Shell.exec("dumpsys batterystats 2>/dev/null | awk '/Estimated power use/{f=1} f&&/^  [^ U]/&&!/Estimated/{exit} f'") }
        if (out != null && out.first == 0) {
            val rows = parse(out.second).map { u ->
                val pkgs = ctx.packageManager.getPackagesForUid(u.uid)?.toList().orEmpty()
                val pkg = pkgs.singleOrNull() ?: pkgs.firstOrNull()
                val label = when {
                    u.uid == 1000 -> "Android system"
                    u.uid == 0 -> "Kernel / root"
                    pkg != null -> JunkScanner.appLabel(runCatching { ctx.packageManager.getApplicationInfo(pkg, 0) }.getOrNull(), pkg) +
                        (if (pkgs.size > 1) " +${pkgs.size - 1}" else "")
                    else -> "UID ${u.uid}"
                }
                PowerUse(label, pkg, u.mAh, 0, u.parts)
            }
            if (rows.isNotEmpty()) return@withContext BatteryReport(rows, "Android battery stats since last full charge (via Shizuku)")
        }
        BatteryReport(usageFallback(ctx), "Screen-on time, last 24 h (start Shizuku for real power numbers)")
    }

    data class UidPower(val uid: Int, val mAh: Double, val parts: String)

    /** Parses the "Estimated power use (mAh)" section of `dumpsys batterystats`. */
    fun parse(text: String): List<UidPower> {
        val lines = text.lines()
        val start = lines.indexOfFirst { it.trim().startsWith("Estimated power use") }
        if (start < 0) return emptyList()
        val head = headRe
        val comp = compRe
        val out = ArrayList<UidPower>()
        var i = start + 1
        while (i < lines.size) {
            val ln = lines[i]
            if (ln.isNotBlank() && !ln.startsWith("    ") && !ln.startsWith("  UID")) break   // next top-level section
            val m = head.find(ln)
            if (m != null) {
                val uid = uidOf(m.groupValues[1])
                val total = m.groupValues[2].toDoubleOrNull() ?: 0.0
                val parts = HashMap<String, Double>()
                val next = lines.getOrNull(i + 1).orEmpty()
                if (head.find(next) == null) comp.findAll(next).forEach { c ->
                    parts.merge(c.groupValues[1], c.groupValues[2].toDoubleOrNull() ?: 0.0, Double::plus)
                }
                if (uid != null && total > 0) {
                    val sum = parts.values.sum().takeIf { it > 0 } ?: 1.0
                    val desc = parts.entries.sortedByDescending { it.value }.take(3)
                        .joinToString(", ") { "${it.key} ${(it.value * 100 / sum).toInt()}%" }
                    out += UidPower(uid, total, desc)
                }
            }
            i++
        }
        return out.sortedByDescending { it.mAh }
    }

    /** "u0a155" -> 10155, "u10a3" -> 1010003, "1000" -> 1000. */
    fun uidOf(s: String): Int? {
        s.toIntOrNull()?.let { return it }
        val m = userAppRe.matchEntire(s) ?: return userSharedRe.matchEntire(s)?.let {
            it.groupValues[1].toInt() * 100_000 + it.groupValues[2].toInt()
        }
        return m.groupValues[1].toInt() * 100_000 + 10_000 + m.groupValues[2].toInt()
    }

    private fun usageFallback(ctx: Context): List<PowerUse> {
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val now = System.currentTimeMillis()
        val stats = runCatching { usm.queryAndAggregateUsageStats(now - 24 * 3600_000L, now) }.getOrNull().orEmpty()
        return stats.values.filter { it.totalTimeInForeground > 60_000 && it.packageName != ctx.packageName }
            .sortedByDescending { it.totalTimeInForeground }
            .map { s ->
                val ai = runCatching { ctx.packageManager.getApplicationInfo(s.packageName, 0) }.getOrNull()
                PowerUse(JunkScanner.appLabel(ai, s.packageName), s.packageName, Double.NaN, s.totalTimeInForeground, "")
            }
    }
}
