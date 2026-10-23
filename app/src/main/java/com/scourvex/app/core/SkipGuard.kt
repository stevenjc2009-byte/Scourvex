package com.scourvex.app.core

/**
 * Immutable snapshot of the skip list. Entries are normalised once; all checks are pure string
 * logic and never touch the filesystem, so a skipped path is never stat'd, opened or entered.
 */
class SkipSet private constructor(val raw: List<String>, private val keys: List<String>) {

    /** [path] is a skip entry or lies inside one. */
    fun isSkipped(path: String): Boolean {
        if (keys.isEmpty()) return false
        val k = key(path)
        if (k.isEmpty()) return false
        return keys.any { it == k || k.startsWith(prefix(it)) }
    }

    /** A skip entry lies strictly inside [path] (deleting [path] whole would destroy it). */
    fun isAncestorOfSkip(path: String): Boolean {
        if (keys.isEmpty()) return false
        val k = key(path)
        if (k.isEmpty()) return false
        val pre = prefix(k)
        return keys.any { it != k && it.startsWith(pre) }
    }

    /** Absolute, no ".." segment, not skipped: the only paths allowed to be opened or deleted. */
    fun allows(path: String) = path.startsWith("/") && !hasDotDot(path) && !isSkipped(path)

    /** True when `pm trim-caches` (which empties every app's cache, system-wide) could reach a skip entry. */
    fun blocksTrimCaches() = keys.any { k -> k == "/" || TRIM.any { it.matches(k) } }

    companion object {
        fun of(entries: List<String>): SkipSet {
            val norm = entries.map(::normalize).filter { it.isNotEmpty() }.distinct()
            return SkipSet(norm, norm.map(::key).distinct())
        }

        private fun prefix(k: String) = if (k.endsWith("/")) k else "$k/"

        fun hasDotDot(p: String) = p.split('/').any { it == ".." }

        private const val PRIMARY = "/storage/emulated/0"
        private val ALIASES = listOf(
            "/storage/self/primary", "/sdcard", "/mnt/sdcard", "/mnt/user/0/emulated/0", "/mnt/user/0/primary",
            "/data/media/0", "/mnt/shell/emulated/0", "/mnt/pass_through/0/emulated/0",
            "/mnt/runtime/default/emulated/0", "/mnt/runtime/read/emulated/0", "/mnt/runtime/write/emulated/0",
            "/mnt/runtime/default/self/primary", "/mnt/runtime/read/self/primary", "/mnt/runtime/write/self/primary",
        )

        /** Lexical clean-up only: trims, collapses "//", "/./", "..", trailing "/", and maps storage aliases. */
        fun normalize(path: String): String {
            val t = path.trim()
            if (t.isEmpty()) return ""
            val clean = if (isClean(t)) t else collapse(t)
            for (a in ALIASES) {
                if (clean == a) return PRIMARY
                if (clean.startsWith("$a/")) return PRIMARY + clean.substring(a.length)
            }
            return clean
        }

        /** Comparison form: [normalize], lower-cased on shared storage (FAT/FUSE are case-insensitive). */
        fun key(path: String): String {
            val n = normalize(path)
            return if (n.startsWith("/storage/") || n == "/storage") n.lowercase(java.util.Locale.ROOT) else n
        }

        private fun isClean(t: String) =
            t.startsWith("/") && (t.length == 1 || (!t.endsWith("/") && !t.contains("//") && !t.contains("/.")))

        private fun collapse(t: String): String {
            val out = ArrayList<String>()
            val abs = t.startsWith("/")
            for (seg in t.split('/')) {
                when (seg) {
                    "", "." -> {}
                    ".." -> if (out.isNotEmpty() && out.last() != "..") out.removeAt(out.lastIndex) else if (!abs) out.add(seg)
                    else -> out.add(seg)
                }
            }
            return (if (abs) "/" else "") + out.joinToString("/")
        }

        private const val VOL = "(?:emulated/\\d+|[^/]+)"
        private const val PKG_CACHE = "[^/]+(?:/(?:code_)?cache(?:/.*)?)?"
        // Skip entries (lower-cased keys) that `pm trim-caches` can reach: a cache folder, or any ancestor of one.
        private val TRIM = listOf(
            Regex("^/storage(?:/emulated|/$VOL(?:/android(?:/data(?:/[^/]+(?:/cache(?:/.*)?)?)?)?)?)?$"),
            Regex("^/data(?:/data(?:/$PKG_CACHE)?|/user(?:_de)?(?:/\\d+(?:/$PKG_CACHE)?)?)?$"),
        )
    }
}

/** The live skip list (Prefs.skip, read on every call) behind the pure [SkipSet] logic. */
object SkipGuard {
    @Volatile private var cached: Pair<List<String>, SkipSet>? = null

    fun of(entries: List<String>) = SkipSet.of(entries)

    /** Snapshot of the current list; cheap while the list is unchanged. */
    fun live(): SkipSet {
        val cur = Prefs.skip.value
        cached?.let { if (it.first === cur) return it.second }
        return SkipSet.of(cur).also { cached = cur to it }
    }

    fun normalize(path: String) = SkipSet.normalize(path)
    fun isSkipped(path: String) = live().isSkipped(path)
    fun isAncestorOfSkip(path: String) = live().isAncestorOfSkip(path)
    fun allows(path: String) = live().allows(path)
    fun blocksTrimCaches() = live().blocksTrimCaches()
}
