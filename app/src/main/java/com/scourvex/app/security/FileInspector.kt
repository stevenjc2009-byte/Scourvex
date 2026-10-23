package com.scourvex.app.security

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

/**
 * Checks one file against the sig pack: MD5/SHA hash signatures, ClamAV body signatures
 * (.ndb/.ldb) on executables and scripts, and the same again for every member of a zip/APK
 * (one level of nesting). Not thread safe: each worker owns one inspector and its buffers.
 */
class FileInspector(private val pack: SigPack, private val cap: Int = 16 shl 20) {

    class Verdict(val detections: List<String>, val sha256: String?, val inspected: Boolean)

    private val top = ByteArray(cap)
    private val member = ByteArray(cap)
    private val nested by lazy { ByteArray(cap) }

    var bytesRead = 0L
        private set

    suspend fun inspect(path: String, size: Long, open: suspend () -> InputStream?): Verdict {
        val ext = path.substringAfterLast('/').substringAfterLast('.', "").lowercase()
        val wantsHash = pack.wantsHash(size)
        val execExt = ext in EXEC_EXT
        val maybeExec = execExt || (ext !in DATA_EXT && size in 4..SNIFF_MAX)
        if (!wantsHash && !maybeExec) return NONE

        val md5 = MessageDigest.getInstance("MD5")
        val sha = MessageDigest.getInstance("SHA-256")
        var n = 0
        var total = 0L
        (open() ?: return NONE).use { inp ->
            while (true) {
                // Sniff only the header first when the file is only a maybe.
                val want = if (n == 0 && !wantsHash && !execExt) 64 else cap - n
                val r = if (n < cap) inp.read(top, n, want) else inp.read(member, 0, cap)
                if (r < 0) break
                if (n < cap) {
                    md5.update(top, n, r); sha.update(top, n, r); n += r
                } else {
                    md5.update(member, 0, r); sha.update(member, 0, r)
                }
                total += r
                // Not an executable after all and no hash needed: stop early.
                if (!wantsHash && !execExt && n >= 8 && kindOf(top, n) == Kind.OTHER) return NONE
            }
        }
        bytesRead += total
        val kind = kindOf(top, n)
        if (!wantsHash && !execExt && kind == Kind.OTHER) return NONE

        val md5b = md5.digest()
        val md5hex = hex(md5b)
        val shahex = hex(sha.digest())
        if (pack.isFalsePositive(md5hex, total) || pack.isFalsePositive(shahex, total)) return Verdict(emptyList(), shahex, true)

        val found = LinkedHashSet<String>()
        pack.md5(total, md5b)?.let { found += it }
        pack.hash(shahex, total)?.let { found += it }
        pack.hash(md5hex, total)?.let { found += it }

        when {
            kind == Kind.ZIP -> {
                val src = if (total <= cap) ByteArrayInputStream(top, 0, n) else open()
                src?.use { scanZip(it, depth = 1, found) }
            }
            kind != Kind.OTHER || execExt -> found += pack.body.match(top, n, inZip = false)
        }
        return Verdict(found.toList(), shahex, true)
    }

    private fun scanZip(inp: InputStream, depth: Int, found: MutableSet<String>) {
        val buf = if (depth == 1) member else nested
        runCatching {
            ZipInputStream(inp).use { z ->
                while (true) {
                    val e = z.nextEntry ?: break
                    if (e.isDirectory) continue
                    val ext = e.name.substringAfterLast('.', "").lowercase()
                    if (ext in MEDIA_EXT) continue
                    var n = 0
                    var total = 0L
                    val md5 = MessageDigest.getInstance("MD5")
                    val skip = ByteArray(8192)
                    while (true) {
                        val r = if (n < cap) z.read(buf, n, cap - n) else z.read(skip)
                        if (r < 0) break
                        if (n < cap) { md5.update(buf, n, r); n += r } else md5.update(skip, 0, r)
                        total += r
                    }
                    bytesRead += total
                    if (pack.wantsHash(total)) pack.md5(total, md5.digest())?.let { found += it }
                    if (kindOf(buf, n) == Kind.ZIP && depth < 2) {
                        scanZip(ByteArrayInputStream(buf, 0, n), depth + 1, found)
                    } else {
                        found += pack.body.match(buf, n, inZip = true)
                    }
                }
            }
        }
    }

    enum class Kind { ZIP, DEX, ELF, SCRIPT, OTHER }

    companion object {
        private val NONE = Verdict(emptyList(), null, false)
        private const val SNIFF_MAX = 8L shl 20

        val EXEC_EXT = setOf("apk", "apks", "xapk", "apkm", "jar", "zip", "dex", "odex", "vdex", "oat", "so", "elf", "bin",
            "sh", "bash", "py", "pl", "js", "jse", "vbs", "ps1", "bat", "cmd", "exe", "dll", "scr", "php", "hta")

        /** Content that is never executable code; only checked when a hash signature has its size. */
        val MEDIA_EXT = setOf("jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "bmp", "avif", "dng", "raw",
            "mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v", "ts",
            "mp3", "m4a", "aac", "ogg", "opus", "flac", "wav", "amr", "mid",
            "ttf", "otf", "woff", "woff2", "9.png")
        val DATA_EXT = MEDIA_EXT + setOf("txt", "json", "xml", "csv", "log", "db", "db-wal", "db-shm", "sqlite", "pdf",
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "srt", "vtt", "md", "html", "htm", "css", "nomedia", "tmp", "cache", "dat")

        fun kindOf(b: ByteArray, n: Int): Kind = when {
            n >= 4 && b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte() && b[2] == 3.toByte() && b[3] == 4.toByte() -> Kind.ZIP
            n >= 4 && b[0] == 'd'.code.toByte() && b[1] == 'e'.code.toByte() && b[2] == 'x'.code.toByte() && b[3] == '\n'.code.toByte() -> Kind.DEX
            n >= 4 && b[0] == 0x7F.toByte() && b[1] == 'E'.code.toByte() && b[2] == 'L'.code.toByte() && b[3] == 'F'.code.toByte() -> Kind.ELF
            n >= 2 && b[0] == '#'.code.toByte() && b[1] == '!'.code.toByte() -> Kind.SCRIPT
            else -> Kind.OTHER
        }

        fun hex(b: ByteArray): String {
            val c = CharArray(b.size * 2)
            for (i in b.indices) {
                val v = b[i].toInt() and 0xFF
                c[i * 2] = "0123456789abcdef"[v shr 4]
                c[i * 2 + 1] = "0123456789abcdef"[v and 15]
            }
            return String(c)
        }
    }
}
