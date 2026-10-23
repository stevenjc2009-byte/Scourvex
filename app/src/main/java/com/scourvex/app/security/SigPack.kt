package com.scourvex.app.security

import java.io.File
import java.util.zip.ZipFile

/**
 * The signature pack built by tools/build_sigpack.py from real ClamAV databases
 * (plus stalkerware-indicators). Loaded fully into memory.
 */
class SigPack private constructor(
    val manifest: String,
    private val sizes: IntArray,          // u32 file sizes, sorted (then by md5)
    private val md5s: ByteArray,          // 16 bytes per record, same order
    private val names: ByteArray,         // names.txt raw
    private val nameStart: IntArray,      // start offset of name i in [names]
    private val sha: Map<String, List<Pair<Long, String>>>,  // hex -> (size or -1 for any, name)
    private val fp: Set<String>,          // "hex:size"
    val body: BodySigs,
    val bodySkipped: Int,
    val stalkerPkgs: Map<String, String>, // package -> stalkerware family
    val stalkerCerts: Map<String, String>,// cert SHA1 (lowercase hex) -> family
) {
    val md5Count: Int get() = sizes.size
    val shaCount: Int get() = sha.values.sumOf { it.size }

    /** True if a size-specific hash signature has exactly this file size. (Size-less hashes are
     *  only checked for files the scanner hashes anyway: executables and archives.) */
    fun wantsHash(size: Long): Boolean = size == EICAR_SIZE || (size in 0..0xFFFF_FFFFL && lowerBound(size.toInt()) < sizes.size &&
        sizes[lowerBound(size.toInt())] == size.toInt()) || shaSizes.contains(size)

    private val shaSizes: Set<Long> = sha.values.flatten().map { it.first }.filter { it >= 0 }.toSet()

    private fun lowerBound(size: Int): Int {
        var lo = 0
        var hi = sizes.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (Integer.compareUnsigned(sizes[mid], size) < 0) lo = mid + 1 else hi = mid
        }
        return lo
    }

    private fun name(i: Int): String {
        val end = if (i + 1 < nameStart.size) nameStart[i + 1] - 1 else names.size
        return String(names, nameStart[i], end - nameStart[i], Charsets.UTF_8)
    }

    /** Looks up a file by MD5 (16 raw bytes) and size. Returns the detection name. */
    fun md5(size: Long, md5: ByteArray): String? {
        if (size == EICAR_SIZE && md5.contentEquals(EICAR_MD5)) return "Eicar-Test-Signature"
        if (size !in 0..0xFFFF_FFFFL) return null
        val s = size.toInt()
        var i = lowerBound(s)
        while (i < sizes.size && sizes[i] == s) {
            var cmp = 0
            for (k in 0 until 16) {
                cmp = (md5s[i * 16 + k].toInt() and 0xFF) - (md5[k].toInt() and 0xFF)
                if (cmp != 0) break
            }
            if (cmp == 0) return name(i)
            if (cmp > 0) return null
            i++
        }
        return null
    }

    /** SHA1/SHA256 (and size-less MD5) lookup by lowercase hex. */
    fun hash(hex: String, size: Long): String? =
        sha[hex]?.firstOrNull { it.first < 0 || it.first == size }?.second

    /** ClamAV's own false-positive whitelist. */
    fun isFalsePositive(hex: String, size: Long) = "$hex:$size" in fp || "$hex:*" in fp

    companion object {
        const val EICAR_SIZE = 68L
        val EICAR_MD5: ByteArray = hex("44d88612fea8a8f36de82e1278abb02f")

        fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        fun load(file: File): SigPack = ZipFile(file).use { z ->
            fun bytes(n: String): ByteArray = z.getEntry(n)?.let { e -> z.getInputStream(e).use { it.readBytes() } } ?: ByteArray(0)
            fun lines(n: String): Sequence<String> =
                z.getEntry(n)?.let { e -> z.getInputStream(e).bufferedReader().readLines().asSequence() } ?: emptySequence()

            val manifest = String(bytes("manifest.json"))
            require(Regex(""""format"\s*:\s*1""").containsMatchIn(manifest)) { "unsupported sig pack format" }

            val raw = bytes("md5.bin")
            require(raw.size >= 8 && String(raw, 0, 4) == "SVM1") { "bad md5.bin" }
            val n = u32(raw, 4).toInt()
            require(raw.size == 8 + n * 24) { "md5.bin size mismatch" }
            val sizes = IntArray(n)
            val md5s = ByteArray(n * 16)
            for (i in 0 until n) {
                val o = 8 + i * 24
                sizes[i] = u32(raw, o).toInt()
                System.arraycopy(raw, o + 4, md5s, i * 16, 16)
            }

            val names = bytes("names.txt")
            val starts = IntArray(n)
            var idx = 0
            if (n > 0) starts[idx++] = 0
            for (p in names.indices) if (names[p] == '\n'.code.toByte() && idx < n) starts[idx++] = p + 1
            require(idx == n) { "names.txt has $idx names, md5.bin has $n" }

            val sha = HashMap<String, MutableList<Pair<Long, String>>>()
            for (ln in lines("sha.txt")) {
                val p = ln.split(':', limit = 3)
                if (p.size < 3) continue
                sha.getOrPut(p[0]) { ArrayList(1) } += (p[1].toLongOrNull() ?: -1L) to p[2]
            }
            val fp = lines("fp.txt").filter { it.isNotBlank() }.toHashSet()

            val (body, skipped) = BodySigs.parse(lines("body.txt"))

            val pkgs = HashMap<String, String>()
            val certs = HashMap<String, String>()
            for (ln in lines("stalkerware.tsv")) {
                val p = ln.split('\t')
                if (p.size < 3) continue
                if (p[0] == "pkg") pkgs[p[1]] = p[2] else if (p[0] == "cert") certs[p[1].lowercase()] = p[2]
            }

            SigPack(manifest, sizes, md5s, names, starts, sha, fp, body, skipped, pkgs, certs)
        }

        private fun u32(b: ByteArray, o: Int): Long =
            (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
                ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)
    }
}
