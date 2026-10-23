package com.scourvex.app.security

/**
 * ClamAV .ndb (extended) and .ldb (logical) signatures, matched against a byte buffer.
 * https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html
 * https://docs.clamav.net/manual/Signatures/LogicalSignatures.html
 */
class BodySigs private constructor(private val sigs: List<Sig>) {

    /** Where a subsignature may start. shift > 0 allows start..start+shift. */
    sealed interface Offset
    object AnyOffset : Offset
    class Abs(val start: Int, val shift: Int) : Offset
    class Eof(val back: Int, val shift: Int) : Offset

    class Sub(val patterns: List<HexPattern>, val offset: Offset)

    class Sig(
        val name: String,
        val target: Int,
        val zipOnly: Boolean,
        val minSize: Long,
        val maxSize: Long,
        val subs: List<Sub>,
        val expr: LdbExpr?,   // null for .ndb: matched when its single subsig matches
    )

    private class Ref(val sig: Int, val sub: Int, val pat: HexPattern)

    private val exactRefs = ArrayList<Ref>()
    private val foldRefs = ArrayList<Ref>()
    private val fixedRefs = ArrayList<Ref>()
    private val exactAc: AhoCorasick
    private val foldAc: AhoCorasick

    val size: Int get() = sigs.size

    init {
        sigs.forEachIndexed { si, s ->
            s.subs.forEachIndexed { ui, sub ->
                for (p in sub.patterns) {
                    val r = Ref(si, ui, p)
                    when {
                        sub.offset !is AnyOffset -> fixedRefs += r
                        p.caseless -> foldRefs += r
                        else -> exactRefs += r
                    }
                }
            }
        }
        exactAc = AhoCorasick(exactRefs.map { it.pat.anchor!!.bytes }, fold = false)
        foldAc = AhoCorasick(foldRefs.map { it.pat.anchor!!.bytes }, fold = true)
    }

    /** Returns the names of all signatures that match [buf][0, len). */
    fun match(buf: ByteArray, len: Int, inZip: Boolean): List<String> {
        val isElf = len >= 4 && buf[0] == 0x7F.toByte() && buf[1] == 'E'.code.toByte() &&
            buf[2] == 'L'.code.toByte() && buf[3] == 'F'.code.toByte()
        fun applies(s: Sig) = (!s.zipOnly || inZip) && (s.target != 6 || isElf) && len in s.minSize..s.maxSize

        // Allocated on the first hit only: a clean file (nearly every call) allocates nothing here. BodySigs is
        // shared by all workers, so these are per call, never fields.
        var counts: HashMap<Long, Int>? = null
        fun bump(r: Ref) {
            val key = (r.sig.toLong() shl 16) or r.sub.toLong()
            val c = counts ?: HashMap<Long, Int>().also { counts = it }
            c[key] = (c[key] ?: 0) + 1
        }
        var verifies: HashMap<Int, Int>? = null

        val onHit = { refs: List<Ref> ->
            { id: Int, end: Int ->
                val r = refs[id]
                val s = sigs[r.sig]
                val v = verifies?.get(r.sig) ?: 0
                if (applies(s) && v < MAX_VERIFY) {
                    (verifies ?: HashMap<Int, Int>().also { verifies = it })[r.sig] = v + 1
                    val a = r.pat.anchor!!
                    val at = end - a.bytes.size
                    for (start in (at - a.maxOff).coerceAtLeast(0)..(at - a.minOff)) {
                        val e = r.pat.matchSegmentAt(buf, len, a.seg, start)
                        if (e >= 0 && r.pat.verifyAround(buf, len, a.seg, start, e)) { bump(r); break }
                    }
                }
            }
        }
        exactAc.scan(buf, len, onHit(exactRefs))
        if (foldRefs.isNotEmpty()) foldAc.scan(buf, len, onHit(foldRefs))

        for (r in fixedRefs) {
            val s = sigs[r.sig]
            if (!applies(s)) continue
            val starts = when (val o = s.subs[r.sub].offset) {
                is Abs -> o.start..(o.start + o.shift)
                is Eof -> (len - o.back)..(len - o.back + o.shift)
                AnyOffset -> continue
            }
            if (r.pat.matchFrom(buf, len, starts)) bump(r)
        }

        val found = counts ?: return emptyList()
        val hitSigs = found.keys.map { (it shr 16).toInt() }.toSet()
        return hitSigs.mapNotNull { si ->
            val s = sigs[si]
            val c = IntArray(s.subs.size) { found[(si.toLong() shl 16) or it.toLong()] ?: 0 }
            val ok = s.expr?.eval(c)?.let { it.count > 0 } ?: (c[0] > 0)
            if (ok) s.name else null
        }
    }

    companion object {
        private const val MAX_VERIFY = 20_000

        /** Parses body.txt from the sig pack. Lines the matcher can't handle are skipped and counted. */
        fun parse(lines: Sequence<String>): Pair<BodySigs, Int> {
            val out = ArrayList<Sig>()
            var skipped = 0
            for (ln in lines) {
                if (ln.length < 3) continue
                val sig = runCatching { if (ln[0] == 'N') parseNdb(ln.substring(2)) else parseLdb(ln.substring(2)) }.getOrNull()
                if (sig != null) out += sig else skipped++
            }
            return BodySigs(out) to skipped
        }

        private fun parseOffset(s: String): Offset? {
            if (s == "*") return AnyOffset
            val (base, shift) = s.split(',').let { it[0] to (it.getOrNull(1)?.toInt() ?: 0) }
            return when {
                base.startsWith("EOF-") -> Eof(base.substring(4).toInt(), shift)
                base.all { it.isDigit() } -> Abs(base.toInt(), shift)
                else -> null
            }
        }

        private fun usable(p: HexPattern, off: Offset) = off !is AnyOffset || (p.anchor?.bytes?.size ?: 0) >= 3

        private fun parseNdb(line: String): Sig? {
            val p = line.split(':')
            val off = parseOffset(p[2]) ?: return null
            val pat = HexPattern.parse(p[3]) ?: return null
            if (!usable(pat, off)) return null
            return Sig(p[0], p[1].toInt(), false, 0, Long.MAX_VALUE, listOf(Sub(listOf(pat), off)), null)
        }

        private fun parseLdb(line: String): Sig? {
            val p = line.split(';')
            var target = 0
            var zip = false
            var min = 0L
            var max = Long.MAX_VALUE
            for (kv in p[1].split(',')) {
                val (k, v) = kv.split(':', limit = 2).let { it[0] to it.getOrElse(1) { "" } }
                when (k) {
                    "Target" -> target = v.toInt()
                    "Container" -> zip = v == "CL_TYPE_ZIP"
                    "FileSize" -> v.split('-').let { min = it[0].toLong(); max = it.getOrNull(1)?.toLongOrNull() ?: Long.MAX_VALUE }
                }
            }
            val subs = p.drop(3).map { raw ->
                var body = raw
                var mods = ""
                if ("::" in body) { mods = body.substringAfter("::"); body = body.substringBefore("::") }
                var off: Offset = AnyOffset
                if (':' in body) { off = parseOffset(body.substringBefore(':')) ?: return null; body = body.substringAfter(':') }
                val ci = 'i' in mods
                val pats = buildList {
                    if ('w' !in mods || 'a' in mods) add(HexPattern.parse(body, wide = false, caseless = ci) ?: return null)
                    if ('w' in mods || 'a' in mods) add(HexPattern.parse(body, wide = true, caseless = ci) ?: return null)
                }
                if (pats.any { !usable(it, off) }) return null
                Sub(pats, off)
            }
            val expr = LdbExpr.parse(p[2]) ?: return null
            if (expr.maxIndex() >= subs.size) return null
            return Sig(p[0], target, zip, min, max, subs, expr)
        }
    }
}
