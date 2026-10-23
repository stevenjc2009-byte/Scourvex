package com.scourvex.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** Runs against the real sig pack built from ClamAV (path: -Dsigpack=... or the dev cache). */
class SigPackTest {

    companion object {
        private val file = File(System.getProperty("sigpack") ?: "C:/Users/steve/devtools-cache/sigpack.zip")
        private var pack: SigPack? = null

        @BeforeClass @JvmStatic fun load() {
            if (file.exists()) pack = SigPack.load(file)
        }

        val EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*".toByteArray()
    }

    private fun p(): SigPack { assumeTrue("sig pack missing", pack != null); return pack!! }

    private fun md5(b: ByteArray) = MessageDigest.getInstance("MD5").digest(b)
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test fun loadsEverything() {
        val sp = p()
        assertTrue(sp.md5Count > 100_000)
        assertTrue(sp.body.size > 4_000)
        assertEquals(0, sp.bodySkipped)
        assertTrue(sp.stalkerPkgs.size > 500)
    }

    @Test fun eicarByMd5AndSha256() {
        val sp = p()
        assertEquals(68, EICAR.size)
        assertTrue(sp.wantsHash(68))
        assertEquals("Eicar-Test-Signature", sp.md5(68, md5(EICAR)))
        assertEquals("Eicar-Test-Signature", sp.hash(sha256(EICAR), 68))
    }

    @Test fun everyMd5RecordIsFindable() {
        val sp = p()
        val raw = ZipFile(file).use { z -> z.getInputStream(z.getEntry("md5.bin")).readBytes() }
        val names = ZipFile(file).use { z -> z.getInputStream(z.getEntry("names.txt")).bufferedReader().readLines() }
        val n = sp.md5Count
        for (i in listOf(0, 1, n / 3, n / 2, n - 2, n - 1)) {
            val o = 8 + i * 24
            val size = (raw[o].toLong() and 0xFF) or ((raw[o + 1].toLong() and 0xFF) shl 8) or
                ((raw[o + 2].toLong() and 0xFF) shl 16) or ((raw[o + 3].toLong() and 0xFF) shl 24)
            val h = raw.copyOfRange(o + 4, o + 20)
            assertEquals(names[i], sp.md5(size, h))
            h[15] = (h[15] + 1).toByte()
            assertTrue(sp.md5(size, h) != names[i])
        }
        assertNull(sp.md5(68, ByteArray(16)))
    }

    @Test fun ndbKmin5() {
        val sp = p()
        val url = "http://su.5k3g.com/portal/m/c5/0.ashx?"
        val dex = "dex\n035\u0000".toByteArray() + ByteArray(5000) + url.toByteArray() + ByteArray(100)
        assertTrue(sp.body.match(dex, dex.size, inZip = false).contains("Andr.Trojan.Kmin-5"))
        // same bytes not at offset 0: the sig is anchored at 0, so no hit
        val shifted = ByteArray(1) + dex
        assertTrue(!sp.body.match(shifted, shifted.size, inZip = false).contains("Andr.Trojan.Kmin-5"))
    }

    @Test fun ldbISpyooOnlyInsideZip() {
        val sp = p()
        val s = "com.ispyoo.common".flatMap { listOf(it.code.toByte(), 0) }.toByteArray()
        val member = ByteArray(300) + s + ByteArray(300)
        assertTrue(sp.body.match(member, member.size, inZip = true).any { it.startsWith("Andr.Spyware.iSpyoo") })
        assertTrue(sp.body.match(member, member.size, inZip = false).none { it.startsWith("Andr.Spyware.iSpyoo") })
    }

    @Test fun cleanBufferHasNoHits() {
        val sp = p()
        val rnd = java.util.Random(7)
        val buf = ByteArray(4 shl 20).also { rnd.nextBytes(it) }
        val t = System.nanoTime()
        val hits = sp.body.match(buf, buf.size, inZip = true)
        val ms = (System.nanoTime() - t) / 1_000_000
        println("4 MB random body scan: $ms ms, hits=$hits")
        assertTrue(hits.isEmpty())
    }

    @Test fun zipRoundTrip() {
        // Sanity: a zip member is what ThreatScanner feeds to match(inZip = true).
        val tmp = File.createTempFile("svx", ".zip")
        ZipOutputStream(tmp.outputStream()).use { it.putNextEntry(ZipEntry("e.txt")); it.write(EICAR) }
        val back = ZipFile(tmp).use { z -> z.getInputStream(z.getEntry("e.txt")).readBytes() }
        tmp.delete()
        assertEquals("Eicar-Test-Signature", p().md5(back.size.toLong(), md5(back)))
    }
}
