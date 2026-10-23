package com.scourvex.app.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** 40-hex (SHA-1) signatures in sha.txt: the inspector computes a SHA-1 only when the pack has one, and matches it. */
class Sha1MatchTest {

    private val data = ByteArray(5000) { (it * 31 + 7).toByte() }
    private val sha1 = FileInspector.hex(MessageDigest.getInstance("SHA-1").digest(data))

    private fun pack(shaTxt: String): SigPack {
        val f = File.createTempFile("minipack", ".zip")
        f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z ->
            fun put(n: String, b: ByteArray) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
            put("manifest.json", """{"format":1}""".toByteArray())
            put("md5.bin", "SVM1".toByteArray() + ByteArray(4))
            put("names.txt", ByteArray(0))
            put("sha.txt", shaTxt.toByteArray())
        }
        return SigPack.load(f)
    }

    private fun run(p: SigPack, bytes: ByteArray) = runBlocking {
        FileInspector(p, cap = 1 shl 16).inspect("/sdcard/x/sample.bin", bytes.size.toLong()) { ByteArrayInputStream(bytes) }
    }

    @Test fun sha1EntryMatches() {
        val p = pack("$sha1:5000:Test.Sha1Hit\n")
        assertTrue(p.hasSha1)
        assertEquals(listOf("Test.Sha1Hit"), run(p, data).detections)
    }

    @Test fun sha1OfOtherSizeOrContentDoesNotMatch() {
        val p = pack("$sha1:5001:Test.Sha1Hit\n")
        assertTrue(run(p, data).detections.isEmpty())
        val other = data.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertTrue(run(pack("$sha1:5000:Test.Sha1Hit\n"), other).detections.isEmpty())
    }

    @Test fun noSha1WorkWithoutSha1Entries() {
        val p = pack("${"a".repeat(64)}:5000:Test.Sha256Only\n")
        assertFalse(p.hasSha1)
        assertTrue(run(p, data).detections.isEmpty())
    }
}
