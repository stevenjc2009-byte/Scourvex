package com.scourvex.app.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Whole-file inspection (hashes + body sigs + zip members) against the real sig pack. */
class FileInspectorTest {

    private val file = File(System.getProperty("sigpack") ?: "C:/Users/steve/devtools-cache/sigpack.zip")
    private val pack by lazy { SigPack.load(file) }

    private fun zip(vararg members: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z -> for ((n, b) in members) { z.putNextEntry(ZipEntry(n)); z.write(b) } }
        return out.toByteArray()
    }

    private fun run(path: String, b: ByteArray) = runBlocking {
        FileInspector(pack, cap = 1 shl 20).inspect(path, b.size.toLong()) { ByteArrayInputStream(b) }
    }

    private val kminDex = "dex\n035\u0000".toByteArray() + ByteArray(3000) + "http://su.5k3g.com/portal/m/c5/0.ashx?".toByteArray()

    @Test fun detectsAll() {
        assumeTrue(file.exists())
        assertEquals(listOf("Eicar-Test-Signature"), run("/sdcard/Download/eicar.com", SigPackTest.EICAR).detections)
        assertTrue("Andr.Trojan.Kmin-5" in run("/sdcard/x/classes.dex", kminDex).detections)
        val apk = zip("AndroidManifest.xml" to ByteArray(100), "classes.dex" to kminDex)
        assertTrue("Andr.Trojan.Kmin-5" in run("/sdcard/Download/game.apk", apk).detections)
        // EICAR inside a zip inside a zip, no telling extension on the outer file
        val nestedZip = zip("inner.zip" to zip("eicar.txt" to SigPackTest.EICAR))
        assertTrue("Eicar-Test-Signature" in run("/sdcard/Download/bundle.bin", nestedZip).detections)
    }

    @Test fun cleanFilesStayClean() {
        assumeTrue(file.exists())
        val v = run("/sdcard/Download/notes.apk", zip("classes.dex" to ("dex\n035\u0000".toByteArray() + ByteArray(5000))))
        assertTrue(v.detections.isEmpty())
        // a photo is not opened at all unless a hash signature has its exact size
        val photo = run("/sdcard/DCIM/a.jpg", ByteArray(123_457))
        assertFalse(photo.inspected)
    }
}
