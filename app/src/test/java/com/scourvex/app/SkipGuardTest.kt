package com.scourvex.app

import com.scourvex.app.core.GuardedDelete
import com.scourvex.app.core.SkipGuard
import com.scourvex.app.core.SkipSet
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.FileTime

class SkipGuardTest {

    private fun g(vararg e: String) = SkipGuard.of(e.toList())
    private val P = "/storage/emulated/0"

    // ---- normalisation ----
    @Test fun aliasesMapToPrimary() {
        for (a in listOf("/sdcard", "/storage/self/primary", "/mnt/user/0/emulated/0", "/data/media/0", "/mnt/sdcard"))
            assertEquals(a, "$P/DCIM", SkipGuard.normalize("$a/DCIM"))
        assertEquals(P, SkipGuard.normalize("/sdcard"))
        assertEquals("/sdcardx/a", SkipGuard.normalize("/sdcardx/a"))   // alias must match whole segment
    }

    @Test fun collapsesNoise() {
        assertEquals("$P/a/b", SkipGuard.normalize("$P//a/./b/"))
        assertEquals("$P/b", SkipGuard.normalize("$P/a/../b"))
        assertEquals("/b", SkipGuard.normalize("/../../b"))
        assertEquals("$P/a b", SkipGuard.normalize("  $P/a b/  "))
        assertEquals("/", SkipGuard.normalize("//"))
        assertEquals("$P/DCIM", SkipGuard.normalize("/sdcard/./x/../DCIM///"))
    }

    @Test fun caseInsensitiveOnSharedStorageOnly() {
        assertTrue(g("/sdcard/dcim/camera").isSkipped("$P/DCIM/Camera/a.jpg"))
        assertTrue(g("/storage/ABCD-1234/Music").isSkipped("/storage/abcd-1234/music"))
        assertFalse(g("/data/local/tmp/X").isSkipped("/data/local/tmp/x"))
    }

    // ---- skipped / ancestor ----
    @Test fun skippedFolderAndFile() {
        val s = g("/sdcard/Docs", "$P/Pics/secret.jpg")
        assertTrue(s.isSkipped("$P/Docs"))
        assertTrue(s.isSkipped("/sdcard/Docs/x/y.txt"))
        assertTrue(s.isSkipped("$P/Pics/secret.jpg"))
        assertFalse(s.isSkipped("$P/Pics"))
        assertFalse(s.isSkipped("$P/Pics/secret.jpg2"))
        assertTrue(s.isSkipped("$P/Docs/../Docs/z"))
    }

    @Test fun siblingPrefixTrap() {
        val s = g("/a/b")
        assertFalse(s.isSkipped("/a/bc"))
        assertFalse(s.isSkipped("/a/bc/d"))
        assertTrue(s.isSkipped("/a/b/c"))
        assertFalse(s.isAncestorOfSkip("/a/bc"))
        assertTrue(s.isAncestorOfSkip("/a"))
        assertFalse(s.isAncestorOfSkip("/a/b"))   // strictly inside only
        assertTrue(s.isAncestorOfSkip("/"))
    }

    @Test fun ancestorAcrossAliases() {
        val s = g("$P/Android/data/com.x/cache/keep")
        assertTrue(s.isAncestorOfSkip("/sdcard/Android"))
        assertTrue(s.isAncestorOfSkip("/storage/emulated/0"))
        assertTrue(s.isAncestorOfSkip("/storage/EMULATED/0/ANDROID/data/com.x"))
        assertFalse(s.isAncestorOfSkip("$P/Android/data/com.y"))
    }

    @Test fun allowsRejectsRelativeAndDotDot() {
        val s = g("/a/b")
        assertTrue(s.allows("/a/c"))
        assertFalse(s.allows("/a/b/c"))
        assertFalse(s.allows("a/c"))
        assertFalse(s.allows("/a/../a/c"))
    }

    // ---- pm trim-caches ----
    @Test fun trimCachesBlockedCases() {
        for (e in listOf(
            "$P/Android/data/com.x/cache", "$P/Android/data/com.x/cache/sub", "$P/Android/data/com.x", "$P/Android/data",
            "$P/Android", P, "/sdcard", "/storage/emulated", "/storage", "/", "/storage/1A2B-3C4D", "/storage/1A2B-3C4D/Android/data/p/cache/a",
            "/data/data/com.x/cache/f", "/data/data/com.x", "/data/data", "/data", "/data/user/0/com.x/code_cache",
        )) assertTrue(e, g(e).blocksTrimCaches())
    }

    @Test fun trimCachesNotBlockedCases() {
        for (e in listOf(
            "$P/DCIM", "$P/Android/data/com.x/files", "$P/Android/obb", "$P/Android/media", "/storage/1A2B-3C4D/Music",
            "/data/local/tmp", "/data/data/com.x/files", "$P/Android/data/com.x/files/cache",
        )) assertFalse(e, g(e).blocksTrimCaches())
        assertFalse(g().blocksTrimCaches())
    }

    // ---- guarded tree delete on a real directory ----
    @get:Rule val tmp = TemporaryFolder()

    private fun p(f: File) = f.path.replace('\\', '/')

    @Test fun deletesJunkKeepsSkippedUntouched() {
        val parent = tmp.newFolder("parent")
        val keep = File(parent, "keep").apply { mkdirs() }
        val kf = File(keep, "a.bin").apply { writeBytes(ByteArray(5000) { it.toByte() }) }
        val kdeep = File(keep, "sub/deep").apply { mkdirs() }
        val kd = File(kdeep, "b.txt").apply { writeText("precious") }
        val skippedFile = File(parent, "single.dat").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        File(parent, "junk1.tmp").writeBytes(ByteArray(100))
        File(parent, "junkdir/inner").apply { mkdirs() }
        File(parent, "junkdir/inner/j2.tmp").writeBytes(ByteArray(250))
        val stamp = 1_600_000_000_000L
        listOf(kf, kd, skippedFile, keep).forEach { it.setLastModified(stamp) }
        val before = listOf(kf, kd, skippedFile).map { it.readBytes() }
        val mt = listOf(kf, kd, skippedFile).map { it.lastModified() }

        val skip = SkipGuard.of(listOf(p(keep), p(skippedFile)))
        val freed = GuardedDelete.delete(p(parent)) { skip }

        assertEquals(350L, freed)
        assertFalse(File(parent, "junk1.tmp").exists())
        assertFalse(File(parent, "junkdir").exists())
        assertTrue(parent.exists())      // left in place: it holds skipped entries
        assertArrayEquals(before[0], kf.readBytes())
        assertArrayEquals(before[1], kd.readBytes())
        assertArrayEquals(before[2], skippedFile.readBytes())
        assertEquals(mt, listOf(kf, kd, skippedFile).map { it.lastModified() })
        assertEquals(stamp, keep.lastModified())
    }

    @Test fun refusesSkippedAndInsideSkipped() {
        val d = tmp.newFolder("s")
        val f = File(d, "x.txt").apply { writeText("x") }
        val skip = SkipGuard.of(listOf(p(d)))
        assertEquals(-1L, GuardedDelete.delete(p(d)) { skip })
        assertEquals(-1L, GuardedDelete.delete(p(f)) { skip })
        assertTrue(f.exists())
        assertEquals(-1L, GuardedDelete.delete("relative/x") { skip })
        assertEquals(-1L, GuardedDelete.delete(p(d) + "/../s/x.txt") { skip })
    }

    @Test fun plainTreeDeletesFullyAndMissingIsZero() {
        val d = tmp.newFolder("plain")
        File(d, "a/b").mkdirs(); File(d, "a/b/c.txt").writeText("12345")
        assertEquals(5L, GuardedDelete.delete(p(d)) { SkipGuard.of(emptyList()) })
        assertFalse(d.exists())
        assertEquals(0L, GuardedDelete.delete(p(d)) { SkipGuard.of(emptyList()) })
    }

    @Test fun listChangesMidDeleteAreHonoured() {
        val d = tmp.newFolder("live")
        val a = File(d, "a.txt").apply { writeText("a") }
        val b = File(d, "b.txt").apply { writeText("b") }
        var calls = 0
        // The list gains b.txt after the first guard look-ups: b must survive.
        val guard = { if (++calls > 2) SkipGuard.of(listOf(p(b))) else SkipGuard.of(emptyList()) }
        GuardedDelete.delete(p(d), guard)
        assertTrue(b.exists())
        assertEquals("b", b.readText())
    }

    @Test fun symlinkRemovedAsLinkOnly() {
        val parent = tmp.newFolder("lp")
        val keep = File(parent, "keep").apply { mkdirs() }
        val inner = File(keep, "k.txt").apply { writeText("keepme") }
        val outside = tmp.newFolder("outside")
        File(outside, "o.txt").writeText("outside")
        val link = File(parent, "linkToKeep").toPath()
        val link2 = File(parent, "linkToOutside").toPath()
        try {
            Files.createSymbolicLink(link, keep.toPath())
            Files.createSymbolicLink(link2, outside.toPath())
        } catch (e: Exception) {   // Windows without symlink privilege: say so, skip
            assumeNoException("cannot create symlinks on this host", e)
        }
        val skip = SkipGuard.of(listOf(p(keep)))
        GuardedDelete.delete(p(parent)) { skip }
        assertFalse(Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(link2, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        assertEquals("keepme", inner.readText())
        assertEquals("outside", File(outside, "o.txt").readText())
    }
}
