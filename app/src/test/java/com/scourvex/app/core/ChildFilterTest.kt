package com.scourvex.app.core

import org.junit.Assert.assertEquals
import org.junit.Test

/** The per-directory name filter must give the same answer as normalising each full child path. */
class ChildFilterTest {

    private val skip = SkipSet.of(listOf(
        "/storage/emulated/0/Android/data/com.keep.me",
        "/storage/emulated/0/DCIM/Private/",
        "/storage/emulated/0/Download/Secret Stuff",
        "/storage/emulated/0/Documents",
        "/storage/ABCD-1234/Backup",
        "/data/local/tmp/keep",
        "/sdcard/Pictures/Hidden",
    ))

    private val dirs = listOf(
        "/storage/emulated/0", "/storage/emulated/0/Android/data", "/storage/emulated/0/DCIM", "/storage/emulated/0/DCIM/Private",
        "/storage/emulated/0/Download", "/storage/emulated/0/Documents", "/storage/emulated/0/Documents/sub", "/storage/emulated/0/Pictures",
        "/storage/ABCD-1234", "/storage", "/data/local/tmp", "/data/local", "/storage/emulated", "/storage/emulated/0/Music",
    )
    private val names = listOf(
        "com.keep.me", "COM.KEEP.ME", "com.keep.me2", "com.other", "Private", "private", "PRIVATE", "Secret Stuff", "secret stuff",
        "Secret Stuff ", "x", "Backup", "backup", "keep", "Keep", "Hidden", "Pictures", "sub", "Download", "Documents", "emulated", "0",
    )

    @Test fun sameAnswerAsFullNormalisation() {
        for (d in dirs) {
            val filter = skip.childFilter(d)
            for (n in names) {
                val path = "$d/$n"
                assertEquals("dir=$d name=$n", skip.isSkipped(path), filter.skips(path, n))
            }
        }
    }

    @Test fun emptyListSkipsNothing() {
        val none = SkipSet.of(emptyList())
        assertEquals(false, none.childFilter("/storage/emulated/0").skips("/storage/emulated/0/DCIM", "DCIM"))
    }
}
