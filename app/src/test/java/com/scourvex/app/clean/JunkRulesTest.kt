package com.scourvex.app.clean

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class JunkRulesTest {
    private val installed = { p: String -> p == "com.whatsapp" || p == "com.android.chrome" }
    private fun dir(rel: String) = JunkRules.classifyDir(rel, installed)

    @Test fun directories() {
        assertEquals(JunkCategory.APP_CACHE, dir("Android/data/com.android.chrome/cache")?.category)
        assertEquals(JunkCategory.LEFTOVERS, dir("Android/data/com.gone.app")?.category)
        assertEquals("com.gone.app", dir("Android/data/com.gone.app")?.pkg)
        assertNull(dir("Android/data/com.gone.app/files"))             // parent already reported
        assertEquals(JunkCategory.THUMBNAILS, dir("DCIM/.thumbnails")?.category)
        assertEquals(JunkCategory.RECYCLE_BINS, dir("Android/.Trash/com.sec.android.gallery3d")?.category)
        assertEquals(JunkCategory.LOST_FILES, dir("LOST.DIR")?.category)
        assertNull(dir("DCIM/Camera"))
        assertNull(dir("Android/data/com.whatsapp/files"))
        assertNull(dir("Android/data"))
    }

    @Test fun files() {
        assertEquals(JunkCategory.RECYCLE_BINS, JunkRules.classifyFile("DCIM/Camera/.trashed-1712345678-IMG_1.jpg"))
        assertEquals(JunkCategory.OS_LITTER, JunkRules.classifyFile("Download/.DS_Store"))
        assertEquals(JunkCategory.APK_FILES, JunkRules.classifyFile("Download/game.apk"))
        assertNull(JunkRules.classifyFile("Android/obb/com.game/main.apk"))
        assertNull(JunkRules.classifyFile("DCIM/Camera/IMG_1.jpg"))
        assertNull(JunkRules.classifyFile("Documents/report.pdf"))
    }
}
