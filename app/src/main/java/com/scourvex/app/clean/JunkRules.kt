package com.scourvex.app.clean

/**
 * What counts as junk. Locations come from SD Maid SE's SystemCleaner / AppCleaner /
 * CorpseFinder filter lists plus Samsung's per-app trash folder (see vault scourvex-research).
 * Pure functions so they can be unit-tested off-device.
 */
enum class JunkCategory(val label: String, val auto: Boolean, val detail: String) {
    APP_CACHE("App caches", true, "Internal + external caches of every installed app, plus hidden cache folders"),
    THUMBNAILS("Thumbnail caches", true, "Preview images, including ones for photos you already deleted"),
    TEMP("Temporary files", true, ".tmp / .temp / partial download leftovers"),
    LOGS("Log & crash files", true, "App logs, crash dumps, bug reports"),
    ADS("Ad & tracker data", true, "Folders ad and analytics SDKs leave on storage"),
    OS_LITTER("System litter", true, "desktop.ini, Thumbs.db, .DS_Store, ._ files copied from PCs"),
    EMPTY_FOLDERS("Empty folders", true, "Folders with nothing inside"),
    RECYCLE_BINS("Recycle bins & trash", false, "Gallery / My Files / app trash and hidden bins"),
    LEFTOVERS("Uninstalled app leftovers", false, "Data folders of apps that are no longer installed"),
    LOST_FILES("Recovered fragments", false, "LOST.DIR file fragments from storage errors"),
    APK_FILES("Installer files", false, "APK / APKS / XAPK installers already used"),
}

object JunkRules {

    private val thumbDirs = setOf(".thumbnails", "thumbnails", ".thumbs", "thumbs", "albumthumbs", ".thumbcache")
    private val binDirs = setOf(
        ".trash", "trash", ".trashfiles", "trashfiles", ".trashbin", "trashbin", ".recycle", "recycle",
        ".recyclebin", "recyclebin", ".recycle.bin", ".garbage", ".deleted", ".recentlydeleted",
    )
    private val hiddenCacheDirs = setOf(
        "cache", ".cache", "code_cache", "tmp", ".tmp", "temp", ".temp", "imagecache", ".imagecache",
        "image_cache", "videocache", ".videocache", "video_cache", "mediacache", "media_cache",
        "diskcache", "disk_cache", "webviewcache", "app_webview", "glide_cache", "image_manager_disk_cache",
        "picasso-cache", "fresco_cache", ".statuses", "shaders", "pipeline_cache",
    )
    private val adDirs = setOf(
        ".mologiq", ".adcenix", "applifiervideocache", "ppy_cross", ".bugsense", ".tlocalcookieid",
        ".installation", ".utsystemconfig", ".dataservice", ".um", ".uxx", ".vdevdir", ".gs_fs0",
        ".imprint", ".mta", ".tbs", ".clientid",
    )
    private val litterNames = setOf("desktop.ini", "thumbs.db", ".ds_store", "ehthumbs.db", ".localized", "icon\r")
    private val tempExt = listOf(".tmp", ".temp", ".mmsyscache", ".crdownload", ".part", ".partial", ".download", ".dlpart", ".bak~", "~")
    private val logExt = listOf(".log", ".txt.old", ".log.old", ".log.bak", ".trace", ".dmp", ".hprof", ".stacktrace")
    private val logNames = setOf("bt_activity_pkt.txt.last", "bugreport.txt", "crash.txt", "logcat.txt")
    private val apkExt = listOf(".apk", ".apks", ".xapk", ".apkm")

    /** Top-level folders never reported as empty (Android recreates or expects them). */
    val keepEmpty = setOf(
        "Alarms", "Android", "Audiobooks", "DCIM", "Documents", "Download", "Movies", "Music",
        "Notifications", "Pictures", "Podcasts", "Recordings", "Ringtones", "Samsung",
    )

    /** A directory that is junk as a whole (everything inside belongs to the same item). */
    data class DirHit(val category: JunkCategory, val pkg: String? = null)

    /**
     * Classifies a directory. [rel] is the path relative to the storage root, e.g.
     * "Android/data/com.foo/cache". [installed] answers whether a package is installed.
     */
    fun classifyDir(rel: String, installed: (String) -> Boolean): DirHit? {
        val seg = rel.split('/')
        val name = seg.last().lowercase()
        if (seg.size >= 3 && seg[0] == "Android" && seg[1] in appAreas) {
            val pkg = seg[2]
            if (!pkg.contains('.')) return null
            if (!installed(pkg)) return if (seg.size == 3) DirHit(JunkCategory.LEFTOVERS, pkg) else null
            if (seg.size >= 4 && name in hiddenCacheDirs) return DirHit(JunkCategory.APP_CACHE, pkg)
            if (seg.size >= 4 && name in thumbDirs) return DirHit(JunkCategory.THUMBNAILS, pkg)
            if (seg.size >= 4 && (name in binDirs || name.startsWith(".trash-"))) return DirHit(JunkCategory.RECYCLE_BINS, pkg)
            return null
        }
        // Samsung keeps each app's deleted files in Android/.Trash/<package>/.
        if (seg.size == 3 && seg[0] == "Android" && seg[1] == ".Trash") return DirHit(JunkCategory.RECYCLE_BINS, seg[2])
        if (seg[0] == "Android" && seg.size <= 2) return null
        // Outside app folders only hidden (dot) thumbnail caches count: a plain "Thumbnails" folder may be the user's own (auto-cleaned category).
        if (name in thumbDirs && (name.startsWith(".") || name == "albumthumbs")) return DirHit(JunkCategory.THUMBNAILS)
        if (name in binDirs || name.startsWith(".trash-")) return DirHit(JunkCategory.RECYCLE_BINS)
        if (name == "lost.dir") return DirHit(JunkCategory.LOST_FILES)
        if (seg.size <= 2 && name in adDirs) return DirHit(JunkCategory.ADS)
        if (name.startsWith(".mologiq")) return DirHit(JunkCategory.ADS)
        return null
    }

    /** Classifies a single file that is not inside a junk directory. */
    fun classifyFile(rel: String): JunkCategory? {
        val name = rel.substringAfterLast('/')
        val lower = name.lowercase()
        if (lower.startsWith(".trashed-")) return JunkCategory.RECYCLE_BINS
        if (lower.startsWith(".thumbdata")) return JunkCategory.THUMBNAILS
        if (lower in litterNames || (name.startsWith("._") && name.length > 2)) return JunkCategory.OS_LITTER
        if (lower in logNames || logExt.any { lower.endsWith(it) } || Regex("""\.log\.\d+$""").containsMatchIn(lower)) {
            return JunkCategory.LOGS
        }
        if (tempExt.any { lower.endsWith(it) } && lower.length > 4) return JunkCategory.TEMP
        if (apkExt.any { lower.endsWith(it) } && !rel.startsWith("Android/")) return JunkCategory.APK_FILES
        return null
    }

    private val appAreas = setOf("data", "media", "obb")
}
