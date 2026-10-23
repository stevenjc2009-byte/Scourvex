package com.scourvex.app.core

import java.io.IOException
import java.nio.file.DirectoryNotEmptyException
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes

/**
 * Deletes a tree without ever touching a skip-list entry. The skip check runs on the path string
 * before any stat, the list is re-read ([guard]) at every node, symlinks are removed as links and
 * never followed, and a folder that holds a skipped entry is left in place with only its other
 * content deleted. Pure java.nio so it runs in the app, in the Shizuku shell process and in JVM tests.
 */
object GuardedDelete {

    /** Bytes freed (0 if already gone), or -1 when refused (path is skipped / not absolute) or something failed. */
    fun delete(path: String, guard: () -> SkipSet): Long {
        val root = try { Paths.get(path) } catch (_: java.nio.file.InvalidPathException) { return -1 }
        if (!root.isAbsolute || SkipSet.hasDotDot(path) || guard().isSkipped(path.replace('\\', '/'))) return -1
        val run = Run(guard)
        run.node(root)
        return if (run.failed) -1 else run.freed
    }

    private class Run(val guard: () -> SkipSet) {
        var freed = 0L
        var failed = false

        /** True when [p] is gone afterwards; false when kept (skipped content) or failed. */
        fun node(p: Path): Boolean {
            val s = p.toString().replace('\\', '/')
            if (guard().isSkipped(s)) return false
            val a = try {
                java.nio.file.Files.readAttributes(p, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (_: NoSuchFileException) {
                return true
            } catch (_: IOException) {
                failed = true; return false
            }
            if (a.isDirectory) {
                val kids = try {
                    java.nio.file.Files.newDirectoryStream(p).use { it.toList() }
                } catch (_: IOException) {
                    failed = true; return false
                }
                var all = true
                for (k in kids) if (!node(k)) all = false
                // A skip entry added meanwhile makes the folder non-empty: leave it.
                if (!all || guard().isAncestorOfSkip(s)) return false
                return remove(p, 0)
            }
            return remove(p, if (a.isRegularFile) a.size() else 0)
        }

        private fun remove(p: Path, len: Long): Boolean = try {
            java.nio.file.Files.delete(p); freed += len; true
        } catch (_: NoSuchFileException) {
            true
        } catch (_: DirectoryNotEmptyException) {
            false
        } catch (_: IOException) {
            failed = true; false
        }
    }
}
