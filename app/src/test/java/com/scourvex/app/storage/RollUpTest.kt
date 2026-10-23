package com.scourvex.app.storage

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Random

/** Folder totals: the one-pass roll-up must equal adding every file to every ancestor below its volume root. */
class RollUpTest {

    private val roots = listOf("/storage/emulated/0", "/storage/ABCD-1234")

    private fun climb(files: List<Pair<String, Long>>): Map<String, List<Long>> {
        val folder = HashMap<String, LongArray>()
        for ((path, size) in files) {
            val root = roots.firstOrNull { path.startsWith("$it/") } ?: continue
            var d = path.substringBeforeLast('/')
            while (d.length > root.length) {
                val a = folder.getOrPut(d) { LongArray(2) }
                a[0] += size; a[1]++
                d = d.substringBeforeLast('/')
            }
        }
        return folder.mapValues { it.value.toList() }
    }

    private fun rolled(files: List<Pair<String, Long>>): Map<String, List<Long>> {
        val direct = HashMap<String, LongArray>()
        for ((path, size) in files) {
            val prefix = roots.map { "$it/" }.firstOrNull { path.startsWith(it) } ?: continue
            val parent = path.substringBeforeLast('/')
            if (parent.length < prefix.length) continue
            val a = direct.getOrPut(parent) { LongArray(2) }
            a[0] += size; a[1]++
        }
        return StorageAnalyzer.rollUp(direct, roots).mapValues { it.value.toList() }
    }

    @Test fun matchesAncestorClimb() {
        val rnd = Random(7)
        val dirs = listOf("DCIM", "DCIM/Camera", "DCIM/Camera/2024", "Download", "Android/data/a.b/files/x/y", "Music/A/B/C/D")
        val files = List(2000) {
            val root = roots[rnd.nextInt(2)]
            val d = if (rnd.nextInt(10) == 0) "" else dirs[rnd.nextInt(dirs.size)] + "/"
            "$root/$d" + "f$it.bin" to (1 + rnd.nextInt(5000)).toLong()
        } + listOf("/other/place/file" to 5L)
        assertEquals(climb(files), rolled(files))
    }

    @Test fun rootItselfIsNeverListed() {
        val r = rolled(listOf("/storage/emulated/0/a.txt" to 10L, "/storage/emulated/0/d/b.txt" to 5L))
        assertEquals(mapOf("/storage/emulated/0/d" to listOf(5L, 1L)), r)
    }
}
