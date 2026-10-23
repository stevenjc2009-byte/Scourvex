package com.scourvex.app.core

import android.content.Context
import com.scourvex.app.ScourvexApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** User settings: skip list, update preferences. */
object Prefs {
    private val sp by lazy { ScourvexApp.instance.getSharedPreferences("scourvex", Context.MODE_PRIVATE) }

    private val _skip by lazy { MutableStateFlow(loadSkip()) }
    val skip: StateFlow<List<String>> get() = _skip

    /** Stored entries, normalised on load so old raw entries (/sdcard/x, trailing /, //) still match. */
    private fun loadSkip(): List<String> =
        sp.getString("skip", "")!!.split('\n').map { SkipGuard.normalize(it) }.filter { it.startsWith("/") }.distinct()

    fun addSkip(path: String) {
        val clean = SkipGuard.normalize(path)
        if (!clean.startsWith("/")) return
        val next = (loadSkip() + clean).distinct().sorted()
        sp.edit().putString("skip", next.joinToString("\n")).apply()
        _skip.value = next
    }

    fun removeSkip(path: String) {
        val next = loadSkip() - SkipGuard.normalize(path)
        sp.edit().putString("skip", next.joinToString("\n")).apply()
        _skip.value = next
    }

    var autoUpdateCheck: Boolean
        get() = sp.getBoolean("auto_update", true)
        set(v) = sp.edit().putBoolean("auto_update", v).apply()

    var lastUpdateCheck: Long
        get() = sp.getLong("last_update_check", 0)
        set(v) = sp.edit().putLong("last_update_check", v).apply()

    /** Package names / file paths the user marked as "not a threat". */
    var ignoredThreats: Set<String>
        get() = sp.getStringSet("ignored_threats", emptySet())!!
        set(v) = sp.edit().putStringSet("ignored_threats", v).apply()
}
