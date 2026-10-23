package com.scourvex.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object Neon {
    val Bg = Color(0xFF07070F)
    val Surface = Color(0xFF10111E)
    val Surface2 = Color(0xFF181A2C)
    val Cyan = Color(0xFF00E5FF)
    val Magenta = Color(0xFFFF2BD6)
    val Violet = Color(0xFF8A5CFF)
    val Lime = Color(0xFF7CFF6B)
    val Amber = Color(0xFFFFB020)
    val Red = Color(0xFFFF3B5C)
    val Text = Color(0xFFE8ECFF)
    val Dim = Color(0xFF8A90B0)

    val Primary = Brush.linearGradient(listOf(Cyan, Violet, Magenta))
    val Danger = Brush.linearGradient(listOf(Red, Magenta))
    val Safe = Brush.linearGradient(listOf(Lime, Cyan))
}

private val scheme = darkColorScheme(
    primary = Neon.Cyan,
    onPrimary = Neon.Bg,
    secondary = Neon.Magenta,
    tertiary = Neon.Lime,
    background = Neon.Bg,
    onBackground = Neon.Text,
    surface = Neon.Surface,
    onSurface = Neon.Text,
    surfaceVariant = Neon.Surface2,
    onSurfaceVariant = Neon.Dim,
    error = Neon.Red,
    outline = Neon.Dim,
)

private val type = Typography(
    displayLarge = TextStyle(fontWeight = FontWeight.Black, fontSize = 44.sp, letterSpacing = (-1).sp),
    headlineMedium = TextStyle(fontWeight = FontWeight.ExtraBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontWeight = FontWeight.Bold, fontSize = 20.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 16.sp),
    bodyLarge = TextStyle(fontSize = 15.sp),
    bodyMedium = TextStyle(fontSize = 14.sp),
    labelLarge = TextStyle(fontWeight = FontWeight.Bold, fontSize = 14.sp, letterSpacing = 1.sp),
    labelSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
)

@Composable
fun ScourvexTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = scheme, typography = type, content = content)
}
