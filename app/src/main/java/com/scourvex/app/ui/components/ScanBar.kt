package com.scourvex.app.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.scourvex.app.ui.theme.Neon

/**
 * Loading bar shown under every running scan. [progress] null = the length of the job is not known yet:
 * a glowing segment sweeps back and forth so it is always visibly moving.
 */
@Composable
fun ScanBar(label: String, progress: Float?, modifier: Modifier = Modifier, accent: Color = Neon.Cyan) {
    val t = rememberInfiniteTransition(label = "scanbar")
    val sweep by t.animateFloat(-0.35f, 1f, infiniteRepeatable(tween(1100, easing = LinearEasing)), label = "sweep")
    val shown by animateFloatAsState((progress ?: 0f).coerceIn(0f, 1f), label = "scanbarProgress")
    Column(modifier.fillMaxWidth()) {
        Text(label, color = Neon.Dim, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Canvas(Modifier.fillMaxWidth().height(8.dp)) {
            val h = size.height
            val r = CornerRadius(h / 2, h / 2)
            drawRoundRect(Neon.Surface2, cornerRadius = r)
            val brush = Brush.horizontalGradient(listOf(accent, Neon.Magenta))
            if (progress != null) drawRoundRect(brush, size = Size(size.width * shown, h), cornerRadius = r)
            // The sweep runs on top of a determinate bar too, so a slow step never looks frozen.
            val w = size.width * 0.35f
            val x = size.width * sweep
            val left = x.coerceAtLeast(0f)
            val right = (x + w).coerceAtMost(size.width)
            if (right > left) drawRoundRect(
                Brush.horizontalGradient(listOf(Color.Transparent, accent.copy(alpha = if (progress != null) 0.55f else 1f), Color.Transparent), left, right),
                Offset(left, 0f), Size(right - left, h), r,
            )
        }
    }
}
