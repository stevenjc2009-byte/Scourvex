package com.scourvex.app.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.scourvex.app.ui.theme.Neon

/** Dark card with a thin gradient rim and a soft coloured glow behind it. */
@Composable
fun GlowCard(
    modifier: Modifier = Modifier,
    glow: Color = Neon.Cyan,
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(22.dp)
    Box(
        modifier
            .fillMaxWidth()
            .drawBehind {
                drawRoundRect(
                    Brush.radialGradient(listOf(glow.copy(alpha = 0.18f), Color.Transparent), center = Offset(size.width * 0.15f, 0f), radius = size.maxDimension),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(22.dp.toPx()),
                )
            }
            .clip(shape)
            .background(Brush.verticalGradient(listOf(Neon.Surface2, Neon.Surface)))
            .border(1.dp, Brush.linearGradient(listOf(glow.copy(alpha = 0.7f), Color.Transparent, glow.copy(alpha = 0.25f))), shape)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(18.dp),
    ) { content() }
}

/** Big gradient pill button. */
@Composable
fun NeonButton(
    text: String,
    modifier: Modifier = Modifier,
    brush: Brush = Neon.Primary,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(50)
    Row(
        modifier
            .clip(shape)
            .background(if (enabled) brush else Brush.linearGradient(listOf(Neon.Surface2, Neon.Surface2)))
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 22.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        if (icon != null) {
            Icon(icon, null, tint = if (enabled) Neon.Bg else Neon.Dim, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text.uppercase(), color = if (enabled) Neon.Bg else Neon.Dim, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Black)
    }
}

/** Outline button for secondary actions. */
@Composable
fun GhostButton(text: String, modifier: Modifier = Modifier, color: Color = Neon.Cyan, onClick: () -> Unit) {
    Text(
        text.uppercase(),
        modifier
            .clip(RoundedCornerShape(50))
            .border(1.dp, color.copy(alpha = 0.7f), RoundedCornerShape(50))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        color = color,
        style = MaterialTheme.typography.labelLarge,
    )
}

/**
 * The scan orb: rotating sweep rings while [active], a progress arc for [progress] (0..1, or
 * null for indeterminate) and a big centre label.
 */
@Composable
fun ScanOrb(
    title: String,
    subtitle: String,
    active: Boolean,
    progress: Float?,
    modifier: Modifier = Modifier,
    size: Dp = 240.dp,
    accent: Color = Neon.Cyan,
) {
    val t = rememberInfiniteTransition(label = "orb")
    val spin by t.animateFloat(0f, 360f, infiniteRepeatable(tween(if (active) 1600 else 9000, easing = LinearEasing)), label = "spin")
    val spin2 by t.animateFloat(360f, 0f, infiniteRepeatable(tween(if (active) 2600 else 14000, easing = LinearEasing)), label = "spin2")
    val pulse by t.animateFloat(0.85f, 1f, infiniteRepeatable(tween(1200), RepeatMode.Reverse), label = "pulse")
    val shown by animateFloatAsState(progress ?: 0f, label = "progress")

    Box(modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size)) {
            val r = this.size.minDimension / 2
            drawCircle(Brush.radialGradient(listOf(accent.copy(alpha = 0.22f * pulse), Color.Transparent)), r)
            val ring = Stroke(width = r * 0.05f, cap = StrokeCap.Round)
            val inset = r * 0.12f
            val box = Size(this.size.width - inset * 2, this.size.height - inset * 2)
            drawArc(Neon.Surface2, 0f, 360f, false, Offset(inset, inset), box, style = ring)
            rotate(spin) {
                drawArc(Brush.sweepGradient(listOf(Color.Transparent, accent, Neon.Magenta, Color.Transparent)), 0f, 300f, false,
                    Offset(inset, inset), box, style = Stroke(r * 0.03f, cap = StrokeCap.Round))
            }
            val inset2 = r * 0.26f
            val box2 = Size(this.size.width - inset2 * 2, this.size.height - inset2 * 2)
            rotate(spin2) {
                drawArc(Brush.sweepGradient(listOf(Color.Transparent, Neon.Violet, Color.Transparent)), 0f, 220f, false,
                    Offset(inset2, inset2), box2, style = Stroke(r * 0.015f, cap = StrokeCap.Round))
            }
            if (progress != null) {
                drawArc(Brush.sweepGradient(listOf(Neon.Lime, accent, Neon.Lime)), -90f, 360f * shown, false,
                    Offset(inset, inset), box, style = ring)
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(title, style = MaterialTheme.typography.displayLarge, color = Neon.Text, textAlign = TextAlign.Center)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = Neon.Dim, textAlign = TextAlign.Center,
                modifier = Modifier.width(size * 0.62f))
        }
    }
}

/** Thin gradient bar, [value] 0..1. */
@Composable
fun NeonBar(value: Float, modifier: Modifier = Modifier, brush: Brush = Neon.Primary, height: Dp = 8.dp) {
    val v by animateFloatAsState(value.coerceIn(0f, 1f), label = "bar")
    Box(modifier.fillMaxWidth().height(height).clip(RoundedCornerShape(50)).background(Neon.Surface2)) {
        Box(Modifier.fillMaxWidth(v).height(height).clip(RoundedCornerShape(50)).background(brush))
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(text.uppercase(), modifier.padding(top = 18.dp, bottom = 8.dp), color = Neon.Cyan,
        style = MaterialTheme.typography.labelLarge)
}

/** Warning / info strip with an optional action. */
@Composable
fun Banner(text: String, color: Color = Neon.Amber, action: String? = null, onAction: () -> Unit = {}) {
    GlowCard(glow = color, onClick = if (action != null) onAction else null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(10.dp).clip(RoundedCornerShape(50)).background(color))
            Spacer(Modifier.width(12.dp))
            Text(text, Modifier.weight(1f), color = Neon.Text, style = MaterialTheme.typography.bodyMedium)
            if (action != null) {
                Spacer(Modifier.width(8.dp))
                Text(action.uppercase(), color = color, style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}

@Composable
fun Stat(value: String, label: String, color: Color = Neon.Cyan, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(value, color = color, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Black)
        Text(label, color = Neon.Dim, style = MaterialTheme.typography.bodyMedium)
    }
}
