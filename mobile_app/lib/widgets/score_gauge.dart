import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class ScoreGauge extends StatelessWidget {
  final int score;
  final String level;
  final bool isHighContrast;
  final double size;

  const ScoreGauge({
    super.key,
    required this.score,
    required this.level,
    this.isHighContrast = false,
    this.size = 140,
  });

  @override
  Widget build(BuildContext context) {
    final color = AppTheme.getVerdictColor(level, isHighContrast: isHighContrast);

    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        alignment: Alignment.center,
        children: [
          CustomPaint(
            size: Size(size, size),
            painter: _GaugePainter(
              score: score,
              color: color,
              backgroundColor: isHighContrast
                  ? Colors.grey.shade900
                  : (Theme.of(context).brightness == Brightness.dark
                      ? const Color(0xFF2C2C2E)
                      : const Color(0xFFE5E5EA)),
            ),
          ),
          Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                '$score',
                style: TextStyle(
                  fontSize: size * 0.28,
                  fontWeight: FontWeight.w800,
                  color: isHighContrast
                      ? AppTheme.hcYellow
                      : (Theme.of(context).brightness == Brightness.dark ? Colors.white : Colors.black),
                ),
              ),
              Text(
                'de 100',
                style: TextStyle(
                  fontSize: size * 0.11,
                  fontWeight: FontWeight.w500,
                  color: isHighContrast ? AppTheme.hcYellow : Colors.grey,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _GaugePainter extends CustomPainter {
  final int score;
  final Color color;
  final Color backgroundColor;

  _GaugePainter({
    required this.score,
    required this.color,
    required this.backgroundColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final strokeWidth = size.width * 0.09;
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width - strokeWidth) / 2;

    const startAngle = 0.75 * math.pi;
    const totalSweep = 1.5 * math.pi;
    final currentSweep = (score / 100.0) * totalSweep;

    final bgPaint = Paint()
      ..color = backgroundColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    final fgPaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    // Background track
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      totalSweep,
      false,
      bgPaint,
    );

    // Foreground progress
    if (score > 0) {
      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        startAngle,
        currentSweep,
        false,
        fgPaint,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _GaugePainter oldDelegate) {
    return oldDelegate.score != score || oldDelegate.color != color;
  }
}
