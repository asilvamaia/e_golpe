import 'package:flutter/material.dart';
import '../models/analysis_result.dart';
import '../theme/app_theme.dart';

class VerdictCard extends StatelessWidget {
  final AnalysisResult result;
  final bool isHighContrast;

  const VerdictCard({
    super.key,
    required this.result,
    this.isHighContrast = false,
  });

  @override
  Widget build(BuildContext context) {
    final color = AppTheme.getVerdictColor(result.level, isHighContrast: isHighContrast);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    String title;
    String subtitle;

    switch (result.level) {
      case 'safe':
        title = 'CONTEÚDO SEGURO';
        subtitle = 'Nenhum indício grave de fraude ou ameaça foi detectado.';
        break;
      case 'danger':
        title = 'ALERTA DE GOLPE!';
        subtitle = 'Foram identificados fortes indícios de fraude ou tentativa de golpe.';
        break;
      default:
        title = 'ATENÇÃO: SUSPEITO';
        subtitle = 'Proceda com cautela extrema e verifique com fontes oficiais.';
        break;
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: isHighContrast
            ? AppTheme.hcBackground
            : (isDark ? color.withOpacity(0.15) : color.withOpacity(0.08)),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: color,
          width: isHighContrast ? 2.5 : 1.5,
        ),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                result.icon,
                style: const TextStyle(fontSize: 28),
              ),
              const SizedBox(width: 10),
              Flexible(
                child: Text(
                  title,
                  style: TextStyle(
                    fontSize: isHighContrast ? 22 : 18,
                    fontWeight: FontWeight.w800,
                    color: color,
                    letterSpacing: -0.3,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            subtitle,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: isHighContrast ? 16 : 14,
              fontWeight: isHighContrast ? FontWeight.bold : FontWeight.w500,
              color: isHighContrast
                  ? AppTheme.hcYellow
                  : (isDark ? Colors.white70 : Colors.black87),
            ),
          ),
          if (result.cached) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: isHighContrast ? AppTheme.hcBackground : Colors.black12,
                borderRadius: BorderRadius.circular(8),
                border: isHighContrast ? Border.all(color: AppTheme.hcYellow) : null,
              ),
              child: Text(
                '⚡ Resultado em Cache (Verificado Recentemente)',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: isHighContrast ? AppTheme.hcYellow : Colors.grey.shade600,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
