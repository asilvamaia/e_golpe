import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/security_tip.dart';
import '../services/storage_service.dart';
import '../theme/app_theme.dart';

class GuideTab extends StatelessWidget {
  final StorageService storageService;

  const GuideTab({
    super.key,
    required this.storageService,
  });

  Future<void> _callPhone(String number) async {
    final uri = Uri(scheme: 'tel', path: number);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isHc = storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final tips = SecurityTip.getDefaultTips();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Guia Anti-Golpe'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // Emergency Helpline Banner
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: isHc
                  ? AppTheme.hcBackground
                  : (isDark ? const Color(0xFF1C1C1E) : Colors.white),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: isHc ? AppTheme.hcYellow : AppTheme.dangerRed.withOpacity(0.5),
                width: isHc ? 2.5 : 1.5,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.phone_in_talk, color: AppTheme.dangerRed),
                    const SizedBox(width: 8),
                    Text(
                      'Telefones de Emergência',
                      style: TextStyle(
                        fontSize: isHc ? 18 : 16,
                        fontWeight: FontWeight.bold,
                        color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  'Caiu em um golpe? Bloqueie suas contas e faça o B.O. imediatamente:',
                  style: TextStyle(
                    fontSize: 13,
                    color: isHc ? Colors.white70 : Colors.grey.shade600,
                  ),
                ),
                const SizedBox(height: 14),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: [
                    _buildEmergencyButton('Disque 190 (Polícia)', '190', isHc),
                    _buildEmergencyButton('Disque 100 (Direitos)', '100', isHc),
                    _buildEmergencyButton('Disque 181 (Denúncia)', '181', isHc),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          Text(
            'Golpes Mais Frequentes no Brasil:',
            style: TextStyle(
              fontSize: isHc ? 19 : 17,
              fontWeight: FontWeight.bold,
              color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
            ),
          ),
          const SizedBox(height: 12),

          // List of Educational Tips
          ...tips.map((tip) => _buildTipCard(tip, isHc, isDark, context)),
          const SizedBox(height: 30),
        ],
      ),
    );
  }

  Widget _buildEmergencyButton(String label, String number, bool isHc) {
    return ElevatedButton.icon(
      onPressed: () => _callPhone(number),
      icon: const Icon(Icons.phone, size: 16),
      label: Text(label),
      style: ElevatedButton.styleFrom(
        backgroundColor: AppTheme.dangerRed,
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
      ),
    );
  }

  Widget _buildTipCard(SecurityTip tip, bool isHc, bool isDark, BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: ExpansionTile(
        shape: const Border(),
        collapsedShape: const Border(),
        leading: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: isDark ? Colors.black26 : const Color(0xFFF2F2F7),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Text(tip.icon, style: const TextStyle(fontSize: 22)),
        ),
        title: Text(
          tip.title,
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            fontWeight: FontWeight.bold,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
          ),
        ),
        subtitle: Text(
          tip.category,
          style: TextStyle(
            fontSize: 12,
            color: isHc ? AppTheme.hcYellow.withOpacity(0.8) : AppTheme.iosBlue,
            fontWeight: FontWeight.w600,
          ),
        ),
        childrenPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        children: [
          Text(
            tip.description,
            style: TextStyle(
              fontSize: 14,
              height: 1.4,
              color: isHc ? Colors.white : (isDark ? Colors.white70 : Colors.black87),
            ),
          ),
          const SizedBox(height: 14),

          // Como Funciona
          Text(
            '🔍 Como o golpe funciona:',
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.bold,
              color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
            ),
          ),
          const SizedBox(height: 6),
          ...tip.howItWorks.map((step) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('• ', style: TextStyle(fontWeight: FontWeight.bold)),
                    Expanded(
                      child: Text(
                        step,
                        style: TextStyle(
                          fontSize: 13,
                          color: isHc ? Colors.white70 : Colors.grey.shade700,
                        ),
                      ),
                    ),
                  ],
                ),
              )),
          const SizedBox(height: 14),

          // Como se Proteger
          Text(
            '🛡️ Como se proteger:',
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.bold,
              color: AppTheme.safeGreen,
            ),
          ),
          const SizedBox(height: 6),
          ...tip.howToProtect.map((step) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('✓ ', style: TextStyle(color: AppTheme.safeGreen, fontWeight: FontWeight.bold)),
                    Expanded(
                      child: Text(
                        step,
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                          color: isHc ? Colors.white : (isDark ? Colors.white70 : Colors.black87),
                        ),
                      ),
                    ),
                  ],
                ),
              )),
          const SizedBox(height: 14),

          // Exemplo Real
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isDark ? Colors.black38 : const Color(0xFFF2F2F7),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: Colors.grey.withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Exemplo real de mensagem golpista:',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey),
                ),
                const SizedBox(height: 4),
                Text(
                  tip.realExample,
                  style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
                ),
              ],
            ),
          ),
          const SizedBox(height: 10),
        ],
      ),
    );
  }
}
