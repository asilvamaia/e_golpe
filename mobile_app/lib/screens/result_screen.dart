import 'package:flutter/material.dart';
import 'package:share_plus/share_plus.dart';
import '../models/analysis_result.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../services/tts_service.dart';
import '../theme/app_theme.dart';
import '../widgets/score_gauge.dart';
import '../widgets/verdict_card.dart';

class ResultScreen extends StatefulWidget {
  final AnalysisResult result;
  final String? inputSource;
  final ApiService apiService;
  final StorageService storageService;
  final TtsService ttsService;

  const ResultScreen({
    super.key,
    required this.result,
    this.inputSource,
    required this.apiService,
    required this.storageService,
    required this.ttsService,
  });

  @override
  State<ResultScreen> createState() => _ResultScreenState();
}

class _ResultScreenState extends State<ResultScreen> {
  bool _isSpeaking = false;
  String? _feedbackSent;

  @override
  void initState() {
    super.initState();
    if (widget.storageService.isAutoTts()) {
      _speakResult();
    }
  }

  @override
  void dispose() {
    widget.ttsService.stop();
    super.dispose();
  }

  void _speakResult() async {
    setState(() => _isSpeaking = true);
    final textToSpeak = "${widget.result.verdict}. Nível de segurança: ${widget.result.score} de 100. ${widget.result.summaryText}";
    await widget.ttsService.speak(textToSpeak);
    if (mounted) {
      setState(() => _isSpeaking = false);
    }
  }

  void _toggleSpeak() async {
    if (_isSpeaking) {
      await widget.ttsService.stop();
      setState(() => _isSpeaking = false);
    } else {
      _speakResult();
    }
  }

  void _shareResult() {
    final alertEmoji = widget.result.icon;
    final text = """$alertEmoji *Alerta do App É Golpe?*
Veredito: *${widget.result.verdict}* (Score: ${widget.result.score}/100)

${widget.result.url != null ? "🔗 Link Analisado: ${widget.result.url}\n\n" : ""}📋 *Resumo da Análise:*
${widget.result.summaryText}

🛡️ Proteja-se de golpes baixando o app *É Golpe?*""";

    Share.share(text);
  }

  void _sendFeedback(String avaliacao) async {
    final success = await widget.apiService.sendFeedback(
      inputUsuario: widget.inputSource ?? widget.result.url ?? 'Análise Mobile',
      outputIa: widget.result.analysis,
      avaliacao: avaliacao,
    );

    if (mounted) {
      setState(() => _feedbackSent = avaliacao);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(success ? 'Obrigado pelo seu feedback! 👍' : 'Feedback registrado localmente.'),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Resultado da Análise'),
        actions: [
          IconButton(
            icon: Icon(_isSpeaking ? Icons.volume_off : Icons.volume_up),
            tooltip: _isSpeaking ? 'Parar Voz' : 'Ouvir Resultado',
            onPressed: _toggleSpeak,
          ),
          IconButton(
            icon: const Icon(Icons.share),
            tooltip: 'Compartilhar',
            onPressed: _shareResult,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            // 1. Verdict Card
            VerdictCard(result: widget.result, isHighContrast: isHc),
            const SizedBox(height: 24),

            // 2. Score Gauge
            ScoreGauge(
              score: widget.result.score,
              level: widget.result.level,
              isHighContrast: isHc,
              size: 150,
            ),
            const SizedBox(height: 24),

            // 3. Audio Narration Banner
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: isHc
                    ? AppTheme.hcBackground
                    : (isDark ? const Color(0xFF1C1C1E) : Colors.white),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                  color: isHc ? AppTheme.hcYellow : const Color(0xFFE5E5EA),
                  width: isHc ? 2 : 1,
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    _isSpeaking ? Icons.graphic_eq : Icons.record_voice_over,
                    color: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _isSpeaking ? 'Narrando resultado por voz...' : 'Ouvir explicação com voz para idosos',
                      style: TextStyle(
                        fontSize: isHc ? 16 : 14,
                        fontWeight: FontWeight.w600,
                        color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
                      ),
                    ),
                  ),
                  TextButton(
                    onPressed: _toggleSpeak,
                    child: Text(
                      _isSpeaking ? 'Parar' : 'Ouvir',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // 4. Details / Analysis Markdown card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: isHc
                    ? AppTheme.hcBackground
                    : (isDark ? const Color(0xFF1C1C1E) : Colors.white),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: isHc ? AppTheme.hcYellow : const Color(0xFFE5E5EA),
                  width: isHc ? 2 : 1,
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.analytics_outlined, size: 22),
                      const SizedBox(width: 8),
                      Text(
                        'Relatório Detalhado',
                        style: TextStyle(
                          fontSize: isHc ? 20 : 16,
                          fontWeight: FontWeight.bold,
                          color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
                        ),
                      ),
                    ],
                  ),
                  const Divider(height: 24),
                  SelectableText(
                    widget.result.summaryText,
                    style: TextStyle(
                      fontSize: isHc ? 17 : 15,
                      height: 1.5,
                      color: isHc ? AppTheme.hcWhite : (isDark ? Colors.white70 : Colors.black87),
                    ),
                  ),
                  if (widget.result.resolvedUrl != null) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: isDark ? Colors.black26 : const Color(0xFFF2F2F7),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Endereço Destino Final:',
                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.grey),
                          ),
                          const SizedBox(height: 4),
                          SelectableText(
                            widget.result.resolvedUrl!,
                            style: const TextStyle(fontSize: 13, fontFamily: 'monospace'),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 24),

            // 5. Feedback Box
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: isHc
                    ? AppTheme.hcBackground
                    : (isDark ? const Color(0xFF1C1C1E) : Colors.white),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: isHc ? AppTheme.hcYellow : const Color(0xFFE5E5EA),
                  width: isHc ? 2 : 1,
                ),
              ),
              child: Column(
                children: [
                  Text(
                    'Esta análise foi útil para você?',
                    style: TextStyle(
                      fontSize: isHc ? 16 : 14,
                      fontWeight: FontWeight.w600,
                      color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      ElevatedButton.icon(
                        onPressed: _feedbackSent != null ? null : () => _sendFeedback('Gostei'),
                        icon: const Icon(Icons.thumb_up_alt_outlined, size: 18),
                        label: const Text('Útil'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _feedbackSent == 'Gostei' ? AppTheme.safeGreen : null,
                          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                        ),
                      ),
                      const SizedBox(width: 16),
                      OutlinedButton.icon(
                        onPressed: _feedbackSent != null ? null : () => _sendFeedback('NaoGostei'),
                        icon: const Icon(Icons.thumb_down_alt_outlined, size: 18),
                        label: const Text('Não útil'),
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // 6. Action Share Button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _shareResult,
                icon: const Icon(Icons.share),
                label: const Text('Avisar Familiares / Amigos'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.iosBlue,
                ),
              ),
            ),
            const SizedBox(height: 40),
          ],
        ),
      ),
    );
  }
}
