import 'package:flutter_tts/flutter_tts.dart';

class TtsService {
  final FlutterTts _flutterTts = FlutterTts();
  bool _isSpeaking = false;

  bool get isSpeaking => _isSpeaking;

  Future<void> init() async {
    try {
      await _flutterTts.setLanguage("pt-BR");
      await _flutterTts.setSpeechRate(0.5);
      await _flutterTts.setVolume(1.0);
      await _flutterTts.setPitch(1.0);

      _flutterTts.setStartHandler(() {
        _isSpeaking = true;
      });

      _flutterTts.setCompletionHandler(() {
        _isSpeaking = false;
      });

      _flutterTts.setErrorHandler((msg) {
        _isSpeaking = false;
      });
    } catch (_) {}
  }

  Future<void> speak(String text) async {
    if (text.trim().isEmpty) return;
    try {
      // Limpeza de símbolos para fala natural
      final cleanText = text
          .replaceAll(RegExp(r'[*#_`~]'), '')
          .replaceAll(':green', '')
          .replaceAll(':red', '')
          .replaceAll(':orange', '')
          .replaceAll('🛡️', '')
          .replaceAll('✅', 'Seguro: ')
          .replaceAll('🚨', 'Alerta de Golpe: ')
          .replaceAll('⚠️', 'Atenção: ');

      _isSpeaking = true;
      await _flutterTts.speak(cleanText);
    } catch (_) {
      _isSpeaking = false;
    }
  }

  Future<void> stop() async {
    try {
      await _flutterTts.stop();
      _isSpeaking = false;
    } catch (_) {}
  }
}
