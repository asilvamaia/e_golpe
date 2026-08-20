class AnalysisResult {
  final String status;
  final bool cached;
  final String type; // 'url', 'text', 'file'
  final String verdict; // 'SEGURO', 'ALERTA', 'GOLPE'
  final int score; // 0 to 100
  final String level; // 'safe', 'warning', 'danger'
  final String icon; // '✅', '⚠️', '🚨'
  final String analysis; // Markdown or formatted text
  final String? url;
  final String? resolvedUrl;
  final String? filename;
  final String? mimeType;
  final DateTime timestamp;

  AnalysisResult({
    required this.status,
    required this.cached,
    required this.type,
    required this.verdict,
    required this.score,
    required this.level,
    required this.icon,
    required this.analysis,
    this.url,
    this.resolvedUrl,
    this.filename,
    this.mimeType,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    final rawVerdict = (json['verdict'] as String? ?? 'ALERTA').toUpperCase();
    final rawScore = json['score'] is int ? json['score'] as int : int.tryParse(json['score']?.toString() ?? '50') ?? 50;
    final rawLevel = json['level'] as String? ?? _inferLevel(rawVerdict, rawScore);
    final rawIcon = json['icon'] as String? ?? _inferIcon(rawLevel);

    return AnalysisResult(
      status: json['status'] as String? ?? 'success',
      cached: json['cached'] as bool? ?? false,
      type: json['type'] as String? ?? 'url',
      verdict: rawVerdict,
      score: rawScore,
      level: rawLevel,
      icon: rawIcon,
      analysis: json['analysis'] as String? ?? '',
      url: json['url'] as String?,
      resolvedUrl: json['resolved_url'] as String?,
      filename: json['filename'] as String?,
      mimeType: json['mime_type'] as String?,
      timestamp: json['timestamp'] != null
          ? DateTime.tryParse(json['timestamp'].toString()) ?? DateTime.now()
          : DateTime.now(),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'status': status,
      'cached': cached,
      'type': type,
      'verdict': verdict,
      'score': score,
      'level': level,
      'icon': icon,
      'analysis': analysis,
      'url': url,
      'resolved_url': resolvedUrl,
      'filename': filename,
      'mime_type': mimeType,
      'timestamp': timestamp.toIso8601String(),
    };
  }

  static String _inferLevel(String verdict, int score) {
    if (verdict.contains('SEGURO') || verdict.contains('CONFIÁVEL') || score >= 80) {
      return 'safe';
    } else if (verdict.contains('GOLPE') || verdict.contains('PERIGO') || verdict.contains('PHISHING') || score <= 40) {
      return 'danger';
    }
    return 'warning';
  }

  static String _inferIcon(String level) {
    switch (level) {
      case 'safe':
        return '✅';
      case 'danger':
        return '🚨';
      default:
        return '⚠️';
    }
  }

  String get summaryText {
    // Extracts the "Análise:" or explanation block from the analysis string
    if (analysis.isEmpty) return 'Análise concluída com sucesso.';
    final clean = analysis.replaceAll('**', '').replaceAll('#', '').replaceAll(':green', '').replaceAll(':red', '').replaceAll(':orange', '');
    return clean;
  }
}
