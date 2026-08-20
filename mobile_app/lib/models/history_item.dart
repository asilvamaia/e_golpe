import 'analysis_result.dart';

class HistoryItem {
  final String id;
  final String input;
  final String inputType; // 'Link', 'Mensagem', 'Arquivo'
  final AnalysisResult result;
  final DateTime createdAt;

  HistoryItem({
    required this.id,
    required this.input,
    required this.inputType,
    required this.result,
    DateTime? createdAt,
  }) : createdAt = createdAt ?? DateTime.now();

  factory HistoryItem.fromJson(Map<String, dynamic> json) {
    return HistoryItem(
      id: json['id'] as String? ?? DateTime.now().millisecondsSinceEpoch.toString(),
      input: json['input'] as String? ?? '',
      inputType: json['input_type'] as String? ?? 'Link',
      result: AnalysisResult.fromJson(json['result'] as Map<String, dynamic>),
      createdAt: json['created_at'] != null
          ? DateTime.tryParse(json['created_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'input': input,
      'input_type': inputType,
      'result': result.toJson(),
      'created_at': createdAt.toIso8601String(),
    };
  }
}
