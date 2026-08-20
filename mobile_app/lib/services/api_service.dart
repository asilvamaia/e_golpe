import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';
import '../models/analysis_result.dart';
import 'storage_service.dart';

class ApiService {
  final StorageService _storage;

  ApiService(this._storage);

  String get _baseUrl {
    String url = _storage.getApiUrl().trim();
    if (url.endsWith('/')) {
      url = url.substring(0, url.length - 1);
    }
    return url;
  }

  Map<String, String> _getHeaders({bool isJson = true}) {
    final headers = <String, String>{};
    if (isJson) {
      headers['Content-Type'] = 'application/json';
      headers['Accept'] = 'application/json';
    }
    final apiKey = _storage.getApiKey();
    if (apiKey != null && apiKey.isNotEmpty) {
      headers['x-api-key'] = apiKey;
    }
    return headers;
  }

  /// Analisa Link ou Texto geral
  Future<AnalysisResult> analyzeContent(String text, {String source = 'mobile_app'}) async {
    final uri = Uri.parse('$_baseUrl/api/v1/analyze');
    final body = jsonEncode({
      'text': text,
      'source': source,
    });

    try {
      final response = await http
          .post(uri, headers: _getHeaders(), body: body)
          .timeout(const Duration(seconds: 40));

      if (response.statusCode >= 200 && response.statusCode < 300) {
        final data = jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
        return AnalysisResult.fromJson(data);
      } else {
        String detail = 'Erro no servidor (${response.statusCode})';
        try {
          final errJson = jsonDecode(utf8.decode(response.bodyBytes));
          if (errJson['detail'] != null) {
            detail = errJson['detail'].toString();
          }
        } catch (_) {}
        throw Exception(detail);
      }
    } catch (e) {
      if (e is Exception) rethrow;
      throw Exception('Falha ao conectar com o servidor: $e');
    }
  }

  /// Analisa Texto / SMS / WhatsApp
  Future<AnalysisResult> analyzeText(String text, {String source = 'mobile_app (Texto)'}) async {
    final uri = Uri.parse('$_baseUrl/api/v1/analyze-text');
    final body = jsonEncode({
      'text': text,
      'source': source,
    });

    try {
      final response = await http
          .post(uri, headers: _getHeaders(), body: body)
          .timeout(const Duration(seconds: 40));

      if (response.statusCode >= 200 && response.statusCode < 300) {
        final data = jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
        return AnalysisResult.fromJson(data);
      } else {
        String detail = 'Erro na análise de texto (${response.statusCode})';
        try {
          final errJson = jsonDecode(utf8.decode(response.bodyBytes));
          if (errJson['detail'] != null) {
            detail = errJson['detail'].toString();
          }
        } catch (_) {}
        throw Exception(detail);
      }
    } catch (e) {
      if (e is Exception) rethrow;
      throw Exception('Falha de conexão com a API: $e');
    }
  }

  /// Analisa Arquivo (Imagem / Print de Tela / PDF) via multipart upload
  Future<AnalysisResult> analyzeFile({
    required Uint8List fileBytes,
    required String filename,
    required String mimeType,
    String source = 'mobile_app (Arquivo)',
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/analyze-file?source=$source');
    final request = http.MultipartRequest('POST', uri);

    final apiKey = _storage.getApiKey();
    if (apiKey != null && apiKey.isNotEmpty) {
      request.headers['x-api-key'] = apiKey;
    }

    final mediaTypeParts = mimeType.split('/');
    final mediaType = mediaTypeParts.length == 2
        ? MediaType(mediaTypeParts[0], mediaTypeParts[1])
        : MediaType('application', 'octet-stream');

    request.files.add(
      http.MultipartFile.fromBytes(
        'file',
        fileBytes,
        filename: filename,
        contentType: mediaType,
      ),
    );

    try {
      final streamedResponse = await request.send().timeout(const Duration(seconds: 60));
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode >= 200 && response.statusCode < 300) {
        final data = jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
        return AnalysisResult.fromJson(data);
      } else {
        String detail = 'Erro na análise do arquivo (${response.statusCode})';
        try {
          final errJson = jsonDecode(utf8.decode(response.bodyBytes));
          if (errJson['detail'] != null) {
            detail = errJson['detail'].toString();
          }
        } catch (_) {}
        throw Exception(detail);
      }
    } catch (e) {
      if (e is Exception) rethrow;
      throw Exception('Falha ao enviar arquivo para análise: $e');
    }
  }

  /// Checa vazamento de senhas (Have I Been Pwned)
  Future<Map<String, dynamic>> checkPasswordLeak(String password) async {
    final uri = Uri.parse('$_baseUrl/api/v1/check-password');
    final body = jsonEncode({'password': password});

    try {
      final response = await http
          .post(uri, headers: _getHeaders(), body: body)
          .timeout(const Duration(seconds: 15));

      if (response.statusCode >= 200 && response.statusCode < 300) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      } else {
        throw Exception('Erro ao checar senha (${response.statusCode})');
      }
    } catch (e) {
      throw Exception('Erro ao consultar base de vazamentos: $e');
    }
  }

  /// Envia feedback da IA
  Future<bool> sendFeedback({
    required String inputUsuario,
    required String outputIa,
    required String avaliacao,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/feedback');
    final body = jsonEncode({
      'input_usuario': inputUsuario,
      'output_ia': outputIa,
      'avaliacao': avaliacao,
    });

    try {
      final response = await http
          .post(uri, headers: _getHeaders(), body: body)
          .timeout(const Duration(seconds: 10));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Consulta estatísticas
  Future<Map<String, dynamic>> getStats() async {
    final uri = Uri.parse('$_baseUrl/api/v1/stats');
    try {
      final response = await http
          .get(uri, headers: _getHeaders())
          .timeout(const Duration(seconds: 10));
      if (response.statusCode == 200) {
        return jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>;
      }
      return {'total_analises': 0, 'total_usuarios': 0};
    } catch (_) {
      return {'total_analises': 0, 'total_usuarios': 0};
    }
  }

  /// Health check
  Future<bool> checkHealth() async {
    final uri = Uri.parse('$_baseUrl/health');
    try {
      final response = await http.get(uri).timeout(const Duration(seconds: 6));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
