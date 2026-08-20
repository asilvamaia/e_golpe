import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/history_item.dart';

class StorageService {
  static const String _keyHistory = 'egolpe_scan_history';
  static const String _keyApiUrl = 'egolpe_api_url';
  static const String _keyApiKey = 'egolpe_api_key';
  static const String _keyHighContrast = 'egolpe_high_contrast';
  static const String _keyDarkMode = 'egolpe_dark_mode';
  static const String _keyAutoTts = 'egolpe_auto_tts';

  static const String defaultApiUrl = 'https://ia-contra-fraude.fly.dev';

  final SharedPreferences _prefs;

  StorageService(this._prefs);

  static Future<StorageService> init() async {
    final prefs = await SharedPreferences.getInstance();
    return StorageService(prefs);
  }

  // --- API Configurations ---

  String getApiUrl() {
    final url = _prefs.getString(_keyApiUrl);
    if (url == null || url.trim().isEmpty) {
      return defaultApiUrl;
    }
    return url.trim();
  }

  Future<void> setApiUrl(String url) async {
    await _prefs.setString(_keyApiUrl, url.trim());
  }

  String? getApiKey() {
    return _prefs.getString(_keyApiKey);
  }

  Future<void> setApiKey(String? key) async {
    if (key == null || key.trim().isEmpty) {
      await _prefs.remove(_keyApiKey);
    } else {
      await _prefs.setString(_keyApiKey, key.trim());
    }
  }

  // --- Accessibility & UI Settings ---

  bool isHighContrast() {
    return _prefs.getBool(_keyHighContrast) ?? false;
  }

  Future<void> setHighContrast(bool value) async {
    await _prefs.setBool(_keyHighContrast, value);
  }

  bool isDarkMode() {
    return _prefs.getBool(_keyDarkMode) ?? false;
  }

  Future<void> setDarkMode(bool value) async {
    await _prefs.setBool(_keyDarkMode, value);
  }

  bool isAutoTts() {
    return _prefs.getBool(_keyAutoTts) ?? true;
  }

  Future<void> setAutoTts(bool value) async {
    await _prefs.setBool(_keyAutoTts, value);
  }

  // --- Scan History Management ---

  List<HistoryItem> getHistory() {
    final rawList = _prefs.getStringList(_keyHistory);
    if (rawList == null || rawList.isEmpty) {
      return [];
    }

    final items = <HistoryItem>[];
    for (final itemStr in rawList) {
      try {
        final map = jsonDecode(itemStr) as Map<String, dynamic>;
        items.add(HistoryItem.fromJson(map));
      } catch (e) {
        // Ignore corrupt entry
      }
    }
    // Most recent first
    items.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return items;
  }

  Future<void> addHistoryItem(HistoryItem item) async {
    final current = getHistory();
    current.insert(0, item);
    // Keep max 50 items
    if (current.length > 50) {
      current.removeRange(50, current.length);
    }

    final encodedList = current.map((i) => jsonEncode(i.toJson())).toList();
    await _prefs.setStringList(_keyHistory, encodedList);
  }

  Future<void> removeHistoryItem(String id) async {
    final current = getHistory();
    current.removeWhere((i) => i.id == id);
    final encodedList = current.map((i) => jsonEncode(i.toJson())).toList();
    await _prefs.setStringList(_keyHistory, encodedList);
  }

  Future<void> clearHistory() async {
    await _prefs.remove(_keyHistory);
  }
}
