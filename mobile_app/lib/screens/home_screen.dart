import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../services/tts_service.dart';
import '../theme/app_theme.dart';
import 'scanner_tab.dart';
import 'password_tab.dart';
import 'guide_tab.dart';
import 'history_tab.dart';
import 'settings_tab.dart';

class HomeScreen extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;
  final TtsService ttsService;
  final VoidCallback onThemeChanged;

  const HomeScreen({
    super.key,
    required this.storageService,
    required this.apiService,
    required this.ttsService,
    required this.onThemeChanged,
  });

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final tabs = [
      ScannerTab(
        apiService: widget.apiService,
        storageService: widget.storageService,
        ttsService: widget.ttsService,
      ),
      PasswordTab(
        apiService: widget.apiService,
        storageService: widget.storageService,
      ),
      GuideTab(
        storageService: widget.storageService,
      ),
      HistoryTab(
        apiService: widget.apiService,
        storageService: widget.storageService,
        ttsService: widget.ttsService,
      ),
      SettingsTab(
        storageService: widget.storageService,
        apiService: widget.apiService,
        onThemeChanged: widget.onThemeChanged,
      ),
    ];

    return Scaffold(
      body: IndexedStack(
        index: _currentIndex,
        children: tabs,
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: (idx) {
          setState(() {
            _currentIndex = idx;
          });
        },
        backgroundColor: isHc
            ? AppTheme.hcBackground
            : (isDark ? const Color(0xFF1C1C1E) : const Color(0xFFF2F2F7)),
        indicatorColor: isHc
            ? AppTheme.hcYellow
            : AppTheme.iosBlue.withOpacity(0.2),
        destinations: [
          NavigationDestination(
            icon: const Icon(Icons.shield_outlined),
            selectedIcon: Icon(
              Icons.shield,
              color: isHc ? Colors.black : AppTheme.iosBlue,
            ),
            label: 'Auditor',
          ),
          NavigationDestination(
            icon: const Icon(Icons.key_outlined),
            selectedIcon: Icon(
              Icons.key,
              color: isHc ? Colors.black : AppTheme.iosBlue,
            ),
            label: 'Senhas',
          ),
          NavigationDestination(
            icon: const Icon(Icons.menu_book_outlined),
            selectedIcon: Icon(
              Icons.menu_book,
              color: isHc ? Colors.black : AppTheme.iosBlue,
            ),
            label: 'Guia',
          ),
          NavigationDestination(
            icon: const Icon(Icons.history_outlined),
            selectedIcon: Icon(
              Icons.history,
              color: isHc ? Colors.black : AppTheme.iosBlue,
            ),
            label: 'Histórico',
          ),
          NavigationDestination(
            icon: const Icon(Icons.settings_outlined),
            selectedIcon: Icon(
              Icons.settings,
              color: isHc ? Colors.black : AppTheme.iosBlue,
            ),
            label: 'Ajustes',
          ),
        ],
      ),
    );
  }
}
