import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'screens/home_screen.dart';
import 'services/api_service.dart';
import 'services/storage_service.dart';
import 'services/tts_service.dart';
import 'theme/app_theme.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Set system navigation overlay styling
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
    ),
  );

  final storageService = await StorageService.init();
  final apiService = ApiService(storageService);
  final ttsService = TtsService();
  await ttsService.init();

  runApp(EGolpeApp(
    storageService: storageService,
    apiService: apiService,
    ttsService: ttsService,
  ));
}

class EGolpeApp extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;
  final TtsService ttsService;

  const EGolpeApp({
    super.key,
    required this.storageService,
    required this.apiService,
    required this.ttsService,
  });

  @override
  State<EGolpeApp> createState() => _EGolpeAppState();
}

class _EGolpeAppState extends State<EGolpeApp> {
  void _reloadTheme() {
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = widget.storageService.isDarkMode();

    ThemeData theme;
    if (isHc) {
      theme = AppTheme.highContrastTheme();
    } else if (isDark) {
      theme = AppTheme.darkTheme();
    } else {
      theme = AppTheme.lightTheme();
    }

    return MaterialApp(
      title: 'É Golpe?',
      debugShowCheckedModeBanner: false,
      theme: theme,
      home: HomeScreen(
        storageService: widget.storageService,
        apiService: widget.apiService,
        ttsService: widget.ttsService,
        onThemeChanged: _reloadTheme,
      ),
    );
  }
}
