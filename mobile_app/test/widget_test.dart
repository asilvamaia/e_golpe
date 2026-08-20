import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:egolpe/main.dart';
import 'package:egolpe/services/storage_service.dart';
import 'package:egolpe/services/api_service.dart';
import 'package:egolpe/services/tts_service.dart';

void main() {
  testWidgets('App smoke test and initial render', (WidgetTester tester) async {
    SharedPreferences.setMockInitialValues({});
    final storage = await StorageService.init();
    final api = ApiService(storage);
    final tts = TtsService();

    await tester.pumpWidget(EGolpeApp(
      storageService: storage,
      apiService: api,
      ttsService: tts,
    ));

    expect(find.text('É Golpe?'), findsWidgets);
    expect(find.text('Auditor'), findsOneWidget);
    expect(find.text('Guia'), findsOneWidget);
    expect(find.text('Senhas'), findsOneWidget);
  });
}
