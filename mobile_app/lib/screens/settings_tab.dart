import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../theme/app_theme.dart';

class SettingsTab extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;
  final VoidCallback onThemeChanged;

  const SettingsTab({
    super.key,
    required this.storageService,
    required this.apiService,
    required this.onThemeChanged,
  });

  @override
  State<SettingsTab> createState() => _SettingsTabState();
}

class _SettingsTabState extends State<SettingsTab> {
  late TextEditingController _apiUrlController;
  late TextEditingController _apiKeyController;
  bool _isTestingConnection = false;
  String? _connectionStatus;
  Map<String, dynamic>? _serverStats;

  @override
  void initState() {
    super.initState();
    _apiUrlController = TextEditingController(text: widget.storageService.getApiUrl());
    _apiKeyController = TextEditingController(text: widget.storageService.getApiKey() ?? '');
  }

  @override
  void dispose() {
    _apiUrlController.dispose();
    _apiKeyController.dispose();
    super.dispose();
  }

  Future<void> _saveApiSettings() async {
    await widget.storageService.setApiUrl(_apiUrlController.text.trim());
    await widget.storageService.setApiKey(_apiKeyController.text.trim());

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Configurações da API salvas com sucesso!')),
      );
    }
  }

  Future<void> _testConnection() async {
    setState(() {
      _isTestingConnection = true;
      _connectionStatus = null;
      _serverStats = null;
    });

    // Salva temporariamente
    await widget.storageService.setApiUrl(_apiUrlController.text.trim());
    await widget.storageService.setApiKey(_apiKeyController.text.trim());

    final isHealthy = await widget.apiService.checkHealth();
    Map<String, dynamic>? stats;
    if (isHealthy) {
      stats = await widget.apiService.getStats();
    }

    if (mounted) {
      setState(() {
        _isTestingConnection = false;
        _connectionStatus = isHealthy ? 'online' : 'offline';
        _serverStats = stats;
      });
    }
  }

  void _resetApiUrl() {
    setState(() {
      _apiUrlController.text = StorageService.defaultApiUrl;
    });
    _saveApiSettings();
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = widget.storageService.isDarkMode();
    final isAutoTts = widget.storageService.isAutoTts();
    final isThemeDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Configurações'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // Section 1: Acessibilidade & Visual
          _buildSectionHeader('Acessibilidade e Visual', isHc),
          const SizedBox(height: 10),
          Card(
            child: Column(
              children: [
                SwitchListTile(
                  title: Text(
                    'Modo Alto Contraste (Idosos)',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: isHc ? 17 : 15,
                      color: isHc ? AppTheme.hcYellow : (isThemeDark ? Colors.white : Colors.black),
                    ),
                  ),
                  subtitle: const Text('Fundo preto e texto amarelo com letras ampliadas para máxima legibilidade.'),
                  value: isHc,
                  onChanged: (val) async {
                    await widget.storageService.setHighContrast(val);
                    widget.onThemeChanged();
                    setState(() {});
                  },
                ),
                const Divider(height: 1),
                SwitchListTile(
                  title: Text(
                    'Tema Escuro (Dark Mode)',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: isHc ? 17 : 15,
                      color: isHc ? AppTheme.hcYellow : (isThemeDark ? Colors.white : Colors.black),
                    ),
                  ),
                  subtitle: const Text('Visual moderno escuro para economizar bateria.'),
                  value: isDark,
                  onChanged: isHc
                      ? null
                      : (val) async {
                          await widget.storageService.setDarkMode(val);
                          widget.onThemeChanged();
                          setState(() {});
                        },
                ),
                const Divider(height: 1),
                SwitchListTile(
                  title: Text(
                    'Narração por Voz Automática',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: isHc ? 17 : 15,
                      color: isHc ? AppTheme.hcYellow : (isThemeDark ? Colors.white : Colors.black),
                    ),
                  ),
                  subtitle: const Text('Lê em voz alta o veredito e o alerta de segurança ao concluir o escaneamento.'),
                  value: isAutoTts,
                  onChanged: (val) async {
                    await widget.storageService.setAutoTts(val);
                    setState(() {});
                  },
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Section 2: Servidor e API
          _buildSectionHeader('Servidor e Conectividade', isHc),
          const SizedBox(height: 10),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'URL do Servidor API:',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: isHc ? 16 : 14,
                      color: isHc ? AppTheme.hcYellow : (isThemeDark ? Colors.white : Colors.black87),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _apiUrlController,
                    keyboardType: TextInputType.url,
                    decoration: InputDecoration(
                      hintText: 'https://ia-contra-fraude.fly.dev',
                      suffixIcon: IconButton(
                        icon: const Icon(Icons.refresh),
                        tooltip: 'Restaurar padrão',
                        onPressed: _resetApiUrl,
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'Chave de API (Opcional se público):',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: isHc ? 16 : 14,
                      color: isHc ? AppTheme.hcYellow : (isThemeDark ? Colors.white : Colors.black87),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _apiKeyController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      hintText: 'x-api-key',
                    ),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: _saveApiSettings,
                          icon: const Icon(Icons.save_outlined),
                          label: const Text('Salvar'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: ElevatedButton.icon(
                          onPressed: _isTestingConnection ? null : _testConnection,
                          icon: _isTestingConnection
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                                )
                              : const Icon(Icons.wifi_tethering),
                          label: const Text('Testar Conexão'),
                        ),
                      ),
                    ],
                  ),

                  if (_connectionStatus != null) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: _connectionStatus == 'online'
                            ? AppTheme.safeGreen.withOpacity(0.15)
                            : AppTheme.dangerRed.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: _connectionStatus == 'online'
                              ? AppTheme.safeGreen
                              : AppTheme.dangerRed,
                        ),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            _connectionStatus == 'online' ? Icons.check_circle : Icons.error,
                            color: _connectionStatus == 'online'
                                ? AppTheme.safeGreen
                                : AppTheme.dangerRed,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              _connectionStatus == 'online'
                                  ? 'Servidor Conectado e Operacional! 🚀\nTotal de Análises na Base: ${_serverStats?['total_analises'] ?? 0}'
                                  : 'Não foi possível conectar ao servidor. Verifique a URL e a internet.',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: _connectionStatus == 'online'
                                    ? AppTheme.safeGreen
                                    : AppTheme.dangerRed,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),

          // Section 3: Sobre o App
          _buildSectionHeader('Sobre o Aplicativo', isHc),
          const SizedBox(height: 10),
          Card(
            child: Column(
              children: [
                ListTile(
                  leading: const Icon(Icons.security, color: AppTheme.iosBlue),
                  title: const Text('É Golpe? (IA Contra Fraude)'),
                  subtitle: const Text('Versão 1.0.0 (Build GitHub Actions CI/CD)'),
                ),
                const Divider(height: 1),
                ListTile(
                  leading: const Icon(Icons.install_mobile, color: AppTheme.safeGreen),
                  title: const Text('Compatibilidade iOS / AltStore'),
                  subtitle: const Text('Compilado para sideloading direto via AltStore, Sideloadly e TrollStore.'),
                ),
                const Divider(height: 1),
                ListTile(
                  leading: const Icon(Icons.code, color: Colors.purple),
                  title: const Text('Motor de Inteligência Artificial'),
                  subtitle: const Text('Google Gemini Flash + VirusTotal + PhishTank + URLScan + HIBP'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title, bool isHc) {
    return Text(
      title,
      style: TextStyle(
        fontSize: isHc ? 18 : 16,
        fontWeight: FontWeight.bold,
        color: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
        letterSpacing: -0.2,
      ),
    );
  }
}
