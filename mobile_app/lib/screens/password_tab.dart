import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../theme/app_theme.dart';

class PasswordTab extends StatefulWidget {
  final ApiService apiService;
  final StorageService storageService;

  const PasswordTab({
    super.key,
    required this.apiService,
    required this.storageService,
  });

  @override
  State<PasswordTab> createState() => _PasswordTabState();
}

class _PasswordTabState extends State<PasswordTab> {
  final TextEditingController _passwordController = TextEditingController();
  bool _obscureText = true;
  bool _isLoading = false;
  Map<String, dynamic>? _checkResult;

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _checkPassword() async {
    final password = _passwordController.text.trim();
    if (password.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Digite uma senha para verificar.')),
      );
      return;
    }

    setState(() {
      _isLoading = true;
      _checkResult = null;
    });

    try {
      final result = await widget.apiService.checkPasswordLeak(password);
      if (mounted) {
        setState(() {
          _isLoading = false;
          _checkResult = result;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isLoading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceAll('Exception: ', ''))),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Verificador de Senhas'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header card
            Container(
              padding: const EdgeInsets.all(18),
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
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: AppTheme.iosBlue.withOpacity(0.12),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.key, color: AppTheme.iosBlue, size: 28),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Sua senha vazou na internet?',
                          style: TextStyle(
                            fontSize: isHc ? 18 : 16,
                            fontWeight: FontWeight.bold,
                            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'Consulte bilhões de senhas expostas no banco mundial do Have I Been Pwned.',
                          style: TextStyle(
                            fontSize: 13,
                            color: isHc ? Colors.white70 : Colors.grey.shade600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            Text(
              'Digite uma senha para testar:',
              style: TextStyle(
                fontSize: isHc ? 17 : 15,
                fontWeight: FontWeight.w600,
                color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
              ),
            ),
            const SizedBox(height: 10),

            TextField(
              controller: _passwordController,
              obscureText: _obscureText,
              style: TextStyle(
                fontSize: isHc ? 18 : 16,
                color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
              ),
              decoration: InputDecoration(
                hintText: 'Digite a senha aqui...',
                prefixIcon: const Icon(Icons.lock_outline),
                suffixIcon: IconButton(
                  icon: Icon(_obscureText ? Icons.visibility : Icons.visibility_off),
                  onPressed: () => setState(() => _obscureText = !_obscureText),
                ),
              ),
            ),
            const SizedBox(height: 18),

            SizedBox(
              width: double.infinity,
              height: 52,
              child: ElevatedButton.icon(
                onPressed: _isLoading ? null : _checkPassword,
                icon: _isLoading
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                      )
                    : const Icon(Icons.search),
                label: Text(
                  _isLoading ? 'Consultando Vazamentos...' : 'Verificar Vazamento',
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Results Card
            if (_checkResult != null) _buildResultCard(isHc, isDark),

            const SizedBox(height: 20),

            // Privacy Assurance Card
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: isHc
                    ? AppTheme.hcBackground
                    : (isDark ? Colors.black26 : const Color(0xFFE5E5EA).withOpacity(0.5)),
                borderRadius: BorderRadius.circular(14),
                border: isHc ? Border.all(color: AppTheme.hcYellow) : null,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.privacy_tip_outlined, size: 20, color: AppTheme.safeGreen),
                      const SizedBox(width: 8),
                      Text(
                        '100% Seguro e Privado (K-Anonymity)',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.bold,
                          color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Sua senha real NUNCA é salva. O protocolo de k-anonimato utiliza apenas os primeiros 5 dígitos do resumo criptográfico SHA-1 para buscar correspondências na base de dados de forma estritamente anônima.',
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.4,
                      color: isHc ? Colors.white70 : Colors.grey.shade700,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultCard(bool isHc, bool isDark) {
    final isBreached = _checkResult!['breached'] as bool? ?? false;
    final color = isBreached ? AppTheme.dangerRed : AppTheme.safeGreen;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: isHc
            ? AppTheme.hcBackground
            : (isDark ? color.withOpacity(0.15) : color.withOpacity(0.08)),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: color,
          width: isHc ? 2.5 : 1.5,
        ),
      ),
      child: Column(
        children: [
          Icon(
            isBreached ? Icons.warning_amber_rounded : Icons.check_circle_outline,
            size: 48,
            color: color,
          ),
          const SizedBox(height: 10),
          Text(
            isBreached ? 'SENHA VAZADA!' : 'SENHA NÃO ENCONTRADA',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _checkResult!['message']?.toString() ?? '',
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 14,
              color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
            ),
          ),
          if (isBreached) ...[
            const SizedBox(height: 14),
            Text(
              '⚠️ Recomendação: Se você usa esta senha em qualquer serviço bancário, e-mail ou rede social, altere-a imediatamente!',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
