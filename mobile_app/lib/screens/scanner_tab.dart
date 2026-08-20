import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:file_picker/file_picker.dart';
import '../models/analysis_result.dart';
import '../models/history_item.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../services/tts_service.dart';
import '../theme/app_theme.dart';
import 'result_screen.dart';

class ScannerTab extends StatefulWidget {
  final ApiService apiService;
  final StorageService storageService;
  final TtsService ttsService;

  const ScannerTab({
    super.key,
    required this.apiService,
    required this.storageService,
    required this.ttsService,
  });

  @override
  State<ScannerTab> createState() => _ScannerTabState();
}

class _ScannerTabState extends State<ScannerTab> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final TextEditingController _urlController = TextEditingController();
  final TextEditingController _textController = TextEditingController();

  Uint8List? _selectedFileBytes;
  String? _selectedFileName;
  String? _selectedMimeType;

  bool _isLoading = false;
  String _loadingStatus = "Iniciando verificação de segurança...";

  final ImagePicker _picker = ImagePicker();

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _urlController.dispose();
    _textController.dispose();
    super.dispose();
  }

  Future<void> _pasteToController(TextEditingController controller) async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null && data!.text!.trim().isNotEmpty) {
      if (!mounted) return;
      setState(() {
        controller.text = data.text!.trim();
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Conteúdo colado da área de transferência!'),
          duration: Duration(seconds: 1),
        ),
      );
    }
  }

  Future<void> _pickImage(ImageSource source) async {
    try {
      final picked = await _picker.pickImage(
        source: source,
        maxWidth: 1920,
        maxHeight: 1920,
        imageQuality: 85,
      );

      if (picked != null) {
        final bytes = await picked.readAsBytes();
        if (!mounted) return;
        setState(() {
          _selectedFileBytes = bytes;
          _selectedFileName = picked.name;
          _selectedMimeType = picked.mimeType ?? 'image/jpeg';
        });
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Erro ao selecionar imagem: $e')),
      );
    }
  }

  Future<void> _pickPdfDocument() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['pdf', 'png', 'jpg', 'jpeg'],
        withData: true,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        if (file.bytes != null) {
          if (!mounted) return;
          setState(() {
            _selectedFileBytes = file.bytes;
            _selectedFileName = file.name;
            final ext = file.extension?.toLowerCase();
            if (ext == 'pdf') {
              _selectedMimeType = 'application/pdf';
            } else {
              _selectedMimeType = 'image/jpeg';
            }
          });
        }
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Erro ao selecionar documento: $e')),
      );
    }
  }

  void _clearSelectedFile() {
    setState(() {
      _selectedFileBytes = null;
      _selectedFileName = null;
      _selectedMimeType = null;
    });
  }

  Future<void> _runAnalysis() async {
    final currentTab = _tabController.index;
    String input = "";
    String inputType = "Link";

    if (currentTab == 0) {
      input = _urlController.text.trim();
      inputType = "Link";
      if (input.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Por favor, digite ou cole um link para verificar.')),
        );
        return;
      }
    } else if (currentTab == 1) {
      input = _textController.text.trim();
      inputType = "Mensagem";
      if (input.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Por favor, digite ou cole o texto da mensagem suspeita.')),
        );
        return;
      }
    } else {
      inputType = "Arquivo";
      if (_selectedFileBytes == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Por favor, selecione uma foto, print ou documento PDF.')),
        );
        return;
      }
      input = _selectedFileName ?? "Arquivo";
    }

    setState(() {
      _isLoading = true;
      _loadingStatus = "Conectando com o motor de análise...";
    });

    try {
      AnalysisResult result;

      if (currentTab == 0) {
        setState(() => _loadingStatus = "Consultando bases de phishing e reputação...");
        result = await widget.apiService.analyzeContent(input);
      } else if (currentTab == 1) {
        setState(() => _loadingStatus = "Inteligência Artificial analisando mensagem...");
        result = await widget.apiService.analyzeText(input);
      } else {
        setState(() => _loadingStatus = "Executando OCR e análise de autenticidade no documento...");
        result = await widget.apiService.analyzeFile(
          fileBytes: _selectedFileBytes!,
          filename: _selectedFileName ?? 'documento.jpg',
          mimeType: _selectedMimeType ?? 'image/jpeg',
        );
      }

      // Salva no histórico local
      final historyItem = HistoryItem(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        input: input,
        inputType: inputType,
        result: result,
      );
      await widget.storageService.addHistoryItem(historyItem);

      if (!mounted) return;
      setState(() => _isLoading = false);

      // Abre a tela de resultado detalhada
      Navigator.of(context).push(
        MaterialPageRoute(
          builder: (ctx) => ResultScreen(
            result: result,
            inputSource: input,
            apiService: widget.apiService,
            storageService: widget.storageService,
            ttsService: widget.ttsService,
          ),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() => _isLoading = false);
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Erro na Verificação'),
          content: Text(e.toString().replaceAll('Exception: ', '')),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Entendido'),
            ),
          ],
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'É Golpe?',
              style: TextStyle(
                fontWeight: FontWeight.w900,
                fontSize: 22,
                color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
              ),
            ),
            const SizedBox(width: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: AppTheme.iosBlue.withOpacity(0.15),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Text(
                'IA',
                style: TextStyle(
                  color: AppTheme.iosBlue,
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
        bottom: TabBar(
          controller: _tabController,
          labelColor: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
          unselectedLabelColor: isHc ? Colors.grey : Colors.grey.shade600,
          indicatorColor: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
          indicatorWeight: 3,
          labelStyle: TextStyle(
            fontWeight: FontWeight.bold,
            fontSize: isHc ? 16 : 14,
          ),
          tabs: const [
            Tab(icon: Icon(Icons.link), text: 'Link / Site'),
            Tab(icon: Icon(Icons.chat_bubble_outline), text: 'Mensagem'),
            Tab(icon: Icon(Icons.document_scanner_outlined), text: 'Print / Doc'),
          ],
        ),
      ),
      body: _isLoading
          ? _buildLoadingState(isHc, isDark)
          : SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                children: [
                  SizedBox(
                    height: 380,
                    child: TabBarView(
                      controller: _tabController,
                      children: [
                        _buildLinkTab(isHc, isDark),
                        _buildMessageTab(isHc, isDark),
                        _buildFileTab(isHc, isDark),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),
                  SizedBox(
                    width: double.infinity,
                    height: 56,
                    child: ElevatedButton.icon(
                      onPressed: _runAnalysis,
                      icon: const Icon(Icons.shield_outlined, size: 24),
                      label: Text(
                        'Auditar Segurança Agora',
                        style: TextStyle(
                          fontSize: isHc ? 19 : 17,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  _buildQuickTipsCard(isHc, isDark),
                ],
              ),
            ),
    );
  }

  Widget _buildLoadingState(bool isHc, bool isDark) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            SizedBox(
              width: 70,
              height: 70,
              child: CircularProgressIndicator(
                strokeWidth: 5,
                valueColor: AlwaysStoppedAnimation<Color>(
                  isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
                ),
              ),
            ),
            const SizedBox(height: 30),
            Text(
              'Auditando Segurança com IA',
              style: TextStyle(
                fontSize: isHc ? 22 : 18,
                fontWeight: FontWeight.bold,
                color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
              ),
            ),
            const SizedBox(height: 12),
            Text(
              _loadingStatus,
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: isHc ? 16 : 14,
                color: isHc ? Colors.white70 : Colors.grey.shade600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLinkTab(bool isHc, bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Cole ou digite o link que você recebeu:',
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            fontWeight: FontWeight.w600,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _urlController,
          keyboardType: TextInputType.url,
          autocorrect: false,
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
          ),
          decoration: InputDecoration(
            hintText: 'https://exemplo-suspeito.com...',
            prefixIcon: const Icon(Icons.link),
            suffixIcon: IconButton(
              icon: const Icon(Icons.content_paste),
              tooltip: 'Colar Link',
              onPressed: () => _pasteToController(_urlController),
            ),
          ),
        ),
        const SizedBox(height: 14),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => _pasteToController(_urlController),
                icon: const Icon(Icons.paste, size: 18),
                label: const Text('Colar Link Copiado'),
              ),
            ),
            const SizedBox(width: 10),
            if (_urlController.text.isNotEmpty)
              IconButton.outlined(
                onPressed: () => setState(() => _urlController.clear()),
                icon: const Icon(Icons.clear),
                tooltip: 'Limpar',
              ),
          ],
        ),
        const Spacer(),
        _buildInfoBox(
          'Verifica redirecionamentos ocultos, idade do domínio, certificado SSL, typosquatting e bases globais de phishing.',
          isHc,
          isDark,
        ),
      ],
    );
  }

  Widget _buildMessageTab(bool isHc, bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Cole o texto da mensagem (WhatsApp / SMS / E-mail):',
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            fontWeight: FontWeight.w600,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _textController,
          maxLines: 5,
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
          ),
          decoration: InputDecoration(
            hintText: 'Ex: "Oi mãe, troquei de número...", "Prezado cliente, sua conta foi bloqueada...", "Alvará liberado..."',
            alignLabelWithHint: true,
            suffixIcon: IconButton(
              icon: const Icon(Icons.content_paste),
              tooltip: 'Colar Mensagem',
              onPressed: () => _pasteToController(_textController),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => _pasteToController(_textController),
                icon: const Icon(Icons.paste, size: 18),
                label: const Text('Colar Mensagem'),
              ),
            ),
            const SizedBox(width: 10),
            if (_textController.text.isNotEmpty)
              IconButton.outlined(
                onPressed: () => setState(() => _textController.clear()),
                icon: const Icon(Icons.clear),
                tooltip: 'Limpar',
              ),
          ],
        ),
        const Spacer(),
        _buildInfoBox(
          'A IA analisa o contexto, promessas irreais, falsas urgências, cobranças judiciais e boatos de Fake News.',
          isHc,
          isDark,
        ),
      ],
    );
  }

  Widget _buildFileTab(bool isHc, bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Envie uma foto de documento ou print de tela:',
          style: TextStyle(
            fontSize: isHc ? 17 : 15,
            fontWeight: FontWeight.w600,
            color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
          ),
        ),
        const SizedBox(height: 14),
        if (_selectedFileBytes == null) ...[
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () => _pickImage(ImageSource.camera),
                  icon: const Icon(Icons.camera_alt),
                  label: const Text('Tirar Foto'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _pickImage(ImageSource.gallery),
                  icon: const Icon(Icons.photo_library),
                  label: const Text('Galeria'),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: _pickPdfDocument,
              icon: const Icon(Icons.picture_as_pdf),
              label: const Text('Selecionar Documento PDF'),
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 14),
              ),
            ),
          ),
        ] else ...[
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isDark ? const Color(0xFF1C1C1E) : Colors.white,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
                width: 1.5,
              ),
            ),
            child: Row(
              children: [
                Icon(
                  _selectedMimeType == 'application/pdf'
                      ? Icons.picture_as_pdf
                      : Icons.image,
                  size: 36,
                  color: AppTheme.iosBlue,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        _selectedFileName ?? 'Arquivo Selecionado',
                        style: const TextStyle(fontWeight: FontWeight.bold),
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Pronto para análise com OCR',
                        style: TextStyle(fontSize: 12, color: Colors.grey.shade600),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.close, color: Colors.red),
                  tooltip: 'Remover',
                  onPressed: _clearSelectedFile,
                ),
              ],
            ),
          ),
        ],
        const Spacer(),
        _buildInfoBox(
          'Lê prints de boletos, conversas de WhatsApp, falsos alvarás e petições com conferência de assinaturas.',
          isHc,
          isDark,
        ),
      ],
    );
  }

  Widget _buildInfoBox(String text, bool isHc, bool isDark) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isHc
            ? AppTheme.hcBackground
            : (isDark ? Colors.black26 : const Color(0xFFE5E5EA).withOpacity(0.5)),
        borderRadius: BorderRadius.circular(12),
        border: isHc ? Border.all(color: AppTheme.hcYellow) : null,
      ),
      child: Row(
        children: [
          Icon(
            Icons.info_outline,
            size: 20,
            color: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: TextStyle(
                fontSize: 12,
                color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white70 : Colors.black87),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickTipsCard(bool isHc, bool isDark) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF1C1C1E) : Colors.white,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isHc ? AppTheme.hcYellow : const Color(0xFFE5E5EA),
          width: isHc ? 2 : 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text('💡', style: TextStyle(fontSize: 18)),
              const SizedBox(width: 8),
              Text(
                'Regra de Ouro da Segurança',
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                  color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Bancos e advogados nunca solicitam pagamentos antecipados via Pix por mensagem para liberar dinheiro ou cancelar compras. Em caso de dúvida, ligue no canal oficial.',
            style: TextStyle(
              fontSize: 13,
              height: 1.4,
              color: isHc ? Colors.white70 : Colors.grey.shade700,
            ),
          ),
        ],
      ),
    );
  }
}
