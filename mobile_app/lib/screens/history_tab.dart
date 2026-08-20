import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../models/history_item.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../services/tts_service.dart';
import '../theme/app_theme.dart';
import 'result_screen.dart';

class HistoryTab extends StatefulWidget {
  final ApiService apiService;
  final StorageService storageService;
  final TtsService ttsService;

  const HistoryTab({
    super.key,
    required this.apiService,
    required this.storageService,
    required this.ttsService,
  });

  @override
  State<HistoryTab> createState() => _HistoryTabState();
}

class _HistoryTabState extends State<HistoryTab> {
  List<HistoryItem> _history = [];
  String _filter = 'Todos'; // 'Todos', 'Seguros', 'Golpes'

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  void _loadHistory() {
    setState(() {
      _history = widget.storageService.getHistory();
    });
  }

  List<HistoryItem> get _filteredHistory {
    if (_filter == 'Seguros') {
      return _history.where((i) => i.result.level == 'safe').toList();
    } else if (_filter == 'Golpes') {
      return _history.where((i) => i.result.level == 'danger' || i.result.level == 'warning').toList();
    }
    return _history;
  }

  Future<void> _clearAll() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Limpar Histórico'),
        content: const Text('Tem certeza que deseja apagar todo o histórico de análises?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.dangerRed),
            child: const Text('Apagar Tudo'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      await widget.storageService.clearHistory();
      _loadHistory();
    }
  }

  Future<void> _deleteItem(String id) async {
    await widget.storageService.removeHistoryItem(id);
    _loadHistory();
  }

  @override
  Widget build(BuildContext context) {
    final isHc = widget.storageService.isHighContrast();
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final items = _filteredHistory;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Histórico de Verificações'),
        actions: [
          if (_history.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_sweep_outlined),
              tooltip: 'Limpar Histórico',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: Column(
        children: [
          // Filter Chips
          if (_history.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
              child: Row(
                children: [
                  _buildFilterChip('Todos', isHc),
                  const SizedBox(width: 8),
                  _buildFilterChip('Seguros', isHc),
                  const SizedBox(width: 8),
                  _buildFilterChip('Golpes', isHc),
                ],
              ),
            ),

          Expanded(
            child: items.isEmpty
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(32),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.history,
                            size: 64,
                            color: isHc ? AppTheme.hcYellow : Colors.grey.shade400,
                          ),
                          const SizedBox(height: 16),
                          Text(
                            'Nenhuma verificação recente',
                            style: TextStyle(
                              fontSize: isHc ? 20 : 16,
                              fontWeight: FontWeight.bold,
                              color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black87),
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Os links, mensagens e documentos analisados aparecerão aqui.',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              fontSize: 14,
                              color: isHc ? Colors.white70 : Colors.grey.shade600,
                            ),
                          ),
                        ],
                      ),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                    itemCount: items.length,
                    itemBuilder: (ctx, index) {
                      final item = items[index];
                      final color = AppTheme.getVerdictColor(item.result.level, isHighContrast: isHc);
                      final formattedDate = DateFormat('dd/MM/yyyy HH:mm').format(item.createdAt);

                      return Dismissible(
                        key: Key(item.id),
                        direction: DismissDirection.endToStart,
                        background: Container(
                          alignment: Alignment.centerRight,
                          padding: const EdgeInsets.only(right: 20),
                          decoration: BoxDecoration(
                            color: AppTheme.dangerRed,
                            borderRadius: BorderRadius.circular(16),
                          ),
                          child: const Icon(Icons.delete, color: Colors.white),
                        ),
                        onDismissed: (_) => _deleteItem(item.id),
                        child: Card(
                          margin: const EdgeInsets.only(bottom: 12),
                          child: ListTile(
                          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                          leading: CircleAvatar(
                            backgroundColor: color.withOpacity(0.15),
                            child: Text(item.result.icon, style: const TextStyle(fontSize: 20)),
                          ),
                          title: Text(
                            item.input,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: isHc ? 17 : 15,
                              color: isHc ? AppTheme.hcYellow : (isDark ? Colors.white : Colors.black),
                            ),
                          ),
                          subtitle: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const SizedBox(height: 4),
                              Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: color.withOpacity(0.15),
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: Text(
                                      item.result.verdict,
                                      style: TextStyle(
                                        fontSize: 11,
                                        fontWeight: FontWeight.bold,
                                        color: color,
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  Text(
                                    'Score: ${item.result.score}/100',
                                    style: TextStyle(
                                      fontSize: 12,
                                      fontWeight: FontWeight.w500,
                                      color: isHc ? Colors.white70 : Colors.grey.shade600,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 4),
                              Text(
                                '$formattedDate • ${item.inputType}',
                                style: TextStyle(
                                  fontSize: 11,
                                  color: isHc ? Colors.white54 : Colors.grey.shade500,
                                ),
                              ),
                            ],
                          ),
                          trailing: IconButton(
                            icon: const Icon(Icons.chevron_right),
                            onPressed: () {
                              Navigator.of(context).push(
                                MaterialPageRoute(
                                  builder: (c) => ResultScreen(
                                    result: item.result,
                                    inputSource: item.input,
                                    apiService: widget.apiService,
                                    storageService: widget.storageService,
                                    ttsService: widget.ttsService,
                                  ),
                                ),
                              );
                            },
                          ),
                          onTap: () {
                            Navigator.of(context).push(
                              MaterialPageRoute(
                                builder: (c) => ResultScreen(
                                  result: item.result,
                                  inputSource: item.input,
                                  apiService: widget.apiService,
                                  storageService: widget.storageService,
                                  ttsService: widget.ttsService,
                                ),
                              ),
                            );
                          },
                        ),
                      ),
                    );
                  },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChip(String label, bool isHc) {
    final isSelected = _filter == label;
    return ChoiceChip(
      label: Text(label),
      selected: isSelected,
      onSelected: (val) {
        if (val) setState(() => _filter = label);
      },
      selectedColor: isHc ? AppTheme.hcYellow : AppTheme.iosBlue,
      labelStyle: TextStyle(
        fontWeight: FontWeight.bold,
        color: isSelected
            ? (isHc ? Colors.black : Colors.white)
            : (isHc ? AppTheme.hcYellow : Colors.grey.shade700),
      ),
    );
  }
}
