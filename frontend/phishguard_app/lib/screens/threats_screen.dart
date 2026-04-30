import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../services/analyze_service.dart';
import '../models/analyze_response.dart';
import '../widgets/bottom_nav.dart';
import 'threat_details_screen.dart';

class ThreatsScreen extends StatefulWidget {
  const ThreatsScreen({super.key});
  @override
  State<ThreatsScreen> createState() => _ThreatsScreenState();
}

class _ThreatsScreenState extends State<ThreatsScreen> {
  final _svc = AnalyzeService();
  final _inputCtrl = TextEditingController();
  String _type = 'url';
  bool _loading = false;
  final List<AnalyzeResponse> _results = [];

  Future<void> _run() async {
    if (_inputCtrl.text.isEmpty) return;
    setState(() => _loading = true);
    try {
      AnalyzeResponse r;
      if (_type == 'url') {
        r = await _svc.analyzeUrl(_inputCtrl.text);
      } else if (_type == 'sms') {
        r = await _svc.analyzeSms(_inputCtrl.text);
      } else {
        r = await _svc.analyzeEmail(
            sender: 'test@test.com', headers: _inputCtrl.text);
      }
      setState(() {
        _results.insert(0, r);
        _inputCtrl.clear();
      });
    } catch (e) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Erro: $e')));
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: const Icon(Icons.menu),
        title: const Text('Threats'),
        actions: const [Icon(Icons.filter_list), SizedBox(width: 16)],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: SegmentedButton<String>(
              segments: const [
                ButtonSegment(value: 'url', label: Text('Web')),
                ButtonSegment(value: 'sms', label: Text('SMS')),
                ButtonSegment(value: 'email', label: Text('Email')),
              ],
              selected: {_type},
              onSelectionChanged: (s) => setState(() => _type = s.first),
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Row(children: [
              Expanded(
                  child: TextField(
                controller: _inputCtrl,
                decoration: InputDecoration(
                  hintText: _type == 'url'
                      ? 'https://...'
                      : _type == 'sms'
                          ? 'Corpo do SMS'
                          : 'Headers do e-mail',
                  border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10)),
                ),
              )),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _loading ? null : _run,
                style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white),
                child: _loading
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Text('Analisar'),
              )
            ]),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: _results.isEmpty
                ? const Center(
                    child: Text('Nenhuma análise ainda.',
                        style: TextStyle(color: AppColors.textMuted)))
                : ListView.separated(
                    padding: const EdgeInsets.all(12),
                    itemCount: _results.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 8),
                    itemBuilder: (_, i) => _tile(_results[i]),
                  ),
          ),
        ],
      ),
      bottomNavigationBar: const AppBottomNav(currentIndex: 1),
    );
  }

  Widget _tile(AnalyzeResponse r) {
    final color = r.isUnsafe ? AppColors.danger : AppColors.success;
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: AppColors.border)),
      child: ListTile(
        leading: CircleAvatar(
            backgroundColor: color.withOpacity(0.15),
            child: Icon(r.isUnsafe ? Icons.warning : Icons.check_circle,
                color: color)),
        title: Text(r.verdict,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Text('Score: ${r.score} · ${r.reasons.take(1).join()}',
            maxLines: 1, overflow: TextOverflow.ellipsis),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => Navigator.push(context,
            MaterialPageRoute(builder: (_) => ThreatDetailsScreen(result: r))),
      ),
    );
  }
}
