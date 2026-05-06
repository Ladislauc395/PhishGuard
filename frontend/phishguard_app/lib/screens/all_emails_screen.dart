import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../services/integrations_service.dart';

enum EmailVerdict { safe, suspicious, blocked }

class AnalysedEmail {
  final String id;
  final String subject;
  final String sender;
  final String date;
  final String snippet;
  final int score;
  final String verdictRaw;
  final List<String> reasons;
  final bool autoBlocked;

  const AnalysedEmail({
    required this.id,
    required this.subject,
    required this.sender,
    required this.date,
    required this.snippet,
    required this.score,
    required this.verdictRaw,
    required this.reasons,
    required this.autoBlocked,
  });

  EmailVerdict get verdict {
    if (autoBlocked || score >= 60 || verdictRaw.contains('NÃO SEGURO')) {
      return EmailVerdict.blocked;
    }
    if (score >= 30 || verdictRaw.contains('SUSPEITO')) {
      return EmailVerdict.suspicious;
    }
    return EmailVerdict.safe;
  }

  factory AnalysedEmail.fromJson(Map<String, dynamic> json) {
    final email = json['email'] as Map<String, dynamic>? ?? json;
    final analysis = json['analysis'] as Map<String, dynamic>? ?? {};
    return AnalysedEmail(
      id: email['id']?.toString() ?? '',
      subject: email['subject']?.toString() ?? '(sem assunto)',
      sender: email['sender']?.toString() ?? '',
      date: email['date']?.toString() ?? '',
      snippet: email['snippet']?.toString() ?? '',
      score: (analysis['score'] as num?)?.toInt() ?? 0,
      verdictRaw: analysis['verdict']?.toString() ?? 'SEGURO',
      reasons:
          (analysis['reasons'] as List?)?.map((r) => r.toString()).toList() ??
              [],
      autoBlocked: analysis['blocked'] == true,
    );
  }

  Color get scoreColor {
    if (score >= 60) return AppColors.danger;
    if (score >= 30) return AppColors.warning;
    return AppColors.success;
  }

  String get primaryReason {
    if (reasons.isEmpty) return 'Sem sinais de phishing';
    final priority = [
      'virustotal',
      'google_safe',
      'link malicioso',
      'link suspeito',
      'spoof',
      'typosquatting',
      'SPF',
      'DKIM',
      'DMARC',
      'BLOQUEADO',
    ];
    for (final p in priority) {
      final match = reasons.firstWhere(
        (r) => r.toLowerCase().contains(p.toLowerCase()),
        orElse: () => '',
      );
      if (match.isNotEmpty) return _translateReason(match);
    }
    return _translateReason(reasons.first);
  }

  static String _translateReason(String r) {
    if (r.contains('virustotal')) return '🦠 Detectado pelo VirusTotal';
    if (r.contains('google_safe') || r.contains('safe_browsing'))
      return '🔴 Google Safe Browsing alerta';
    if (r.contains('spoof_known') ||
        r.contains('display_name_spoof') ||
        r.contains('spoof')) return '🎭 Imitação de marca conhecida';
    if (r.contains('typosquatting')) return '🔤 Domínio falso (typosquatting)';
    if (r.contains('auth_fail')) return '🔐 Falha SPF/DKIM/DMARC';
    if (r.contains('SPF falhou')) return '🔐 SPF falhou';
    if (r.contains('DKIM falhou')) return '🔐 DKIM falhou';
    if (r.contains('DMARC falhou')) return '🔐 DMARC falhou';
    if (r.contains('suspicious_link') ||
        r.contains('Link malicioso') ||
        r.contains('link malicioso')) return '🔗 Link malicioso detectado';
    if (r.contains('Link suspeito') || r.contains('link suspeito'))
      return '🔗 Link suspeito detectado';
    if (r.contains('domain_mismatch'))
      return '🌐 Domínio do remetente suspeito';
    if (r.contains('very_new_domain')) return '📅 Domínio recém-criado';
    if (r.contains('new_domain')) return '📅 Domínio recente';
    if (r.contains('parked_domain')) return '🅿️ Domínio estacionado';
    if (r.contains('NÃO é oficial')) return '🏷️ Domínio não oficial da marca';
    if (r.contains('analysis_timeout'))
      return '⏱️ Análise inconclusiva (timeout)';
    if (r.contains('sinal técnico forte'))
      return '⚠️ Sinal técnico forte detectado';
    if (r.contains('IA:') || r.contains('IA detectou'))
      return '🤖 ${r.replaceFirst(RegExp(r'IA:?\s*'), '')}';
    if (r.contains('Palavra'))
      return '🗣️ ${r.replaceFirst(RegExp(r'Palavra\s*suspeita:?\s*'), 'Palavra: ')}';
    if (r.contains('BLOQUEADO:')) return r.replaceFirst('BLOQUEADO: ', '');
    if (r.contains('no_real_threats')) return '✅ Nenhuma ameaça real detectada';
    return r;
  }

  List<String> get allTranslatedReasons =>
      reasons.map(_translateReason).toList();
}

// ─── Ecrã principal ───────────────────────────────────────────────

class AllEmailsScreen extends StatefulWidget {
  const AllEmailsScreen({super.key});

  @override
  State<AllEmailsScreen> createState() => _AllEmailsScreenState();
}

class _AllEmailsScreenState extends State<AllEmailsScreen>
    with SingleTickerProviderStateMixin {
  final _svc = IntegrationsService();

  List<AnalysedEmail> _all = [];
  bool _loading = true;
  bool _refreshing = false;
  String? _error;
  bool _scanningInBackground = false;
  bool _gmailConnected = true;
  int _pollAttempts = 0;
  static const int _maxPollAttempts = 20;

  late TabController _tab;
  final _searchCtrl = TextEditingController();
  String _query = '';

  @override
  void initState() {
    super.initState();
    _tab = TabController(length: 4, vsync: this);
    _searchCtrl.addListener(
        () => setState(() => _query = _searchCtrl.text.toLowerCase()));
    _load();
  }

  @override
  void dispose() {
    _tab.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
      _scanningInBackground = false;
      _gmailConnected = true;
      _pollAttempts = 0;
    });
    try {
      final response = await _svc.getAllAnalysedEmailsWithStatus().timeout(
            const Duration(seconds: 30),
            onTimeout: () => throw Exception('Timeout ao carregar emails'),
          );

      if (!mounted) return;
      setState(() {
        _all = response.emails.map((j) => AnalysedEmail.fromJson(j)).toList();
        _loading = false;
        _scanningInBackground = response.scanning;
      });

      // Só faz polling se houver scan em background E a cache estiver vazia
      if (response.scanning && _all.isEmpty) {
        _pollUntilScanDone();
      } else if (response.scanning && _all.isNotEmpty) {
        // Já temos dados em cache, mostrar imediatamente
        setState(() => _scanningInBackground = false);
      }
    } catch (e) {
      if (!mounted) return;
      final errStr = e.toString();
      final isNotConnected = errStr.contains('403') ||
          errStr.contains('Gmail não conectado') ||
          errStr.contains('não conectado');
      setState(() {
        _error = errStr;
        _loading = false;
        _gmailConnected = !isNotConnected;
      });
    }
  }

  Future<void> _forceRefresh() async {
    setState(() {
      _refreshing = true;
      _error = null;
      _pollAttempts = 0;
    });
    try {
      final response = await _svc.forceRefresh(maxResults: 30).timeout(
            const Duration(seconds: 120),
            onTimeout: () =>
                throw Exception('Scan demorou demasiado — tente de novo'),
          );

      if (!mounted) return;
      setState(() {
        _all = response.emails.map((j) => AnalysedEmail.fromJson(j)).toList();
        _scanningInBackground = response.scanning;
        _refreshing = false;
      });

      if (response.scanning && _all.isEmpty) {
        _pollUntilScanDone();
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _refreshing = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _pollUntilScanDone() async {
    for (int attempt = 0; attempt < _maxPollAttempts && mounted; attempt++) {
      _pollAttempts = attempt + 1;
      await Future.delayed(const Duration(seconds: 3));
      if (!mounted) break;

      try {
        final response = await _svc
            .getAllAnalysedEmailsWithStatus()
            .timeout(const Duration(seconds: 15));

        if (!mounted) break;

        setState(() {
          _all = response.emails.map((j) => AnalysedEmail.fromJson(j)).toList();
          _scanningInBackground = response.scanning;
        });

        // Parar polling se:
        // - Scan terminou (scanning=false)
        // - Já temos emails e não está a scanear
        if (!response.scanning) break;
        if (_all.isNotEmpty && attempt >= 3) {
          setState(() => _scanningInBackground = false);
          break;
        }
      } catch (_) {
        break;
      }
    }

    if (mounted) setState(() => _scanningInBackground = false);
  }

  List<AnalysedEmail> _filtered(EmailVerdict? filter) {
    var list =
        filter == null ? _all : _all.where((e) => e.verdict == filter).toList();
    if (_query.isNotEmpty) {
      list = list
          .where((e) =>
              e.subject.toLowerCase().contains(_query) ||
              e.sender.toLowerCase().contains(_query))
          .toList();
    }
    return list;
  }

  Future<void> _unblock(AnalysedEmail email) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Restaurar email?'),
        content: Text(
          'Vai mover o email de "${email.sender}" de volta para a caixa de entrada.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.success,
              foregroundColor: Colors.white,
            ),
            child: const Text('Restaurar'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await _svc.unblockEmail(email.id);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('Email restaurado'),
        backgroundColor: AppColors.success,
      ));
      await _load();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Erro: $e'),
        backgroundColor: AppColors.danger,
      ));
    }
  }

  Future<void> _blockEmail(AnalysedEmail email) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Bloquear email?'),
        content: Text(
          'Vai marcar o email de "${email.sender}" como phishing e movê-lo para o lixo.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.danger,
              foregroundColor: Colors.white,
            ),
            child: const Text('Bloquear'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await _svc.blockEmail(
        email.id,
        reasons: ['Bloqueado manualmente pelo utilizador'],
        score: 100,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('Email bloqueado com sucesso'),
        backgroundColor: AppColors.danger,
      ));
      await _load();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Erro ao bloquear: $e'),
        backgroundColor: AppColors.danger,
      ));
    }
  }

  void _showDetail(AnalysedEmail email) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => _DetailSheet(
        email: email,
        onUnblock: email.verdict == EmailVerdict.blocked
            ? () {
                Navigator.pop(context);
                _unblock(email);
              }
            : null,
        onBlock: email.verdict != EmailVerdict.blocked
            ? () {
                Navigator.pop(context);
                _blockEmail(email);
              }
            : null,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final blocked = _all.where((e) => e.verdict == EmailVerdict.blocked).length;
    final suspicious =
        _all.where((e) => e.verdict == EmailVerdict.suspicious).length;
    final safe = _all.where((e) => e.verdict == EmailVerdict.safe).length;

    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FB),
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded, color: Color(0xFF1A1A2E)),
          onPressed: () => Navigator.pop(context),
        ),
        title: const Text(
          'Emails Analisados',
          style: TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 18,
            color: Color(0xFF1A1A2E),
          ),
        ),
        actions: [
          if (_refreshing || _scanningInBackground)
            const Padding(
              padding: EdgeInsets.all(14),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            PopupMenuButton<String>(
              icon: const Icon(Icons.refresh_rounded, color: Color(0xFF1A1A2E)),
              tooltip: 'Actualizar',
              onSelected: (value) {
                if (value == 'quick') _load();
                if (value == 'full') _forceRefresh();
              },
              itemBuilder: (_) => [
                const PopupMenuItem(
                  value: 'quick',
                  child: Row(children: [
                    Icon(Icons.cached_rounded, size: 18),
                    SizedBox(width: 8),
                    Text('Atualizar cache'),
                  ]),
                ),
                const PopupMenuItem(
                  value: 'full',
                  child: Row(children: [
                    Icon(Icons.sync_rounded, size: 18),
                    SizedBox(width: 8),
                    Text('Scan completo (30 emails)'),
                  ]),
                ),
              ],
            ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(48),
          child: TabBar(
            controller: _tab,
            labelColor: AppColors.primary,
            unselectedLabelColor: const Color(0xFF9CA3AF),
            indicatorColor: AppColors.primary,
            indicatorSize: TabBarIndicatorSize.label,
            tabs: [
              Tab(text: 'Todos (${_all.length})'),
              Tab(text: '🚫 ($blocked)'),
              Tab(text: '⚠️ ($suspicious)'),
              Tab(text: '✅ ($safe)'),
            ],
          ),
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : !_gmailConnected
              ? _buildGmailNotConnected()
              : _error != null
                  ? _buildError()
                  : Column(
                      children: [
                        if (_refreshing) _refreshingBanner(),
                        if (_scanningInBackground && !_refreshing)
                          _scanningBanner(),
                        _searchBar(),
                        if (_all.isNotEmpty)
                          _summaryRow(blocked, suspicious, safe),
                        Expanded(
                          child: TabBarView(
                            controller: _tab,
                            children: [
                              _buildList(null),
                              _buildList(EmailVerdict.blocked),
                              _buildList(EmailVerdict.suspicious),
                              _buildList(EmailVerdict.safe),
                            ],
                          ),
                        ),
                      ],
                    ),
    );
  }

  Widget _buildGmailNotConnected() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: AppColors.primary.withOpacity(0.1),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.mark_email_unread_outlined,
                  size: 40, color: AppColors.primary),
            ),
            const SizedBox(height: 24),
            const Text(
              'Gmail não conectado',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            const Text(
              'O backend não conseguiu autenticar com o Gmail.\n\n'
              'Se o GMAIL_REFRESH_TOKEN está no .env, verifica os logs do servidor '
              'para diagnosticar o problema (token inválido ou expirado).',
              textAlign: TextAlign.center,
              style: TextStyle(color: AppColors.textMuted, height: 1.5),
            ),
            const SizedBox(height: 32),
            ElevatedButton.icon(
              onPressed: _load,
              icon: const Icon(Icons.refresh),
              label: const Text('Tentar novamente'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
                padding:
                    const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.wifi_off_rounded,
                size: 48, color: AppColors.textMuted),
            const SizedBox(height: 16),
            const Text('Erro ao carregar emails',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Text(
              _error ?? '',
              textAlign: TextAlign.center,
              style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _load,
              icon: const Icon(Icons.refresh),
              label: const Text('Tentar novamente'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _refreshingBanner() => Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 16),
        color: AppColors.primary.withOpacity(0.1),
        child: const Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            SizedBox(
              width: 14,
              height: 14,
              child: CircularProgressIndicator(
                  strokeWidth: 2, color: AppColors.primary),
            ),
            SizedBox(width: 10),
            Text('A fazer scan completo...',
                style: TextStyle(color: AppColors.primary, fontSize: 13)),
          ],
        ),
      );

  Widget _scanningBanner() => Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
        color: AppColors.warning.withOpacity(0.1),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const SizedBox(
              width: 12,
              height: 12,
              child: CircularProgressIndicator(
                  strokeWidth: 2, color: AppColors.warning),
            ),
            const SizedBox(width: 10),
            Text(
              _scanningInBackground
                  ? 'Scan em background... (${(_pollAttempts * 3).clamp(0, 60)}s)'
                  : 'A processar...',
              style: const TextStyle(color: AppColors.warning, fontSize: 12),
            ),
            if (_pollAttempts >= 15)
              TextButton(
                onPressed: () => setState(() => _scanningInBackground = false),
                child: const Text('Parar',
                    style: TextStyle(fontSize: 11, color: AppColors.danger)),
              ),
          ],
        ),
      );

  Widget _searchBar() => Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
        child: TextField(
          controller: _searchCtrl,
          decoration: InputDecoration(
            hintText: 'Pesquisar por assunto ou remetente...',
            prefixIcon: const Icon(Icons.search_rounded, size: 20),
            contentPadding: const EdgeInsets.symmetric(vertical: 10),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide: const BorderSide(color: AppColors.border),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide: const BorderSide(color: AppColors.border),
            ),
          ),
        ),
      );

  Widget _summaryRow(int blocked, int suspicious, int safe) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Row(children: [
          _chip('🚫 $blocked', AppColors.danger),
          const SizedBox(width: 8),
          _chip('⚠️ $suspicious', AppColors.warning),
          const SizedBox(width: 8),
          _chip('✅ $safe', AppColors.success),
        ]),
      );

  Widget _chip(String label, Color color) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Text(label,
            style: TextStyle(
                color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      );

  Widget _buildList(EmailVerdict? filter) {
    final list = _filtered(filter);
    if (list.isEmpty) {
      final emptyMsg = _query.isNotEmpty
          ? 'Nenhum resultado para "$_query"'
          : _scanningInBackground
              ? 'A analisar emails...\nAguarde enquanto o scan está em curso.'
              : filter == null
                  ? 'Nenhum email analisado ainda.\nToque em refresh → Scan completo para iniciar.'
                  : filter == EmailVerdict.blocked
                      ? '✅ Nenhum email bloqueado'
                      : filter == EmailVerdict.suspicious
                          ? '✅ Nenhum email suspeito'
                          : '✅ Todos os emails seguros';
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                _scanningInBackground
                    ? Icons.hourglass_empty_rounded
                    : filter == EmailVerdict.blocked
                        ? Icons.block_rounded
                        : filter == EmailVerdict.suspicious
                            ? Icons.warning_amber_rounded
                            : Icons.mark_email_read_outlined,
                size: 48,
                color: AppColors.textMuted.withOpacity(0.4),
              ),
              const SizedBox(height: 16),
              Text(
                emptyMsg,
                textAlign: TextAlign.center,
                style: const TextStyle(color: AppColors.textMuted, height: 1.5),
              ),
            ],
          ),
        ),
      );
    }

    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 24),
      itemCount: list.length,
      separatorBuilder: (_, __) => const SizedBox(height: 6),
      itemBuilder: (_, i) => _EmailTile(
        email: list[i],
        onTap: () => _showDetail(list[i]),
        onUnblock: list[i].verdict == EmailVerdict.blocked
            ? () => _unblock(list[i])
            : null,
      ),
    );
  }
}

// ─── Tile de email ────────────────────────────────────────────────

class _EmailTile extends StatelessWidget {
  final AnalysedEmail email;
  final VoidCallback onTap;
  final VoidCallback? onUnblock;

  const _EmailTile({
    required this.email,
    required this.onTap,
    this.onUnblock,
  });

  @override
  Widget build(BuildContext context) {
    final color = email.scoreColor;

    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: color.withOpacity(0.3)),
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                _verdictBadge(),
                const Spacer(),
                Text(
                  '${email.score}/100',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
              ]),
              const SizedBox(height: 6),
              Text(
                email.subject,
                style:
                    const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 2),
              Text(
                email.sender,
                style:
                    const TextStyle(fontSize: 12, color: AppColors.textMuted),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              if (email.snippet.isNotEmpty) ...[
                const SizedBox(height: 4),
                Text(
                  email.snippet,
                  style:
                      const TextStyle(fontSize: 12, color: Color(0xFF6B7280)),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
              const SizedBox(height: 8),
              Row(children: [
                const Icon(Icons.info_outline_rounded,
                    size: 13, color: AppColors.textMuted),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    email.primaryReason,
                    style:
                        const TextStyle(fontSize: 12, color: Color(0xFF374151)),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (onUnblock != null) ...[
                  const SizedBox(width: 4),
                  OutlinedButton(
                    onPressed: onUnblock,
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 3),
                      minimumSize: Size.zero,
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      side: const BorderSide(color: AppColors.success),
                      foregroundColor: AppColors.success,
                    ),
                    child:
                        const Text('Restaurar', style: TextStyle(fontSize: 11)),
                  ),
                ],
              ]),
            ],
          ),
        ),
      ),
    );
  }

  Widget _verdictBadge() {
    String label;
    Color bg;
    switch (email.verdict) {
      case EmailVerdict.blocked:
        label = '🚫 BLOQUEADO';
        bg = AppColors.danger;
        break;
      case EmailVerdict.suspicious:
        label = '⚠️ SUSPEITO';
        bg = AppColors.warning;
        break;
      case EmailVerdict.safe:
        label = '✅ SEGURO';
        bg = AppColors.success;
        break;
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: bg.withOpacity(0.15),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(label,
          style:
              TextStyle(color: bg, fontSize: 9, fontWeight: FontWeight.bold)),
    );
  }
}

// ─── Bottom Sheet de detalhe ─────────────────────────────────────

class _DetailSheet extends StatelessWidget {
  final AnalysedEmail email;
  final VoidCallback? onUnblock;
  final VoidCallback? onBlock;

  const _DetailSheet({required this.email, this.onUnblock, this.onBlock});

  @override
  Widget build(BuildContext context) {
    final color = email.scoreColor;
    return DraggableScrollableSheet(
      initialChildSize: 0.75,
      minChildSize: 0.4,
      maxChildSize: 0.95,
      expand: false,
      builder: (_, ctrl) => ListView(
        controller: ctrl,
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
        children: [
          Center(
            child: Container(
              width: 36,
              height: 4,
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                  color: Colors.grey[300],
                  borderRadius: BorderRadius.circular(2)),
            ),
          ),
          Row(children: [
            Icon(
              email.verdict == EmailVerdict.blocked
                  ? Icons.block_rounded
                  : email.verdict == EmailVerdict.suspicious
                      ? Icons.warning_amber_rounded
                      : Icons.check_circle_outline_rounded,
              color: color,
              size: 26,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                email.verdict == EmailVerdict.blocked
                    ? 'Email Bloqueado'
                    : email.verdict == EmailVerdict.suspicious
                        ? 'Email Suspeito'
                        : 'Email Seguro',
                style: TextStyle(
                    fontSize: 18, fontWeight: FontWeight.bold, color: color),
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                  color: color, borderRadius: BorderRadius.circular(20)),
              child: Text('${email.score}/100',
                  style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 12)),
            ),
          ]),
          const SizedBox(height: 20),
          _row(Icons.subject, 'Assunto', email.subject),
          _row(Icons.person_outline, 'Remetente', email.sender),
          _row(Icons.calendar_today_outlined, 'Data', email.date),
          if (email.snippet.isNotEmpty) ...[
            const SizedBox(height: 14),
            const Text('Pré-visualização',
                style: TextStyle(
                    fontWeight: FontWeight.w600,
                    color: AppColors.textMuted,
                    fontSize: 12)),
            const SizedBox(height: 6),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(10)),
              child: Text(email.snippet,
                  style: const TextStyle(fontSize: 13, height: 1.5)),
            ),
          ],
          const SizedBox(height: 16),
          const Text('Motivos da análise',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
          const SizedBox(height: 10),
          if (email.reasons.isEmpty)
            _reasonTile('✅ Nenhuma ameaça detectada', AppColors.success,
                primary: true)
          else
            ...email.allTranslatedReasons
                .asMap()
                .entries
                .map((e) => _reasonTile(e.value, color, primary: e.key == 0)),
          const SizedBox(height: 20),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFFF8F9FB),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(children: [
              const Icon(Icons.analytics_outlined,
                  size: 16, color: Color(0xFF9CA3AF)),
              const SizedBox(width: 8),
              Text(
                'Score de risco: ${email.score}/100 '
                '(${email.score >= 60 ? "Phishing confirmado" : email.score >= 30 ? "Suspeito" : "Seguro"})',
                style: const TextStyle(fontSize: 12, color: Color(0xFF6B7280)),
              ),
            ]),
          ),
          if (onUnblock != null) ...[
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                onPressed: onUnblock,
                icon: const Icon(Icons.restore, size: 18),
                label: const Text('Restaurar para a Caixa de Entrada'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppColors.success,
                  side: const BorderSide(color: AppColors.success),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ),
          ],
          if (onBlock != null) ...[
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: onBlock,
                icon: const Icon(Icons.block_rounded, size: 18),
                label: const Text('Bloquear como Phishing'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.danger,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _row(IconData icon, String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(icon, size: 15, color: AppColors.textMuted),
          const SizedBox(width: 8),
          Text('$label: ',
              style: const TextStyle(color: AppColors.textMuted, fontSize: 13)),
          Expanded(
              child: Text(value,
                  style: const TextStyle(
                      fontWeight: FontWeight.w500, fontSize: 13))),
        ]),
      );

  Widget _reasonTile(String text, Color color, {bool primary = false}) =>
      Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: primary ? color.withOpacity(0.08) : Colors.grey[50],
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
              color: primary ? color.withOpacity(0.3) : Colors.grey[200]!),
        ),
        child: Text(text,
            style: TextStyle(
                fontSize: 13,
                fontWeight: primary ? FontWeight.w600 : FontWeight.normal,
                height: 1.4)),
      );
}
