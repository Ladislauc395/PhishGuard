import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../services/integrations_service.dart';
import '../widgets/bottom_nav.dart';

// ─── Modelo ───────────────────────────────────────────────────────

class BlockedEmail {
  final String id;
  final String subject;
  final String sender;
  final String date;
  final String snippet;
  final int score;
  final String verdict;
  final List<String> reasons;
  final bool autoBlocked;

  const BlockedEmail({
    required this.id,
    required this.subject,
    required this.sender,
    required this.date,
    required this.snippet,
    required this.score,
    required this.verdict,
    required this.reasons,
    required this.autoBlocked,
  });

  factory BlockedEmail.fromJson(Map<String, dynamic> json) {
    final email = json['email'] as Map<String, dynamic>? ?? {};
    final analysis = json['analysis'] as Map<String, dynamic>? ?? {};
    final reasons =
        (analysis['reasons'] as List?)?.map((r) => r.toString()).toList() ?? [];
    return BlockedEmail(
      id: email['id']?.toString() ?? '',
      subject: email['subject']?.toString() ?? '(sem assunto)',
      sender: email['sender']?.toString() ?? '',
      date: email['date']?.toString() ?? '',
      snippet: email['snippet']?.toString() ?? '',
      score: (analysis['score'] as num?)?.toInt() ?? 0,
      verdict: analysis['verdict']?.toString() ?? 'NÃO SEGURO',
      reasons: reasons,
      autoBlocked: analysis['blocked'] == true,
    );
  }

  /// Traduz os motivos técnicos para português legível
  String get readableReason {
    if (reasons.isEmpty) return 'Motivo desconhecido';
    final r = reasons.first;
    if (r.contains('virustotal')) return '🦠 Detectado pelo VirusTotal';
    if (r.contains('google_safe')) return '🔴 Google Safe Browsing';
    if (r.contains('spoof_known')) return '🎭 Imitação de marca conhecida';
    if (r.contains('typosquatting')) return '🔤 Domínio falso (typosquatting)';
    if (r.contains('auth_fail')) return '🔐 Falha de autenticação (SPF/DKIM)';
    if (r.contains('suspicious_link')) return '🔗 Link malicioso detectado';
    if (r.contains('domain_mismatch'))
      return '🌐 Domínio do remetente suspeito';
    if (r.contains('very_new_domain')) return '📅 Domínio recém-criado';
    if (r.contains('parked_domain')) return '🅿️ Domínio estacionado';
    if (r.contains('IA:')) return '🤖 ${r.replaceFirst("IA: ", "")}';
    if (r.contains('BLOQUEADO:')) return r.replaceFirst('BLOQUEADO: ', '');
    return r;
  }

  Color get scoreColor {
    if (score >= 70) return AppColors.danger;
    if (score >= 40) return AppColors.warning;
    return Colors.orange;
  }
}

// ─── Ecrã principal ───────────────────────────────────────────────

class BlockedEmailsScreen extends StatefulWidget {
  const BlockedEmailsScreen({super.key});

  @override
  State<BlockedEmailsScreen> createState() => _BlockedEmailsScreenState();
}

class _BlockedEmailsScreenState extends State<BlockedEmailsScreen> {
  final _svc = IntegrationsService();
  List<BlockedEmail> _blocked = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final raw = await _svc.getBlockedEmails();
      setState(() {
        _blocked = raw.map((j) => BlockedEmail.fromJson(j)).toList();
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _unblock(BlockedEmail email) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Desbloquear email?'),
        content: Text(
          'Vai restaurar o email de "${email.sender}" para a caixa de entrada. '
          'Tem a certeza?',
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
      _showSnack('Email restaurado para a caixa de entrada', success: true);
      await _load();
    } catch (e) {
      _showSnack('Erro ao desbloquear: $e');
    }
  }

  void _showSnack(String msg, {bool success = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: success ? AppColors.success : AppColors.danger,
    ));
  }

  void _showDetails(BlockedEmail email) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => _DetailSheet(
          email: email,
          onUnblock: () {
            Navigator.pop(context);
            _unblock(email);
          }),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Emails Bloqueados'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _load,
            tooltip: 'Actualizar',
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Icon(Icons.error_outline, color: AppColors.danger, size: 48),
          const SizedBox(height: 12),
          Text('Erro ao carregar: $_error',
              textAlign: TextAlign.center,
              style: const TextStyle(color: AppColors.textMuted)),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: _load,
            icon: const Icon(Icons.refresh),
            label: const Text('Tentar de novo'),
          ),
        ]),
      );
    }

    if (_blocked.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Icon(Icons.shield_outlined, color: AppColors.success, size: 64),
          const SizedBox(height: 12),
          const Text('Nenhum email bloqueado',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          const Text('O PhishGuard ainda não bloqueou nenhum email.',
              style: TextStyle(color: AppColors.textMuted)),
        ]),
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: Column(
        children: [
          _summaryBanner(),
          Expanded(
            child: ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: _blocked.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (_, i) => _BlockedCard(
                email: _blocked[i],
                onTap: () => _showDetails(_blocked[i]),
                onUnblock: () => _unblock(_blocked[i]),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _summaryBanner() {
    final total = _blocked.length;
    final autoBlocked = _blocked.where((e) => e.autoBlocked).length;
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 16, 16, 0),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [AppColors.danger, Color(0xFFB71C1C)],
        ),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(children: [
        const Icon(Icons.block, color: Colors.white, size: 32),
        const SizedBox(width: 12),
        Expanded(
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('$total emails bloqueados',
                style: const TextStyle(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.bold)),
            Text('$autoBlocked bloqueados automaticamente pelo PhishGuard',
                style: const TextStyle(color: Colors.white70, fontSize: 12)),
          ]),
        ),
      ]),
    );
  }
}

// ─── Card de email bloqueado ──────────────────────────────────────

class _BlockedCard extends StatelessWidget {
  final BlockedEmail email;
  final VoidCallback onTap;
  final VoidCallback onUnblock;

  const _BlockedCard({
    required this.email,
    required this.onTap,
    required this.onUnblock,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: email.scoreColor.withOpacity(0.4), width: 1.5),
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(14),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                // Score badge
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: email.scoreColor.withOpacity(0.15),
                    shape: BoxShape.circle,
                  ),
                  child: Center(
                    child: Text(
                      '${email.score}',
                      style: TextStyle(
                        color: email.scoreColor,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        email.subject,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            fontWeight: FontWeight.w600, fontSize: 14),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        email.sender,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            color: AppColors.textMuted, fontSize: 12),
                      ),
                    ],
                  ),
                ),
                if (email.autoBlocked)
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: AppColors.danger.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Text('AUTO',
                        style: TextStyle(
                            color: AppColors.danger,
                            fontSize: 9,
                            fontWeight: FontWeight.bold)),
                  ),
              ]),
              const SizedBox(height: 10),
              // Motivo principal
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: email.scoreColor.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(children: [
                  Icon(Icons.warning_amber_rounded,
                      size: 14, color: email.scoreColor),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      email.readableReason,
                      style: TextStyle(
                          fontSize: 12,
                          color: email.scoreColor,
                          fontWeight: FontWeight.w500),
                    ),
                  ),
                ]),
              ),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    _formatDate(email.date),
                    style: const TextStyle(
                        color: AppColors.textMuted, fontSize: 11),
                  ),
                  Row(children: [
                    TextButton(
                      onPressed: onTap,
                      style: TextButton.styleFrom(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 4),
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                      child: const Text('Ver detalhes',
                          style: TextStyle(fontSize: 12)),
                    ),
                    const SizedBox(width: 4),
                    OutlinedButton(
                      onPressed: onUnblock,
                      style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 4),
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                          side: const BorderSide(color: AppColors.success),
                          foregroundColor: AppColors.success),
                      child: const Text('Restaurar',
                          style: TextStyle(fontSize: 12)),
                    ),
                  ]),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _formatDate(String raw) {
    if (raw.isEmpty) return '';
    try {
      if (raw.length > 16) return raw.substring(0, 16);
    } catch (_) {}
    return raw;
  }
}

// ─── Bottom Sheet de detalhes ─────────────────────────────────────

class _DetailSheet extends StatelessWidget {
  final BlockedEmail email;
  final VoidCallback onUnblock;

  const _DetailSheet({required this.email, required this.onUnblock});

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.75,
      minChildSize: 0.4,
      maxChildSize: 0.95,
      expand: false,
      builder: (_, controller) => ListView(
        controller: controller,
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
        children: [
          // Handle
          Center(
            child: Container(
              width: 36,
              height: 4,
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                color: Colors.grey[300],
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),

          // Título
          Row(children: [
            Icon(Icons.block_rounded, color: email.scoreColor, size: 28),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                'Email Bloqueado',
                style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: email.scoreColor),
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: email.scoreColor,
                borderRadius: BorderRadius.circular(20),
              ),
              child: Text(
                '${email.score}/100',
                style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 13),
              ),
            ),
          ]),

          const SizedBox(height: 20),

          // Info do email
          _infoTile(Icons.subject, 'Assunto', email.subject),
          _infoTile(Icons.person_outline, 'Remetente', email.sender),
          _infoTile(Icons.calendar_today_outlined, 'Data', email.date),

          const SizedBox(height: 16),

          // Snippet
          if (email.snippet.isNotEmpty) ...[
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
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(email.snippet,
                  style: const TextStyle(fontSize: 13, height: 1.4)),
            ),
            const SizedBox(height: 16),
          ],

          // Motivos do bloqueio
          const Text('Por que foi bloqueado?',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
          const SizedBox(height: 10),

          ...email.reasons.asMap().entries.map((entry) {
            final i = entry.key;
            final r = entry.value;
            final icon = _iconForReason(r);
            final label = _labelForReason(r);
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: i == 0
                    ? email.scoreColor.withOpacity(0.08)
                    : Colors.grey[50],
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: i == 0
                      ? email.scoreColor.withOpacity(0.3)
                      : Colors.grey[200]!,
                ),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(icon, style: const TextStyle(fontSize: 18)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(label,
                        style: TextStyle(
                            fontSize: 13,
                            fontWeight:
                                i == 0 ? FontWeight.w600 : FontWeight.normal,
                            height: 1.4)),
                  ),
                ],
              ),
            );
          }),

          const SizedBox(height: 24),

          // Acções
          if (email.autoBlocked)
            Container(
              padding: const EdgeInsets.all(10),
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                color: AppColors.primary.withOpacity(0.08),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Row(children: [
                Icon(Icons.auto_awesome, color: AppColors.primary, size: 16),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Este email foi bloqueado automaticamente pelo PhishGuard.',
                    style: TextStyle(fontSize: 12, color: AppColors.primary),
                  ),
                ),
              ]),
            ),

          Row(children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: onUnblock,
                icon: const Icon(Icons.restore, size: 18),
                label: const Text('Restaurar'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppColors.success,
                  side: const BorderSide(color: AppColors.success),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ),
          ]),
        ],
      ),
    );
  }

  Widget _infoTile(IconData icon, String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 16, color: AppColors.textMuted),
            const SizedBox(width: 8),
            Text('$label: ',
                style:
                    const TextStyle(color: AppColors.textMuted, fontSize: 13)),
            Expanded(
              child: Text(value,
                  style: const TextStyle(
                      fontWeight: FontWeight.w500, fontSize: 13)),
            ),
          ],
        ),
      );

  String _iconForReason(String r) {
    if (r.contains('virustotal')) return '🦠';
    if (r.contains('google_safe')) return '🔴';
    if (r.contains('spoof')) return '🎭';
    if (r.contains('typosquatting')) return '🔤';
    if (r.contains('auth_fail')) return '🔐';
    if (r.contains('suspicious_link')) return '🔗';
    if (r.contains('domain_mismatch')) return '🌐';
    if (r.contains('IA:')) return '🤖';
    if (r.contains('Palavra')) return '🗣️';
    if (r.contains('BLOQUEADO')) return '🚫';
    if (r.contains('new_domain')) return '📅';
    return '⚠️';
  }

  String _labelForReason(String r) {
    final clean = r
        .replaceFirst('BLOQUEADO: ', '')
        .replaceFirst('IA: ', 'IA detectou: ')
        .replaceFirst('Palavra suspeita: ', 'Palavra suspeita: ')
        .replaceFirst('suspicious_link:', 'Link suspeito: ')
        .replaceFirst('auth_fail:', 'Falha de autenticação: ')
        .replaceFirst('virustotal', 'VirusTotal: URL maliciosa')
        .replaceFirst(
            'google_safe_browsing', 'Google Safe Browsing: URL bloqueada')
        .replaceFirst('spoof_known:', 'Imitação de marca: ')
        .replaceFirst('typosquatting:', 'Domínio falso de: ')
        .replaceFirst('very_new_domain:', 'Domínio criado há apenas ')
        .replaceFirst('domain_mismatch:', 'Domínio suspeito: ')
        .replaceFirst(
            'parked_domain', 'Domínio estacionado (sem conteúdo real)')
        .replaceFirst('domain_not_found', 'Domínio inexistente no DNS');
    return clean;
  }
}
