// lib/screens/connections_screen.dart
//
// Ecrã de Ligações — PhishGuard Angola
//
// CORRECÇÕES v12:
//   - Tema WHITE/BLUE restaurado (era dark 0xFF0F1117, agora 0xFFF8F9FB)
//   - Gmail OAuth usa LaunchMode.inAppWebView (não abre browser externo)
//   - AppBar branco com texto escuro, consistente com AllEmailsScreen

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/integrations_service.dart';
import '../services/extension_service.dart';

// ─── Paleta de cores clara (White / Blue) ────────────────────────

const _kBg = Color(0xFFF8F9FB); // fundo geral
const _kCard = Colors.white; // cartões
const _kBlue = Color(0xFF3B82F6); // azul principal
const _kTextDark = Color(0xFF1A1A2E); // texto escuro
const _kTextMuted = Color(0xFF6B7280); // texto secundário
const _kBorder = Color(0xFFE5E7EB); // bordas suaves
const _kGreen = Color(0xFF10B981);
const _kRed = Color(0xFFEF4444);

class ConnectionsScreen extends StatefulWidget {
  const ConnectionsScreen({super.key});

  @override
  State<ConnectionsScreen> createState() => _ConnectionsScreenState();
}

class _ConnectionsScreenState extends State<ConnectionsScreen>
    with SingleTickerProviderStateMixin {
  final _integrations = IntegrationsService();
  final _extensionSvc = ExtensionService();

  // Estado
  IntegrationStatus _status = IntegrationStatus.disconnected();
  ExtensionStatus _extStatus = ExtensionStatus.offline();
  ExtensionStats _extStats = ExtensionStats.empty();

  bool _loadingGmail = false;
  bool _loadingExtension = false;
  bool _loadingUrlCheck = false;
  String? _gmailError;
  String? _extError;

  // Teste de URL
  final _urlController = TextEditingController();
  UrlCheckResult? _urlCheckResult;

  // Expansão das secções
  bool _gmailExpanded = true;
  bool _smsExpanded = false;
  bool _chromeExpanded = true;

  @override
  void initState() {
    super.initState();
    _loadAll();
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _loadAll() async {
    await Future.wait([_loadStatus(), _loadExtensionStatus()]);
  }

  Future<void> _loadStatus() async {
    final s = await _integrations.getStatus();
    if (mounted) setState(() => _status = s);
  }

  Future<void> _loadExtensionStatus() async {
    setState(() => _loadingExtension = true);
    try {
      final s = await _extensionSvc.getStatus();
      final st = await _extensionSvc.getStats();
      if (mounted) {
        setState(() {
          _extStatus = s;
          _extStats = st;
          _extError = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _extError = e.toString());
    } finally {
      if (mounted) setState(() => _loadingExtension = false);
    }
  }

  // ── Gmail actions ────────────────────────────────────────────────

  /// CORRIGIDO v12: usa inAppWebView para não abandonar o app.
  /// O browser OAuth interno faz redirect para o servidor que guarda o token
  /// e fecha o WebView automaticamente.
  Future<void> _connectGmail() async {
    setState(() {
      _loadingGmail = true;
      _gmailError = null;
    });
    try {
      final url = await _integrations.getGmailAuthUrl();
      final uri = Uri.parse(url);

      // Preferir WebView interno; fallback para browser externo se falhar
      bool launched = false;
      try {
        launched = await launchUrl(uri, mode: LaunchMode.inAppWebView);
      } catch (_) {
        launched = false;
      }

      if (!launched) {
        // Fallback — browser externo (iOS Safari / Chrome Android)
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      }

      // Aguardar callback e verificar estado
      await Future.delayed(const Duration(seconds: 4));
      await _loadStatus();
    } catch (e) {
      if (mounted) setState(() => _gmailError = e.toString());
    } finally {
      if (mounted) setState(() => _loadingGmail = false);
    }
  }

  Future<void> _disconnectGmail() async {
    setState(() => _loadingGmail = true);
    try {
      await _integrations.disconnectGmail();
      await _loadStatus();
    } catch (e) {
      if (mounted) setState(() => _gmailError = e.toString());
    } finally {
      if (mounted) setState(() => _loadingGmail = false);
    }
  }

  Future<void> _scanGmail() async {
    setState(() => _loadingGmail = true);
    try {
      await _integrations.scanGmail(maxResults: 20);
      _showSnack('✅ Scan iniciado em segundo plano');
      await _loadStatus();
    } catch (e) {
      _showSnack('Erro: ${e.toString()}', isError: true);
    } finally {
      if (mounted) setState(() => _loadingGmail = false);
    }
  }

  // ── SMS actions ──────────────────────────────────────────────────

  Future<void> _toggleSms(bool enabled) async {
    try {
      await _integrations.toggleSms(enabled);
      await _loadStatus();
    } catch (e) {
      _showSnack('Erro: ${e.toString()}', isError: true);
    }
  }

  // ── Extension: URL check ─────────────────────────────────────────

  Future<void> _checkUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;
    setState(() {
      _loadingUrlCheck = true;
      _urlCheckResult = null;
    });
    try {
      final result = await _extensionSvc.checkUrl(url);
      if (mounted) setState(() => _urlCheckResult = result);
    } catch (e) {
      _showSnack('Erro: ${e.toString()}', isError: true);
    } finally {
      if (mounted) setState(() => _loadingUrlCheck = false);
    }
  }

  Future<void> _copyToClipboard(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    _showSnack('✅ Copiado para a área de transferência');
  }

  Future<void> _launchUrl(String url) async {
    if (url.isEmpty) return;
    final uri = Uri.parse(url);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } else {
      _showSnack('Não foi possível abrir o link', isError: true);
    }
  }

  void _showSnack(String msg, {bool isError = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: isError ? _kRed : _kGreen,
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ));
  }

  // ── UI ───────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _kBg,
      appBar: AppBar(
        backgroundColor: Colors.white,
        foregroundColor: _kTextDark,
        elevation: 0,
        shadowColor: Colors.black12,
        surfaceTintColor: Colors.white,
        title: const Text(
          'Ligações',
          style: TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 18,
            color: _kTextDark,
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: _kTextDark),
            onPressed: _loadAll,
            tooltip: 'Actualizar',
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: _kBorder),
        ),
      ),
      body: RefreshIndicator(
        onRefresh: _loadAll,
        color: _kBlue,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _buildGmailSection(),
            const SizedBox(height: 12),
            _buildSmsSection(),
            const SizedBox(height: 12),
            _buildChromeExtensionSection(),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  // ── SECÇÃO GMAIL ─────────────────────────────────────────────────

  Widget _buildGmailSection() {
    final connected = _status.gmailConnected;
    return _buildCard(
      onTap: () => setState(() => _gmailExpanded = !_gmailExpanded),
      header: Row(
        children: [
          _buildServiceIcon(
            Icons.email_rounded,
            connected ? _kGreen : const Color(0xFF9CA3AF),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Gmail',
                  style: TextStyle(
                    color: _kTextDark,
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  connected
                      ? (_status.gmailEmail ?? 'Conectado')
                      : 'Não conectado',
                  style: TextStyle(
                    color: connected ? _kGreen : _kTextMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          _buildStatusBadge(connected ? 'ACTIVO' : 'INACTIVO', connected),
          const SizedBox(width: 8),
          Icon(
            _gmailExpanded ? Icons.expand_less : Icons.expand_more,
            color: _kTextMuted,
          ),
        ],
      ),
      body: _gmailExpanded ? _buildGmailBody(connected) : null,
    );
  }

  Widget _buildGmailBody(bool connected) {
    return Column(
      children: [
        if (_gmailError != null) _buildErrorBanner(_gmailError!),
        const SizedBox(height: 12),
        if (!connected)
          _buildActionButton(
            label: 'Ligar Gmail',
            icon: Icons.link_rounded,
            color: _kBlue,
            loading: _loadingGmail,
            onPressed: _connectGmail,
          )
        else ...[
          if (_status.lastScanAt != null)
            _buildInfoRow('Último scan', _status.lastScanAt!),
          if (_status.lastScanThreats > 0)
            _buildInfoRow(
              'Ameaças encontradas',
              '${_status.lastScanThreats}',
              valueColor: Colors.orange[700],
            ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: _buildActionButton(
                  label: 'Scan Agora',
                  icon: Icons.search_rounded,
                  color: _kGreen,
                  loading: _loadingGmail,
                  onPressed: _scanGmail,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _buildActionButton(
                  label: 'Desligar',
                  icon: Icons.link_off_rounded,
                  color: _kRed,
                  loading: _loadingGmail,
                  onPressed: _disconnectGmail,
                ),
              ),
            ],
          ),
        ],
      ],
    );
  }

  // ── SECÇÃO SMS ───────────────────────────────────────────────────

  Widget _buildSmsSection() {
    final enabled = _status.smsEnabled;
    return _buildCard(
      onTap: () => setState(() => _smsExpanded = !_smsExpanded),
      header: Row(
        children: [
          _buildServiceIcon(
            Icons.sms_rounded,
            enabled ? _kGreen : const Color(0xFF9CA3AF),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'SMS / Smishing',
                  style: TextStyle(
                    color: _kTextDark,
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  enabled ? 'Monitorização activa' : 'Monitorização inactiva',
                  style: TextStyle(
                    color: enabled ? _kGreen : _kTextMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          Switch(
            value: enabled,
            onChanged: _toggleSms,
            activeColor: _kGreen,
          ),
          Icon(
            _smsExpanded ? Icons.expand_less : Icons.expand_more,
            color: _kTextMuted,
          ),
        ],
      ),
      body: _smsExpanded
          ? Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                'Quando activo, o PhishGuard analisa automaticamente os SMS '
                'recebidos e alerta para mensagens suspeitas.',
                style: TextStyle(color: _kTextMuted, fontSize: 13),
              ),
            )
          : null,
    );
  }

  // ── SECÇÃO EXTENSÃO CHROME ────────────────────────────────────────

  Widget _buildChromeExtensionSection() {
    final quality = _extStatus.quality;
    final Color qualityColor = switch (quality) {
      ExtensionQuality.full => _kGreen,
      ExtensionQuality.partial => Colors.orange,
      ExtensionQuality.minimal => Colors.orange[300]!,
      ExtensionQuality.offline => const Color(0xFF9CA3AF),
    };
    final String qualityLabel = switch (quality) {
      ExtensionQuality.full => 'TOTALMENTE CONFIGURADO',
      ExtensionQuality.partial => 'PARCIALMENTE CONFIGURADO',
      ExtensionQuality.minimal => 'CONFIGURAÇÃO MÍNIMA',
      ExtensionQuality.offline => 'SEM LIGAÇÃO',
    };

    return _buildCard(
      onTap: () => setState(() => _chromeExpanded = !_chromeExpanded),
      header: Row(
        children: [
          _buildServiceIcon(Icons.extension_rounded, qualityColor),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Extensão Chrome',
                  style: TextStyle(
                    color: _kTextDark,
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  'PhishGuard Angola',
                  style: TextStyle(color: _kTextMuted, fontSize: 12),
                ),
              ],
            ),
          ),
          _loadingExtension
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child:
                      CircularProgressIndicator(strokeWidth: 2, color: _kBlue),
                )
              : _buildStatusBadge(
                  qualityLabel,
                  quality != ExtensionQuality.offline,
                  color: qualityColor,
                ),
          const SizedBox(width: 8),
          Icon(
            _chromeExpanded ? Icons.expand_less : Icons.expand_more,
            color: _kTextMuted,
          ),
        ],
      ),
      body: _chromeExpanded ? _buildChromeBody() : null,
    );
  }

  Widget _buildChromeBody() {
    if (_extError != null && _extStatus.quality == ExtensionQuality.offline) {
      return Column(
        children: [
          _buildErrorBanner(
              'Backend inacessível. Verifique se o servidor está activo.'),
          const SizedBox(height: 8),
          _buildActionButton(
            label: 'Tentar novamente',
            icon: Icons.refresh_rounded,
            color: _kBlue,
            loading: _loadingExtension,
            onPressed: _loadExtensionStatus,
          ),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // ── Estatísticas ──────────────────────────────────────────
        if (_extStats.totalChecks > 0) ...[
          _buildSectionLabel('Estatísticas da Extensão'),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                  child: _buildStatCard('${_extStats.totalChecks}',
                      'Verificações', Icons.search_rounded, _kBlue)),
              const SizedBox(width: 8),
              Expanded(
                  child: _buildStatCard('${_extStats.phishingFound}',
                      'Bloqueados', Icons.block_rounded, _kRed)),
              const SizedBox(width: 8),
              Expanded(
                  child: _buildStatCard('${_extStats.safe}', 'Seguros',
                      Icons.check_circle_rounded, _kGreen)),
            ],
          ),
          const SizedBox(height: 16),
        ],

        // ── APIs configuradas ─────────────────────────────────────
        _buildSectionLabel('APIs de Análise'),
        const SizedBox(height: 8),
        _buildApiProgressBar(),
        const SizedBox(height: 4),
        Text(
          '${_extStatus.apisConfigured} de ${_extStatus.apisTotal} APIs configuradas',
          style: TextStyle(color: _kTextMuted, fontSize: 11),
        ),
        const SizedBox(height: 8),
        ..._extStatus.apisStatus.entries
            .map((e) => _buildApiRow(e.key, e.value)),

        const SizedBox(height: 16),

        // ── Instalar extensão ─────────────────────────────────────
        _buildSectionLabel('Instalar a Extensão'),
        const SizedBox(height: 8),
        _buildInstallCard(),

        const SizedBox(height: 16),

        // ── URL do servidor ───────────────────────────────────────
        _buildSectionLabel('URL do Servidor (copiar para a extensão)'),
        const SizedBox(height: 8),
        _buildUrlCopyCard(),

        const SizedBox(height: 16),

        // ── Passos de configuração ────────────────────────────────
        _buildSectionLabel('Como Configurar'),
        const SizedBox(height: 8),
        _buildSetupSteps(),

        const SizedBox(height: 16),

        // ── Teste de URL ──────────────────────────────────────────
        _buildSectionLabel('Testar URL Manualmente'),
        const SizedBox(height: 8),
        _buildUrlTestCard(),
      ],
    );
  }

  Widget _buildApiProgressBar() {
    final pct = _extStatus.apiCoverage;
    final color = pct == 1.0 ? _kGreen : (pct >= 0.4 ? Colors.orange : _kRed);
    return ClipRRect(
      borderRadius: BorderRadius.circular(4),
      child: LinearProgressIndicator(
        value: pct,
        backgroundColor: const Color(0xFFE5E7EB),
        valueColor: AlwaysStoppedAnimation<Color>(color),
        minHeight: 6,
      ),
    );
  }

  Widget _buildApiRow(String name, String status) {
    final isOk = status == 'configured';
    final label = switch (name) {
      'virustotal' => 'VirusTotal',
      'safe_browsing' => 'Google Safe Browsing',
      'urlscan' => 'URLScan.io',
      'groq_ml' => 'Groq IA',
      'abuseipdb' => 'AbuseIPDB',
      _ => name,
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Icon(
            isOk
                ? Icons.check_circle_rounded
                : Icons.radio_button_unchecked_rounded,
            size: 14,
            color: isOk ? _kGreen : const Color(0xFFD1D5DB),
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              color: isOk ? _kTextDark : _kTextMuted,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInstallCard() {
    if (_extStatus.chromeStoreAvailable) {
      return _buildActionButton(
        label: 'Instalar da Chrome Web Store',
        icon: Icons.open_in_browser_rounded,
        color: _kBlue,
        loading: false,
        onPressed: () => _launchUrl(_extStatus.chromeStoreUrl),
      );
    }
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.orange[50],
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Colors.orange.withOpacity(0.4)),
      ),
      child: Row(
        children: [
          Icon(Icons.info_outline_rounded, color: Colors.orange[700], size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'A extensão ainda não está na Chrome Web Store. '
              'Active o "Modo de Programador" em chrome://extensions e '
              'carregue a pasta da extensão manualmente.',
              style: TextStyle(color: Colors.orange[800], fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildUrlCopyCard() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: _kBlue.withOpacity(0.05),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: _kBlue.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              _extStatus.backendUrl,
              style: const TextStyle(
                color: _kBlue,
                fontSize: 13,
                fontFamily: 'monospace',
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.copy_rounded, size: 18),
            color: _kBlue,
            onPressed: () => _copyToClipboard(_extStatus.backendUrl),
            tooltip: 'Copiar URL',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }

  Widget _buildSetupSteps() {
    final steps = _extensionSvc.getSetupInstructions(_extStatus);

    return Column(
      children: steps.asMap().entries.map((entry) {
        final i = entry.key;
        final step = entry.value;
        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 24,
                height: 24,
                decoration: BoxDecoration(
                  color: _kBlue.withOpacity(0.1),
                  shape: BoxShape.circle,
                  border: Border.all(color: _kBlue.withOpacity(0.5)),
                ),
                child: Center(
                  child: Text(
                    '${i + 1}',
                    style: const TextStyle(
                      color: _kBlue,
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      step['title'] ?? '',
                      style: const TextStyle(
                        color: _kTextDark,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      step['description'] ?? '',
                      style: TextStyle(color: _kTextMuted, fontSize: 12),
                    ),
                    if (step['action'] == 'copy_url' &&
                        (step['url'] ?? '').isNotEmpty) ...[
                      const SizedBox(height: 4),
                      GestureDetector(
                        onTap: () => _copyToClipboard(step['url']!),
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: const Color(0xFFF3F4F6),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                step['url']!,
                                style: const TextStyle(
                                  color: _kBlue,
                                  fontSize: 11,
                                  fontFamily: 'monospace',
                                ),
                              ),
                              const SizedBox(width: 4),
                              const Icon(Icons.copy_rounded,
                                  size: 12, color: _kBlue),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ),
        );
      }).toList(),
    );
  }

  Widget _buildUrlTestCard() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _urlController,
                style: const TextStyle(color: _kTextDark, fontSize: 13),
                decoration: InputDecoration(
                  hintText: 'https://exemplo.ao/login',
                  hintStyle: TextStyle(color: _kTextMuted, fontSize: 13),
                  filled: true,
                  fillColor: Colors.white,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: _kBorder),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: _kBorder),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: _kBlue),
                  ),
                  contentPadding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                onSubmitted: (_) => _checkUrl(),
              ),
            ),
            const SizedBox(width: 8),
            SizedBox(
              height: 42,
              child: ElevatedButton(
                onPressed: _loadingUrlCheck ? null : _checkUrl,
                style: ElevatedButton.styleFrom(
                  backgroundColor: _kBlue,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10)),
                  padding: const EdgeInsets.symmetric(horizontal: 14),
                ),
                child: _loadingUrlCheck
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.search_rounded,
                        color: Colors.white, size: 20),
              ),
            ),
          ],
        ),
        if (_urlCheckResult != null) ...[
          const SizedBox(height: 12),
          _buildUrlResult(_urlCheckResult!),
        ],
      ],
    );
  }

  Widget _buildUrlResult(UrlCheckResult r) {
    final Color color =
        r.isDangerous ? _kRed : (r.isSuspicious ? Colors.orange : _kGreen);
    final IconData icon = r.isDangerous
        ? Icons.dangerous_rounded
        : (r.isSuspicious ? Icons.warning_rounded : Icons.check_circle_rounded);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.07),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.35)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 18),
              const SizedBox(width: 8),
              Text(
                r.verdict,
                style: TextStyle(
                    color: color, fontWeight: FontWeight.w700, fontSize: 14),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(
                  'Score: ${r.score}',
                  style: TextStyle(
                      color: color, fontSize: 11, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          if (r.reasons.isNotEmpty) ...[
            const SizedBox(height: 8),
            ...r.reasons.map((reason) => Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('• ',
                          style: TextStyle(
                              color: color.withOpacity(0.7), fontSize: 11)),
                      Expanded(
                        child: Text(reason,
                            style: TextStyle(color: _kTextMuted, fontSize: 11)),
                      ),
                    ],
                  ),
                )),
          ],
          if (r.cached) ...[
            const SizedBox(height: 4),
            Text('(resultado em cache)',
                style: TextStyle(color: _kTextMuted, fontSize: 10)),
          ],
        ],
      ),
    );
  }

  // ── Componentes reutilizáveis ─────────────────────────────────────

  Widget _buildCard({
    required Widget header,
    Widget? body,
    VoidCallback? onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: _kCard,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: _kBorder),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.04),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            header,
            if (body != null) ...[
              const SizedBox(height: 12),
              const Divider(color: _kBorder, height: 1),
              const SizedBox(height: 12),
              body,
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildServiceIcon(IconData icon, Color color) {
    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Icon(icon, color: color, size: 20),
    );
  }

  Widget _buildStatusBadge(String label, bool active, {Color? color}) {
    final c = color ?? (active ? _kGreen : const Color(0xFF9CA3AF));
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: c.withOpacity(0.1),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: c.withOpacity(0.4)),
      ),
      child: Text(
        label,
        style: TextStyle(
            color: c,
            fontSize: 9,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.5),
      ),
    );
  }

  Widget _buildActionButton({
    required String label,
    required IconData icon,
    required Color color,
    required bool loading,
    required VoidCallback onPressed,
  }) {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: loading ? null : onPressed,
        icon: loading
            ? const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                    strokeWidth: 2, color: Colors.white))
            : Icon(icon, size: 16),
        label: Text(label,
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
        style: ElevatedButton.styleFrom(
          backgroundColor: color,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(vertical: 12),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
    );
  }

  Widget _buildErrorBanner(String msg) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: _kRed.withOpacity(0.07),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _kRed.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline_rounded, color: _kRed, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child:
                Text(msg, style: const TextStyle(color: _kRed, fontSize: 12)),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value, {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Text(label, style: TextStyle(color: _kTextMuted, fontSize: 12)),
          const Spacer(),
          Text(
            value,
            style: TextStyle(
                color: valueColor ?? _kTextDark,
                fontSize: 12,
                fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(
      String value, String label, IconData icon, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.07),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(
                color: color, fontSize: 18, fontWeight: FontWeight.w800),
          ),
          Text(
            label,
            style: TextStyle(color: _kTextMuted, fontSize: 10),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildSectionLabel(String label) {
    return Text(
      label.toUpperCase(),
      style: const TextStyle(
          color: _kBlue,
          fontSize: 10,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.2),
    );
  }
}
