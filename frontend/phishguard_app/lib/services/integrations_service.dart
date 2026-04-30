// lib/services/integrations_service.dart
//
// CORRECÇÕES v8:
//   - getAllAnalysedEmailsWithStatus(): timeout 30 s (resposta é sempre imediata).
//   - forceRefresh(): novo método para botão "Actualizar" — chama
//     POST /gmail/scan/refresh e aguarda resultado completo (timeout 120 s).
//   - _defaultTimeout reduzido para 30 s (era 30 s mas por vezes esquecido).
//   - Comentários actualizados para reflectir comportamento real.

import 'dart:convert';
import 'dart:async';
import 'package:http/http.dart' as http;

// ─── URL do backend ───────────────────────────────────────────────
const String _baseUrl = 'http://10.249.221.68:8000';

// Timeout para scans (pode demorar até 120 s para 30 emails com análise completa)
const Duration _scanTimeout = Duration(seconds: 120);

// Timeout para chamadas normais — o backend responde imediatamente
const Duration _defaultTimeout = Duration(seconds: 30);

// ─── Modelos ──────────────────────────────────────────────────────

class IntegrationStatus {
  final bool gmailConnected;
  final bool gmailMonitorRunning;
  final bool smsEnabled;
  final String? gmailEmail;
  final String? lastScanAt;
  final int lastScanThreats;

  const IntegrationStatus({
    required this.gmailConnected,
    required this.gmailMonitorRunning,
    required this.smsEnabled,
    this.gmailEmail,
    this.lastScanAt,
    this.lastScanThreats = 0,
  });

  factory IntegrationStatus.disconnected() {
    return const IntegrationStatus(
      gmailConnected: false,
      gmailMonitorRunning: false,
      smsEnabled: false,
    );
  }

  factory IntegrationStatus.fromJson(Map<String, dynamic> j) {
    return IntegrationStatus(
      gmailConnected: j['gmail_connected'] == true,
      gmailMonitorRunning: j['gmail_monitor_running'] == true,
      smsEnabled: j['sms_enabled'] == true,
      gmailEmail: j['gmail_email']?.toString(),
      lastScanAt: j['last_scan_at']?.toString(),
      lastScanThreats: (j['last_scan_threats'] as num?)?.toInt() ?? 0,
    );
  }
}

class ScanResult {
  final int scanned;
  final int threatsFound;
  final int autoBlocked;
  final List<dynamic> results;

  const ScanResult({
    required this.scanned,
    required this.threatsFound,
    required this.autoBlocked,
    required this.results,
  });

  factory ScanResult.fromJson(Map<String, dynamic> j) {
    return ScanResult(
      scanned: (j['scanned'] as num?)?.toInt() ?? 0,
      threatsFound: (j['threats_found'] as num?)?.toInt() ?? 0,
      autoBlocked: (j['auto_blocked'] as num?)?.toInt() ?? 0,
      results: (j['results'] as List?) ?? [],
    );
  }
}

/// Resposta do endpoint /gmail/emails/all.
/// [scanning] = true → scan em background a decorrer no servidor; fazer polling.
class EmailsResponse {
  final List<Map<String, dynamic>> emails;
  final int total;
  final bool scanning;

  const EmailsResponse({
    required this.emails,
    required this.total,
    required this.scanning,
  });

  factory EmailsResponse.fromJson(Map<String, dynamic> j) {
    return EmailsResponse(
      emails: (j['emails'] as List?)
              ?.map((e) => e as Map<String, dynamic>)
              .toList() ??
          [],
      total: (j['total'] as num?)?.toInt() ?? 0,
      scanning: j['scanning'] == true,
    );
  }
}

// ─── Serviço ──────────────────────────────────────────────────────

class IntegrationsService {
  // ── Status ──────────────────────────────────────────────────────

  Future<IntegrationStatus> getStatus() async {
    try {
      final resp = await http
          .get(Uri.parse('$_baseUrl/integrations/status'))
          .timeout(_defaultTimeout);
      _check(resp);
      return IntegrationStatus.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (_) {
      return IntegrationStatus.disconnected();
    }
  }

  // ── Gmail connect / disconnect ───────────────────────────────────

  Future<String> getGmailAuthUrl() async {
    final resp = await http
        .get(Uri.parse('$_baseUrl/integrations/auth/gmail/url'))
        .timeout(_defaultTimeout);
    _check(resp);
    final body = jsonDecode(resp.body) as Map<String, dynamic>;
    final url = body['auth_url']?.toString();
    if (url == null || url.isEmpty) {
      throw Exception('Backend não devolveu auth_url');
    }
    return url;
  }

  Future<void> connectGmail() async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/gmail/connect'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  Future<void> disconnectGmail() async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/gmail/disconnect'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  // ── Scan Gmail ──────────────────────────────────────────────────

  Future<ScanResult> scanGmail({int maxResults = 10}) async {
    try {
      final resp = await http
          .post(Uri.parse(
              '$_baseUrl/integrations/gmail/scan?max_results=$maxResults&auto_block=true'))
          .timeout(_scanTimeout);
      _check(resp);
      return ScanResult.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
    } on TimeoutException {
      rethrow;
    } catch (e) {
      final msg = e.toString();
      if (msg.contains('Connection refused') ||
          msg.contains('SocketException') ||
          msg.contains('Connection failed')) {
        throw Exception(
          'Sem ligação ao servidor PhishGuard. '
          'Verifique se o backend está activo.',
        );
      }
      rethrow;
    }
  }

  // ── Force Refresh (botão "Actualizar") ──────────────────────────

  /// Força um scan completo no servidor e aguarda resultado.
  ///
  /// NOVO v8: Chama POST /gmail/scan/refresh.
  /// Pode demorar até 120 s para 30 emails — use com indicador de loading.
  /// Devolve a lista actualizada de emails.
  Future<EmailsResponse> forceRefresh({int maxResults = 30}) async {
    try {
      final resp = await http
          .post(Uri.parse(
              '$_baseUrl/integrations/gmail/scan/refresh?max_results=$maxResults'))
          .timeout(_scanTimeout);
      _check(resp);
      return EmailsResponse.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } on TimeoutException {
      // Timeout no scan completo → tentar obter o que existe no cache
      return getAllAnalysedEmailsWithStatus(maxResults: maxResults);
    } catch (e) {
      rethrow;
    }
  }

  // ── Monitor Gmail ────────────────────────────────────────────────

  Future<void> startGmailMonitor({int intervalSeconds = 60}) async {
    final resp = await http
        .post(Uri.parse(
            '$_baseUrl/integrations/gmail/monitor/start?interval_seconds=$intervalSeconds'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  Future<void> stopGmailMonitor() async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/gmail/monitor/stop'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  // ── Emails (todos analisados) ─────────────────────────────────────

  /// Devolve TODOS os emails analisados + flag [scanning].
  ///
  /// CORRIGIDO v8:
  /// - O backend responde SEMPRE imediatamente (devolve cache).
  /// - Se scanning=true → fazer polling a cada 3 s até scanning=false.
  /// - Emails ordenados por data de recepção (mais recente primeiro).
  Future<EmailsResponse> getAllAnalysedEmailsWithStatus({
    int maxResults = 100,
  }) async {
    try {
      final resp = await http
          .get(Uri.parse(
              '$_baseUrl/integrations/gmail/emails/all?max_results=$maxResults'))
          .timeout(_defaultTimeout); // 30 s — resposta é sempre imediata
      _check(resp);
      return EmailsResponse.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (_) {
      // Fallback: tenta os emails bloqueados se o endpoint principal falhar
      final fallback = await getBlockedEmails(maxResults: maxResults);
      return EmailsResponse(
        emails: fallback,
        total: fallback.length,
        scanning: false,
      );
    }
  }

  /// Compatibilidade com código existente — devolve só a lista.
  Future<List<Map<String, dynamic>>> getAllAnalysedEmails({
    int maxResults = 100,
  }) async {
    final result = await getAllAnalysedEmailsWithStatus(maxResults: maxResults);
    return result.emails;
  }

  /// Lista todos os emails bloqueados pelo PhishGuard.
  Future<List<Map<String, dynamic>>> getBlockedEmails({
    int maxResults = 50,
  }) async {
    final resp = await http
        .get(Uri.parse(
            '$_baseUrl/integrations/gmail/emails/blocked?max_results=$maxResults'))
        .timeout(_defaultTimeout);
    _check(resp);

    final decoded = jsonDecode(resp.body);
    if (decoded is List) {
      return decoded.map((e) => e as Map<String, dynamic>).toList();
    }
    final body = decoded as Map<String, dynamic>;
    final list = (body['blocked'] as List?) ?? (body['emails'] as List?) ?? [];
    return list.map((e) => e as Map<String, dynamic>).toList();
  }

  /// Restaura um email bloqueado para a caixa de entrada.
  Future<void> unblockEmail(String messageId) async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/gmail/unblock/$messageId'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  /// Bloqueia manualmente um email de phishing.
  Future<void> blockEmail(
    String messageId, {
    List<String> reasons = const [],
    int score = 100,
  }) async {
    final resp = await http
        .post(
          Uri.parse('$_baseUrl/integrations/gmail/block/$messageId'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'reasons': reasons, 'score': score}),
        )
        .timeout(_defaultTimeout);
    _check(resp);
  }

  // ── SMS ──────────────────────────────────────────────────────────

  Future<void> toggleSms(bool enabled) async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/sms/toggle?enabled=$enabled'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

  // ── Helper interno ───────────────────────────────────────────────

  void _check(http.Response resp) {
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      String detail = resp.body;
      try {
        final body = jsonDecode(resp.body) as Map<String, dynamic>;
        detail = body['detail']?.toString() ?? resp.body;
      } catch (_) {}
      throw Exception('Servidor ${resp.statusCode}: $detail');
    }
  }
}
