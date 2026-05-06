// lib/services/integrations_service.dart
//
// CORRECÇÕES v9:
//   - IP atualizado para 172.27.16.68
//   - getAllAnalysedEmailsWithStatus(): melhor tratamento de erros
//   - Timeouts ajustados

import 'dart:convert';
import 'dart:async';
import 'package:http/http.dart' as http;

// ─── URL do backend ───────────────────────────────────────────────
const String _baseUrl = 'http://10.249.221.68:8000';

const Duration _scanTimeout = Duration(seconds: 120);
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
  Future<IntegrationStatus> getStatus() async {
    try {
      final resp = await http
          .get(Uri.parse('$_baseUrl/integrations/status'))
          .timeout(_defaultTimeout);
      _check(resp);
      return IntegrationStatus.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (e) {
      print('❌ getStatus error: $e');
      return IntegrationStatus.disconnected();
    }
  }

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

  Future<ScanResult> scanGmail({int maxResults = 10}) async {
    try {
      final resp = await http
          .post(Uri.parse(
              '$_baseUrl/integrations/gmail/scan?max_results=$maxResults&auto_block=true'))
          .timeout(_scanTimeout);
      _check(resp);
      return ScanResult.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (e) {
      print('❌ scanGmail error: $e');
      rethrow;
    }
  }

  Future<EmailsResponse> forceRefresh({int maxResults = 30}) async {
    try {
      final resp = await http
          .post(Uri.parse(
              '$_baseUrl/integrations/gmail/scan/refresh?max_results=$maxResults'))
          .timeout(_scanTimeout);
      _check(resp);
      return EmailsResponse.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (e) {
      print('❌ forceRefresh error: $e');
      return getAllAnalysedEmailsWithStatus(maxResults: maxResults);
    }
  }

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

  /// Devolve TODOS os emails analisados + flag [scanning].
  Future<EmailsResponse> getAllAnalysedEmailsWithStatus({
    int maxResults = 100,
  }) async {
    try {
      print('🔍 Buscando emails de: $_baseUrl/integrations/gmail/emails/all');
      final resp = await http
          .get(Uri.parse(
              '$_baseUrl/integrations/gmail/emails/all?max_results=$maxResults'))
          .timeout(_defaultTimeout);
      print('📡 Status: ${resp.statusCode}');
      _check(resp);
      final decoded = jsonDecode(resp.body) as Map<String, dynamic>;
      print(
          '📧 Resposta: total=${decoded['total']}, scanning=${decoded['scanning']}');
      return EmailsResponse.fromJson(decoded);
    } catch (e) {
      print('❌ getAllAnalysedEmailsWithStatus error: $e');
      return EmailsResponse(emails: [], total: 0, scanning: false);
    }
  }

  Future<List<Map<String, dynamic>>> getAllAnalysedEmails({
    int maxResults = 100,
  }) async {
    final result = await getAllAnalysedEmailsWithStatus(maxResults: maxResults);
    return result.emails;
  }

  Future<List<Map<String, dynamic>>> getBlockedEmails({
    int maxResults = 50,
  }) async {
    try {
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
      final list =
          (body['blocked'] as List?) ?? (body['emails'] as List?) ?? [];
      return list.map((e) => e as Map<String, dynamic>).toList();
    } catch (e) {
      print('❌ getBlockedEmails error: $e');
      return [];
    }
  }

  Future<void> unblockEmail(String messageId) async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/gmail/unblock/$messageId'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

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

  Future<void> toggleSms(bool enabled) async {
    final resp = await http
        .post(Uri.parse('$_baseUrl/integrations/sms/toggle?enabled=$enabled'))
        .timeout(_defaultTimeout);
    _check(resp);
  }

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
