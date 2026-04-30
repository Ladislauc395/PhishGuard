// lib/services/extension_service.dart
//
// Serviço Flutter para gerir a integração com a extensão Chrome PhishGuard.
//
// Responsabilidades:
//   - Verificar estado do backend da extensão (GET /extension/status)
//   - Consultar estatísticas (GET /extension/stats)
//   - Verificar uma URL manualmente (POST /extension/check-url)
//   - Fornecer instruções de instalação da extensão

import 'dart:convert';
import 'dart:async';
import 'package:http/http.dart' as http;

const String _baseUrl = 'http://10.249.221.68:8000';
const Duration _timeout = Duration(seconds: 10);

// ─── Modelos ──────────────────────────────────────────────────────

class ExtensionStatus {
  final bool backendOnline;
  final String backendUrl;
  final String checkUrlEndpoint;
  final String chromeStoreUrl;
  final bool chromeStoreAvailable;
  final int apisConfigured;
  final int apisTotal;
  final Map<String, String> apisStatus;
  final int totalChecks;
  final int phishingBlocked;
  final int cacheEntries;

  const ExtensionStatus({
    required this.backendOnline,
    required this.backendUrl,
    required this.checkUrlEndpoint,
    required this.chromeStoreUrl,
    required this.chromeStoreAvailable,
    required this.apisConfigured,
    required this.apisTotal,
    required this.apisStatus,
    required this.totalChecks,
    required this.phishingBlocked,
    required this.cacheEntries,
  });

  factory ExtensionStatus.offline() {
    return const ExtensionStatus(
      backendOnline: false,
      backendUrl: _baseUrl,
      checkUrlEndpoint: '$_baseUrl/extension/check-url',
      chromeStoreUrl: '',
      chromeStoreAvailable: false,
      apisConfigured: 0,
      apisTotal: 5,
      apisStatus: {},
      totalChecks: 0,
      phishingBlocked: 0,
      cacheEntries: 0,
    );
  }

  factory ExtensionStatus.fromJson(Map<String, dynamic> j) {
    final rawApis = j['apis_status'] as Map<String, dynamic>? ?? {};
    final apisStatus = rawApis.map((k, v) => MapEntry(k, v.toString()));
    return ExtensionStatus(
      backendOnline: j['backend_online'] == true,
      backendUrl: j['backend_url']?.toString() ?? _baseUrl,
      checkUrlEndpoint: j['check_url_endpoint']?.toString() ?? '',
      chromeStoreUrl: j['chrome_store_url']?.toString() ?? '',
      chromeStoreAvailable: j['chrome_store_available'] == true,
      apisConfigured: (j['apis_configured'] as num?)?.toInt() ?? 0,
      apisTotal: (j['apis_total'] as num?)?.toInt() ?? 5,
      apisStatus: apisStatus,
      totalChecks: (j['total_checks'] as num?)?.toInt() ?? 0,
      phishingBlocked: (j['phishing_blocked'] as num?)?.toInt() ?? 0,
      cacheEntries: (j['cache_entries'] as num?)?.toInt() ?? 0,
    );
  }

  /// Percentagem de APIs configuradas (0.0 – 1.0)
  double get apiCoverage => apisTotal > 0 ? apisConfigured / apisTotal : 0.0;

  /// Qualidade geral da integração
  ExtensionQuality get quality {
    if (!backendOnline) return ExtensionQuality.offline;
    if (apisConfigured == apisTotal) return ExtensionQuality.full;
    if (apisConfigured >= 2) return ExtensionQuality.partial;
    return ExtensionQuality.minimal;
  }
}

enum ExtensionQuality { offline, minimal, partial, full }

class ExtensionStats {
  final int totalChecks;
  final int phishingFound;
  final int suspicious;
  final int safe;
  final int cacheHits;
  final int apiErrors;
  final int cacheSize;
  final String startedAt;

  const ExtensionStats({
    required this.totalChecks,
    required this.phishingFound,
    required this.suspicious,
    required this.safe,
    required this.cacheHits,
    required this.apiErrors,
    required this.cacheSize,
    required this.startedAt,
  });

  factory ExtensionStats.empty() {
    return const ExtensionStats(
      totalChecks: 0,
      phishingFound: 0,
      suspicious: 0,
      safe: 0,
      cacheHits: 0,
      apiErrors: 0,
      cacheSize: 0,
      startedAt: '',
    );
  }

  factory ExtensionStats.fromJson(Map<String, dynamic> j) {
    return ExtensionStats(
      totalChecks: (j['total_checks'] as num?)?.toInt() ?? 0,
      phishingFound: (j['phishing_found'] as num?)?.toInt() ?? 0,
      suspicious: (j['suspicious'] as num?)?.toInt() ?? 0,
      safe: (j['safe'] as num?)?.toInt() ?? 0,
      cacheHits: (j['cache_hits'] as num?)?.toInt() ?? 0,
      apiErrors: (j['api_errors'] as num?)?.toInt() ?? 0,
      cacheSize: (j['cache_size'] as num?)?.toInt() ?? 0,
      startedAt: j['started_at']?.toString() ?? '',
    );
  }
}

class UrlCheckResult {
  final String url;
  final int score;
  final String verdict;
  final List<String> reasons;
  final bool cached;
  final String? error;

  const UrlCheckResult({
    required this.url,
    required this.score,
    required this.verdict,
    required this.reasons,
    required this.cached,
    this.error,
  });

  factory UrlCheckResult.fromJson(Map<String, dynamic> j) {
    return UrlCheckResult(
      url: j['url']?.toString() ?? '',
      score: (j['score'] as num?)?.toInt() ?? 0,
      verdict: j['verdict']?.toString() ?? 'SEGURO',
      reasons: (j['reasons'] as List?)?.map((e) => e.toString()).toList() ?? [],
      cached: j['cached'] == true,
      error: j['error']?.toString(),
    );
  }

  bool get isSafe => score < 30;
  bool get isSuspicious => score >= 30 && score < 60;
  bool get isDangerous => score >= 60;
}

// ─── Serviço ──────────────────────────────────────────────────────

class ExtensionService {
  /// Estado completo da integração extensão ↔ backend.
  Future<ExtensionStatus> getStatus() async {
    try {
      final resp = await http
          .get(Uri.parse('$_baseUrl/extension/status'))
          .timeout(_timeout);
      _check(resp);
      return ExtensionStatus.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (_) {
      return ExtensionStatus.offline();
    }
  }

  /// Estatísticas de verificações feitas pela extensão.
  Future<ExtensionStats> getStats() async {
    try {
      final resp = await http
          .get(Uri.parse('$_baseUrl/extension/stats'))
          .timeout(_timeout);
      _check(resp);
      return ExtensionStats.fromJson(
          jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (_) {
      return ExtensionStats.empty();
    }
  }

  /// Verifica uma URL manualmente — útil para teste directo no app.
  Future<UrlCheckResult> checkUrl(String url) async {
    final resp = await http
        .post(
          Uri.parse('$_baseUrl/extension/check-url'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'url': url}),
        )
        .timeout(const Duration(seconds: 15));
    _check(resp);
    return UrlCheckResult.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  /// Instruções para o utilizador configurar a extensão Chrome.
  ///
  /// CORRIGIDO: devolve List<Map<String, String>> com tipos explícitos
  /// para evitar erros de cast em runtime no connections_screen.
  List<Map<String, String>> getSetupInstructions(ExtensionStatus status) {
    final steps = <Map<String, String>>[];

    if (status.chromeStoreAvailable) {
      steps.add({
        'title': 'Instalar a Extensão',
        'description': 'Abra a Chrome Web Store e instale o PhishGuard Angola.',
        'action': 'install',
        'url': status.chromeStoreUrl,
      });
    } else {
      steps.add({
        'title': 'Instalar a Extensão Manualmente',
        'description': 'A extensão ainda não está na Chrome Web Store. '
            'Active o "Modo de Programador" em chrome://extensions '
            'e carregue a pasta da extensão.',
        'action': 'manual',
        'url': '',
      });
    }

    steps.add({
      'title': 'Configurar o Servidor',
      'description':
          'Nas definições da extensão, cole o seguinte URL do servidor:',
      'action': 'copy_url',
      'url': status.backendUrl,
    });

    steps.add({
      'title': 'Testar a Ligação',
      'description': 'Clique em "Testar ligação" nas definições da extensão. '
          'O ícone deverá ficar verde.',
      'action': 'test',
      'url': '',
    });

    return steps;
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
