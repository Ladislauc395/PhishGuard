import 'dart:convert';
import 'dart:io';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

/// Excepções tipadas — permite tratar erros específicos na UI
class ApiException implements Exception {
  final int statusCode;
  final String message;
  const ApiException(this.statusCode, this.message);

  @override
  String toString() => 'ApiException($statusCode): $message';
}

class UnauthorizedException extends ApiException {
  const UnauthorizedException()
      : super(401, 'Sessão expirada. Faça login novamente.');
}

class NetworkException implements Exception {
  final String message;
  const NetworkException(this.message);

  @override
  String toString() => 'NetworkException: $message';
}

// ─────────────────────────────────────────────────────────────────

class ApiClient {
  final String baseUrl;
  final http.Client _http;
  final FlutterSecureStorage _storage;

  static const _tokenKey = 'phishguard_token';
  static const _defaultTimeout = Duration(seconds: 90);
  static const _shortTimeout = Duration(seconds: 15);

  // ⚠️ ALTERAR AQUI quando o IP do backend mudar
  static const String _fallbackBaseUrl = 'http://10.249.221.68:8000';

  /// Construtor principal — resolve o baseUrl de forma robusta.
  ///
  /// CORRECÇÃO: Anteriormente usava `const String.fromEnvironment` com `??`
  /// que resultava em string vazia em runtime, causando TimeoutException.
  /// Agora o método [_resolveBaseUrl] garante que uma URL válida é sempre usada.
  ApiClient({
    String? baseUrl,
    http.Client? httpClient,
    FlutterSecureStorage? storage,
  })  : baseUrl = _resolveBaseUrl(baseUrl),
        _http = httpClient ?? http.Client(),
        _storage = storage ?? const FlutterSecureStorage();

  /// Resolve o baseUrl de forma robusta, ignorando fromEnvironment vazio.
  static String _resolveBaseUrl(String? explicitUrl) {
    // 1. Se foi passado explicitamente no construtor, usar esse
    if (explicitUrl != null && explicitUrl.isNotEmpty) {
      return explicitUrl;
    }

    // 2. Tentar ler da variável de ambiente em compile-time
    //    (definida com --dart-define=API_URL=http://...)
    try {
      const envUrl = String.fromEnvironment('API_URL');
      if (envUrl.isNotEmpty) return envUrl;
    } catch (_) {
      // fromEnvironment pode falhar em alguns contextos de runtime
    }

    // 3. Fallback para o IP hardcoded — NUNCA retorna string vazia
    return _fallbackBaseUrl;
  }

  // ─── Token ──────────────────────────────────────────────────────

  Future<String?> getToken() => _storage.read(key: _tokenKey);

  Future<void> saveToken(String token) =>
      _storage.write(key: _tokenKey, value: token);

  Future<void> clearToken() => _storage.delete(key: _tokenKey);

  // ─── Headers ────────────────────────────────────────────────────

  Future<Map<String, String>> _headers({
    bool requiresAuth = true,
    bool isForm = false,
  }) async {
    final headers = <String, String>{
      'Content-Type':
          isForm ? 'application/x-www-form-urlencoded' : 'application/json',
      'Accept': 'application/json',
    };
    if (requiresAuth) {
      final token = await getToken();
      if (token != null) headers['Authorization'] = 'Bearer $token';
    }
    return headers;
  }

  // ─── Response handler ───────────────────────────────────────────

  Map<String, dynamic> _handleResponse(http.Response resp) {
    if (resp.statusCode == 401) throw const UnauthorizedException();

    Map<String, dynamic>? data;
    try {
      data = jsonDecode(resp.body) as Map<String, dynamic>;
    } catch (_) {
      throw ApiException(
          resp.statusCode, 'Erro no servidor (${resp.statusCode})');
    }

    switch (resp.statusCode) {
      case 200:
      case 201:
        return data;
      default:
        throw ApiException(
          resp.statusCode,
          data['detail']?.toString() ?? 'Erro ${resp.statusCode}',
        );
    }
  }

  // ─── POST ────────────────────────────────────────────────────────

  Future<Map<String, dynamic>> post(
    String path,
    Map<String, dynamic> body, {
    bool requiresAuth = true,
    bool isForm = false,
    Duration? timeout,
  }) async {
    try {
      final resp = await _http
          .post(
            Uri.parse('$baseUrl$path'),
            headers: await _headers(
              requiresAuth: requiresAuth,
              isForm: isForm,
            ),
            body: isForm ? body : jsonEncode(body),
          )
          .timeout(timeout ?? _defaultTimeout);

      return _handleResponse(resp);
    } on SocketException {
      throw const NetworkException('Sem conexão à internet');
    } on HttpException {
      throw const NetworkException('Erro de rede');
    }
  }

  // ─── GET ─────────────────────────────────────────────────────────

  Future<Map<String, dynamic>> get(
    String path, {
    bool requiresAuth = true,
    Duration? timeout,
    Map<String, String>? queryParams,
  }) async {
    try {
      final uri =
          Uri.parse('$baseUrl$path').replace(queryParameters: queryParams);

      final resp = await _http
          .get(uri, headers: await _headers(requiresAuth: requiresAuth))
          .timeout(timeout ?? _shortTimeout);

      return _handleResponse(resp);
    } on SocketException {
      throw const NetworkException('Sem conexão à internet');
    } on HttpException {
      throw const NetworkException('Erro de rede');
    }
  }

  // ─── DELETE ──────────────────────────────────────────────────────

  Future<Map<String, dynamic>> delete(
    String path, {
    bool requiresAuth = true,
  }) async {
    try {
      final resp = await _http
          .delete(
            Uri.parse('$baseUrl$path'),
            headers: await _headers(requiresAuth: requiresAuth),
          )
          .timeout(_shortTimeout);

      return _handleResponse(resp);
    } on SocketException {
      throw const NetworkException('Sem conexão à internet');
    } on HttpException {
      throw const NetworkException('Erro de rede');
    }
  }
}
