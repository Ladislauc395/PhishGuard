import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../core/api_client.dart';
import '../models/user_model.dart';

final _googleSignIn = GoogleSignIn(
  scopes: ['email', 'profile'],
);

/// Chave única usada em todo o projecto para o token JWT.
/// Usada aqui, no ApiClient (cabeçalho Authorization) e no SplashScreen.
const kTokenKey = 'auth_token';
const _kUserKey = 'auth_user';

class AuthService {
  // CORRECÇÃO: ApiClient é instância, não classe estática.
  // Partilhamos uma única instância por AuthService.
  final ApiClient _api;

  AuthService({ApiClient? apiClient}) : _api = apiClient ?? ApiClient();

  // ─── Login com email + password ──────────────────────────────────

  Future<UserModel> loginWithEmail({
    required String email,
    required String password,
  }) async {
    // O endpoint usa OAuth2PasswordRequestForm → application/x-www-form-urlencoded
    // CORRECÇÃO: parâmetro posicional 'body' e flag 'isForm' (não 'isFormData')
    final response = await _api.post(
      '/auth/token',
      {'username': email.trim(), 'password': password},
      isForm: true,
      requiresAuth: false,
    );

    final token = response['access_token'] as String;
    final user = UserModel.fromJson(response['user'] as Map<String, dynamic>);

    // ⚠️ CRÍTICO: guardar token ANTES de navegar — o SplashScreen lê daqui
    await _api.saveToken(token);
    await _saveUserLocally(user);
    return user;
  }

  // ─── Registo ─────────────────────────────────────────────────────

  Future<UserModel> register({
    required String name,
    required String email,
    required String password,
  }) async {
    final response = await _api.post(
      '/auth/register',
      {
        'name': name.trim(),
        'email': email.trim(),
        'password': password,
      },
      requiresAuth: false,
    );

    final token = response['access_token'] as String;
    final user = UserModel.fromJson(response['user'] as Map<String, dynamic>);

    await _api.saveToken(token);
    await _saveUserLocally(user);
    return user;
  }

  // ─── Login com Google ────────────────────────────────────────────

  Future<UserModel> loginWithGoogle() async {
    // 1. Lançar o ecrã de selecção de conta Google
    final googleUser = await _googleSignIn.signIn();
    if (googleUser == null) {
      // Utilizador cancelou o fluxo
      throw const ApiException(0, 'Login cancelado');
    }

    // 2. Obter o id_token para enviar ao backend
    final googleAuth = await googleUser.authentication;
    final idToken = googleAuth.idToken;
    if (idToken == null) {
      throw const ApiException(0, 'Não foi possível obter o token do Google');
    }

    // 3. Enviar id_token ao backend → devolve JWT + user
    final response = await _api.post(
      '/auth/google',
      {'id_token': idToken},
      requiresAuth: false,
    );

    final token = response['access_token'] as String;
    final user = UserModel.fromJson(response['user'] as Map<String, dynamic>);

    await _api.saveToken(token);
    await _saveUserLocally(user);
    return user;
  }

  // ─── Validar token junto ao servidor ─────────────────────────────
  //
  // USADO PELO SplashScreen: se lançar excepção → token inválido/expirado.
  // Se o servidor não estiver acessível, lança NetworkException → logout.
  //
  Future<UserModel> fetchMe() async {
    final response = await _api.get('/auth/me');
    return UserModel.fromJson(response);
  }

  // ─── Token / sessão ──────────────────────────────────────────────

  /// Devolve o token guardado, ou null se não existir.
  Future<String?> getToken() async {
    final token = await _api.getToken();
    return (token != null && token.isNotEmpty) ? token : null;
  }

  /// Devolve o utilizador guardado localmente, ou null.
  Future<UserModel?> getSavedUser() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_kUserKey);
    if (raw == null || raw.isEmpty) return null;
    try {
      return UserModel.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  /// Remove token e dados do utilizador — chamar antes de ir para LoginScreen.
  Future<void> logout() async {
    await _api.clearToken();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_kUserKey);
  }

  // ─── Validadores de formulário ────────────────────────────────────

  static String? validateName(String? v) {
    if (v == null || v.trim().isEmpty) return 'Nome obrigatório';
    if (v.trim().length < 2) return 'Nome demasiado curto';
    return null;
  }

  static String? validateEmail(String? v) {
    if (v == null || v.trim().isEmpty) return 'Email obrigatório';
    final re = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');
    if (!re.hasMatch(v.trim())) return 'Email inválido';
    return null;
  }

  static String? validatePassword(String? v) {
    if (v == null || v.isEmpty) return 'Password obrigatória';
    if (v.length < 8) return 'Mínimo 8 caracteres';
    if (!v.contains(RegExp(r'[A-Z]')))
      return 'Precisa de pelo menos uma maiúscula';
    if (!v.contains(RegExp(r'[0-9]'))) return 'Precisa de pelo menos um número';
    return null;
  }

  static String? validateConfirmPassword(String? v, String password) {
    if (v == null || v.isEmpty) return 'Confirme a password';
    if (v != password) return 'As passwords não coincidem';
    return null;
  }

  // ─── Helpers privados ─────────────────────────────────────────────

  Future<void> _saveUserLocally(UserModel user) async {
    final prefs = await SharedPreferences.getInstance();
    try {
      await prefs.setString(_kUserKey, jsonEncode(user.toJson()));
    } catch (e) {
      debugPrint('AuthService: erro ao guardar user: $e');
    }
  }
}
