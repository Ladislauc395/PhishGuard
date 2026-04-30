import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/api_client.dart';
import '../services/auth_service.dart';
import '../models/user_model.dart';
import 'dashboard_screen.dart';
import 'register_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _emailCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _svc = AuthService();

  bool _obscure = true;
  bool _loading = false;
  bool _googleLoading = false;
  String? _serverError;

  @override
  void dispose() {
    _emailCtrl.dispose();
    _passwordCtrl.dispose();
    super.dispose();
  }

  void _clearError() {
    if (_serverError != null) setState(() => _serverError = null);
  }

  Future<void> _submit() async {
    _clearError();
    if (!(_formKey.currentState?.validate() ?? false)) return;

    setState(() => _loading = true);
    try {
      final user = await _svc.loginWithEmail(
        email: _emailCtrl.text,
        password: _passwordCtrl.text,
      );
      _goHome(user);
    } catch (e) {
      setState(() => _serverError = _parseError(e));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _googleSignIn() async {
    _clearError();
    setState(() => _googleLoading = true);
    try {
      final user = await _svc.loginWithGoogle();
      _goHome(user);
    } catch (e) {
      setState(() => _serverError = _parseError(e));
    } finally {
      if (mounted) setState(() => _googleLoading = false);
    }
  }

  String _parseError(Object e) {
    if (e is UnauthorizedException) return 'Email ou password incorrectos';
    if (e is ApiException) {
      final msg = e.message;
      if (msg.contains('Credenciais inválidas'))
        return 'Email ou password incorrectos';
      if (msg.contains('Erro no servidor'))
        return 'Erro no servidor. Tente novamente.';
      return msg;
    }
    if (e is NetworkException)
      return 'Sem ligação à internet. Verifique a sua rede.';
    final s = e.toString().replaceFirst('Exception: ', '');
    if (s.contains('Credenciais inválidas'))
      return 'Email ou password incorrectos';
    if (s.contains('cancelado')) return 'Login cancelado';
    return s;
  }

  void _goHome(UserModel user) {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const DashboardScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: SafeArea(
        child: Form(
          key: _formKey,
          child: ListView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            children: [
              const SizedBox(height: 40),

              // ── Logo ──────────────────────────────────────
              Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                const Icon(Icons.shield, color: AppColors.primary, size: 32),
                const SizedBox(width: 8),
                Text.rich(TextSpan(children: [
                  const TextSpan(
                      text: 'Phishing',
                      style:
                          TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                  TextSpan(
                      text: 'Guard',
                      style: const TextStyle(
                          fontSize: 24,
                          fontWeight: FontWeight.bold,
                          color: AppColors.primary)),
                ])),
              ]),

              const SizedBox(height: 48),
              const Center(
                  child: Text('Bem-vindo de volta',
                      style: TextStyle(color: AppColors.textMuted))),
              const SizedBox(height: 4),
              const Center(
                  child: Text('Proteja a sua vida digital',
                      style: TextStyle(
                          fontSize: 22, fontWeight: FontWeight.w600))),

              const SizedBox(height: 32),

              // ── Erro do servidor ───────────────────────────
              if (_serverError != null) ...[
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color: AppColors.danger.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(10),
                    border:
                        Border.all(color: AppColors.danger.withOpacity(0.3)),
                  ),
                  child: Row(children: [
                    const Icon(Icons.error_outline,
                        color: AppColors.danger, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                        child: Text(_serverError!,
                            style: const TextStyle(
                                color: AppColors.danger, fontSize: 13))),
                  ]),
                ),
                const SizedBox(height: 16),
              ],

              // ── Campo Email ────────────────────────────────
              TextFormField(
                controller: _emailCtrl,
                keyboardType: TextInputType.emailAddress,
                textInputAction: TextInputAction.next,
                onChanged: (_) => _clearError(),
                validator: AuthService.validateEmail,
                decoration: _inputDeco(
                  hint: 'Email',
                  icon: Icons.mail_outline,
                ),
              ),
              const SizedBox(height: 12),

              // ── Campo Password ─────────────────────────────
              TextFormField(
                controller: _passwordCtrl,
                obscureText: _obscure,
                textInputAction: TextInputAction.done,
                onFieldSubmitted: (_) => _submit(),
                onChanged: (_) => _clearError(),
                validator: AuthService.validatePassword,
                decoration: _inputDeco(
                  hint: 'Password',
                  icon: Icons.lock_outline,
                  suffix: IconButton(
                    icon: Icon(
                        _obscure ? Icons.visibility_off : Icons.visibility,
                        color: AppColors.textMuted),
                    onPressed: () => setState(() => _obscure = !_obscure),
                  ),
                ),
              ),

              // ── Esqueci Password ───────────────────────────
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: () {}, // TODO: reset password flow
                  child: const Text('Esqueceu a password?',
                      style: TextStyle(color: AppColors.primary, fontSize: 13)),
                ),
              ),

              const SizedBox(height: 8),

              // ── Botão Sign In ──────────────────────────────
              SizedBox(
                height: 52,
                child: ElevatedButton(
                  onPressed: _loading ? null : _submit,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(30)),
                    disabledBackgroundColor: AppColors.primary.withOpacity(0.5),
                  ),
                  child: _loading
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: Colors.white))
                      : const Text('Entrar', style: TextStyle(fontSize: 16)),
                ),
              ),

              const SizedBox(height: 24),

              // ── Divisor ────────────────────────────────────
              Row(children: [
                const Expanded(child: Divider()),
                const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 12),
                    child: Text('ou continuar com',
                        style: TextStyle(
                            color: AppColors.textMuted, fontSize: 12))),
                const Expanded(child: Divider()),
              ]),

              const SizedBox(height: 20),

              // ── Google Sign-In ─────────────────────────────
              SizedBox(
                height: 52,
                child: OutlinedButton(
                  onPressed: _googleLoading ? null : _googleSignIn,
                  style: OutlinedButton.styleFrom(
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(30)),
                    side: const BorderSide(color: AppColors.border, width: 1.5),
                  ),
                  child: _googleLoading
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                              // SVG inline substituído por imagem network para simplicidade
                              Image.network(
                                'https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg',
                                height: 22,
                                errorBuilder: (_, __, ___) =>
                                    const Icon(Icons.g_mobiledata, size: 26),
                              ),
                              const SizedBox(width: 10),
                              const Text('Entrar com Google',
                                  style: TextStyle(
                                      color: Colors.black87,
                                      fontWeight: FontWeight.w500)),
                            ]),
                ),
              ),

              const SizedBox(height: 20),

              // ── Criar conta ────────────────────────────────
              Center(
                child: TextButton(
                  onPressed: () => Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) => const RegisterScreen())),
                  child: Text.rich(TextSpan(children: [
                    const TextSpan(
                        text: 'Não tem conta? ',
                        style: TextStyle(color: AppColors.textMuted)),
                    TextSpan(
                        text: 'Registe-se',
                        style: const TextStyle(
                            color: AppColors.primary,
                            fontWeight: FontWeight.w600)),
                  ])),
                ),
              ),

              const SizedBox(height: 16),
            ],
          ),
        ),
      ),
    );
  }

  InputDecoration _inputDeco({
    required String hint,
    required IconData icon,
    Widget? suffix,
  }) =>
      InputDecoration(
        prefixIcon: Icon(icon, color: AppColors.textMuted),
        hintText: hint,
        suffixIcon: suffix,
        filled: true,
        fillColor: const Color(0xFFF1F5F9),
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(30),
            borderSide: BorderSide.none),
        errorBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(30),
            borderSide: const BorderSide(color: AppColors.danger, width: 1.5)),
        focusedErrorBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(30),
            borderSide: const BorderSide(color: AppColors.danger, width: 1.5)),
        focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(30),
            borderSide: const BorderSide(color: AppColors.primary, width: 1.5)),
        errorStyle: const TextStyle(fontSize: 12),
      );
}
