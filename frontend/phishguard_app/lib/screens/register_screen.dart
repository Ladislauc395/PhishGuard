import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/api_client.dart';
import '../services/auth_service.dart';
import '../models/user_model.dart';
import 'dashboard_screen.dart';

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameCtrl = TextEditingController();
  final _emailCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  final _confirmCtrl = TextEditingController();
  final _svc = AuthService();

  bool _obscurePass = true;
  bool _obscureConfirm = true;
  bool _loading = false;
  String? _serverError;

  @override
  void dispose() {
    _nameCtrl.dispose();
    _emailCtrl.dispose();
    _passCtrl.dispose();
    _confirmCtrl.dispose();
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
      final user = await _svc.register(
        name: _nameCtrl.text,
        email: _emailCtrl.text,
        password: _passCtrl.text,
      );
      _goHome(user);
    } catch (e) {
      String msg;
      if (e is ApiException) {
        msg = e.message.contains('já registado') ||
                e.message.contains('já existe')
            ? 'Este email já está em uso'
            : e.message.contains('Erro no servidor')
                ? 'Erro no servidor. Tente novamente.'
                : e.message;
      } else if (e is NetworkException) {
        msg = 'Sem ligação à internet. Verifique a sua rede.';
      } else {
        final raw = e.toString().replaceFirst('Exception: ', '');
        msg = raw.contains('já registado') ? 'Este email já está em uso' : raw;
      }
      setState(() => _serverError = msg);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _goHome(UserModel user) {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const DashboardScreen()),
    );
  }

  // ── Password strength indicator ────────────────────────────────
  int _strengthLevel(String pass) {
    if (pass.isEmpty) return 0;
    int score = 0;
    if (pass.length >= 8) score++;
    if (pass.contains(RegExp(r'[A-Z]'))) score++;
    if (pass.contains(RegExp(r'[0-9]'))) score++;
    if (pass.contains(RegExp(r'[!@#\$%^&*(),.?":{}|<>]'))) score++;
    return score;
  }

  Color _strengthColor(int level) {
    switch (level) {
      case 1:
        return AppColors.danger;
      case 2:
        return AppColors.warning;
      case 3:
        return const Color(0xFF22C55E);
      case 4:
        return AppColors.success;
      default:
        return AppColors.border;
    }
  }

  String _strengthLabel(int level) {
    switch (level) {
      case 1:
        return 'Fraca';
      case 2:
        return 'Razoável';
      case 3:
        return 'Boa';
      case 4:
        return 'Excelente';
      default:
        return '';
    }
  }

  @override
  Widget build(BuildContext context) {
    final pass = _passCtrl.text;
    final strength = _strengthLevel(pass);

    return Scaffold(
      backgroundColor: Colors.white,
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        leading: const BackButton(color: AppColors.primary),
      ),
      body: SafeArea(
        child: Form(
          key: _formKey,
          child: ListView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            children: [
              const SizedBox(height: 8),

              // ── Título ─────────────────────────────────────
              const Text('Criar Conta',
                  style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              const Text('Proteja a sua vida digital hoje',
                  style: TextStyle(color: AppColors.textMuted)),

              const SizedBox(height: 28),

              // ── Erro servidor ──────────────────────────────
              if (_serverError != null) ...[
                _errorBanner(_serverError!),
                const SizedBox(height: 16),
              ],

              // ── Nome ───────────────────────────────────────
              TextFormField(
                controller: _nameCtrl,
                textInputAction: TextInputAction.next,
                onChanged: (_) => _clearError(),
                validator: AuthService.validateName,
                decoration: _inputDeco(
                    hint: 'Nome completo', icon: Icons.person_outline),
              ),
              const SizedBox(height: 12),

              // ── Email ──────────────────────────────────────
              TextFormField(
                controller: _emailCtrl,
                keyboardType: TextInputType.emailAddress,
                textInputAction: TextInputAction.next,
                onChanged: (_) => _clearError(),
                validator: AuthService.validateEmail,
                decoration: _inputDeco(hint: 'Email', icon: Icons.mail_outline),
              ),
              const SizedBox(height: 12),

              // ── Password ───────────────────────────────────
              TextFormField(
                controller: _passCtrl,
                obscureText: _obscurePass,
                textInputAction: TextInputAction.next,
                onChanged: (_) => setState(() {}), // rebuilds strength bar
                validator: AuthService.validatePassword,
                decoration: _inputDeco(
                  hint: 'Password',
                  icon: Icons.lock_outline,
                  suffix: IconButton(
                    icon: Icon(
                        _obscurePass ? Icons.visibility_off : Icons.visibility,
                        color: AppColors.textMuted),
                    onPressed: () =>
                        setState(() => _obscurePass = !_obscurePass),
                  ),
                ),
              ),

              // ── Barra de força ─────────────────────────────
              if (pass.isNotEmpty) ...[
                const SizedBox(height: 8),
                Row(children: [
                  ...List.generate(4, (i) {
                    final filled = i < strength;
                    return Expanded(
                      child: Container(
                        height: 4,
                        margin: EdgeInsets.only(right: i < 3 ? 4 : 0),
                        decoration: BoxDecoration(
                          color: filled
                              ? _strengthColor(strength)
                              : AppColors.border,
                          borderRadius: BorderRadius.circular(2),
                        ),
                      ),
                    );
                  }),
                  const SizedBox(width: 8),
                  Text(_strengthLabel(strength),
                      style: TextStyle(
                          fontSize: 11,
                          color: _strengthColor(strength),
                          fontWeight: FontWeight.w600)),
                ]),
                const SizedBox(height: 4),
              ],
              const SizedBox(height: 12),

              // ── Confirmar Password ─────────────────────────
              TextFormField(
                controller: _confirmCtrl,
                obscureText: _obscureConfirm,
                textInputAction: TextInputAction.done,
                onFieldSubmitted: (_) => _submit(),
                validator: (v) =>
                    AuthService.validateConfirmPassword(v, _passCtrl.text),
                decoration: _inputDeco(
                  hint: 'Confirmar password',
                  icon: Icons.lock_outline,
                  suffix: IconButton(
                    icon: Icon(
                        _obscureConfirm
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: AppColors.textMuted),
                    onPressed: () =>
                        setState(() => _obscureConfirm = !_obscureConfirm),
                  ),
                ),
              ),

              const SizedBox(height: 24),

              // ── Criar Conta ────────────────────────────────
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
                      : const Text('Criar Conta',
                          style: TextStyle(fontSize: 16)),
                ),
              ),

              const SizedBox(height: 16),

              // ── Voltar ao login ────────────────────────────
              Center(
                child: TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: Text.rich(TextSpan(children: [
                    const TextSpan(
                        text: 'Já tem conta? ',
                        style: TextStyle(color: AppColors.textMuted)),
                    TextSpan(
                        text: 'Entrar',
                        style: const TextStyle(
                            color: AppColors.primary,
                            fontWeight: FontWeight.w600)),
                  ])),
                ),
              ),

              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _errorBanner(String msg) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: AppColors.danger.withOpacity(0.08),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppColors.danger.withOpacity(0.3)),
        ),
        child: Row(children: [
          const Icon(Icons.error_outline, color: AppColors.danger, size: 18),
          const SizedBox(width: 8),
          Expanded(
              child: Text(msg,
                  style:
                      const TextStyle(color: AppColors.danger, fontSize: 13))),
        ]),
      );

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
