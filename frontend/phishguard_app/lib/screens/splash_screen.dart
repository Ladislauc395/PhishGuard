import 'dart:async';
import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../services/auth_service.dart';
import 'login_screen.dart';
import 'dashboard_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  double _progress = 0;
  Timer? _timer;

  // CORRECÇÃO: AuthService é instância — criamos uma única instância aqui.
  // Anteriormente o AuthService chamava ApiClient estático que não existia.
  final _svc = AuthService();

  @override
  void initState() {
    super.initState();

    // Animação de progresso: 50 iterações × 40ms = 2 s de splash
    _timer = Timer.periodic(const Duration(milliseconds: 40), (t) {
      if (!mounted) {
        t.cancel();
        return;
      }
      setState(() => _progress += 0.02);
      if (_progress >= 1) {
        t.cancel();
        _navigate();
      }
    });
  }

  /// Decide para onde navegar após o splash.
  ///
  /// CORRECÇÃO DO BUG "app abre na dashboard sem login":
  ///
  /// 1. [getToken()] lê do FlutterSecureStorage via ApiClient — devolve null
  ///    se vazio → sem token = login imediato.
  /// 2. Qualquer falha em [fetchMe()] (rede, 401, 403, timeout) → logout + login.
  Future<void> _navigate() async {
    if (!mounted) return;

    // 1. Verificar se existe token guardado localmente
    final token = await _svc.getToken();

    if (token == null) {
      // Sem token → login obrigatório
      _goTo(const LoginScreen());
      return;
    }

    // 2. Token existe → validar junto ao servidor (/auth/me)
    //    Se o servidor devolver 401/403 ou não estiver acessível → logout + login
    try {
      await _svc.fetchMe();
      // fetchMe() passou → token válido → dashboard
      _goTo(const DashboardScreen());
    } catch (_) {
      // Token expirado, inválido ou servidor inacessível → limpar sessão
      await _svc.logout();
      _goTo(const LoginScreen());
    }
  }

  void _goTo(Widget screen) {
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => screen),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [AppColors.primaryDark, AppColors.primary],
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              const Spacer(),
              Container(
                width: 140,
                height: 140,
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(28),
                ),
                child: const Icon(Icons.shield, size: 90, color: Colors.white),
              ),
              const SizedBox(height: 32),
              const Text(
                'PhishGuard',
                style: TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Your Digital Security Shield',
                style: TextStyle(color: Colors.white70, fontSize: 16),
              ),
              const Spacer(),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 40),
                child: Column(
                  children: [
                    Text(
                      'Initializing Protection Engine…',
                      style: TextStyle(color: Colors.white.withOpacity(0.8)),
                    ),
                    const SizedBox(height: 12),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(10),
                      child: LinearProgressIndicator(
                        value: _progress.clamp(0.0, 1.0),
                        minHeight: 6,
                        backgroundColor: Colors.white24,
                        valueColor: const AlwaysStoppedAnimation(Colors.white),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${(_progress * 100).clamp(0, 100).toInt()}%',
                      style: const TextStyle(color: Colors.white70),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 40),
            ],
          ),
        ),
      ),
    );
  }
}
