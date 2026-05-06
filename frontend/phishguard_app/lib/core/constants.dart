class ApiConfig {
  static const String baseUrl = 'http://10.26.54.68:8000';

  // Timeout aumentado para 90 s — o pipeline de análise de URL
  // (DNS + WHOIS + Crawler + VirusTotal polling) pode demorar até ~45 s.
  static const Duration timeout = Duration(seconds: 90);

  // Timeout separado para operações rápidas (login, histórico, etc.)
  static const Duration shortTimeout = Duration(seconds: 15);
}
