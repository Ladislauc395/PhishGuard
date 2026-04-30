class AnalyzeResponse {
  final int score;
  final String verdict;
  final Map<String, dynamic> details;
  final int? analysisId;
  final DateTime timestamp;

  AnalyzeResponse({
    required this.score,
    required this.verdict,
    required this.details,
    required this.timestamp,
    this.analysisId,
  });

  factory AnalyzeResponse.fromJson(Map<String, dynamic> json) {
    return AnalyzeResponse(
      score: (json['score'] ?? 0) as int,
      verdict: (json['verdict'] ?? json['classification'] ?? '').toString(),
      details: (json['details'] as Map<String, dynamic>?) ??
          {'reasons': json['reasons'] ?? []},
      analysisId: json['analysis_id'] as int?,
      timestamp: DateTime.tryParse(json['timestamp']?.toString() ?? '') ??
          DateTime.now(),
    );
  }

  // Getters para facilitar o acesso na UI
  List<String> get reasons {
    final r = details['reasons'];
    if (r is List) return r.map((e) => e.toString()).toList();
    return [];
  }

  bool get isUnsafe =>
      verdict.toUpperCase().contains('NÃO') ||
      verdict.toLowerCase() == 'phishing' ||
      verdict.toLowerCase() == 'suspicious' ||
      score >= 60; // Dica: define um limiar numérico também

  // Integração dos dados de Machine Learning
  Map<String, dynamic>? get ml => details['ml'] as Map<String, dynamic>?;
  int? get mlScore => ml?['ml_score'] as int?;
  String? get mlReasoning => ml?['reasoning'] as String?;

  List<String> get keywordsFound {
    final k = ml?['keywords_found'];
    if (k is List) return k.map((e) => e.toString()).toList();
    return [];
  }
}
