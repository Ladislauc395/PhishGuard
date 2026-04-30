class StatsResponse {
  final int totalAnalyses;
  final int totalSafe;
  final int totalUnsafe;
  final double unsafeRatePercent;
  final Map<String, int> byChannel;
  final Map<String, int> byVerdict;

  StatsResponse({
    required this.totalAnalyses,
    required this.totalSafe,
    required this.totalUnsafe,
    required this.unsafeRatePercent,
    required this.byChannel,
    required this.byVerdict,
  });

  factory StatsResponse.fromJson(Map<String, dynamic> j) => StatsResponse(
        totalAnalyses: j['total_analyses'] ?? 0,
        totalSafe: j['total_safe'] ?? 0,
        totalUnsafe: j['total_unsafe'] ?? 0,
        unsafeRatePercent: (j['unsafe_rate_percent'] ?? 0).toDouble(),
        byChannel: Map<String, int>.from(j['by_channel'] ?? {}),
        byVerdict: Map<String, int>.from(j['by_verdict'] ?? {}),
      );
}
