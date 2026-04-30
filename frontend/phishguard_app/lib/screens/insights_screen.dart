import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../core/theme.dart';
import '../services/dashboard_service.dart';
import '../models/stats_response.dart';
import '../widgets/bottom_nav.dart';

class InsightsScreen extends StatefulWidget {
  const InsightsScreen({super.key});
  @override
  State<InsightsScreen> createState() => _InsightsScreenState();
}

class _InsightsScreenState extends State<InsightsScreen> {
  final _svc = DashboardService();
  StatsResponse? _s;
  bool _loading = true;
  int _touchedIndex = -1;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final s = await _svc.getStats();
      setState(() {
        _s = s;
        _loading = false;
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FB),
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        title: const Text(
          'Insights',
          style: TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 20,
            color: Color(0xFF1A1A2E),
            letterSpacing: -0.5,
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: Color(0xFF1A1A2E)),
            onPressed: () {
              setState(() => _loading = true);
              _load();
            },
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _load,
              color: AppColors.primary,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
                children: [
                  const Text(
                    'Overview',
                    style: TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 16,
                      color: Color(0xFF1A1A2E),
                    ),
                  ),
                  const SizedBox(height: 12),
                  _countersGrid(),
                  const SizedBox(height: 24),
                  _chartSection(),
                  const SizedBox(height: 24),
                  _legendSection(),
                ],
              ),
            ),
      bottomNavigationBar: const AppBottomNav(currentIndex: 2),
    );
  }

  Widget _countersGrid() {
    final total = _s?.totalAnalyses ?? 0;
    final blocked = _s?.totalUnsafe ?? 0;
    final safe = _s?.totalSafe ?? 0;
    final rate =
        total > 0 ? ((safe / total) * 100).toStringAsFixed(1) : '100.0';

    return Column(
      children: [
        Row(children: [
          _counterCard(
            '$total',
            'Total Analysed',
            Icons.analytics_rounded,
            const Color(0xFF6366F1),
          ),
          const SizedBox(width: 10),
          _counterCard(
            '$blocked',
            'Threats Blocked',
            Icons.block_rounded,
            AppColors.danger,
          ),
        ]),
        const SizedBox(height: 10),
        Row(children: [
          _counterCard(
            '$safe',
            'Safe Items',
            Icons.check_circle_rounded,
            AppColors.success,
          ),
          const SizedBox(width: 10),
          _counterCard(
            '$rate%',
            'Safety Rate',
            Icons.verified_user_rounded,
            AppColors.warning,
          ),
        ]),
      ],
    );
  }

  Widget _counterCard(String value, String label, IconData icon, Color color) =>
      Expanded(
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(16),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.04),
                blurRadius: 10,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: color.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(icon, color: color, size: 20),
              ),
              const SizedBox(height: 12),
              Text(
                value,
                style: TextStyle(
                  color: color,
                  fontSize: 22,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -0.5,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                label,
                style: const TextStyle(
                  color: Color(0xFF9CA3AF),
                  fontSize: 11,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      );

  Widget _chartSection() {
    final data = _s?.byChannel ?? {};
    final total = data.values.fold<int>(0, (a, b) => a + b);

    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.05),
            blurRadius: 15,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Threats by Channel',
            style: TextStyle(
              fontWeight: FontWeight.w700,
              fontSize: 16,
              color: Color(0xFF1A1A2E),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            '$total total threats detected',
            style: const TextStyle(
              color: Color(0xFF9CA3AF),
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 20),
          total == 0 ? _emptyChart() : SizedBox(height: 200, child: _pie(data)),
        ],
      ),
    );
  }

  Widget _emptyChart() => Container(
        height: 160,
        decoration: BoxDecoration(
          color: const Color(0xFFF8F9FB),
          borderRadius: BorderRadius.circular(12),
        ),
        child: const Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.bar_chart_rounded, color: Color(0xFFD1D5DB), size: 40),
              SizedBox(height: 8),
              Text(
                'No threat data yet',
                style: TextStyle(
                  color: Color(0xFF9CA3AF),
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
              SizedBox(height: 4),
              Text(
                'Data will appear as threats are detected',
                style: TextStyle(
                  color: Color(0xFFD1D5DB),
                  fontSize: 11,
                ),
              ),
            ],
          ),
        ),
      );

  final _channelColors = const {
    'sms': AppColors.danger,
    'email': Color(0xFF6366F1),
    'web': AppColors.success,
  };

  Widget _pie(Map<String, int> data) {
    return PieChart(
      PieChartData(
        sectionsSpace: 3,
        centerSpaceRadius: 55,
        pieTouchData: PieTouchData(
          touchCallback: (event, response) {
            setState(() {
              if (!event.isInterestedForInteractions ||
                  response == null ||
                  response.touchedSection == null) {
                _touchedIndex = -1;
              } else {
                _touchedIndex = response.touchedSection!.touchedSectionIndex;
              }
            });
          },
        ),
        sections: data.entries.toList().asMap().entries.map((entry) {
          final i = entry.key;
          final e = entry.value;
          final isTouched = i == _touchedIndex;
          return PieChartSectionData(
            value: e.value.toDouble(),
            color: _channelColors[e.key] ?? Colors.grey,
            title: isTouched ? '${e.value}' : '',
            radius: isTouched ? 68 : 60,
            titleStyle: const TextStyle(
              color: Colors.white,
              fontSize: 14,
              fontWeight: FontWeight.w800,
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _legendSection() {
    final data = _s?.byChannel ?? {};
    if (data.isEmpty) return const SizedBox.shrink();

    final labels = {'sms': 'SMS', 'email': 'Email', 'web': 'Web'};

    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.04),
            blurRadius: 10,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Channel Breakdown',
            style: TextStyle(
              fontWeight: FontWeight.w700,
              fontSize: 14,
              color: Color(0xFF1A1A2E),
            ),
          ),
          const SizedBox(height: 12),
          ...data.entries.map((e) {
            final total = data.values.fold<int>(0, (a, b) => a + b);
            final pct = total > 0 ? (e.value / total * 100).toInt() : 0;
            final color = _channelColors[e.key] ?? Colors.grey;
            return Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: Column(
                children: [
                  Row(
                    children: [
                      Container(
                        width: 10,
                        height: 10,
                        decoration: BoxDecoration(
                          color: color,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        labels[e.key] ?? e.key,
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                          color: Color(0xFF374151),
                        ),
                      ),
                      const Spacer(),
                      Text(
                        '${e.value} ($pct%)',
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: color,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: total > 0 ? e.value / total : 0,
                      backgroundColor: color.withOpacity(0.1),
                      valueColor: AlwaysStoppedAnimation<Color>(color),
                      minHeight: 5,
                    ),
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }
}
