import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../screens/dashboard_screen.dart';
import '../screens/threats_screen.dart';
import '../screens/insights_screen.dart';
import '../screens/settings_screen.dart';

class AppBottomNav extends StatelessWidget {
  final int currentIndex;
  const AppBottomNav({super.key, required this.currentIndex});

  void _go(BuildContext ctx, int i) {
    if (i == currentIndex) return;
    Widget page;
    switch (i) {
      case 0:
        page = const DashboardScreen();
        break;
      case 1:
        page = const ThreatsScreen();
        break;
      case 2:
        page = const InsightsScreen();
        break;
      default:
        page = const SettingsScreen();
    }
    Navigator.of(ctx).pushReplacement(MaterialPageRoute(builder: (_) => page));
  }

  @override
  Widget build(BuildContext context) {
    return BottomNavigationBar(
      currentIndex: currentIndex,
      onTap: (i) => _go(context, i),
      type: BottomNavigationBarType.fixed,
      selectedItemColor: AppColors.primary,
      unselectedItemColor: AppColors.textMuted,
      backgroundColor: Colors.white,
      items: const [
        BottomNavigationBarItem(
            icon: Icon(Icons.home_outlined), label: 'Dashboard'),
        BottomNavigationBarItem(
            icon: Icon(Icons.shield_outlined), label: 'Threats'),
        BottomNavigationBarItem(
            icon: Icon(Icons.insights_outlined), label: 'Insights'),
        BottomNavigationBarItem(
            icon: Icon(Icons.settings_outlined), label: 'Settings'),
      ],
    );
  }
}
