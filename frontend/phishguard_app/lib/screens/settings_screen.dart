import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../widgets/bottom_nav.dart';
import 'connections_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _sms = true, _email = true, _web = true;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FB),
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        title: const Text(
          'Settings',
          style: TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 20,
            color: Color(0xFF1A1A2E),
            letterSpacing: -0.5,
          ),
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
        children: [
          // ── Protection Settings ──────────────────────────────────
          _sectionHeader('Protection', 'Toggle monitoring for each channel'),
          const SizedBox(height: 10),
          _toggleCard(
            icon: Icons.sms_rounded,
            color: Colors.blue,
            title: 'SMS Protection',
            description: 'Detect phishing in incoming text messages',
            value: _sms,
            onChanged: (v) => setState(() => _sms = v),
          ),
          const SizedBox(height: 8),
          _toggleCard(
            icon: Icons.mail_rounded,
            color: Colors.purple,
            title: 'Email Security',
            description: 'Scan Gmail inbox for malicious links',
            value: _email,
            onChanged: (v) => setState(() => _email = v),
          ),
          const SizedBox(height: 8),
          _toggleCard(
            icon: Icons.language_rounded,
            color: Colors.teal,
            title: 'Web Protection',
            description: 'Block dangerous websites in real-time',
            value: _web,
            onChanged: (v) => setState(() => _web = v),
          ),

          const SizedBox(height: 28),

          // ── Integrations ─────────────────────────────────────────
          _sectionHeader('Integrations', 'Manage connected services'),
          const SizedBox(height: 10),
          _navCard(
            icon: Icons.link_rounded,
            iconBg: AppColors.primary,
            title: 'Manage Connections',
            description: 'Gmail, SMS monitor & browser extension',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ConnectionsScreen()),
            ),
          ),

          const SizedBox(height: 28),

          // ── Preferences ──────────────────────────────────────────
          _sectionHeader('Preferences', 'Customise your experience'),
          const SizedBox(height: 10),
          _navCard(
            icon: Icons.notifications_outlined,
            iconBg: Colors.orange,
            title: 'Notifications',
            description: 'Manage alert preferences',
            onTap: () {},
          ),
          const SizedBox(height: 8),
          _navCard(
            icon: Icons.lock_outline_rounded,
            iconBg: const Color(0xFF6366F1),
            title: 'Privacy Controls',
            description: 'Manage your data and privacy',
            onTap: () {},
          ),

          const SizedBox(height: 28),

          // ── About ────────────────────────────────────────────────
          _sectionHeader('About', null),
          const SizedBox(height: 10),
          _navCard(
            icon: Icons.info_outline_rounded,
            iconBg: const Color(0xFF6B7280),
            title: 'About PhishGuard',
            description: 'Version 1.0.0',
            onTap: () {},
            showArrow: false,
          ),
        ],
      ),
      bottomNavigationBar: const AppBottomNav(currentIndex: 3),
    );
  }

  Widget _sectionHeader(String title, String? subtitle) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              fontWeight: FontWeight.w700,
              fontSize: 16,
              color: Color(0xFF1A1A2E),
            ),
          ),
          if (subtitle != null) ...[
            const SizedBox(height: 2),
            Text(
              subtitle,
              style: const TextStyle(
                color: Color(0xFF9CA3AF),
                fontSize: 12,
              ),
            ),
          ],
        ],
      );

  Widget _toggleCard({
    required IconData icon,
    required Color color,
    required String title,
    required String description,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) =>
      Container(
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.04),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 14, 12, 14),
          child: Row(
            children: [
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color:
                      value ? color.withOpacity(0.12) : const Color(0xFFF3F4F6),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  icon,
                  color: value ? color : const Color(0xFFD1D5DB),
                  size: 22,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontWeight: FontWeight.w600,
                        fontSize: 14,
                        color: value
                            ? const Color(0xFF1A1A2E)
                            : const Color(0xFF9CA3AF),
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      description,
                      style: const TextStyle(
                        color: Color(0xFF9CA3AF),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Switch(
                value: value,
                onChanged: onChanged,
                activeColor: color,
                activeTrackColor: color.withOpacity(0.25),
                inactiveThumbColor: const Color(0xFFD1D5DB),
                inactiveTrackColor: const Color(0xFFF3F4F6),
              ),
            ],
          ),
        ),
      );

  Widget _navCard({
    required IconData icon,
    required Color iconBg,
    required String title,
    required String description,
    required VoidCallback onTap,
    bool showArrow = true,
  }) =>
      GestureDetector(
        onTap: onTap,
        child: Container(
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(16),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.04),
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: iconBg.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(icon, color: iconBg, size: 22),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: const TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 14,
                          color: Color(0xFF1A1A2E),
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        description,
                        style: const TextStyle(
                          color: Color(0xFF9CA3AF),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
                if (showArrow)
                  Container(
                    width: 28,
                    height: 28,
                    decoration: BoxDecoration(
                      color: const Color(0xFFF3F4F6),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Icon(Icons.chevron_right_rounded,
                        color: Color(0xFF6B7280), size: 18),
                  ),
              ],
            ),
          ),
        ),
      );
}
