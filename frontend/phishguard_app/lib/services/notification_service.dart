import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:web_socket_channel/io.dart';

class NotificationService {
  static final NotificationService _instance = NotificationService._internal();
  factory NotificationService() => _instance;
  NotificationService._internal();

  WebSocketChannel? _channel;
  Timer? _reconnectTimer;
  bool _isConnecting = false;
  bool _isConnected = false;
  final String _backendUrl = '10.249.221.68'; // Alterar para o IP do seu backend

  final FlutterLocalNotificationsPlugin _localNotifications =
      FlutterLocalNotificationsPlugin();

  // Stream de notificações recebidas (para uso interno)
  final _notificationStreamController =
      StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get notificationStream =>
      _notificationStreamController.stream;

  // Callback quando phishing é detectado
  Function(Map<String, dynamic>)? onPhishingDetected;

  Future<void> init() async {
    // Inicializar notificações locais
    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    const ios = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    const settings = InitializationSettings(android: android, iOS: ios);

    await _localNotifications.initialize(
      settings,
      onDidReceiveNotificationResponse: _onNotificationTap,
    );

    // Pedir permissão para notificações no iOS
    if (await _localNotifications
            .resolvePlatformSpecificImplementation<
                IOSFlutterLocalNotificationsPlugin>()
            ?.requestPermissions() ==
        true) {
      // Permissão concedida
      debugPrint('✅ Permissão de notificações concedida');
    }

    // Conectar WebSocket
    _connect();
  }

  void _connect() {
    if (_isConnecting || _isConnected) return;
    _isConnecting = true;

    try {
      final wsUrl = 'ws://$_backendUrl:8000/notifications/ws';
      debugPrint('🔌 Conectando ao WebSocket: $wsUrl');
      _channel = IOWebSocketChannel.connect(Uri.parse(wsUrl));

      _channel!.stream.listen(
        (message) {
          _isConnected = true;
          _isConnecting = false;
          _handleMessage(message);
        },
        onError: (error) {
          debugPrint('❌ WebSocket error: $error');
          _isConnected = false;
          _isConnecting = false;
          _scheduleReconnect();
        },
        onDone: () {
          debugPrint('🔌 WebSocket disconnected');
          _isConnected = false;
          _isConnecting = false;
          _scheduleReconnect();
        },
      );
    } catch (e) {
      debugPrint('❌ WebSocket connection failed: $e');
      _isConnecting = false;
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 5), () {
      debugPrint('🔄 Attempting to reconnect...');
      _connect();
    });
  }

  void _handleMessage(dynamic message) {
    try {
      final data = jsonDecode(message);
      _notificationStreamController.add(data);
      debugPrint('📨 Mensagem recebida: ${data['type']}');

      if (data['type'] == 'phishing_detected') {
        _showPhishingNotification(data);
        onPhishingDetected?.call(data);
      } else if (data['type'] == 'scan_completed') {
        _showInfoNotification(data);
      }
    } catch (e) {
      debugPrint('❌ Error handling message: $e');
    }
  }

  Future<void> _showPhishingNotification(
      Map<String, dynamic> notification) async {
    final priority = notification['priority'] ?? 'high';
    final isCritical = priority == 'critical';

    // Configuração Android
    const androidDetails = AndroidNotificationDetails(
      'phishing_alerts',
      'Alertas de Phishing',
      channelDescription:
          'Notificações quando emails de phishing são detectados',
      importance: Importance.high,
      priority: Priority.high,
      color: Colors.red,
      playSound: true,
      enableVibration: true,
    );

    // CORREÇÃO: iOS details NÃO pode ser const porque interruptionLevel NÃO é constante
    final iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
      interruptionLevel:
          isCritical ? InterruptionLevel.critical : InterruptionLevel.active,
    );

    final details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );

    // ID único baseado no timestamp
    final id = DateTime.now().millisecondsSinceEpoch % 100000;

    await _localNotifications.show(
      id,
      notification['title'],
      notification['body'],
      details,
      payload: jsonEncode(notification['data']),
    );

    debugPrint('🔔 Notificação de phishing mostrada: ${notification['title']}');
  }

  Future<void> _showInfoNotification(Map<String, dynamic> notification) async {
    const androidDetails = AndroidNotificationDetails(
      'info_alerts',
      'Informação',
      channelDescription: 'Notificações informativas',
      importance: Importance.defaultImportance,
      priority: Priority.defaultPriority,
    );

    // CORREÇÃO: iOS details sem const
    final iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );

    final details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );

    final id = DateTime.now().millisecondsSinceEpoch % 100000;

    await _localNotifications.show(
      id,
      notification['title'],
      notification['body'],
      details,
    );
  }

  void _onNotificationTap(NotificationResponse response) {
    if (response.payload != null) {
      try {
        final data = jsonDecode(response.payload!);
        debugPrint('📱 Notification tapped: $data');
        // Aqui pode navegar para o ecrã de detalhes do email
        // Exemplo: NavigationService().navigateToEmailDetail(data['email_id']);
      } catch (e) {
        debugPrint('❌ Error parsing notification payload: $e');
      }
    }
  }

  void sendPing() {
    if (_channel != null && _isConnected) {
      _channel!.sink.add('ping');
      debugPrint('💓 Ping enviado');
    }
  }

  bool get isConnected => _isConnected;

  void dispose() {
    _reconnectTimer?.cancel();
    _notificationStreamController.close();
    if (_channel != null) {
      _channel!.sink.close();
    }
    debugPrint('🔌 NotificationService disposed');
  }
}
