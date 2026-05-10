import 'dart:convert';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:http/http.dart' as http;

import 'core/theme.dart';
import 'screens/splash_screen.dart';
import 'services/notification_service.dart';

// --------------------------------------------------
// Variáveis globais para as notificações push
// --------------------------------------------------
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

final FlutterLocalNotificationsPlugin flutterLocalNotificationsPlugin =
    FlutterLocalNotificationsPlugin();

@pragma('vm:entry-point')
Future<void> firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();
  // Podemos processar dados em background se necessário
}

// --------------------------------------------------

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Inicializar Firebase
  await Firebase.initializeApp();

  // Inicializar notificações locais (para quando a app está em primeiro plano)
  const AndroidInitializationSettings androidInit =
      AndroidInitializationSettings('@mipmap/ic_launcher');
  const DarwinInitializationSettings iosInit = DarwinInitializationSettings();
  const InitializationSettings initSettings =
      InitializationSettings(android: androidInit, iOS: iosInit);
  await flutterLocalNotificationsPlugin.initialize(initSettings);

  // Solicitar permissão de notificações
  FirebaseMessaging messaging = FirebaseMessaging.instance;
  await messaging.requestPermission(
    alert: true,
    badge: true,
    sound: true,
  );

  // Ouvir mensagens push quando a app está aberta
  FirebaseMessaging.onMessage.listen(_handleForegroundMessage);

  // Quando o utilizador toca na notificação (app em segundo plano/fechada)
  FirebaseMessaging.onMessageOpenedApp.listen(_handleNotificationTap);

  // Se a app foi aberta por um toque em notificação enquanto estava fechada
  final RemoteMessage? initialMessage = await messaging.getInitialMessage();
  if (initialMessage != null) {
    _handleNotificationTap(initialMessage);
  }

  // Registrar handler de background
  FirebaseMessaging.onBackgroundMessage(firebaseMessagingBackgroundHandler);

  // Inicializar o serviço de notificações original
  final notificationService = NotificationService();
  await notificationService.init();

  // Run app
  runApp(const PhishGuardApp());
}

void _handleForegroundMessage(RemoteMessage message) async {
  RemoteNotification? notification = message.notification;
  AndroidNotification? android = notification?.android;
  if (notification != null && android != null) {
    await flutterLocalNotificationsPlugin.show(
      notification.hashCode,
      notification.title,
      notification.body,
      NotificationDetails(
        android: AndroidNotificationDetails(
          'phishguard_channel',
          'PhishGuard Alertas',
          channelDescription: 'Notificações de phishing bloqueado',
          importance: Importance.max,
          priority: Priority.high,
          icon: '@mipmap/ic_launcher',
        ),
      ),
      payload: jsonEncode(message.data),
    );
  }
}

void _handleNotificationTap(RemoteMessage message) {
  final String? emailId = message.data['email_id'];
  if (emailId != null) {
    // Navegar para o ecrã de detalhes do email (exemplo)
    navigatorKey.currentState?.pushNamed('/email/$emailId');
  }
}

// Função para registar o token FCM no backend.
// Deve ser chamada depois do login (ex: no provider de autenticação).
Future<void> registerFCMToken(String authToken) async {
  try {
    final String? token = await FirebaseMessaging.instance.getToken();
    if (token != null) {
      await http.post(
        Uri.parse('http://10.249.221.68:8000/api/register-fcm-token'),
        headers: {
          'Authorization': 'Bearer $authToken',
          'Content-Type': 'application/json',
        },
        body: jsonEncode({'token': token}),
      );
      print('Token FCM registado com sucesso');
    }
  } catch (e) {
    print('Erro ao registar token FCM: $e');
  }
  // Atualizar token quando mudar
  FirebaseMessaging.instance.onTokenRefresh.listen((newToken) {
    http.post(
      Uri.parse('http://10.249.221.68:8000/api/register-fcm-token'),
      headers: {
        'Authorization': 'Bearer $authToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({'token': newToken}),
    );
  });
}

class PhishGuardApp extends StatelessWidget {
  const PhishGuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: navigatorKey,
      title: 'PhishGuard',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(),
      home: const SplashScreen(),
    );
  }
}
