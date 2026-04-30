import 'package:flutter/services.dart';

class NativeBridge {
  static const _ch = MethodChannel('phishguard/native');

  static Future<bool> hasOverlayPermission() async =>
      await _ch.invokeMethod<bool>('hasOverlayPermission') ?? false;

  static Future<void> requestOverlayPermission() async =>
      _ch.invokeMethod('requestOverlayPermission');

  static Future<bool> hasSmsPermission() async =>
      await _ch.invokeMethod<bool>('hasSmsPermission') ?? false;

  static Future<void> requestSmsPermission() async =>
      _ch.invokeMethod('requestSmsPermission');

  static Future<void> enableSmsReceiver(bool enable) async =>
      _ch.invokeMethod('enableSmsReceiver', {'enable': enable});
}
