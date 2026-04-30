import 'package:flutter/material.dart';


class AppRouter {
  static const String splash   = '/splash';
  static const String home     = '/home';
  static const String login    = '/login';
  static const String simulate = '/simulate';
  static const String results  = '/results';


  static void goToHome(BuildContext context) {
    Navigator.pushReplacementNamed(context, home);
  }

 
  static void goToLogin(BuildContext context) {
    Navigator.pushReplacementNamed(context, login);
  }

  static void goToSimulate(BuildContext context) {
    Navigator.pushNamed(context, simulate);
  }

 
  static void goToResults(BuildContext context) {
    Navigator.pushNamed(context, results);
  }

 
  static void goBack(BuildContext context) {
    if (Navigator.canPop(context)) Navigator.pop(context);
  }

  
  static Map<String, WidgetBuilder> get routes => {
  
  };
}