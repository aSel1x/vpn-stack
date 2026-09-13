import 'package:flutter/material.dart';

import 'server_list_screen.dart';

/// The Material app. A utility: no splash, no onboarding, no hero.
///
/// Dark and light both follow the system. Not a preference screen -- a setting
/// nobody asked for is a setting somebody has to maintain, and the OS already
/// knows the answer.
class VpnStackApp extends StatelessWidget {
  const VpnStackApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'vpn-stack',
      debugShowCheckedModeBanner: false,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: const ServerListScreen(),
    );
  }
}

ThemeData _theme(Brightness brightness) {
  final ColorScheme scheme = ColorScheme.fromSeed(
    // Slate. Deliberately not a brand colour: this is a tool, and the only
    // things on screen that should draw the eye are a failure and a QR code.
    seedColor: const Color(0xFF37474F),
    brightness: brightness,
  );
  // Only the scheme is themed. Card shapes and input borders have moved between
  // *Theme and *ThemeData classes across Flutter releases, and this repository
  // cannot run the analyzer -- so the widgets set what they need locally and
  // there is nothing here to get wrong.
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: scheme.surface,
    visualDensity: VisualDensity.adaptivePlatformDensity,
  );
}
