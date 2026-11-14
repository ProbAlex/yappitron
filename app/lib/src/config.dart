import 'package:flutter/foundation.dart';

/// The server to talk to. Override at build time: `--dart-define=YAP_SERVER=https://host`.
/// On the web the app talks to the origin that served it.
String defaultServerUrl() {
  const fromEnv = String.fromEnvironment('YAP_SERVER');
  if (fromEnv.isNotEmpty) return fromEnv;
  if (kIsWeb) return Uri.base.origin;
  return 'https://yap.leafyserver.tech';
}

/// A readable label for this installation, shown in the account's device list.
String deviceLabel() {
  if (kIsWeb) return 'Web browser';
  return switch (defaultTargetPlatform) {
    TargetPlatform.android => 'Android',
    TargetPlatform.iOS => 'iPhone / iPad',
    TargetPlatform.macOS => 'Mac',
    TargetPlatform.windows => 'Windows PC',
    TargetPlatform.linux => 'Linux',
    TargetPlatform.fuchsia => 'Fuchsia',
  };
}
