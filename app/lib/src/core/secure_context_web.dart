import 'package:web/web.dart' as web;

/// Browsers only offer the cryptography and key storage this app needs on HTTPS pages (and
/// localhost). On a plain-HTTP page they are simply missing.
bool get isSecureContext => web.window.isSecureContext;
