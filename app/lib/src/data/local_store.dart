// On-device storage. Sensitive values are sealed by the Rust core (ChaCha20-Poly1305) under a
// random 32-byte key that lives in the platform keystore (Keychain, Android Keystore,
// libsecret, Windows Credential Manager). On the web there is no hardware keystore: the key is
// kept in the browser's storage, which protects against casual disk access only (see
// docs/THREAT_MODEL.md).

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

abstract interface class LocalStore {
  Future<String?> getString(String key);
  Future<void> putString(String key, String value);
  Future<Uint8List?> getBytes(String key);
  Future<void> putBytes(String key, Uint8List value);
  Future<void> delete(String key);

  /// A random 32-byte key for [name], created on first use and kept in the platform keystore.
  Future<Uint8List> secretKey(String name);

  /// A short secret string (a session token) kept in the platform keystore.
  Future<String?> getSecret(String name);
  Future<void> putSecret(String name, String value);
  Future<void> deleteSecret(String name);
}

Uint8List randomBytes(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));
}

class PlatformStore implements LocalStore {
  PlatformStore._(this._prefs);
  static Future<PlatformStore> open() async => PlatformStore._(await SharedPreferences.getInstance());

  final SharedPreferences _prefs;
  final _secure = const FlutterSecureStorage();

  @override
  Future<String?> getString(String key) async => _prefs.getString(key);

  @override
  Future<void> putString(String key, String value) => _prefs.setString(key, value);

  @override
  Future<Uint8List?> getBytes(String key) async {
    final s = _prefs.getString(key);
    return s == null ? null : base64.decode(s);
  }

  @override
  Future<void> putBytes(String key, Uint8List value) => _prefs.setString(key, base64.encode(value));

  @override
  Future<void> delete(String key) => _prefs.remove(key);

  @override
  Future<Uint8List> secretKey(String name) async {
    final existing = await _secure.read(key: 'key.$name');
    if (existing != null) return base64.decode(existing);
    final key = randomBytes(32);
    await _secure.write(key: 'key.$name', value: base64.encode(key));
    return key;
  }

  @override
  Future<String?> getSecret(String name) => _secure.read(key: 'secret.$name');

  @override
  Future<void> putSecret(String name, String value) => _secure.write(key: 'secret.$name', value: value);

  @override
  Future<void> deleteSecret(String name) => _secure.delete(key: 'secret.$name');
}

/// In-memory store for tests.
class MemoryStore implements LocalStore {
  final _strings = <String, String>{};
  final _bytes = <String, Uint8List>{};
  final _secrets = <String, String>{};
  final _keys = <String, Uint8List>{};

  @override
  Future<String?> getString(String key) async => _strings[key];
  @override
  Future<void> putString(String key, String value) async => _strings[key] = value;
  @override
  Future<Uint8List?> getBytes(String key) async => _bytes[key];
  @override
  Future<void> putBytes(String key, Uint8List value) async => _bytes[key] = value;
  @override
  Future<void> delete(String key) async {
    _strings.remove(key);
    _bytes.remove(key);
  }

  @override
  Future<Uint8List> secretKey(String name) async => _keys.putIfAbsent(name, () => randomBytes(32));
  @override
  Future<String?> getSecret(String name) async => _secrets[name];
  @override
  Future<void> putSecret(String name, String value) async => _secrets[name] = value;
  @override
  Future<void> deleteSecret(String name) async => _secrets.remove(name);
}
