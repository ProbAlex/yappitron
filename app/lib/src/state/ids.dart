import 'dart:typed_data';

import '../data/local_store.dart';

/// A random (version 4) UUID, as the lowercase hyphenated string the server uses.
String newUuid() {
  final b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final h = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
}

/// The 16 raw bytes of a UUID string: this is the MLS group id.
Uint8List uuidBytes(String uuid) {
  final hex = uuid.replaceAll('-', '');
  if (hex.length != 32) throw FormatException('not a UUID: $uuid');
  return Uint8List.fromList([for (var i = 0; i < 32; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);
}
