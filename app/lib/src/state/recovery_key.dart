// The recovery key: 256 random bits shown once as 52 base32 characters in groups of four
// (`ABCD-EFGH-...`), easy to write down or paste. It is the only way back in if every device is
// lost, so it must be copied somewhere safe.

import 'dart:typed_data';

const _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// 32 bytes as 13 groups of 4 characters.
String encodeRecoveryKey(Uint8List key) {
  if (key.length != 32) throw ArgumentError('a recovery key is 32 bytes');
  final chars = StringBuffer();
  var buffer = 0, bits = 0;
  for (final b in key) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      chars.write(_alphabet[(buffer >> (bits - 5)) & 31]);
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) chars.write(_alphabet[(buffer << (5 - bits)) & 31]);
  final s = chars.toString();
  return [for (var i = 0; i < s.length; i += 4) s.substring(i, i + 4)].join('-');
}

/// Parse what a person typed or pasted (case, spaces and dashes don't matter). Returns null if
/// it is not a well-formed recovery key.
Uint8List? decodeRecoveryKey(String text) {
  final clean = text.toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
  if (clean.length != 52) return null;
  final out = <int>[];
  var buffer = 0, bits = 0;
  for (final c in clean.split('')) {
    final v = _alphabet.indexOf(c);
    if (v < 0) return null;
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.add((buffer >> (bits - 8)) & 255);
      bits -= 8;
    }
    buffer &= (1 << bits) - 1;
  }
  return out.length == 32 ? Uint8List.fromList(out) : null;
}
