import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:yappitron/src/state/recovery_key.dart';

void main() {
  test('round-trips random keys', () {
    final r = Random(1);
    for (var i = 0; i < 200; i++) {
      final key = Uint8List.fromList(List.generate(32, (_) => r.nextInt(256)));
      final text = encodeRecoveryKey(key);
      expect(text.length, 52 + 12, reason: '13 groups of 4 with 12 dashes');
      expect(RegExp(r'^([A-Z2-7]{4}-){12}[A-Z2-7]{4}$').hasMatch(text), isTrue, reason: text);
      expect(decodeRecoveryKey(text), key);
    }
  });

  test('is forgiving about case, spaces and dashes', () {
    final key = Uint8List.fromList(List.generate(32, (i) => i * 7 % 256));
    final text = encodeRecoveryKey(key);
    expect(decodeRecoveryKey(text.toLowerCase()), key);
    expect(decodeRecoveryKey(text.replaceAll('-', ' ')), key);
    expect(decodeRecoveryKey(text.replaceAll('-', '')), key);
    expect(decodeRecoveryKey('  $text \n'), key);
  });

  test('rejects malformed input', () {
    final text = encodeRecoveryKey(Uint8List(32));
    expect(decodeRecoveryKey(''), isNull);
    expect(decodeRecoveryKey(text.substring(0, text.length - 5)), isNull, reason: 'too short');
    expect(decodeRecoveryKey('${text}A'), isNull, reason: 'too long');
    expect(decodeRecoveryKey(text.replaceFirst('A', '1')), isNull, reason: 'not in the alphabet');
    expect(() => encodeRecoveryKey(Uint8List(31)), throwsArgumentError);
  });

  test('all-zero and all-one keys survive', () {
    for (final fill in [0, 255]) {
      final key = Uint8List.fromList(List.filled(32, fill));
      expect(decodeRecoveryKey(encodeRecoveryKey(key)), key);
    }
  });
}
