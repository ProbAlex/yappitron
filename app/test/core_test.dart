// Exercises the real Rust core through dart:ffi (flutter test runs on the Dart VM).
// Needs the shared library: `cargo build -p yap-ffi`, then YAP_NATIVE_LIB is picked up
// automatically from ../target/debug (or set it yourself).

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:yappitron/src/core/backend.dart';
import 'package:yappitron/src/core/codec.dart';
import 'package:yappitron/src/core/yap_core.dart';

Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

void main() {
  late YapCore core;

  setUpAll(() async {
    if (Platform.environment['YAP_NATIVE_LIB'] == null) {
      final lib = File('../target/debug/libyap_ffi.so');
      if (!lib.existsSync()) fail('build the core first: cargo build -p yap-ffi');
    }
    final backend = await openBackend();
    core = YapCore(backend);
  });

  group('codec', () {
    test('requests and responses round-trip', () {
      final req = encodeRequest(7, [b('ab'), Uint8List(0), b('xyz')]);
      expect(req.sublist(0, 6), [7, 0, 3, 0, 0, 0]);
      final resp = Uint8List.fromList([0, 1, 0, 0, 0, 2, 0, 0, 0, 104, 105]);
      expect(decodeResponse(resp).single, b('hi'));
    });

    test('errors surface as CoreException', () {
      final resp = Uint8List.fromList([1, 1, 0, 0, 0, 2, 0, 0, 0, 111, 107]);
      expect(() => decodeResponse(resp), throwsA(isA<CoreException>()));
      expect(() => decodeResponse(Uint8List(2)), throwsA(isA<CoreException>()));
    });

    test('u64 survives beyond 32 bits', () {
      for (final v in [0, 1, 4294967295, 4294967296, 9007199254740991]) {
        expect(readU64(u64le(v)), v);
      }
    });
  });

  group('core over FFI', () {
    final gid = Uint8List.fromList(List.generate(16, (i) => i + 1));

    ({int alice, int bob}) pair() {
      final alice = core.deviceNew('alice/phone');
      final bob = core.deviceNew('bob/web');
      core.convCreate(alice, gid);
      final added = core.convAddMembers(alice, gid, [core.keyPackage(bob)]);
      expect(core.convJoin(bob, added.welcome), gid);
      return (alice: alice, bob: bob);
    }

    test('two devices exchange encrypted messages', () {
      final p = pair();
      final ct = core.convEncrypt(p.alice, gid, b('hello bob'));
      expect(String.fromCharCodes(core.convDecrypt(p.bob, gid, ct).plaintext), 'hello bob');
      // A sender cannot decrypt its own message, and the error says so.
      final own = core.convEncrypt(p.alice, gid, b('mine'));
      expect(
        () => core.convDecrypt(p.alice, gid, own),
        throwsA(isA<CoreException>().having((e) => e.isOwnMessage, 'isOwnMessage', true)),
      );
    });

    test('decrypt reports who sent the message', () {
      final p = pair();
      final ct = core.convEncrypt(p.alice, gid, b('who is this'));
      expect(core.convDecrypt(p.bob, gid, ct).sender, 'alice/phone');
    });

    test('adding a device: fingerprint match, staged commit, sealed history key', () {
      final p = pair();
      final laptop = core.deviceNew('alice/laptop');
      final link = core.linkKeypair();
      final kp = core.keyPackage(laptop);

      // The approver and the new device compute the same code from their own views.
      final fromApprover = core.fingerprint(core.keyPackageSigner(kp), link.public);
      final fromNewDevice = core.fingerprint(core.deviceSigner(laptop), link.public);
      expect(fromApprover, fromNewDevice);
      expect(RegExp(r'^[0-9A-F]{4}(-[0-9A-F]{4}){4}$').hasMatch(fromApprover), isTrue, reason: fromApprover);
      expect(core.fingerprint(core.keyPackageSigner(kp), core.linkKeypair().public), isNot(fromApprover));

      // Staged: nothing changes until confirmed; a discarded commit leaves no trace.
      final before = core.convEpoch(p.alice, gid);
      core.convAddMembersStaged(p.alice, gid, [kp]);
      expect(core.convEpoch(p.alice, gid), before);
      core.convCommitDiscard(p.alice, gid);
      final staged = core.convAddMembersStaged(p.alice, gid, [kp]);
      core.convCommitConfirm(p.alice, gid);
      core.convApplyCommit(p.bob, gid, staged.commit);
      core.convJoin(laptop, staged.welcome);
      expect(core.convEpoch(laptop, gid), before + 1);

      // The history key travels sealed to the new device's link key, and only to it.
      final history = Uint8List.fromList(List.generate(32, (i) => 255 - i));
      final sealed = core.linkSeal(link.public, history);
      expect(core.linkOpen(link.secret, sealed), history);
      expect(() => core.linkOpen(core.linkKeypair().secret, sealed), throwsA(isA<CoreException>()));

      // The new device reads what Bob writes next, and knows it was Bob.
      final ct = core.convEncrypt(p.bob, gid, b('hello laptop'));
      final out = core.convDecrypt(laptop, gid, ct);
      expect((String.fromCharCodes(out.plaintext), out.sender), ('hello laptop', 'bob/web'));
    });

    test('derived keys are unrelated per purpose', () {
      final secret = Uint8List.fromList(List.filled(32, 3));
      expect(core.deriveKey(secret, 'a'), core.deriveKey(secret, 'a'));
      expect(core.deriveKey(secret, 'a'), isNot(core.deriveKey(secret, 'b')));
    });

    test('live typing frames carry the draft, in order, with unicode', () {
      final p = pair();
      final frame = core.typingSeal(p.alice, gid, 4294967297, 'héllo wörld 👋');
      final opened = core.typingOpen(p.bob, gid, frame);
      expect(opened.seq, 4294967297);
      expect(opened.text, 'héllo wörld 👋');
      // Another conversation's key cannot open it.
      final other = Uint8List.fromList(List.filled(16, 9));
      expect(() => core.typingOpen(p.bob, other, frame), throwsA(isA<CoreException>()));
    });

    test('device state survives export and import', () {
      final p = pair();
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final blob = core.deviceExport(p.alice, key);
      core.deviceFree(p.alice);
      final restored = core.deviceImport(blob, key);
      final ct = core.convEncrypt(restored, gid, b('after restart'));
      expect(String.fromCharCodes(core.convDecrypt(p.bob, gid, ct).plaintext), 'after restart');
      expect(() => core.deviceImport(blob, Uint8List(32)), throwsA(isA<CoreException>()));
    });

    test('vault seals data to a key and context', () {
      final key = Uint8List.fromList(List.filled(32, 7));
      final sealed = core.vaultSeal(key, 'history:a', b('secret note'));
      expect(core.vaultOpen(key, 'history:a', sealed), b('secret note'));
      expect(() => core.vaultOpen(key, 'history:b', sealed), throwsA(isA<CoreException>()));
    });

    test('username rules come from the core', () {
      expect(core.usernameCanonicalize('Alice_1'), 'alice_1');
      expect(() => core.usernameCanonicalize('no spaces'), throwsA(isA<CoreException>()));
      expect(() => core.usernameCanonicalize('admin'), throwsA(isA<CoreException>()));
    });
  });
}
