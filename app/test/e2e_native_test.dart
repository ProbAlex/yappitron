// Native end-to-end test: two real YapApp instances (the Rust core over FFI, real HTTP and
// WebSocket) talk through a real gateway. Run by `e2e/run.sh`, which starts the gateway and sets
//   YAP_E2E_SERVER  (e.g. http://127.0.0.1:18090; the server's YAP_DOMAIN must be its host)
//   YAP_E2E_MAIL_FILE  (the gateway's dev mail file, to read verification codes)
//   YAP_NATIVE_LIB  (the built libyap_ffi.so)
// Skipped when those are not set.
//
// To run against a DEPLOYED server instead (real emails through Resend):
//   YAP_E2E_SERVER=http://yap.example.com
//   YAP_E2E_RESEND_KEY=re_...   (codes are read back from Resend; recipients are Resend's
//                                delivered+<label>@resend.dev test inboxes, so nobody is emailed)
// It creates accounts named e2e*; delete them afterwards.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:yappitron/src/api/api_client.dart';
import 'package:yappitron/src/api/realtime.dart';
import 'package:yappitron/src/core/backend.dart';
import 'package:yappitron/src/core/yap_core.dart';
import 'package:yappitron/src/data/local_store.dart';
import 'package:yappitron/src/state/app_state.dart';
import 'package:yappitron/src/state/models.dart';
import 'package:yappitron/src/state/recovery_key.dart';

final server = Platform.environment['YAP_E2E_SERVER'];
final mailFile = Platform.environment['YAP_E2E_MAIL_FILE'];
final resendKey = Platform.environment['YAP_E2E_RESEND_KEY'];

/// The throwaway Postgres container the local runner started (tests that simulate an older
/// account tamper with the database). Null when running against a deployed server.
final pgContainer = Platform.environment['YAP_E2E_PG'];

/// Where the local gateway keeps encrypted attachments (set by `e2e/run.sh`), so tests can look
/// at what is actually stored. Null against a deployed server.
final blobDir = Platform.environment['YAP_E2E_BLOB_DIR'];

Future<String> sql(String statement) async {
  final r = await Process.run('docker', ['exec', pgContainer!, 'psql', '-U', 'postgres', '-d', 'yape2e', '-Atc', statement]);
  if (r.exitCode != 0) fail('sql failed: ${r.stderr}');
  return (r.stdout as String).trim();
}
const password = 'correct horse battery staple';

/// Poll until [check] is true.
Future<void> eventually(bool Function() check, {String? what, int seconds = 15}) async {
  final deadline = DateTime.now().add(Duration(seconds: seconds));
  while (!check()) {
    if (DateTime.now().isAfter(deadline)) fail('timed out waiting for ${what ?? 'condition'}');
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
}

/// Codes already handed out per address, so a second request returns the NEW code.
final _usedCodes = <String, Set<String>>{};

String _emailFor(String name) => resendKey != null ? 'delivered+$name@resend.dev' : '$name@example.test';

/// Like [eventually], for a check that has to await something (a database query).
Future<void> eventuallyAsync(Future<bool> Function() check, {String? what, int seconds = 15}) async {
  final deadline = DateTime.now().add(Duration(seconds: seconds));
  while (!await check()) {
    if (DateTime.now().isAfter(deadline)) fail('timed out waiting for ${what ?? 'condition'}');
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}

Future<String> codeFor(String email) async {
  final used = _usedCodes.putIfAbsent(email, () => {});
  for (var i = 0; i < 60; i++) {
    final code = resendKey != null ? await _codeFromResend(email, used) : _codeFromFile(email, used);
    if (code != null) {
      used.add(code);
      return code;
    }
    await Future<void>.delayed(Duration(milliseconds: resendKey != null ? 1500 : 100)); // Resend allows 2 requests/s
  }
  fail('no email for $email');
}

String? _codeFromFile(String email, Set<String> used) {
  final f = File(mailFile!);
  if (!f.existsSync()) return null;
  for (final line in f.readAsLinesSync()) {
    final m = jsonDecode(line) as Map<String, dynamic>;
    if (m['to'] != email) continue;
    final code = RegExp(r'(\d{6})').firstMatch(m['subject'] as String)?.group(1);
    if (code != null && !used.contains(code)) return code;
  }
  return null;
}

Future<String?> _codeFromResend(String email, Set<String> used) async {
  final client = HttpClient();
  try {
    final req = await client.getUrl(Uri.parse('https://api.resend.com/emails?limit=40'));
    req.headers.set('authorization', 'Bearer $resendKey');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) {
      // ignore: avoid_print
      print('Resend API answered ${res.statusCode}: ${body.substring(0, body.length.clamp(0, 120))}');
      return null;
    }
    for (final m in (jsonDecode(body)['data'] as List).cast<Map<String, dynamic>>()) {
      if (!(m['to'] as List).contains(email)) continue;
      final code = RegExp(r'code: (\d{6})').firstMatch(m['subject'] as String)?.group(1);
      if (code != null && !used.contains(code)) return code;
    }
    return null;
  } finally {
    client.close(force: true);
  }
}

/// Run a test body; if it fails with a network error, print the underlying cause too.
Future<void> diagnosing(Future<void> Function() body) async {
  try {
    await body();
  } on ApiException catch (e) {
    // ignore: avoid_print
    print('DIAGNOSTIC: ${e.message} (status ${e.status}), cause: ${e.cause}');
    rethrow;
  }
}

String uniqueName(String prefix) => '$prefix${Random().nextInt(1 << 30).toRadixString(36)}';

void main() {
  final skip = (server == null || (mailFile == null && resendKey == null))
      ? 'set YAP_E2E_SERVER and YAP_E2E_MAIL_FILE or YAP_E2E_RESEND_KEY (see e2e/run.sh)'
      : null;
  late YapCore core;

  setUpAll(() async {
    if (skip != null) return;
    core = YapCore(await openBackend());
  });

  Future<(YapApp, MemoryStore, String)> signUp(String label) async {
    final name = uniqueName('e2e$label');
    final email = _emailFor(name);
    final store = MemoryStore();
    final app = YapApp(core: core, store: store, serverUrl: server!, deviceLabel: 'Test device')
      // ignore: avoid_print
      ..onBackgroundError = (e, st) => print('[$name] background error: $e\n$st');
    await app.requestCode('signup', email);
    final ticket = await app.verifyCode('signup', email, await codeFor(email));
    await app.finishSignup(ticket: ticket, username: name, password: password);
    expect(app.phase, Phase.signedIn);
    expect(app.username, name);
    // The live connection must come up, or nothing below can be delivered in real time.
    final started = DateTime.now();
    await eventually(() => app.link == RealtimeStatus.online, what: '$name realtime connection to come online', seconds: 20);
    // ignore: avoid_print
    print('[$name] realtime online after ${DateTime.now().difference(started).inMilliseconds} ms');
    return (app, store, name);
  }

  test('two apps chat with live typing, and state survives a restart', () => diagnosing(() async {
    final (alice, aliceStore, aliceName) = await signUp('alice');
    final (bob, _, bobName) = await signUp('bob');

    // Alice starts a chat; Bob gets a message request through the WebSocket.
    final convId = await alice.startConversation(bobName);
    await eventually(() => bob.conversation(convId) != null, what: 'Bob to receive the request');
    expect(bob.conversation(convId)!.state, ConversationState.invited);
    expect(bob.conversation(convId)!.peer, aliceName);

    // A first message is readable while it is still a request.
    await alice.send(alice.conversation(convId)!, 'hello bob');
    await eventually(() => bob.conversation(convId)!.messages.length == 1, what: 'first message');
    expect(bob.conversation(convId)!.messages.single.text, 'hello bob');
    expect(bob.conversation(convId)!.messages.single.mine, isFalse);

    // Live typing is not relayed until Bob accepts.
    alice.onDraftChanged(alice.conversation(convId)!, 'are you');
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(bob.conversation(convId)!.liveDraft, isNull);

    await bob.accept(bob.conversation(convId)!);
    await eventually(() => alice.conversation(convId)!.state == ConversationState.joined);

    // After acceptance, Bob sees Alice's draft as she types, then it disappears when she sends.
    final aliceChat = alice.conversation(convId)!;
    alice.onDraftChanged(aliceChat, 'are you the');
    await eventually(() => bob.conversation(convId)!.liveDraft == 'are you the', what: 'live draft');
    alice.onDraftChanged(aliceChat, 'are you there?');
    await eventually(() => bob.conversation(convId)!.liveDraft == 'are you there?', what: 'updated draft');

    await alice.send(aliceChat, 'are you there?');
    await eventually(() => bob.conversation(convId)!.messages.length == 2, what: 'second message');
    expect(bob.conversation(convId)!.liveDraft, isNull);
    expect(bob.conversation(convId)!.messages.last.text, 'are you there?');

    // Bob replies.
    await bob.send(bob.conversation(convId)!, 'loud and clear');
    await eventually(() => aliceChat.messages.length == 3, what: "Bob's reply");
    expect(aliceChat.messages.last.text, 'loud and clear');
    expect(aliceChat.messages.last.mine, isFalse);

    // Turning live typing off stops the frames.
    await alice.setLiveTyping(aliceChat, false);
    alice.onDraftChanged(aliceChat, 'secret draft');
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(bob.conversation(convId)!.liveDraft, isNull);

    // "Restart" Alice: a new app instance over the same on-device storage resumes the session,
    // keeps the history, and can still decrypt new messages (the MLS state was persisted).
    alice.dispose();
    final alice2 = YapApp(core: core, store: aliceStore, serverUrl: server!, deviceLabel: 'Test device');
    await alice2.boot();
    expect(alice2.phase, Phase.signedIn);
    expect(alice2.username, aliceName);
    final restored = alice2.conversation(convId)!;
    expect(restored.messages.map((m) => m.text), ['hello bob', 'are you there?', 'loud and clear']);

    await bob.send(bob.conversation(convId)!, 'welcome back');
    await eventually(() => restored.messages.length == 4, what: 'message after restart');
    expect(restored.messages.last.text, 'welcome back');

    alice2.dispose();
    bob.dispose();
  }), skip: skip, timeout: const Timeout(Duration(seconds: 90)));

  test('emoji and non-Latin text survive encryption, live typing and storage unchanged', () => diagnosing(() async {
        final (alice, aliceStore, aliceName) = await signUp('alice');
        final (bob, _, bobName) = await signUp('bob');
        // Joined emoji sequences (a family), flags, skin tones, CJK, right-to-left scripts, a
        // combining accent and Thai: all the shapes that break naive text handling.
        const text = 'emoji 😀🎉 👨‍👩‍👧 🇯🇵 👍🏽 • 你好世界 • こんにちは • 안녕 • مرحبا • שלום • café • สวัสดี';

        final convId = await alice.startConversation(bobName);
        await eventually(() => bob.conversation(convId) != null);
        await bob.accept(bob.conversation(convId)!);
        await eventually(() => alice.conversation(convId)!.state == ConversationState.joined);

        // Live typing carries it (UTF-8 in padded, encrypted frames).
        alice.onDraftChanged(alice.conversation(convId)!, text);
        await eventually(() => bob.conversation(convId)!.liveDraft == text, what: 'the draft with international text');

        // And so do real messages, in both directions.
        await alice.send(alice.conversation(convId)!, text);
        await eventually(() => bob.conversation(convId)!.messages.isNotEmpty);
        expect(bob.conversation(convId)!.messages.single.text, text);
        await bob.send(bob.conversation(convId)!, text.split('').reversed.join()); // arbitrary other text
        await eventually(() => alice.conversation(convId)!.messages.length == 2);

        // The saved (encrypted) history comes back identical after a restart.
        alice.dispose();
        final restored = YapApp(core: core, store: aliceStore, serverUrl: server!, deviceLabel: 'Test device');
        await restored.boot();
        expect(restored.username, aliceName);
        expect(restored.conversation(convId)!.messages.first.text, text);
        restored.dispose();
        bob.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 90)));

  test('an account from before the history key existed is upgraded on its first start, and its history is backed up',
      () => diagnosing(() async {
        final (alice, store, aliceName) = await signUp('alice');
        final (bob, _, bobName) = await signUp('bob');
        final convId = await alice.startConversation(bobName);
        await eventually(() => bob.conversation(convId) != null);
        await bob.accept(bob.conversation(convId)!);
        await alice.send(alice.conversation(convId)!, 'written before the upgrade');
        await eventually(() => bob.conversation(convId)!.messages.length == 1);
        await bob.send(bob.conversation(convId)!, 'answer before the upgrade');
        await eventually(() => alice.conversation(convId)!.messages.length == 2);
        alice.recoveryKeyShown();
        alice.dispose();

        // Turn the clock back: no recovery key or archive on the server, no history key on the
        // device, nothing backed up. This is exactly how an existing account looks.
        await sql('DELETE FROM account_keys');
        await sql('DELETE FROM archive');
        await store.deleteSecret('hist.$aliceName');
        await store.delete('archived.$aliceName');

        // The app starts: it must NOT lock the person out asking for a recovery key that never
        // existed. It creates the keys, shows the recovery key, and backs up the old messages.
        final restarted = YapApp(core: core, store: store, serverUrl: server!, deviceLabel: 'Test device')
          // ignore: avoid_print
          ..onBackgroundError = (e, st) => print('[restarted] background error: $e\n$st');
        await restarted.boot();
        expect(restarted.phase, Phase.signedIn, reason: 'an existing account stays usable');
        expect(restarted.needsHistoryKey, isFalse);
        expect(restarted.recoveryKeyToShow, isNotNull, reason: 'it is offered a recovery key now');
        expect(restarted.conversation(convId)!.messages.map((m) => m.text), ['written before the upgrade', 'answer before the upgrade']);
        await eventuallyAsync(() async => await sql('SELECT count(*) FROM archive') == '2', what: 'local history to be archived');

        // A device added afterwards therefore sees the history from before the upgrade.
        final laptop = YapApp(core: core, store: MemoryStore(), serverUrl: server!, deviceLabel: 'Laptop');
        await laptop.login(aliceName, password);
        await eventually(() => restarted.pendingLinks.isNotEmpty, what: 'the approval request');
        await restarted.approve(await restarted.prepareApproval(restarted.pendingLinks.first));
        await eventually(() => laptop.conversation(convId)?.messages.length == 2, what: 'history on the new device');
        expect(laptop.conversation(convId)!.messages.map((m) => m.text), ['written before the upgrade', 'answer before the upgrade']);

        laptop.dispose();
        restarted.dispose();
        bob.dispose();
      }), skip: skip ?? (pgContainer == null ? 'needs the local runner (YAP_E2E_PG)' : null), timeout: const Timeout(Duration(seconds: 90)));

  test('a device that lost its history key restores it from the recovery key without signing anything out',
      () => diagnosing(() async {
        final (alice, store, aliceName) = await signUp('alice');
        final recoveryText = alice.recoveryKeyToShow!;
        alice.recoveryKeyShown();
        alice.dispose();

        // The device's secure storage was wiped: signed in and approved, but no history key.
        await store.deleteSecret('hist.$aliceName');
        final app = YapApp(core: core, store: store, serverUrl: server!, deviceLabel: 'Test device');
        await app.boot();
        expect(app.phase, Phase.awaitingApproval);
        expect(app.needsHistoryKey, isTrue);

        await expectLater(app.restoreHistoryKey('nonsense'), throwsA(isA<ApiException>()));
        await expectLater(app.restoreHistoryKey(encodeRecoveryKey(Uint8List(32))), throwsA(isA<ApiException>()),
            reason: 'a well-formed but wrong key is refused');
        expect(app.phase, Phase.awaitingApproval);
        await app.restoreHistoryKey(recoveryText);
        expect(app.phase, Phase.signedIn);
        expect((await app.listDevices()).where((d) => d.status == 'approved').length, 1,
            reason: 'restoring the key signs no device out');
        app.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 60)));

  test('a second device is approved, gets the history, works alongside the first; the recovery key rescues a lost account',
      () => diagnosing(() async {
        final (alice1, _, aliceName) = await signUp('alice');
        final (bob, _, bobName) = await signUp('bob');

        // The account's first device produces the recovery key, exactly once.
        final recoveryText = alice1.recoveryKeyToShow!;
        expect(decodeRecoveryKey(recoveryText), isNotNull);
        alice1.recoveryKeyShown();
        expect(alice1.recoveryKeyToShow, isNull);

        // History from before any second device exists.
        final convId = await alice1.startConversation(bobName);
        await eventually(() => bob.conversation(convId) != null, what: 'Bob to receive the request');
        await bob.accept(bob.conversation(convId)!);
        await alice1.send(alice1.conversation(convId)!, 'history one');
        await eventually(() => bob.conversation(convId)!.messages.length == 1);
        await bob.send(bob.conversation(convId)!, 'history two');
        await eventually(() => alice1.conversation(convId)!.messages.length == 2);

        // A new device signs in: it is not the first, so it waits, powerless.
        final store2 = MemoryStore();
        var alice2 = YapApp(core: core, store: store2, serverUrl: server!, deviceLabel: 'Laptop')
          // ignore: avoid_print
          ..onBackgroundError = (e, st) => print('[alice2] background error: $e\n$st');
        await alice2.login(aliceName, password);
        expect(alice2.phase, Phase.awaitingApproval);
        expect(alice2.recoveryKeyToShow, isNull, reason: 'only the first device creates one');
        expect(alice2.conversations, isEmpty, reason: 'it cannot read anything yet');
        final code = alice2.linkFingerprint!;
        expect(RegExp(r'^[0-9A-F]{4}(-[0-9A-F]{4}){4}$').hasMatch(code), isTrue, reason: code);

        // The app is closed and reopened while waiting: same code, still waiting.
        alice2.dispose();
        alice2 = YapApp(core: core, store: store2, serverUrl: server!, deviceLabel: 'Laptop')
          // ignore: avoid_print
          ..onBackgroundError = (e, st) => print('[alice2] background error: $e\n$st');
        await alice2.boot();
        expect(alice2.phase, Phase.awaitingApproval);
        expect(alice2.linkFingerprint, code, reason: 'the link key survives a restart');

        // The first device is told, the person compares the codes, and approves.
        await eventually(() => alice1.pendingLinks.isNotEmpty, what: 'the approval request to reach device 1');
        final preview = await alice1.prepareApproval(alice1.pendingLinks.first);
        expect(preview.fingerprint, code, reason: 'both screens must show the same code');
        await alice1.approve(preview);
        expect(alice1.pendingLinks, isEmpty);
        await eventually(() => alice2.phase == Phase.signedIn, what: 'the new device to be approved');

        // It has the conversation and the history written before it existed.
        await eventually(() => alice2.conversation(convId)?.messages.length == 2, what: 'history on the new device');
        final c2 = alice2.conversation(convId)!;
        expect(c2.stale, isFalse);
        expect([for (final m in c2.messages) (m.text, m.mine)], [('history one', true), ('history two', false)]);

        // It can talk. Both of Alice's devices see her messages as hers; Bob sees them as hers too.
        await alice2.send(c2, 'from the laptop');
        await eventually(() => bob.conversation(convId)!.messages.length == 3, what: 'Bob to get the laptop message');
        expect(bob.conversation(convId)!.messages.last.text, 'from the laptop');
        expect(bob.conversation(convId)!.messages.last.mine, isFalse);
        await eventually(() => alice1.conversation(convId)!.messages.length == 3, what: 'device 1 to see it');
        expect(alice1.conversation(convId)!.messages.last.text, 'from the laptop');
        expect(alice1.conversation(convId)!.messages.last.mine, isTrue, reason: 'written by Alice on another device');

        // Replies reach both devices.
        await bob.send(bob.conversation(convId)!, 'reply to both');
        await eventually(() => alice1.conversation(convId)!.messages.length == 4 && c2.messages.length == 4, what: 'both devices');
        expect(c2.messages.last.text, 'reply to both');

        // Live typing from the new device reaches Bob: it is a real member of the group.
        alice2.onDraftChanged(c2, 'typing on the laptop');
        await eventually(() => bob.conversation(convId)!.liveDraft == 'typing on the laptop', what: 'live typing from device 2');
        alice2.clearDraft(c2);

        // Removing the second device signs it out and wipes it.
        final other = (await alice1.listDevices()).firstWhere((d) => !d.current);
        await alice1.removeDevice(other.id);
        await eventually(() => alice2.phase == Phase.signedOut, what: 'the removed device to be signed out');
        expect(alice2.notice, contains('removed'));
        expect(alice2.conversations, isEmpty);
        alice2.dispose();

        // Everything lost: a fresh device with only the password and the recovery key.
        final alice3 = YapApp(core: core, store: MemoryStore(), serverUrl: server!, deviceLabel: 'Replacement')
          // ignore: avoid_print
          ..onBackgroundError = (e, st) => print('[alice3] background error: $e\n$st');
        await alice3.login(aliceName, password);
        expect(alice3.phase, Phase.awaitingApproval);
        await expectLater(alice3.recoverWithKey('not a key'), throwsA(isA<ApiException>()));
        await expectLater(alice3.recoverWithKey(encodeRecoveryKey(Uint8List(32))), throwsA(isA<ApiException>()),
            reason: 'a well-formed but wrong key is refused');
        expect(alice3.phase, Phase.awaitingApproval);
        await alice3.recoverWithKey(recoveryText);
        expect(alice3.phase, Phase.signedIn);
        expect(alice3.recoveryKeyToShow, isNotNull, reason: 'a fresh recovery key replaces the used one');
        expect(alice3.recoveryKeyToShow, isNot(recoveryText));
        await eventually(() => alice1.phase == Phase.signedOut, what: 'device 1 to be signed out by the recovery');

        // The old chat is readable but read-only; a new chat works.
        await eventually(() => alice3.conversation(convId)?.messages.length == 4, what: 'history from the archive');
        final old = alice3.conversation(convId)!;
        expect(old.stale, isTrue);
        expect([for (final m in old.messages) m.text], ['history one', 'history two', 'from the laptop', 'reply to both']);
        await expectLater(alice3.send(old, 'nope'), throwsA(isA<ApiException>()));
        final fresh = await alice3.startConversation(bobName);
        expect(fresh, isNot(convId));
        await eventually(() => bob.conversation(fresh) != null, what: 'Bob to get the new request');
        await alice3.send(alice3.conversation(fresh)!, 'back again');
        await eventually(() => bob.conversation(fresh)!.messages.length == 1);
        expect(bob.conversation(fresh)!.messages.single.text, 'back again');

        alice3.dispose();
        bob.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 150)));

  /// Two accounts with an accepted conversation between them.
  Future<(YapApp, YapApp, String, String)> chatting() async {
    final (alice, _, _) = await signUp('alice');
    final (bob, _, bobName) = await signUp('bob');
    final convId = await alice.startConversation(bobName);
    await eventually(() => bob.conversation(convId) != null, what: 'Bob to receive the request');
    await bob.accept(bob.conversation(convId)!);
    await eventually(() => alice.conversation(convId)!.state == ConversationState.joined);
    return (alice, bob, convId, bobName);
  }

  Uint8List pattern(int n, int seed) => Uint8List.fromList(List.generate(n, (i) => (i * 7 + seed) % 251));

  test('photos and files are encrypted on the device, stored opaque, and opened only with the key from the message',
      () => diagnosing(() async {
        final (alice, bob, convId, _) = await chatting();
        final a = alice.conversation(convId)!;

        // A "photo" that is not decodable on purpose (this test is about bytes, not pixels), a
        // multi-chunk document with an easy-to-spot marker, and a tiny file.
        final photo = OutgoingFile(name: 'holiday.png', mime: 'image/png', bytes: pattern(70000, 1), width: 640, height: 480);
        final marker = utf8.encode('TOP-SECRET-MARKER-${Random().nextInt(1 << 30)}');
        final docBytes = Uint8List.fromList([for (var i = 0; i < 20; i++) ...marker, ...pattern(9000, 2)]); // > 1 chunk
        final doc = OutgoingFile(name: 'plan.pdf', mime: 'application/pdf', bytes: docBytes);
        final tiny = OutgoingFile(name: 'note.txt', mime: 'text/plain', bytes: Uint8List.fromList(utf8.encode('hi')));

        await alice.sendFiles(a, [photo, doc, tiny], caption: 'here you go');
        expect(alice.busy, isEmpty, reason: 'the upload indicator clears');

        await eventually(() => bob.conversation(convId)!.messages.isNotEmpty, what: 'Bob to receive the files');
        final m = bob.conversation(convId)!.messages.single;
        expect(m.text, 'here you go');
        expect(m.mine, isFalse);
        expect(m.attachments.map((x) => (x.name, x.kind, x.size)),
            [('holiday.png', AttachmentKind.image, 70000), ('plan.pdf', AttachmentKind.file, docBytes.length), ('note.txt', AttachmentKind.file, 2)]);
        expect((m.attachments.first.width, m.attachments.first.height), (640, 480));
        expect(m.summary, 'here you go');

        // Bob downloads and decrypts each one; the bytes are exactly what Alice picked.
        expect(await bob.loadAttachment(m.attachments[0]), photo.bytes);
        expect(await bob.loadAttachment(m.attachments[1]), docBytes);
        expect(await bob.loadAttachment(m.attachments[2]), tiny.bytes);
        // Alice, the sender, can open her own too (her other devices need this).
        expect(await alice.loadAttachment(a.messages.single.attachments[1]), docBytes);

        // The chat list shows something sensible for a file-only message.
        await alice.sendFiles(a, [tiny]);
        await eventually(() => bob.conversation(convId)!.messages.length == 2);
        expect(bob.conversation(convId)!.messages.last.summary, 'note.txt');

        if (blobDir != null) {
          // What the server holds is opaque: no file contains the marker or the pattern.
          final files = Directory(blobDir!).listSync(recursive: true).whereType<File>().where((f) => !f.path.startsWith('$blobDir/tmp/')).toList();
          expect(files.length, 4, reason: 'three files plus the one sent alone');
          for (final f in files) {
            final bytes = f.readAsBytesSync();
            expect(_contains(bytes, Uint8List.fromList(marker)), isFalse, reason: 'plaintext marker found in ${f.path}');
            expect(_contains(bytes, photo.bytes.sublist(100, 164)), isFalse, reason: 'plaintext pixels found in ${f.path}');
          }
          // A file changed on disk is detected, not shown as if it were fine.
          final target = files.firstWhere((f) => f.lengthSync() == 9 + 2 + 16);
          final raw = target.readAsBytesSync();
          raw[raw.length - 3] ^= 1;
          target.writeAsBytesSync(raw);
          await expectLater(alice.loadAttachment(a.messages.last.attachments.single), throwsA(isA<ApiException>()));
        }

        // Someone who is not in the conversation cannot download it.
        final (mallory, _, _) = await signUp('mallory');
        await expectLater(mallory.loadAttachment(m.attachments[0]), throwsA(isA<ApiException>()));

        mallory.dispose();
        alice.dispose();
        bob.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 90)));

  test('link previews: off by default, built by the sender, and the recipient never contacts the website', () => diagnosing(() async {
        // A tiny website that counts who visits.
        final png = pattern(3000, 9);
        final visits = <String>[];
        final web = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        web.listen((req) {
          visits.add(req.uri.path);
          if (req.uri.path == '/cover.png') {
            req.response.headers.contentType = ContentType('image', 'png');
            req.response.add(png);
          } else {
            req.response.headers.contentType = ContentType.html;
            req.response.write('<head><title>Fallback</title><meta property="og:title" content="A <b>great</b> read">'
                '<meta property="og:description" content="Summary of the page">'
                '<meta property="og:image" content="/cover.png"></head>');
          }
          req.response.close();
        });
        final url = 'http://127.0.0.1:${web.port}/story';

        final (alice, bob, convId, _) = await chatting();
        final a = alice.conversation(convId)!;
        final b = bob.conversation(convId)!;

        // Off by default: the link is sent as plain text and the website is never asked.
        expect(alice.linkPreviews, isFalse);
        await alice.send(a, 'first $url');
        await eventually(() => b.messages.length == 1);
        expect(b.messages.single.previews, isEmpty);
        expect(b.messages.single.text, 'first $url');
        expect(visits, isEmpty);

        // On: the sender's app gets a card (through the gateway) and sends it inside the message.
        await alice.setLinkPreviews(true);
        await alice.send(a, 'second $url');
        await eventually(() => b.messages.length == 2, what: 'the message with a card');
        final card = b.messages.last.previews.single;
        expect(card.url, url);
        expect(card.title, 'A <b>great</b> read', reason: 'shown as text, never interpreted');
        expect(card.description, 'Summary of the page');
        expect(card.image, isNotNull);
        expect(visits.toSet(), {'/story', '/cover.png'}, reason: 'the gateway fetched it once, for the sender');
        final fetched = visits.length;

        // Bob opens the picture: it comes from our server, decrypted with the key in the message.
        expect(await bob.loadAttachment(card.image!), png);
        expect(visits.length, fetched, reason: 'the recipient never contacted the website');

        // A link the gateway cannot fetch does not stop the message.
        await alice.send(a, 'broken http://127.0.0.1:1/nothing');
        await eventually(() => b.messages.length == 3);
        expect(b.messages.last.previews, isEmpty);

        // The setting is remembered on this device.
        expect(alice.linkPreviews, isTrue);

        await web.close(force: true);
        alice.dispose();
        bob.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 90)));

  test('a file sent before a second device existed is available on it after approval', () => diagnosing(() async {
        final (alice1, _, aliceName) = await signUp('alice');
        final (bob, _, bobName) = await signUp('bob');
        final convId = await alice1.startConversation(bobName);
        await eventually(() => bob.conversation(convId) != null);
        await bob.accept(bob.conversation(convId)!);
        await eventually(() => alice1.conversation(convId)!.state == ConversationState.joined);

        final bytes = pattern(150000, 5);
        await bob.sendFiles(bob.conversation(convId)!, [OutgoingFile(name: 'report.pdf', mime: 'application/pdf', bytes: bytes)], caption: 'the report');
        await eventually(() => alice1.conversation(convId)!.messages.length == 1, what: 'device 1 to get the file');

        final alice2 = YapApp(core: core, store: MemoryStore(), serverUrl: server!, deviceLabel: 'Laptop')
          // ignore: avoid_print
          ..onBackgroundError = (e, st) => print('[alice2] background error: $e\n$st');
        await alice2.login(aliceName, password);
        await eventually(() => alice1.pendingLinks.isNotEmpty, what: 'the approval request');
        await alice1.approve(await alice1.prepareApproval(alice1.pendingLinks.first));
        await eventually(() => alice2.phase == Phase.signedIn);
        await eventually(() => alice2.conversation(convId)?.messages.length == 1, what: 'history on the new device');

        final m = alice2.conversation(convId)!.messages.single;
        expect(m.text, 'the report');
        expect(m.attachments.single.name, 'report.pdf');
        // The key came through the encrypted history, so the new device can open the file.
        expect(await alice2.loadAttachment(m.attachments.single), bytes);

        alice1.dispose();
        alice2.dispose();
        bob.dispose();
      }), skip: skip, timeout: const Timeout(Duration(seconds: 120)));

  test('wrong password and unknown user are refused; password reset works', () => diagnosing(() async {
    final (app, _, name) = await signUp('carol');
    await app.logout();
    expect(app.phase, Phase.signedOut);

    await expectLater(app.login(name, 'not the password'), throwsA(predicate((e) => '$e'.contains('Wrong username or password'))));
    await expectLater(app.login(uniqueName('ghost'), password), throwsA(predicate((e) => '$e'.contains('Wrong username or password'))));

    // Reset the password with the emailed code, then log in with the new one.
    final email = _emailFor(name);
    await app.requestCode('reset', email);
    final code = await codeFor(email);
    final ticket = await app.verifyCode('reset', email, code);
    expect(await app.finishReset(ticket: ticket, password: 'a brand new passphrase'), name);
    await expectLater(app.login(name, password), throwsA(anything));
    await app.login(name, 'a brand new passphrase');
    expect(app.phase, Phase.signedIn);
    app.dispose();
  }), skip: skip, timeout: const Timeout(Duration(seconds: 60)));
}

bool _contains(Uint8List haystack, Uint8List needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
