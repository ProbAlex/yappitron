// Native end-to-end test: two real YapApp instances (the Rust core over FFI, real HTTP and
// WebSocket) talk through a real gateway. Run by `e2e/run.sh`, which starts the gateway and sets
//   YAP_E2E_SERVER  (e.g. http://127.0.0.1:18090; the server's YAP_DOMAIN must be its host)
//   YAP_E2E_MAIL_FILE  (the gateway's dev mail file, to read verification codes)
//   YAP_NATIVE_LIB  (the built libyap_ffi.so)
// Skipped when those are not set.

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:yappitron/src/api/api_client.dart';
import 'package:yappitron/src/core/backend.dart';
import 'package:yappitron/src/core/yap_core.dart';
import 'package:yappitron/src/data/local_store.dart';
import 'package:yappitron/src/state/app_state.dart';
import 'package:yappitron/src/state/models.dart';

final server = Platform.environment['YAP_E2E_SERVER'];
final mailFile = Platform.environment['YAP_E2E_MAIL_FILE'];
const password = 'correct horse battery staple';

/// Poll until [check] is true.
Future<void> eventually(bool Function() check, {String? what, int seconds = 15}) async {
  final deadline = DateTime.now().add(Duration(seconds: seconds));
  while (!check()) {
    if (DateTime.now().isAfter(deadline)) fail('timed out waiting for ${what ?? 'condition'}');
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
}

Future<String> codeFor(String email) async {
  for (var i = 0; i < 100; i++) {
    final f = File(mailFile!);
    if (f.existsSync()) {
      for (final line in f.readAsLinesSync()) {
        final m = jsonDecode(line) as Map<String, dynamic>;
        if (m['to'] == email) return RegExp(r'(\d{6})').firstMatch(m['subject'] as String)!.group(1)!;
      }
    }
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  fail('no email for $email');
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
  final skip = (server == null || mailFile == null) ? 'set YAP_E2E_SERVER and YAP_E2E_MAIL_FILE (see e2e/run.sh)' : null;
  late YapCore core;

  setUpAll(() async {
    if (skip != null) return;
    core = YapCore(await openBackend());
  });

  Future<(YapApp, MemoryStore, String)> signUp(String label) async {
    final name = uniqueName(label);
    final email = '$name@example.test';
    final store = MemoryStore();
    final app = YapApp(core: core, store: store, serverUrl: server!, deviceLabel: 'Test device');
    await app.requestCode('signup', email);
    final ticket = await app.verifyCode('signup', email, await codeFor(email));
    await app.finishSignup(ticket: ticket, username: name, password: password);
    expect(app.phase, Phase.signedIn);
    expect(app.username, name);
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

  test('wrong password and unknown user are refused; password reset works', () => diagnosing(() async {
    final (app, _, name) = await signUp('carol');
    await app.logout();
    expect(app.phase, Phase.signedOut);

    await expectLater(app.login(name, 'not the password'), throwsA(predicate((e) => '$e'.contains('Wrong username or password'))));
    await expectLater(app.login(uniqueName('ghost'), password), throwsA(predicate((e) => '$e'.contains('Wrong username or password'))));

    // Reset the password with the emailed code, then log in with the new one.
    final email = '$name@example.test';
    final before = File(mailFile!).readAsLinesSync().where((l) => (jsonDecode(l) as Map)['to'] == email).length;
    await app.requestCode('reset', email);
    String? code;
    for (var i = 0; i < 100 && code == null; i++) {
      final mails = File(mailFile!).readAsLinesSync().map((l) => jsonDecode(l) as Map<String, dynamic>).where((m) => m['to'] == email).toList();
      if (mails.length > before) code = RegExp(r'(\d{6})').firstMatch(mails.last['subject'] as String)!.group(1);
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    final ticket = await app.verifyCode('reset', email, code!);
    expect(await app.finishReset(ticket: ticket, password: 'a brand new passphrase'), name);
    await expectLater(app.login(name, password), throwsA(anything));
    await app.login(name, 'a brand new passphrase');
    expect(app.phase, Phase.signedIn);
    app.dispose();
  }), skip: skip, timeout: const Timeout(Duration(seconds: 60)));
}
