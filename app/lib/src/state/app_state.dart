// The app's brain: authentication, the device and its encryption state, conversations, the
// realtime connection, live typing, and multiple devices per account. UI listens to it as a
// ChangeNotifier.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../api/api_client.dart';
import '../api/realtime.dart';
import '../core/codec.dart';
import '../core/yap_core.dart';
import '../data/local_store.dart';
import 'ids.dart';
import 'models.dart';
import 'recovery_key.dart';

enum Phase {
  booting,
  signedOut,

  /// Signed in, but this device cannot read anything yet: it is waiting for another of the
  /// account's devices to approve it, or needs the recovery key to get the history key.
  awaitingApproval,
  signedIn,
}

enum DeviceState { approved, pending }

/// A device of this account that asked to be let in.
class PendingLink {
  PendingLink({required this.id, required this.name, required this.linkPub});
  final String id;
  final String name;
  final Uint8List linkPub;
}

/// What the approving person checks before allowing a new device: the code on this screen must
/// equal the code on the new device's screen.
class ApprovalPreview {
  ApprovalPreview({required this.link, required this.keyPackage, required this.signer, required this.fingerprint});
  final PendingLink link;
  final Uint8List keyPackage;
  final Uint8List signer;
  final String fingerprint;
}

/// How many unused key packages the server should hold for this device.
const _minKeyPackages = 5;
const _newKeyPackages = 20;
const _typingBatch = Duration(milliseconds: 200);
const _typingExpiry = Duration(seconds: 6);
const _approvalPoll = Duration(seconds: 3);
const _recoveryAuthLabel = 'yappitron recovery auth v1';

class YapApp extends ChangeNotifier {
  YapApp({required this.core, required this.store, required String serverUrl, this.deviceLabel = 'This device'})
      : api = ApiClient(serverUrl),
        _serverUrl = serverUrl;

  final YapCore core;
  final LocalStore store;

  /// Called with errors raised while processing background events (incoming messages,
  /// welcomes, sync). They never reach the UI, so tests and diagnostics hook in here.
  void Function(Object error, StackTrace stack)? onBackgroundError;
  final String deviceLabel;
  ApiClient api;
  String _serverUrl;

  Phase phase = Phase.booting;
  String? username;
  RealtimeStatus link = RealtimeStatus.offline;

  /// Shown on the sign-in screen (for example "This device was removed from your account").
  String? notice;

  /// Set once, right after the account's first device is created. The UI must show it and then
  /// call [recoveryKeyShown]: it is never stored and cannot be shown again.
  String? recoveryKeyToShow;

  /// While this device waits to be approved: the code to compare with the approving device.
  String? linkFingerprint;

  /// Devices of this account waiting for this device to approve them.
  List<PendingLink> pendingLinks = [];

  /// Set by the UI while a chat is open, so new messages in it are not counted as unread.
  String? openConversationId;

  final Map<String, Conversation> _convs = {};
  int? _device;
  DeviceState _deviceState = DeviceState.approved;
  Uint8List? _localKey;
  Uint8List? _histKey;
  String? _deviceId;
  ({Uint8List secret, Uint8List public})? _linkKeys;
  Timer? _approvalTimer;
  bool _linking = false;
  Realtime? _rt;
  final _subs = <StreamSubscription<dynamic>>[];
  Future<void> _queue = Future.value();
  final Map<String, Timer> _draftExpiry = {};
  final Map<String, _OutgoingDraft> _drafts = {};
  final List<({String conv, ChatMessage message})> _archiveQueue = [];
  bool _disposed = false;

  String get serverUrl => _serverUrl;

  /// This installation's device id on the server.
  String? get deviceId => _deviceId;

  /// True when the device is approved but has lost its history key (it must be restored with the
  /// recovery key).
  bool get needsHistoryKey => _deviceState == DeviceState.approved && _histKey == null;

  List<Conversation> get conversations {
    final list = _convs.values.toList();
    int rank(Conversation c) => c.state == ConversationState.invited ? 0 : 1;
    list.sort((a, b) {
      final r = rank(a).compareTo(rank(b));
      if (r != 0) return r;
      return (b.last?.time ?? DateTime.fromMillisecondsSinceEpoch(0))
          .compareTo(a.last?.time ?? DateTime.fromMillisecondsSinceEpoch(0));
    });
    return list;
  }

  Conversation? conversation(String id) => _convs[id];

  @override
  void notifyListeners() {
    if (!_disposed) super.notifyListeners();
  }

  // ---------------------------------------------------------------- boot

  Future<void> boot() async {
    final saved = await store.getString('server_url');
    if (saved != null && saved != _serverUrl) _useServer(saved);
    final user = await store.getString('last_user');
    final token = user == null ? null : await store.getSecret('session.$user');
    if (user != null && token != null) {
      api.token = token;
      try {
        await _enterSession(await api.me());
        return;
      } on ApiException catch (e) {
        if (e.isUnauthorized) await store.deleteSecret('session.$user');
        api.token = null;
      }
    }
    phase = Phase.signedOut;
    notifyListeners();
  }

  void _useServer(String url) {
    api.close();
    _serverUrl = url;
    api = ApiClient(url);
  }

  Future<void> setServerUrl(String url) async {
    final clean = url.trim();
    final uri = Uri.tryParse(clean);
    if (uri == null || !(uri.isScheme('https') || uri.isScheme('http')) || uri.host.isEmpty) {
      throw ApiException(0, 'Enter a full address like https://chat.example.com');
    }
    _useServer(clean);
    await store.putString('server_url', clean);
    notifyListeners();
  }

  // ------------------------------------------------- signup / login / reset

  Future<void> requestCode(String purpose, String email) => api.requestCode(purpose, email.trim());

  Future<String> verifyCode(String purpose, String email, String code) =>
      api.verifyCode(purpose, email.trim(), code.trim());

  Future<void> finishSignup({required String ticket, required String username, required String password}) async {
    final name = _canonical(username);
    final start = core.authRegisterStart(password);
    final response = await api.registrationStart('signup', ticket, start.request, username: name);
    final upload = core.authRegisterFinish(start.state, password, name, api.serverId, response);
    await api.registrationFinish('signup', ticket, upload, username: name);
    await login(name, password);
  }

  /// Set a new password after verifying the email. Returns the account's username.
  Future<String> finishReset({required String ticket, required String password}) async {
    final start = core.authRegisterStart(password);
    final r = await api.resetStart(ticket, start.request);
    final upload = core.authRegisterFinish(start.state, password, r.username, api.serverId, r.response);
    await api.registrationFinish('reset', ticket, upload);
    return r.username;
  }

  Future<void> login(String usernameInput, String password) async {
    final name = _canonical(usernameInput);
    final start = core.authLoginStart(password);
    final r = await api.loginStart(name, start.request);
    final ({Uint8List finalization, Uint8List sessionKey}) finish;
    try {
      finish = core.authLoginFinish(start.state, password, name, api.serverId, r.response);
    } on CoreException {
      throw ApiException(401, 'Wrong username or password');
    }
    api.token = await api.loginFinish(r.loginId, finish.finalization);
    await store.putSecret('session.$name', api.token!);
    await store.putString('last_user', name);
    await _enterSession(name);
  }

  String _canonical(String input) {
    try {
      return core.usernameCanonicalize(input.trim());
    } on CoreException catch (e) {
      throw ApiException(0, e.message);
    }
  }

  Future<void> logout() async {
    await _teardownSession();
    final user = username;
    if (user != null) await store.deleteSecret('session.$user');
    api.token = null;
    username = null;
    phase = Phase.signedOut;
    notifyListeners();
  }

  // -------------------------------------------------------------- session

  Future<void> _enterSession(String name) async {
    username = name;
    notice = null;
    _localKey = await store.secretKey('local.$name');
    await _attachDevice(name);
    await _loadLocal(name);
    if (_deviceState == DeviceState.pending || _histKey == null) {
      await _beginAwaitingApproval();
    } else {
      await _becomeActive();
    }
  }

  /// The device can read and send: start syncing.
  ///
  /// [waitForSync]: wait for the first sync to finish. Must be false when called from inside the
  /// event queue (for example while handling the "approved" event): the sync is queued BEHIND
  /// the running event, so waiting for it there would never finish.
  Future<void> _becomeActive({bool waitForSync = true}) async {
    phase = Phase.signedIn;
    linkFingerprint = null;
    notifyListeners();
    if (_rt == null) _startRealtime();
    await _ensureKeyPackages();
    await _loadPendingLinks();
    final sync = _enqueue(_refresh);
    if (waitForSync) await sync;
  }

  Future<void> _teardownSession() async {
    _approvalTimer?.cancel();
    _approvalTimer = null;
    for (final s in _subs) {
      await s.cancel();
    }
    _subs.clear();
    for (final t in _draftExpiry.values) {
      t.cancel();
    }
    _draftExpiry.clear();
    for (final d in _drafts.values) {
      d.timer?.cancel();
    }
    _drafts.clear();
    await _rt?.close();
    _rt = null;
    if (_device != null) core.deviceFree(_device!);
    _device = null;
    _deviceId = null;
    _histKey = null;
    _linkKeys = null;
    _linking = false;
    _convs.clear();
    _archiveQueue.clear();
    pendingLinks = [];
    recoveryKeyToShow = null;
    linkFingerprint = null;
    openConversationId = null;
    link = RealtimeStatus.offline;
  }

  /// Restore this installation's device (keys + MLS state) or register a new one.
  Future<void> _attachDevice(String name) async {
    final blob = await store.getBytes('device.$name');
    final savedId = await store.getString('deviceid.$name');
    if (blob != null && savedId != null) {
      try {
        _device = core.deviceImport(blob, _localKey!);
        _deviceId = savedId;
        final status = await api.attachDevice(savedId);
        _deviceState = status == 'approved' ? DeviceState.approved : DeviceState.pending;
        await _loadHistoryKey(name);
        return;
      } on ApiException catch (e) {
        // 403: removed from the account. 404: the server no longer knows it. Either way the
        // local copy is useless: start over as a new device.
        if (e.status != 403 && e.status != 404) rethrow;
        await _wipeLocal(name);
        notice = 'This device was removed from your account, so it signed in again as a new device.';
      }
    }
    _device = core.deviceNew('$name/${newUuid()}');
    final created = await api.createDevice(deviceLabel);
    _deviceId = created.id;
    _deviceState = created.status == 'approved' ? DeviceState.approved : DeviceState.pending;
    await store.putString('deviceid.$name', _deviceId!);
    await _saveDevice();
    if (_deviceState == DeviceState.approved) await _initFirstDevice(name);
  }

  /// The first device of a new account creates the account's history key and a recovery key.
  Future<void> _initFirstDevice(String name) async {
    _histKey = randomBytes(32);
    await store.putSecret('hist.$name', base64.encode(_histKey!));
    await _issueRecoveryKey();
  }

  Future<void> _loadHistoryKey(String name) async {
    final s = await store.getSecret('hist.$name');
    _histKey = s == null ? null : base64.decode(s);
  }

  /// Delete everything this installation stored for [name] (used when the device was removed).
  Future<void> _wipeLocal(String name) async {
    if (_device != null) core.deviceFree(_device!);
    _device = null;
    _deviceId = null;
    _histKey = null;
    final sealed = await store.getBytes('convs.$name');
    if (sealed != null && _localKey != null) {
      try {
        final list = jsonDecode(utf8.decode(core.vaultOpen(_localKey!, 'convs:$name', sealed))) as List;
        for (final j in list.cast<Map<String, dynamic>>()) {
          await store.delete('msgs.$name.${j['id']}');
        }
      } on CoreException {
        // Unreadable already; nothing more to find.
      }
    }
    for (final k in ['device.$name', 'deviceid.$name', 'convs.$name']) {
      await store.delete(k);
    }
    for (final s in ['hist.$name', 'link.$name']) {
      await store.deleteSecret(s);
    }
    _convs.clear();
  }

  Future<void> _ensureKeyPackages() async {
    try {
      if (await api.keyPackageCount() >= _minKeyPackages) return;
      final packages = [for (var i = 0; i < _newKeyPackages; i++) core.keyPackage(_device!)];
      // The private halves live in the device state: persist them BEFORE publishing.
      await _saveDevice();
      await api.putKeyPackages(packages);
    } on ApiException {
      // Not fatal; retried on the next start.
    }
  }

  // ----------------------------------------------- waiting for approval

  Future<void> _beginAwaitingApproval() async {
    phase = Phase.awaitingApproval;
    linkFingerprint = null;
    if (_deviceState == DeviceState.pending) {
      // The link key must survive restarts: the approval may arrive while the app is closed.
      final stored = await store.getSecret('link.$username');
      if (stored != null) {
        final b = base64.decode(stored);
        _linkKeys = (secret: Uint8List.sublistView(b, 0, 32), public: Uint8List.sublistView(b, 32, 64));
      } else {
        _linkKeys = core.linkKeypair();
        await store.putSecret('link.$username', base64.encode([..._linkKeys!.secret, ..._linkKeys!.public]));
      }
      linkFingerprint = core.fingerprint(core.deviceSigner(_device!), _linkKeys!.public);
      await _ensureKeyPackages();
      try {
        await api.linkRequest(_linkKeys!.public);
      } on ApiException {
        // Retried on the next tick below.
      }
      _startRealtime();
      _approvalTimer?.cancel();
      _approvalTimer = Timer.periodic(_approvalPoll, (_) => _checkApproval());
    }
    notifyListeners();
  }

  Future<void> _checkApproval() async {
    if (phase != Phase.awaitingApproval || _linking || _deviceState != DeviceState.pending) return;
    try {
      if (await api.deviceStatus() == 'approved') {
        await _completeLinking();
      } else {
        await _ensureKeyPackages(); // approvers use up one per conversation
      }
    } on ApiException catch (e) {
      if (e.status == 401 || e.status == 403) await _handleRevoked();
    }
  }

  /// This device was approved: open the bundle the approving device sealed to our link key.
  Future<void> _completeLinking() async {
    if (_linking || _linkKeys == null) return;
    _linking = true;
    try {
      final sealed = await api.bundle();
      if (sealed == null) return;
      _histKey = core.linkOpen(_linkKeys!.secret, sealed);
      await store.putSecret('hist.$username', base64.encode(_histKey!));
      await api.deleteBundle();
      await store.deleteSecret('link.$username');
      _approvalTimer?.cancel();
      _approvalTimer = null;
      _linkKeys = null;
      _deviceState = DeviceState.approved;
      // Called from the event queue (the "approved" push) as well as from the poll timer.
      await _becomeActive(waitForSync: false);
    } on CoreException {
      throw ApiException(0, 'Could not open the approval from your other device. Ask it to approve again.');
    } finally {
      _linking = false;
    }
  }

  /// "I lost my other devices": prove possession of the recovery key. This device becomes the
  /// account's only device and gets the history key back. Existing conversations stay readable
  /// (from the archive) but this device is not part of their encryption groups, so talking again
  /// means starting new chats.
  Future<void> recoverWithKey(String text) async {
    final key = decodeRecoveryKey(text);
    if (key == null) {
      throw ApiException(0, 'That is not a recovery key. It is 52 letters and digits in groups of four.');
    }
    final wrapped = await api.recover(core.deriveKey(key, _recoveryAuthLabel));
    try {
      _histKey = core.vaultOpen(key, 'hist-key', wrapped);
    } on CoreException {
      throw ApiException(0, 'That recovery key does not match this account.');
    }
    await store.putSecret('hist.$username', base64.encode(_histKey!));
    await store.deleteSecret('link.$username');
    _approvalTimer?.cancel();
    _approvalTimer = null;
    _linkKeys = null;
    _deviceState = DeviceState.approved;
    await _becomeActive();
    // Whoever saw the old recovery key text gets no further use of it.
    await _issueRecoveryKey();
  }

  /// Create a new recovery key (wrapping the current history key) and queue it for display.
  Future<void> _issueRecoveryKey() async {
    final key = randomBytes(32);
    await api.putAccountKeys(
      wrappedHistoryKey: core.vaultSeal(key, 'hist-key', _histKey!),
      recoveryAuth: core.deriveKey(key, _recoveryAuthLabel),
    );
    recoveryKeyToShow = encodeRecoveryKey(key);
    notifyListeners();
  }

  /// For the Devices screen: replace the recovery key.
  Future<void> createNewRecoveryKey() => _issueRecoveryKey();

  /// The UI has displayed the recovery key to the person; forget it.
  void recoveryKeyShown() {
    recoveryKeyToShow = null;
    notifyListeners();
  }

  // ------------------------------------------------ approving other devices

  Future<void> _loadPendingLinks() async {
    if (_deviceState != DeviceState.approved) return;
    try {
      pendingLinks = [
        for (final d in await api.pendingDevices()) PendingLink(id: d.id, name: d.name, linkPub: d.linkPub),
      ];
      notifyListeners();
    } on ApiException {
      // Offline; refreshed when the connection returns.
    }
  }

  Future<List<DeviceDto>> listDevices() => api.devices();

  /// Step 1 of approving a new device: take one of its key packages and compute the code the
  /// person compares with the new device's screen. The code covers both the key the new device
  /// will use in conversations and the key secrets are sealed to, so a server that swapped
  /// either would produce a different code.
  Future<ApprovalPreview> prepareApproval(PendingLink l) async {
    final kp = await api.takeDeviceKeyPackage(l.id);
    final signer = core.keyPackageSigner(kp);
    return ApprovalPreview(link: l, keyPackage: kp, signer: signer, fingerprint: core.fingerprint(signer, l.linkPub));
  }

  /// Step 2, once the person confirmed the codes match: add the device to every conversation,
  /// then hand it the history key.
  Future<void> approve(ApprovalPreview p) async {
    await _exclusive(() async {
      await _archiveEverything();
      Uint8List? keyPackage = p.keyPackage; // the first conversation uses the package that was checked
      for (final c in conversations.where((c) => c.state == ConversationState.joined && !c.stale)) {
        try {
          await _addDeviceTo(c, p, keyPackage);
        } on CoreException catch (e, st) {
          onBackgroundError?.call(e, st); // a conversation this device cannot add to is skipped
        }
        keyPackage = null;
      }
      await api.approveDevice(p.link.id, core.linkSeal(p.link.linkPub, _histKey!));
    });
    pendingLinks = pendingLinks.where((l) => l.id != p.link.id).toList();
    notifyListeners();
  }

  /// Add [p]'s device to [c] with an MLS commit. If another member committed first the server
  /// refuses (409); catch up with the log and try again on the new group state.
  Future<void> _addDeviceTo(Conversation c, ApprovalPreview p, Uint8List? firstKeyPackage) async {
    final gid = uuidBytes(c.id);
    var keyPackage = firstKeyPackage;
    for (var attempt = 0; attempt < 5; attempt++) {
      await _fetchMissing(c);
      keyPackage ??= await api.takeDeviceKeyPackage(p.link.id);
      if (!listEquals(core.keyPackageSigner(keyPackage), p.signer)) {
        throw ApiException(0, "The new device's keys changed while approving it. Nothing was approved; start again.");
      }
      final staged = core.convAddMembersStaged(_device!, gid, [keyPackage]);
      try {
        final seq = await api.addDevices(c.id,
            commit: staged.commit, welcome: staged.welcome, recipients: [p.link.id], baseSeq: c.lastSeq);
        core.convCommitConfirm(_device!, gid);
        c.sentSeqs.add(seq); // our own commit: never decrypted again
        _advanceOwn(c);
        await _saveDevice();
        await _saveConvs();
        return;
      } on ApiException catch (e) {
        core.convCommitDiscard(_device!, gid);
        if (e.status == 409 && e.message.contains('already')) return;
        if (e.status == 409 && e.message.contains('changed')) continue;
        rethrow;
      }
    }
    throw ApiException(409, 'The chat with ${c.peer} kept changing. Try approving again.');
  }

  /// The person decided not to let a device in.
  Future<void> rejectLink(PendingLink l) async {
    await api.revokeDevice(l.id);
    pendingLinks = pendingLinks.where((x) => x.id != l.id).toList();
    notifyListeners();
  }

  /// Remove one of this account's devices. It is signed out and gets nothing more from the
  /// server. (It stays a member of existing encryption groups until another member removes it.)
  Future<void> removeDevice(String id) async {
    await api.revokeDevice(id);
    if (id == _deviceId) await _handleRevoked();
    notifyListeners();
  }

  /// This device was removed: delete its local data and sign out.
  Future<void> _handleRevoked() async {
    final name = username;
    await _teardownSession();
    if (name != null) await _wipeLocal(name);
    notice = 'This device was removed from your account.';
    api.token = null;
    username = null;
    phase = Phase.signedOut;
    notifyListeners();
  }

  // --------------------------------------------------- local persistence

  Future<void> _saveDevice() async {
    await store.putBytes('device.$username', core.deviceExport(_device!, _localKey!));
  }

  Future<void> _saveConvs() async {
    final meta = jsonEncode([for (final c in _convs.values) c.metaJson()]);
    await store.putBytes(
        'convs.$username', core.vaultSeal(_localKey!, 'convs:$username', Uint8List.fromList(utf8.encode(meta))));
  }

  Future<void> _saveMessages(Conversation c) async {
    final json = jsonEncode([for (final m in c.messages) m.toJson()]);
    await store.putBytes('msgs.$username.${c.id}',
        core.vaultSeal(_localKey!, 'msgs:$username:${c.id}', Uint8List.fromList(utf8.encode(json))));
  }

  Future<void> _loadLocal(String name) async {
    _convs.clear();
    final sealed = await store.getBytes('convs.$name');
    if (sealed == null) return;
    try {
      final list = jsonDecode(utf8.decode(core.vaultOpen(_localKey!, 'convs:$name', sealed))) as List;
      for (final j in list.cast<Map<String, dynamic>>()) {
        final c = Conversation.fromMeta(j);
        final raw = await store.getBytes('msgs.$name.${c.id}');
        if (raw != null) {
          final msgs = jsonDecode(utf8.decode(core.vaultOpen(_localKey!, 'msgs:$name:${c.id}', raw))) as List;
          for (final m in msgs.cast<Map<String, dynamic>>()) {
            c.addMessage(ChatMessage.fromJson(m));
          }
        }
        _convs[c.id] = c;
      }
    } on CoreException {
      // Unreadable local history (for example the keystore was reset): start clean; the server
      // log and archive still hold the encrypted messages.
      _convs.clear();
    }
  }

  // ------------------------------------------------------------- realtime

  void _startRealtime() {
    final rt = Realtime(api.webSocketUri, api.token!);
    _rt = rt;
    _subs
      ..add(rt.status.listen((s) {
        link = s;
        notifyListeners();
        if (s == RealtimeStatus.online && phase == Phase.signedIn) _enqueue(_refresh);
      }))
      ..add(rt.events.listen((e) => _enqueue(() => _onEvent(e))));
    rt.start();
  }

  /// Events are processed strictly one at a time, in arrival order.
  Future<void> _enqueue(Future<void> Function() job) {
    _queue = _queue.then((_) => job()).catchError((Object e, StackTrace st) {
      onBackgroundError?.call(e, st);
    });
    return _queue;
  }

  /// Like [_enqueue], but hands the result (or error) back to the caller. Used for work that
  /// must not interleave with incoming events, such as approving a device.
  Future<T> _exclusive<T>(Future<T> Function() job) {
    final done = Completer<T>();
    _queue = _queue.then((_) async {
      try {
        done.complete(await job());
      } catch (e, st) {
        done.completeError(e, st);
      }
    });
    return done.future;
  }

  Future<void> _onEvent(Map<String, dynamic> e) async {
    // A device that is still waiting for approval reads nothing: its welcomes are collected
    // after approval (joining early would spend the one-time key package for no result).
    final conversationTraffic = const {'welcome', 'msg', 'member', 'typing'}.contains(e['t']);
    if (conversationTraffic && (_deviceState != DeviceState.approved || phase != Phase.signedIn)) return;
    switch (e['t']) {
      case 'welcome':
        await _handleWelcome(e['id'] as int, e['c'] as String, b64d(e['d'] as String), e['join_seq'] as int);
      case 'msg':
        await _handleLog(e['c'] as String, LogEntryDto(seq: e['seq'] as int, kind: e['k'] as int, data: b64d(e['d'] as String)));
      case 'member':
        final c = _convs[e['c'] as String];
        if (c != null && e['s'] == 'declined') {
          c.state = ConversationState.declined;
          await _saveConvs();
          notifyListeners();
        } else if (c != null && e['s'] == 'joined' && c.state == ConversationState.declined) {
          c.state = ConversationState.joined;
        }
      case 'typing':
        _handleTyping(e['c'] as String, e['f'] as String);
      case 'link_request' || 'devices_changed':
        await _loadPendingLinks();
      case 'approved':
        await _completeLinking();
      case 'revoked':
        await _handleRevoked();
    }
  }

  /// Reconcile with the server: new conversations, pending welcomes, missed messages, history.
  Future<void> _refresh() async {
    if (_device == null || _deviceState != DeviceState.approved || _histKey == null) return;
    try {
      for (final w in await api.welcomes()) {
        await _handleWelcome(w.id, w.conversationId, w.data, w.joinSeq);
      }
      final server = {for (final d in await api.conversations()) d.id: d};
      for (final c in _convs.values.toList()) {
        final d = server[c.id];
        if (d == null) {
          if (c.state != ConversationState.declined) {
            _convs.remove(c.id);
            continue;
          }
        } else if (d.state == 'joined' && c.state == ConversationState.invited) {
          c.state = ConversationState.joined;
        }
      }
      // A conversation the account is in but this device has no encryption state for (its keys
      // were reset with the recovery key): keep it as a read-only record from the archive.
      for (final d in server.values) {
        if (_convs.containsKey(d.id) || d.state != 'joined') continue;
        final peer = d.members.where((m) => m.username != username).firstOrNull?.username ?? 'unknown';
        _convs[d.id] = Conversation(id: d.id, peer: peer, state: ConversationState.joined, stale: true, archiveUntil: d.lastSeq);
      }
      for (final c in _convs.values.toList()) {
        if (c.state == ConversationState.declined) continue;
        final d = server[c.id];
        if (!c.stale && d != null && d.lastSeq > c.lastSeq) await _fetchMissing(c);
        if (c.archiveSeq < c.archiveUntil) await _importArchive(c);
      }
      await _saveConvs();
      notifyListeners();
      unawaited(_flushArchive());
    } on ApiException {
      // Offline or session expired; the realtime layer reconnects and we refresh again.
    }
  }

  Future<void> _handleWelcome(int welcomeId, String convId, Uint8List welcome, int joinSeq) async {
    final existing = _convs[convId];
    if (existing == null || existing.stale) {
      // Ask the server about the conversation first: joining spends a one-time key package, so
      // nothing that can fail on the network may come after it.
      final dto = (await api.conversations()).where((d) => d.id == convId).firstOrNull;
      try {
        core.convJoin(_device!, welcome);
      } on CoreException catch (e, st) {
        // Not for this device's keys; leave it for the server to age out. Reported so that a
        // genuine failure (as opposed to a stray welcome) is visible to diagnostics.
        onBackgroundError?.call(e, st);
        return;
      }
      await _saveDevice();
      final peer = dto?.members.where((m) => m.username != username).firstOrNull?.username ?? existing?.peer ?? 'unknown';
      final state = dto?.state == 'joined' ? ConversationState.joined : ConversationState.invited;
      if (existing != null) {
        existing
          ..stale = false
          ..state = state
          ..lastSeq = joinSeq
          ..archiveUntil = joinSeq;
      } else {
        _convs[convId] = Conversation(id: convId, peer: peer, state: state, lastSeq: joinSeq, archiveUntil: joinSeq);
      }
      await _saveConvs();
    }
    await api.deleteWelcome(welcomeId);
    // Messages from before this device joined cannot be decrypted; the archive has them.
    final c = _convs[convId];
    if (c != null && c.archiveSeq < c.archiveUntil) await _importArchive(c);
    notifyListeners();
  }

  Future<void> _handleLog(String convId, LogEntryDto entry) async {
    final c = _convs[convId];
    if (c == null || c.stale || entry.seq <= c.lastSeq) return;
    final gap = [for (var s = c.lastSeq + 1; s < entry.seq; s++) if (!c.sentSeqs.contains(s)) s];
    if (gap.isNotEmpty) {
      await _fetchMissing(c);
      return;
    }
    await _applyEntry(c, entry);
  }

  /// Fetch and apply everything after what we have processed, in order.
  Future<void> _fetchMissing(Conversation c) async {
    while (true) {
      final batch = await api.messages(c.id, c.lastSeq);
      if (batch.isEmpty) break;
      for (final e in batch) {
        await _applyEntry(c, e);
      }
      if (batch.length < 200) break;
    }
  }

  Future<void> _applyEntry(Conversation c, LogEntryDto e) async {
    if (e.seq <= c.lastSeq || c.sentSeqs.contains(e.seq)) {
      _advanceOwn(c);
      return;
    }
    final gid = uuidBytes(c.id);
    if (e.kind == 1) {
      try {
        final out = core.convDecrypt(_device!, gid, e.data);
        final j = jsonDecode(utf8.decode(out.plaintext)) as Map<String, dynamic>;
        // MLS authenticates who sent this. A message from another device of this account is
        // ours, even though this device did not write it.
        final mine = out.sender.split('/').first == username;
        final m = ChatMessage(
          seq: e.seq,
          mine: mine,
          time: DateTime.fromMillisecondsSinceEpoch(j['ts'] as int),
          text: j['body'] as String,
        );
        if (!c.hasSeq(e.seq)) {
          c.addMessage(m);
          if (!mine && openConversationId != c.id) c.unread++;
        }
        _archiveQueue.add((conv: c.id, message: m));
        if (!mine) c.liveDraft = null;
      } on CoreException catch (ex) {
        if (!ex.isOwnMessage) {
          c.addMessage(ChatMessage(
              seq: e.seq, mine: false, time: DateTime.now(), text: 'This message could not be decrypted.'));
        }
      } on FormatException {
        c.addMessage(ChatMessage(seq: e.seq, mine: false, time: DateTime.now(), text: '(unsupported message)'));
      }
    } else {
      try {
        core.convApplyCommit(_device!, gid, e.data);
      } on CoreException {
        // Already reflected, or not for us.
      }
    }
    c.lastSeq = e.seq;
    _advanceOwn(c);
    // Persist the advanced MLS state before telling the server we have it.
    await _saveDevice();
    await _saveMessages(c);
    await _saveConvs();
    _rt?.sendAck(c.id, c.lastSeq);
    notifyListeners();
    unawaited(_flushArchive());
  }

  /// Skip over sequence numbers this device sent itself.
  void _advanceOwn(Conversation c) {
    while (c.sentSeqs.contains(c.lastSeq + 1)) {
      c.lastSeq++;
    }
    c.sentSeqs.removeWhere((s) => s <= c.lastSeq);
  }

  // ------------------------------------------------------- history archive

  Uint8List _sealArchive(String conv, ChatMessage m) => core.vaultSeal(
        _histKey!,
        'arch:$conv:${m.seq}',
        Uint8List.fromList(utf8.encode(jsonEncode({'f': m.mine ? 'me' : 'them', 't': m.time.millisecondsSinceEpoch, 'x': m.text}))),
      );

  /// Upload what this device has read to the account's archive (sealed under the history key,
  /// which the server never sees) so devices added later can read it. Failures are retried.
  Future<void> _flushArchive() async {
    if (_histKey == null || _deviceState != DeviceState.approved || _archiveQueue.isEmpty) return;
    final batch = List.of(_archiveQueue);
    _archiveQueue.clear();
    final byConv = <String, List<ChatMessage>>{};
    for (final item in batch) {
      byConv.putIfAbsent(item.conv, () => []).add(item.message);
    }
    for (final entry in byConv.entries) {
      for (var i = 0; i < entry.value.length; i += 100) {
        final chunk = entry.value.sublist(i, (i + 100).clamp(0, entry.value.length));
        try {
          await api.putArchive(entry.key, [for (final m in chunk) (seq: m.seq, data: _sealArchive(entry.key, m))]);
        } on ApiException {
          _archiveQueue.addAll([for (final m in chunk) (conv: entry.key, message: m)]);
        }
      }
    }
  }

  /// Everything this device holds, to the archive (idempotent), before letting a new device in.
  Future<void> _archiveEverything() async {
    for (final c in _convs.values) {
      if (c.stale) continue;
      for (final m in c.messages) {
        _archiveQueue.add((conv: c.id, message: m));
      }
    }
    await _flushArchive();
    if (_archiveQueue.isNotEmpty) {
      throw ApiException(0, 'Could not back up your history to the server; check your connection and try again.');
    }
  }

  /// Fill in messages from before this device joined from the archive.
  Future<void> _importArchive(Conversation c) async {
    if (_histKey == null) return;
    var changed = false;
    while (true) {
      final batch = await api.archive(c.id, c.archiveSeq);
      if (batch.isEmpty) break;
      for (final e in batch) {
        c.archiveSeq = e.seq;
        if (c.hasSeq(e.seq)) continue;
        try {
          final j = jsonDecode(utf8.decode(core.vaultOpen(_histKey!, 'arch:${c.id}:${e.seq}', e.data))) as Map<String, dynamic>;
          c.addMessage(ChatMessage(
            seq: e.seq,
            mine: j['f'] == 'me',
            time: DateTime.fromMillisecondsSinceEpoch(j['t'] as int),
            text: j['x'] as String,
          ));
          changed = true;
        } on CoreException {
          // Not sealed under our key (or tampered with): skip it.
        }
      }
      if (batch.length < 200) break;
    }
    if (changed) await _saveMessages(c);
  }

  // ---------------------------------------------------------- live typing

  void _handleTyping(String convId, String frameB64) {
    final c = _convs[convId];
    if (c == null || c.stale || c.state != ConversationState.joined) return;
    try {
      final o = core.typingOpen(_device!, uuidBytes(convId), b64d(frameB64));
      // Frames can arrive out of order; a sender restart resets the counter, hence the slack.
      if (o.seq <= c.typingSeqIn && c.typingSeqIn - o.seq < 1000) return;
      c.typingSeqIn = o.seq;
      c.liveDraft = o.text.isEmpty ? null : o.text;
      _draftExpiry[convId]?.cancel();
      if (c.liveDraft != null) {
        _draftExpiry[convId] = Timer(_typingExpiry, () {
          c.liveDraft = null;
          notifyListeners();
        });
      }
      notifyListeners();
    } on CoreException {
      // A frame from another epoch, or garbage: drop it.
    }
  }

  /// Called on every edit of the composer. Frames are batched every 200 ms.
  void onDraftChanged(Conversation c, String text) {
    if (!c.liveTyping || c.stale || c.state != ConversationState.joined || _rt == null) return;
    final d = _drafts.putIfAbsent(c.id, _OutgoingDraft.new);
    d.pending = text;
    d.timer ??= Timer(_typingBatch, () => _flushDraft(c));
  }

  void _flushDraft(Conversation c) {
    final d = _drafts[c.id];
    if (d == null) return;
    d.timer = null;
    if (d.pending == d.lastSent || _device == null) return;
    d.lastSent = d.pending;
    try {
      final frame = core.typingSeal(_device!, uuidBytes(c.id), d.seq++, d.pending);
      _rt?.sendTyping(c.id, b64e(frame));
    } on CoreException {
      // Not in the group (yet); skip.
    }
  }

  /// Tell the other side the draft is gone (sent or cleared) right away.
  void clearDraft(Conversation c) {
    final d = _drafts[c.id];
    d?.timer?.cancel();
    d?.timer = null;
    d?.pending = '';
    if (d != null && d.lastSent.isNotEmpty) _flushDraft(c);
  }

  Future<void> setLiveTyping(Conversation c, bool on) async {
    c.liveTyping = on;
    if (!on) clearDraft(c);
    await _saveConvs();
    notifyListeners();
  }

  // --------------------------------------------------------- conversations

  void markRead(Conversation c) {
    if (c.unread == 0) return;
    c.unread = 0;
    _saveConvs();
    notifyListeners();
  }

  /// Start a conversation with [peerInput]; returns its id.
  Future<String> startConversation(String peerInput) async {
    final peer = _canonical(peerInput);
    if (peer == username) throw ApiException(0, 'You cannot start a chat with yourself');
    if (_convs.values.any((c) => c.peer == peer && c.state != ConversationState.declined && !c.stale)) {
      throw ApiException(0, 'You already have a conversation with $peer');
    }
    final theirs = await api.takeKeyPackages(peer);
    if (theirs.isEmpty) {
      throw ApiException(409, '$peer has no device ready yet. Ask them to open the app first.');
    }
    final mine = await api.takeKeyPackages(username!);
    final id = newUuid();
    final gid = uuidBytes(id);
    core.convCreate(_device!, gid);
    final added = core.convAddMembers(_device!, gid, [for (final d in [...theirs, ...mine]) d.keyPackage]);
    await _saveDevice();
    await api.createConversation(
      id: id,
      member: peer,
      welcome: added.welcome,
      recipients: [for (final d in [...theirs, ...mine]) d.deviceId],
    );
    _convs[id] = Conversation(id: id, peer: peer, state: ConversationState.joined);
    await _saveConvs();
    notifyListeners();
    return id;
  }

  Future<void> accept(Conversation c) async {
    await api.accept(c.id);
    c.state = ConversationState.joined;
    await _saveConvs();
    notifyListeners();
  }

  Future<void> decline(Conversation c) async {
    await api.decline(c.id);
    _convs.remove(c.id);
    await store.delete('msgs.$username.${c.id}');
    await _saveConvs();
    notifyListeners();
  }

  Future<void> send(Conversation c, String text) async {
    final body = text.trim();
    if (body.isEmpty) return;
    if (c.stale) {
      throw ApiException(0, 'This chat can no longer receive messages on this device. Start a new chat with ${c.peer}.');
    }
    if (c.state == ConversationState.declined) {
      throw ApiException(403, 'The other person declined this conversation');
    }
    final now = DateTime.now();
    final payload = jsonEncode({'v': 1, 'ts': now.millisecondsSinceEpoch, 'body': body});
    final ct = core.convEncrypt(_device!, uuidBytes(c.id), Uint8List.fromList(utf8.encode(payload)));
    await _saveDevice();
    final seq = await api.postMessage(c.id, 1, ct);
    final m = ChatMessage(seq: seq, mine: true, time: now, text: body);
    c.addMessage(m);
    c.sentSeqs.add(seq);
    c.liveDraft = null;
    _advanceOwn(c);
    _archiveQueue.add((conv: c.id, message: m));
    await _saveMessages(c);
    await _saveConvs();
    _rt?.sendAck(c.id, c.lastSeq);
    clearDraft(c);
    notifyListeners();
    unawaited(_flushArchive());
  }

  @override
  void dispose() {
    _disposed = true;
    _approvalTimer?.cancel();
    for (final s in _subs) {
      s.cancel();
    }
    for (final t in _draftExpiry.values) {
      t.cancel();
    }
    for (final d in _drafts.values) {
      d.timer?.cancel();
    }
    _rt?.close();
    api.close();
    super.dispose();
  }
}

class _OutgoingDraft {
  String pending = '';
  String lastSent = '';
  int seq = 0;
  Timer? timer;
}
