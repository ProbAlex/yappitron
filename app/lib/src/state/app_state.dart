// The app's brain: authentication, the device and its encryption state, conversations, the
// realtime connection and live typing. UI listens to it as a ChangeNotifier.

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

enum Phase { booting, signedOut, signedIn }

/// How many unused key packages the server should hold for this device.
const _minKeyPackages = 5;
const _newKeyPackages = 20;
const _typingBatch = Duration(milliseconds: 200);
const _typingExpiry = Duration(seconds: 6);

class YapApp extends ChangeNotifier {
  YapApp({required this.core, required this.store, required String serverUrl, this.deviceLabel = 'This device'})
      : api = ApiClient(serverUrl),
        _serverUrl = serverUrl;

  final YapCore core;
  final LocalStore store;
  final String deviceLabel;
  ApiClient api;
  String _serverUrl;

  Phase phase = Phase.booting;
  String? username;
  RealtimeStatus link = RealtimeStatus.offline;

  /// Set by the UI while a chat is open, so new messages in it are not counted as unread.
  String? openConversationId;

  final Map<String, Conversation> _convs = {};
  int? _device;
  Uint8List? _localKey;
  String? _deviceId;
  Realtime? _rt;
  final _subs = <StreamSubscription<dynamic>>[];
  Future<void> _queue = Future.value();
  final Map<String, Timer> _draftExpiry = {};
  final Map<String, _OutgoingDraft> _drafts = {};
  bool _disposed = false;

  String get serverUrl => _serverUrl;

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
    _localKey = await store.secretKey('local.$name');
    await _attachDevice(name);
    await _loadLocal(name);
    phase = Phase.signedIn;
    notifyListeners();
    _startRealtime();
    await _ensureKeyPackages();
    await _enqueue(_refresh);
  }

  Future<void> _teardownSession() async {
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
    _convs.clear();
    openConversationId = null;
    link = RealtimeStatus.offline;
  }

  /// Restore this installation's device (keys + MLS state) or create one and register it.
  Future<void> _attachDevice(String name) async {
    final blob = await store.getBytes('device.$name');
    final savedId = await store.getString('deviceid.$name');
    if (blob != null && savedId != null) {
      _device = core.deviceImport(blob, _localKey!);
      _deviceId = savedId;
      await api.attachDevice(savedId);
      return;
    }
    _device = core.deviceNew('$name/${newUuid()}');
    _deviceId = await api.createDevice(deviceLabel);
    await store.putString('deviceid.$name', _deviceId!);
    await _saveDevice();
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
          c.messages.addAll(msgs.cast<Map<String, dynamic>>().map(ChatMessage.fromJson));
        }
        _convs[c.id] = c;
      }
    } on CoreException {
      // Unreadable local history (for example the keystore was reset): start clean; the server
      // log still holds the encrypted messages.
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
        if (s == RealtimeStatus.online) _enqueue(_refresh);
      }))
      ..add(rt.events.listen((e) => _enqueue(() => _onEvent(e))));
    rt.start();
  }

  /// Events are processed strictly one at a time, in arrival order.
  Future<void> _enqueue(Future<void> Function() job) {
    _queue = _queue.then((_) => job()).catchError((Object _) {});
    return _queue;
  }

  Future<void> _onEvent(Map<String, dynamic> e) async {
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
    }
  }

  /// Reconcile with the server: new conversations, pending welcomes, missed messages.
  Future<void> _refresh() async {
    if (_device == null) return;
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
      for (final c in _convs.values.toList()) {
        if (c.state == ConversationState.declined) continue;
        final d = server[c.id];
        if (d != null && d.lastSeq > c.lastSeq) await _fetchMissing(c);
      }
      await _saveConvs();
      notifyListeners();
    } on ApiException {
      // Offline or session expired; the realtime layer reconnects and we refresh again.
    }
  }

  Future<void> _handleWelcome(int welcomeId, String convId, Uint8List welcome, int joinSeq) async {
    if (!_convs.containsKey(convId)) {
      try {
        core.convJoin(_device!, welcome);
      } on CoreException {
        return; // not for this device's keys; leave it for the server to age out
      }
      await _saveDevice();
      final dto = (await api.conversations()).where((d) => d.id == convId).firstOrNull;
      final peer = dto?.members.where((m) => m.username != username).firstOrNull?.username ?? 'unknown';
      _convs[convId] = Conversation(
        id: convId,
        peer: peer,
        state: dto?.state == 'joined' ? ConversationState.joined : ConversationState.invited,
        lastSeq: joinSeq,
      );
      await _saveConvs();
    }
    await api.deleteWelcome(welcomeId);
    notifyListeners();
  }

  Future<void> _handleLog(String convId, LogEntryDto entry) async {
    final c = _convs[convId];
    if (c == null || entry.seq <= c.lastSeq) return;
    final own = c.ownSeqs;
    final gap = [for (var s = c.lastSeq + 1; s < entry.seq; s++) if (!own.contains(s)) s];
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
    if (e.seq <= c.lastSeq || c.ownSeqs.contains(e.seq)) {
      _advanceOwn(c);
      return;
    }
    final gid = uuidBytes(c.id);
    if (e.kind == 1) {
      try {
        final plain = core.convDecrypt(_device!, gid, e.data);
        final j = jsonDecode(utf8.decode(plain)) as Map<String, dynamic>;
        c.messages.add(ChatMessage(
          seq: e.seq,
          mine: false,
          time: DateTime.fromMillisecondsSinceEpoch(j['ts'] as int),
          text: j['body'] as String,
        ));
        c.liveDraft = null;
        if (openConversationId != c.id) c.unread++;
      } on CoreException catch (ex) {
        if (!ex.isOwnMessage) {
          c.messages.add(ChatMessage(
              seq: e.seq, mine: false, time: DateTime.now(), text: 'This message could not be decrypted.'));
        }
      } on FormatException {
        c.messages.add(ChatMessage(seq: e.seq, mine: false, time: DateTime.now(), text: '(unsupported message)'));
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
  }

  /// Skip over sequence numbers this device sent itself.
  void _advanceOwn(Conversation c) {
    final own = c.ownSeqs;
    while (own.contains(c.lastSeq + 1)) {
      c.lastSeq++;
    }
  }

  // ---------------------------------------------------------- live typing

  void _handleTyping(String convId, String frameB64) {
    final c = _convs[convId];
    if (c == null || c.state != ConversationState.joined) return;
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
    if (!c.liveTyping || c.state != ConversationState.joined || _rt == null) return;
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
    if (_convs.values.any((c) => c.peer == peer && c.state != ConversationState.declined)) {
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
    if (c.state == ConversationState.declined) {
      throw ApiException(403, 'The other person declined this conversation');
    }
    final now = DateTime.now();
    final payload = jsonEncode({'v': 1, 'ts': now.millisecondsSinceEpoch, 'body': body});
    final ct = core.convEncrypt(_device!, uuidBytes(c.id), Uint8List.fromList(utf8.encode(payload)));
    await _saveDevice();
    final seq = await api.postMessage(c.id, 1, ct);
    c.messages.add(ChatMessage(seq: seq, mine: true, time: now, text: body));
    c.liveDraft = null;
    _advanceOwn(c);
    await _saveMessages(c);
    await _saveConvs();
    _rt?.sendAck(c.id, c.lastSeq);
    clearDraft(c);
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
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
