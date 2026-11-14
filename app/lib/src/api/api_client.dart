// REST client for the Yappitron server (see docs/API.md). Binary fields are base64url without
// padding. No logging of requests or responses.

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

String b64e(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List b64d(String s) => base64Url.decode(base64Url.normalize(s));

class ApiException implements Exception {
  ApiException(this.status, this.message, {this.cause});
  final int status;
  final String message;

  /// The underlying network error, for diagnostics (never shown to people).
  final Object? cause;

  bool get isUnauthorized => status == 401;

  @override
  String toString() => message;
}

class DeviceDto {
  DeviceDto({required this.id, required this.name, required this.status, required this.current});
  final String id;
  final String name;
  final String status;
  final bool current;
}

class PendingDeviceDto {
  PendingDeviceDto({required this.id, required this.name, required this.linkPub});
  final String id;
  final String name;
  final Uint8List linkPub;
}

class WelcomeDto {
  WelcomeDto({required this.id, required this.conversationId, required this.joinSeq, required this.data});
  final int id;
  final String conversationId;
  final int joinSeq;
  final Uint8List data;
}

class LogEntryDto {
  LogEntryDto({required this.seq, required this.kind, required this.data});
  final int seq;
  final int kind;
  final Uint8List data;
}

class ConversationDto {
  ConversationDto({required this.id, required this.state, required this.lastSeq, required this.members});
  final String id;
  final String state;
  final int lastSeq;
  final List<({String username, String state})> members;
}

class ApiClient {
  ApiClient(String baseUrl, {http.Client? client})
      : base = Uri.parse(baseUrl.endsWith('/') ? baseUrl.substring(0, baseUrl.length - 1) : baseUrl),
        _http = client ?? http.Client();

  final Uri base;
  final http.Client _http;

  /// Session token once logged in.
  String? token;

  /// The OPAQUE server identifier: the host the client actually talks to.
  String get serverId => base.host;

  Uri get webSocketUri => base.replace(
        scheme: base.scheme == 'https' ? 'wss' : 'ws',
        path: '/ws',
      );

  /// [retryOnConnectionError]: repeat once if the connection dies before any reply. Only for
  /// requests that are harmless to repeat. HTTP keep-alive can hand us a socket the server has
  /// just closed (a "Broken pipe"), and a retry opens a fresh one.
  Future<Map<String, dynamic>> _send(String method, String path,
      [Object? body, bool? retryOnConnectionError]) async {
    final retry = retryOnConnectionError ?? (method == 'GET' || method == 'PUT' || method == 'DELETE');
    try {
      return await _sendOnce(method, path, body);
    } on ApiException catch (e) {
      if (retry && e.status == 0 && e.cause != null) return _sendOnce(method, path, body);
      rethrow;
    }
  }

  Future<Map<String, dynamic>> _sendOnce(String method, String path, Object? body) async {
    final request = http.Request(method, base.replace(path: path.split('?').first, query: path.contains('?') ? path.split('?').last : null));
    request.headers['content-type'] = 'application/json';
    if (token != null) request.headers['authorization'] = 'Bearer $token';
    if (body != null) request.body = jsonEncode(body);
    final http.StreamedResponse streamed;
    try {
      streamed = await _http.send(request);
    } catch (e) {
      throw ApiException(0, 'Cannot reach the server', cause: e);
    }
    final text = await streamed.stream.bytesToString();
    Map<String, dynamic> json = const {};
    if (text.isNotEmpty) {
      try {
        json = jsonDecode(text) as Map<String, dynamic>;
      } catch (_) {}
    }
    if (streamed.statusCode >= 400) {
      throw ApiException(streamed.statusCode, (json['error'] as String?) ?? 'Request failed (${streamed.statusCode})');
    }
    return json;
  }

  // ----- signup / login / reset -----

  Future<void> requestCode(String purpose, String email) =>
      _send('POST', '/api/v1/$purpose/request-code', {'email': email});

  Future<String> verifyCode(String purpose, String email, String code) async =>
      (await _send('POST', '/api/v1/$purpose/verify-code', {'email': email, 'code': code}))['ticket'] as String;

  Future<Uint8List> registrationStart(String purpose, String ticket, Uint8List request, {String? username}) async {
    final r = await _send('POST', '/api/v1/$purpose/start', {
      'ticket': ticket,
      'request': b64e(request),
      'username': ?username,
    });
    return b64d(r['response'] as String);
  }

  Future<void> registrationFinish(String purpose, String ticket, Uint8List upload, {String? username}) =>
      _send('POST', '/api/v1/$purpose/finish', {
        'ticket': ticket,
        'upload': b64e(upload),
        'username': ?username,
      });

  /// Password reset: like registration, but the server also tells us the account's username
  /// (the OPAQUE client identifier), since the user only proved ownership of the email.
  Future<({Uint8List response, String username})> resetStart(String ticket, Uint8List request) async {
    final r = await _send('POST', '/api/v1/reset/start', {'ticket': ticket, 'request': b64e(request)});
    return (response: b64d(r['response'] as String), username: r['username'] as String);
  }

  Future<({String loginId, Uint8List response})> loginStart(String username, Uint8List request) async {
    final r = await _send('POST', '/api/v1/login/start', {'username': username, 'request': b64e(request)});
    return (loginId: r['login_id'] as String, response: b64d(r['response'] as String));
  }

  Future<String> loginFinish(String loginId, Uint8List finalization) async {
    final r = await _send('POST', '/api/v1/login/finish', {'login_id': loginId, 'finalization': b64e(finalization)});
    return r['session_token'] as String;
  }

  Future<String> me() async => (await _send('GET', '/api/v1/me'))['username'] as String;

  // ----- devices -----

  /// Register this installation. The account's first device is `approved` straight away; later
  /// ones are `pending` until an approved device lets them in.
  Future<({String id, String status})> createDevice(String name) async {
    final r = await _send('POST', '/api/v1/devices', {'name': name});
    return (id: r['device_id'] as String, status: r['status'] as String);
  }

  /// Bind this session to the device this installation already has. Returns its status.
  Future<String> attachDevice(String deviceId) async =>
      (await _send('POST', '/api/v1/devices/attach', {'device_id': deviceId}))['status'] as String;

  Future<String> deviceStatus() async => (await _send('GET', '/api/v1/devices/me'))['status'] as String;

  Future<List<DeviceDto>> devices() async {
    final r = await _send('GET', '/api/v1/devices');
    return [
      for (final d in (r['devices'] as List).cast<Map<String, dynamic>>())
        DeviceDto(
            id: d['id'] as String,
            name: d['name'] as String,
            status: d['status'] as String,
            current: d['current'] as bool),
    ];
  }

  /// A pending device announces itself, with the key approvers should seal secrets to.
  Future<void> linkRequest(Uint8List linkPublic) =>
      _send('POST', '/api/v1/devices/me/link-request', {'link_pub': b64e(linkPublic)});

  Future<List<PendingDeviceDto>> pendingDevices() async {
    final r = await _send('GET', '/api/v1/devices/pending');
    return [
      for (final d in (r['pending'] as List).cast<Map<String, dynamic>>())
        PendingDeviceDto(id: d['device_id'] as String, name: d['name'] as String, linkPub: b64d(d['link_pub'] as String)),
    ];
  }

  /// One key package of another device of the same account (handed out once).
  Future<Uint8List> takeDeviceKeyPackage(String deviceId) async =>
      b64d((await _send('POST', '/api/v1/devices/$deviceId/key-package'))['key_package'] as String);

  Future<void> approveDevice(String deviceId, Uint8List bundle) =>
      _send('POST', '/api/v1/devices/$deviceId/approve', {'bundle': b64e(bundle)});

  /// Secrets an approving device sealed to this one, or null if none are waiting.
  Future<Uint8List?> bundle() async {
    try {
      return b64d((await _send('GET', '/api/v1/devices/me/bundle'))['bundle'] as String);
    } on ApiException catch (e) {
      if (e.status == 404) return null;
      rethrow;
    }
  }

  Future<void> deleteBundle() => _send('DELETE', '/api/v1/devices/me/bundle');

  Future<void> revokeDevice(String deviceId) => _send('POST', '/api/v1/devices/$deviceId/revoke');

  /// Add devices to an existing conversation with an MLS commit (for existing members) and one
  /// Welcome (for the new devices). A 409 "conversation changed" means someone else committed
  /// first: catch up and try again. Returns the commit's sequence number.
  Future<int> addDevices(String conversation,
          {required Uint8List commit,
          required Uint8List welcome,
          required List<String> recipients,
          required int baseSeq}) async =>
      (await _send('POST', '/api/v1/conversations/$conversation/devices', {
        'commit': b64e(commit),
        'welcome': b64e(welcome),
        'recipients': recipients,
        'base_seq': baseSeq,
      }))['seq'] as int;

  // ----- history archive and recovery -----

  Future<void> putArchive(String conversation, List<({int seq, Uint8List data})> entries) =>
      _send('PUT', '/api/v1/archive/$conversation', {
        'entries': [for (final e in entries) {'seq': e.seq, 'data': b64e(e.data)}],
      });

  Future<List<({int seq, Uint8List data})>> archive(String conversation, int after) async {
    final r = await _send('GET', '/api/v1/archive/$conversation?after=$after&limit=200');
    return [
      for (final e in (r['entries'] as List).cast<Map<String, dynamic>>())
        (seq: e['seq'] as int, data: b64d(e['data'] as String)),
    ];
  }

  /// Store the history key wrapped under the recovery key. Without [replace] this only creates
  /// the keys (409 if they already exist); with it, an existing recovery key is replaced.
  Future<void> putAccountKeys(
          {required Uint8List wrappedHistoryKey, required Uint8List recoveryAuth, bool replace = false}) =>
      _send('PUT', '/api/v1/account/keys', {
        'wrapped_hist_key': b64e(wrappedHistoryKey),
        'recovery_auth': b64e(recoveryAuth),
        'replace': replace,
      });

  /// The history key wrapped under the recovery key, or null if the account has none yet.
  Future<Uint8List?> accountKeys() async {
    try {
      return b64d((await _send('GET', '/api/v1/account/keys'))['wrapped_hist_key'] as String);
    } on ApiException catch (e) {
      if (e.status == 404) return null;
      rethrow;
    }
  }

  /// Prove possession of the recovery key. On success this device becomes the account's only
  /// approved device and the wrapped history key comes back.
  Future<Uint8List> recover(Uint8List recoveryAuth) async =>
      b64d((await _send('POST', '/api/v1/devices/me/recover', {'recovery_auth': b64e(recoveryAuth)}))['wrapped_hist_key'] as String);

  Future<void> putKeyPackages(List<Uint8List> packages) =>
      _send('PUT', '/api/v1/devices/me/key-packages', {'key_packages': packages.map(b64e).toList()});

  Future<int> keyPackageCount() async =>
      (await _send('GET', '/api/v1/devices/me/key-packages/count'))['count'] as int;

  /// One key package per device of [username], each handed out exactly once.
  Future<List<({String deviceId, Uint8List keyPackage})>> takeKeyPackages(String username) async {
    // Taking a package is safe to repeat (a spare one is merely used up).
    final r = await _send('POST', '/api/v1/users/${Uri.encodeComponent(username)}/key-packages', null, true);
    return [
      for (final d in (r['devices'] as List).cast<Map<String, dynamic>>())
        (deviceId: d['device_id'] as String, keyPackage: b64d(d['key_package'] as String)),
    ];
  }

  // ----- conversations -----

  Future<void> createConversation({
    required String id,
    required String member,
    required Uint8List welcome,
    required List<String> recipients,
  }) =>
      _send('POST', '/api/v1/conversations',
          {'id': id, 'member': member, 'welcome': b64e(welcome), 'recipients': recipients});

  Future<List<ConversationDto>> conversations() async {
    final r = await _send('GET', '/api/v1/conversations');
    return [
      for (final c in (r['conversations'] as List).cast<Map<String, dynamic>>())
        ConversationDto(
          id: c['id'] as String,
          state: c['state'] as String,
          lastSeq: c['last_seq'] as int,
          members: [
            for (final m in (c['members'] as List).cast<Map<String, dynamic>>())
              (username: m['username'] as String, state: m['state'] as String),
          ],
        ),
    ];
  }

  Future<void> accept(String id) => _send('POST', '/api/v1/conversations/$id/accept');

  Future<void> decline(String id) => _send('POST', '/api/v1/conversations/$id/decline');

  Future<int> postMessage(String id, int kind, Uint8List data) async =>
      (await _send('POST', '/api/v1/conversations/$id/messages', {'kind': kind, 'data': b64e(data)}))['seq'] as int;

  Future<List<LogEntryDto>> messages(String id, int after) async {
    final r = await _send('GET', '/api/v1/conversations/$id/messages?after=$after&limit=200');
    return [
      for (final m in (r['messages'] as List).cast<Map<String, dynamic>>())
        LogEntryDto(seq: m['seq'] as int, kind: m['kind'] as int, data: b64d(m['data'] as String)),
    ];
  }

  Future<void> ack(String id, int seq) => _send('POST', '/api/v1/conversations/$id/ack', {'seq': seq});

  Future<List<WelcomeDto>> welcomes() async {
    final r = await _send('GET', '/api/v1/welcomes');
    return [
      for (final w in (r['welcomes'] as List).cast<Map<String, dynamic>>())
        WelcomeDto(
          id: w['id'] as int,
          conversationId: w['conversation_id'] as String,
          joinSeq: w['join_seq'] as int,
          data: b64d(w['data'] as String),
        ),
    ];
  }

  Future<void> deleteWelcome(int id) => _send('DELETE', '/api/v1/welcomes/$id');

  void close() => _http.close();
}
