// The WebSocket connection: live messages, welcomes and the live-typing relay. Reconnects with
// backoff; after every (re)connect the server replays anything not yet acknowledged.

import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

enum RealtimeStatus { connecting, online, offline }

class Realtime {
  Realtime(this._uri, this._token);

  final Uri _uri;
  final String _token;

  final _events = StreamController<Map<String, dynamic>>.broadcast();
  final _status = StreamController<RealtimeStatus>.broadcast();
  WebSocketChannel? _channel;
  bool _closed = false;
  int _attempt = 0;
  Timer? _retry;
  Timer? _heartbeat;

  /// Server events: msg, welcome, member, typing.
  Stream<Map<String, dynamic>> get events => _events.stream;
  Stream<RealtimeStatus> get status => _status.stream;

  void start() => _connect();

  Future<void> _connect() async {
    if (_closed) return;
    _status.add(RealtimeStatus.connecting);
    try {
      final channel = WebSocketChannel.connect(_uri);
      _channel = channel;
      await channel.ready;
      channel.sink.add(jsonEncode({'t': 'auth', 'token': _token}));
      var ready = false;
      channel.stream.listen(
        (data) {
          final v = jsonDecode(data as String) as Map<String, dynamic>;
          if (v['t'] == 'ready') {
            ready = true;
            _attempt = 0;
            _status.add(RealtimeStatus.online);
            return;
          }
          if (v['t'] != 'pong') _events.add(v);
        },
        onDone: () => _lost(ready),
        onError: (_) => _lost(ready),
        cancelOnError: true,
      );
      _heartbeat?.cancel();
      _heartbeat = Timer.periodic(const Duration(seconds: 25), (_) => _send({'t': 'ping'}));
    } catch (_) {
      _lost(false);
    }
  }

  void _lost(bool wasReady) {
    _heartbeat?.cancel();
    _channel = null;
    if (_closed) return;
    _status.add(RealtimeStatus.offline);
    final seconds = [1, 2, 4, 8, 15, 30][_attempt.clamp(0, 5)];
    _attempt++;
    _retry?.cancel();
    _retry = Timer(Duration(seconds: seconds), _connect);
  }

  void _send(Map<String, dynamic> v) {
    try {
      _channel?.sink.add(jsonEncode(v));
    } catch (_) {}
  }

  void sendTyping(String conversation, String frameB64) =>
      _send({'t': 'typing', 'c': conversation, 'f': frameB64});

  void sendAck(String conversation, int seq) => _send({'t': 'ack', 'c': conversation, 'seq': seq});

  Future<void> close() async {
    _closed = true;
    _retry?.cancel();
    _heartbeat?.cancel();
    await _channel?.sink.close();
    await _events.close();
    await _status.close();
  }
}
