// Byte format of the core API (see docs/CORE_API.md).
//
//   request  = method(u16 LE) | argc(u32 LE) | { len(u32 LE) | bytes }*
//   response = status(u8: 0 ok, 1 error) | count(u32 LE) | { len(u32 LE) | bytes }*
//
// dart2js cannot read/write 64-bit integers through ByteData, so u64 values are handled as two
// 32-bit halves (exact up to 2^53, far beyond any sequence number or epoch here).

import 'dart:typed_data';

/// Thrown when the core reports an error.
class CoreException implements Exception {
  CoreException(this.message);
  final String message;

  /// MLS cannot decrypt a sender's own ciphertext; callers skip such echoes.
  bool get isOwnMessage => message == 'own message';

  @override
  String toString() => 'CoreException: $message';
}

Uint8List encodeRequest(int method, List<Uint8List> args) {
  var size = 2 + 4;
  for (final a in args) {
    size += 4 + a.length;
  }
  final out = Uint8List(size);
  final view = ByteData.sublistView(out);
  var at = 0;
  view.setUint16(at, method, Endian.little);
  at += 2;
  view.setUint32(at, args.length, Endian.little);
  at += 4;
  for (final a in args) {
    view.setUint32(at, a.length, Endian.little);
    at += 4;
    out.setRange(at, at + a.length, a);
    at += a.length;
  }
  return out;
}

/// Decode a response; throws [CoreException] if the core reported an error.
List<Uint8List> decodeResponse(Uint8List bytes) {
  if (bytes.length < 5) throw CoreException('truncated response');
  final view = ByteData.sublistView(bytes);
  final ok = bytes[0] == 0;
  final count = view.getUint32(1, Endian.little);
  var at = 5;
  final items = <Uint8List>[];
  for (var i = 0; i < count; i++) {
    if (at + 4 > bytes.length) throw CoreException('truncated response');
    final len = view.getUint32(at, Endian.little);
    at += 4;
    if (at + len > bytes.length) throw CoreException('truncated response');
    items.add(Uint8List.sublistView(bytes, at, at + len));
    at += len;
  }
  if (!ok) {
    throw CoreException(items.isEmpty ? 'unknown error' : String.fromCharCodes(items.first));
  }
  return items;
}

Uint8List u32le(int v) {
  final b = ByteData(4)..setUint32(0, v, Endian.little);
  return b.buffer.asUint8List();
}

Uint8List u64le(int v) {
  final b = ByteData(8)
    ..setUint32(0, v % 4294967296, Endian.little)
    ..setUint32(4, v ~/ 4294967296, Endian.little);
  return b.buffer.asUint8List();
}

int readU32(Uint8List v) => ByteData.sublistView(v).getUint32(0, Endian.little);

int readU64(Uint8List v) {
  final view = ByteData.sublistView(v);
  return view.getUint32(4, Endian.little) * 4294967296 + view.getUint32(0, Endian.little);
}
