// Native platforms: the Rust core is a shared library reached through a two-function C ABI
// (crates/yap-ffi). All calls are synchronous.

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'backend.dart';

typedef _CallC = Pointer<Uint8> Function(Pointer<Uint8>, IntPtr, Pointer<IntPtr>);
typedef _CallDart = Pointer<Uint8> Function(Pointer<Uint8>, int, Pointer<IntPtr>);
typedef _FreeC = Void Function(Pointer<Uint8>, IntPtr);
typedef _FreeDart = void Function(Pointer<Uint8>, int);

class NativeBackend implements CoreBackend {
  NativeBackend._(DynamicLibrary lib)
      : _call = lib.lookupFunction<_CallC, _CallDart>('yap_call'),
        _free = lib.lookupFunction<_FreeC, _FreeDart>('yap_free');

  final _CallDart _call;
  final _FreeDart _free;

  @override
  Uint8List call(Uint8List request) {
    final req = malloc<Uint8>(request.isEmpty ? 1 : request.length);
    final outLen = malloc<IntPtr>();
    try {
      req.asTypedList(request.length).setAll(0, request);
      final ptr = _call(req, request.length, outLen);
      final len = outLen.value;
      final copy = Uint8List.fromList(ptr.asTypedList(len));
      _free(ptr, len);
      return copy;
    } finally {
      malloc.free(req);
      malloc.free(outLen);
    }
  }
}

DynamicLibrary _openLibrary() {
  // Tests and development can point at a specific build.
  final override = Platform.environment['YAP_NATIVE_LIB'];
  if (override != null && override.isNotEmpty) return DynamicLibrary.open(override);
  if (Platform.isIOS) return DynamicLibrary.process(); // statically linked
  if (Platform.isMacOS) return DynamicLibrary.open('libyap_ffi.dylib');
  if (Platform.isWindows) return DynamicLibrary.open('yap_ffi.dll');
  return DynamicLibrary.open('libyap_ffi.so'); // Linux, Android
}

Future<CoreBackend> openBackend() async => NativeBackend._(_openLibrary());
