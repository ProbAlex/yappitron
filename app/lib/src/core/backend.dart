import 'dart:typed_data';

export 'backend_stub.dart'
    if (dart.library.js_interop) 'backend_web.dart'
    if (dart.library.ffi) 'backend_native.dart';

/// Transport to the Rust core: one function taking and returning bytes.
abstract interface class CoreBackend {
  Uint8List call(Uint8List request);
}
