// Web: the Rust core is a WebAssembly module (crates/yap-wasm) loaded by web/yap_boot.js, which
// exposes `yapCall` and a `yapReady` promise on the page.

import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'backend.dart';

@JS('yapCall')
external JSUint8Array _yapCall(JSUint8Array request);

class WebBackend implements CoreBackend {
  @override
  Uint8List call(Uint8List request) => _yapCall(request.toJS).toDart;
}

Future<CoreBackend> openBackend() async {
  final ready = globalContext.getProperty<JSAny?>('yapReady'.toJS);
  if (ready == null) {
    throw StateError('The crypto core did not load (yapReady missing).');
  }
  await (ready as JSPromise).toDart;
  return WebBackend();
}
