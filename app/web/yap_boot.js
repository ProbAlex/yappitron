// Loads the Rust core (compiled to WebAssembly by `just web-core`) before the Flutter app
// starts. The Dart side awaits `yapReady` and then calls `yapCall(bytes) -> bytes`.
import init, { call } from './yap_wasm/yap_wasm.js';

globalThis.yapReady = init().then(() => {
  globalThis.yapCall = (request) => call(request);
});
