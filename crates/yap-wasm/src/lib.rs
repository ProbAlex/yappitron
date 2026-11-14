//! wasm-bindgen entry point over [`yap_core::api::call`] for the browser.

use wasm_bindgen::prelude::*;

/// Run one request; see `yap_core::api` for the request/response byte format.
#[wasm_bindgen]
pub fn call(request: &[u8]) -> Vec<u8> {
    yap_core::api::call(request)
}
