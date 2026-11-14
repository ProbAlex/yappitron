//! Browser/WASM test runner (`wasm-bindgen-test`). Runs the exact same logic as `native.rs`.
#![cfg(target_arch = "wasm32")]

mod common;

use wasm_bindgen_test::*;

macro_rules! wasm {
    ($($name:ident),* $(,)?) => { $( #[wasm_bindgen_test] fn $name() { common::$name(); } )* };
}

wasm!(
    auth_correct_password_logs_in_and_keys_match,
    auth_wrong_password_fails_on_the_client,
    auth_unknown_user_is_indistinguishable_from_wrong_password,
    auth_record_is_bound_to_username,
    mls_two_devices_chat_and_share_typing_key,
    mls_outsider_cannot_decrypt,
);
