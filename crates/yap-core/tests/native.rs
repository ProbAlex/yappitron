//! Native test runner (`cargo test`). The logic lives in `common` and also runs in WASM.
#![cfg(not(target_arch = "wasm32"))]

mod common;

macro_rules! native {
    ($($name:ident),* $(,)?) => { $( #[test] fn $name() { common::$name(); } )* };
}

native!(
    auth_correct_password_logs_in_and_keys_match,
    auth_wrong_password_fails_on_the_client,
    auth_unknown_user_is_indistinguishable_from_wrong_password,
    auth_record_is_bound_to_username,
    mls_two_devices_chat_and_share_typing_key,
    mls_outsider_cannot_decrypt,
);
