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
    mls_state_survives_export_import,
    mls_own_message_is_reported_not_decrypted,
    mls_one_commit_adds_several_devices_and_old_members_follow,
    mls_blob_rejects_wrong_key_and_tampering,
    typing_frames_roundtrip_between_members,
    typing_frames_are_padded_to_buckets,
    typing_frames_reject_tampering_wrong_key_and_wrong_conversation,
    typing_long_drafts_keep_the_tail_on_a_char_boundary,
    api_end_to_end_chat_and_typing,
    api_errors_are_returned_not_panicked,
    api_password_login_through_the_byte_api,
);
