//! Test logic shared by the native (`cargo test`) and browser (`wasm-bindgen-test`) runners.
#![allow(dead_code)]

use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use yap_core::auth::{self, Error};
use yap_core::mls::Device;
use yap_proto::auth::{CONTEXT, YapOpaque, opaque_ke};

const SERVER_ID: &[u8] = b"yap.leafyserver.tech";

type Record = ServerRegistration<YapOpaque>;

fn register(setup: &ServerSetup<YapOpaque>, username: &[u8], password: &[u8]) -> Record {
    let (request, state) = auth::register_start(password).unwrap();
    let response = ServerRegistration::<YapOpaque>::start(
        setup,
        RegistrationRequest::deserialize(&request).unwrap(),
        username,
    )
    .unwrap()
    .message
    .serialize();
    let upload = auth::register_finish(state, password, username, SERVER_ID, &response).unwrap();
    ServerRegistration::finish(RegistrationUpload::<YapOpaque>::deserialize(&upload).unwrap())
}

/// Returns (client session key, server session key) or the client error.
fn login(
    setup: &ServerSetup<YapOpaque>,
    record: Option<Record>,
    username: &[u8],
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (request, state) = auth::login_start(password).unwrap();
    let params = || ServerLoginParameters {
        context: Some(CONTEXT),
        identifiers: Identifiers {
            client: Some(username),
            server: Some(SERVER_ID),
        },
    };
    let server = ServerLogin::start(
        &mut OsRng,
        setup,
        record,
        CredentialRequest::deserialize(&request).unwrap(),
        username,
        params(),
    )
    .unwrap();
    let response = server.message.serialize();
    let out = auth::login_finish(state, password, username, SERVER_ID, &response)?;
    let finished = server
        .state
        .finish(
            CredentialFinalization::deserialize(&out.finalization).unwrap(),
            params(),
        )
        .unwrap();
    Ok((out.session_key, finished.session_key.to_vec()))
}

pub fn auth_correct_password_logs_in_and_keys_match() {
    let setup = ServerSetup::<YapOpaque>::new(&mut OsRng);
    let record = register(&setup, b"alice", b"correct horse battery staple");
    let (client_key, server_key) = login(
        &setup,
        Some(record),
        b"alice",
        b"correct horse battery staple",
    )
    .unwrap();
    assert_eq!(client_key, server_key);
    assert!(!client_key.is_empty());
}

pub fn auth_wrong_password_fails_on_the_client() {
    let setup = ServerSetup::<YapOpaque>::new(&mut OsRng);
    let record = register(&setup, b"alice", b"correct horse battery staple");
    let r = login(&setup, Some(record), b"alice", b"wrong password");
    assert!(matches!(r, Err(Error::LoginFailed)));
}

pub fn auth_unknown_user_is_indistinguishable_from_wrong_password() {
    // With no record the server still answers (a fake credential response), so an attacker
    // cannot tell "no such user" from "wrong password".
    let setup = ServerSetup::<YapOpaque>::new(&mut OsRng);
    let r = login(&setup, None, b"nobody", b"whatever");
    assert!(matches!(r, Err(Error::LoginFailed)));
}

pub fn auth_record_is_bound_to_username() {
    // Replaying alice's record under another username must not log in.
    let setup = ServerSetup::<YapOpaque>::new(&mut OsRng);
    let record = register(&setup, b"alice", b"pw-pw-pw-pw-pw");
    let r = login(&setup, Some(record), b"mallory", b"pw-pw-pw-pw-pw");
    assert!(matches!(r, Err(Error::LoginFailed)));
}

pub fn mls_two_devices_chat_and_share_typing_key() {
    let alice = Device::new(b"alice/phone").unwrap();
    let bob = Device::new(b"bob/laptop").unwrap();

    // Bob publishes a key package; Alice starts the chat and adds him.
    let bob_kp = bob.key_package().unwrap();
    let mut alice_conv = alice.create_conversation().unwrap();
    let (_commit, welcome) = alice.add_member(&mut alice_conv, &bob_kp).unwrap();
    let mut bob_conv = bob.join(&welcome).unwrap();

    assert_eq!(alice_conv.member_count(), 2);
    assert_eq!(bob_conv.member_count(), 2);
    assert_eq!(alice_conv.epoch(), bob_conv.epoch());

    // Messages flow both ways.
    let ct = alice.encrypt(&mut alice_conv, b"hello bob").unwrap();
    assert_eq!(bob.decrypt(&mut bob_conv, &ct).unwrap(), b"hello bob");
    let ct = bob.encrypt(&mut bob_conv, b"hi alice").unwrap();
    assert_eq!(alice.decrypt(&mut alice_conv, &ct).unwrap(), b"hi alice");

    // The ciphertext must not contain the plaintext.
    let ct = alice
        .encrypt(&mut alice_conv, b"super secret text")
        .unwrap();
    assert!(!ct.windows(5).any(|w| w == b"secret"));

    // Both sides derive the same live-typing key, and it is not trivially zero.
    let ka = alice.typing_key(&alice_conv).unwrap();
    let kb = bob.typing_key(&bob_conv).unwrap();
    assert_eq!(ka, kb);
    assert_ne!(ka, [0u8; 32]);
}

pub fn mls_outsider_cannot_decrypt() {
    let alice = Device::new(b"alice/phone").unwrap();
    let bob = Device::new(b"bob/laptop").unwrap();
    let eve = Device::new(b"eve/laptop").unwrap();

    let mut alice_conv = alice.create_conversation().unwrap();
    let (_c, welcome) = alice
        .add_member(&mut alice_conv, &bob.key_package().unwrap())
        .unwrap();
    let _bob_conv = bob.join(&welcome).unwrap();

    // Eve never got a Welcome, so she cannot join with Bob's.
    assert!(eve.join(&welcome).is_err());
}
