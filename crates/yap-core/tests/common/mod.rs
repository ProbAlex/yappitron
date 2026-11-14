//! Test logic shared by the native (`cargo test`) and browser (`wasm-bindgen-test`) runners.
#![allow(dead_code)]

use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use yap_core::api::{self, method};
use yap_core::auth::{self, Error};
use yap_core::mls::Device;
use yap_core::typing;
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

const GID: &[u8] = b"conversation-1";

/// Alice creates a conversation and adds Bob; returns both devices.
fn paired() -> (Device, Device) {
    let alice = Device::new(b"alice/phone").unwrap();
    let bob = Device::new(b"bob/laptop").unwrap();
    alice.create_conversation(GID).unwrap();
    let (_commit, welcome) = alice
        .add_members(GID, &[&bob.key_package().unwrap()])
        .unwrap();
    assert_eq!(bob.join(&welcome).unwrap(), GID);
    (alice, bob)
}

pub fn mls_two_devices_chat_and_share_typing_key() {
    let (alice, bob) = paired();
    assert_eq!(alice.member_count(GID).unwrap(), 2);
    assert_eq!(bob.member_count(GID).unwrap(), 2);
    assert_eq!(alice.epoch(GID).unwrap(), bob.epoch(GID).unwrap());

    let ct = alice.encrypt(GID, b"hello bob").unwrap();
    assert_eq!(bob.decrypt(GID, &ct).unwrap(), b"hello bob");
    let ct = bob.encrypt(GID, b"hi alice").unwrap();
    assert_eq!(alice.decrypt(GID, &ct).unwrap(), b"hi alice");

    // The ciphertext must not contain the plaintext.
    let ct = alice.encrypt(GID, b"super secret text").unwrap();
    assert!(!ct.windows(5).any(|w| w == b"secret"));

    let (ka, kb) = (alice.typing_key(GID).unwrap(), bob.typing_key(GID).unwrap());
    assert_eq!(ka, kb);
    assert_ne!(ka, [0u8; 32]);
}

pub fn mls_outsider_cannot_decrypt() {
    let alice = Device::new(b"alice/phone").unwrap();
    let bob = Device::new(b"bob/laptop").unwrap();
    let eve = Device::new(b"eve/laptop").unwrap();
    alice.create_conversation(GID).unwrap();
    let (_c, welcome) = alice
        .add_members(GID, &[&bob.key_package().unwrap()])
        .unwrap();
    bob.join(&welcome).unwrap();
    // Eve never got a Welcome for her own key package, so Bob's cannot be used by her.
    assert!(eve.join(&welcome).is_err());
    assert!(
        eve.encrypt(GID, b"hi").is_err(),
        "Eve is not in the conversation"
    );
}

pub fn mls_state_survives_export_import() {
    let (alice, bob) = paired();
    let ct = alice.encrypt(GID, b"before restart").unwrap();
    assert_eq!(bob.decrypt(GID, &ct).unwrap(), b"before restart");

    let (key_a, key_b) = ([1u8; 32], [2u8; 32]);
    let (blob_a, blob_b) = (alice.export(&key_a).unwrap(), bob.export(&key_b).unwrap());
    drop((alice, bob));

    let alice = Device::import(&blob_a, &key_a).unwrap();
    let bob = Device::import(&blob_b, &key_b).unwrap();
    assert_eq!(alice.name(), b"alice/phone");
    let ct = alice.encrypt(GID, b"after restart").unwrap();
    assert_eq!(bob.decrypt(GID, &ct).unwrap(), b"after restart");
    let ct = bob.encrypt(GID, b"and back").unwrap();
    assert_eq!(alice.decrypt(GID, &ct).unwrap(), b"and back");
}

pub fn mls_own_message_is_reported_not_decrypted() {
    let (alice, bob) = paired();
    let ct = alice.encrypt(GID, b"mine").unwrap();
    assert!(matches!(
        alice.decrypt(GID, &ct),
        Err(yap_core::mls::Error::OwnMessage)
    ));
    // The recipient is unaffected by Alice having seen her own echo.
    assert_eq!(bob.decrypt(GID, &ct).unwrap(), b"mine");
}

pub fn mls_one_commit_adds_several_devices_and_old_members_follow() {
    let alice = Device::new(b"alice/phone").unwrap();
    let alice2 = Device::new(b"alice/laptop").unwrap();
    let bob = Device::new(b"bob/phone").unwrap();
    alice.create_conversation(GID).unwrap();
    let (_c, welcome) = alice
        .add_members(
            GID,
            &[&alice2.key_package().unwrap(), &bob.key_package().unwrap()],
        )
        .unwrap();
    alice2.join(&welcome).unwrap();
    bob.join(&welcome).unwrap();
    assert_eq!(bob.member_count(GID).unwrap(), 3);

    let ct = alice.encrypt(GID, b"to everyone").unwrap();
    assert_eq!(alice2.decrypt(GID, &ct).unwrap(), b"to everyone");
    assert_eq!(bob.decrypt(GID, &ct).unwrap(), b"to everyone");

    // A later commit (adding a fourth device) must be applied by existing members.
    let carol = Device::new(b"carol/phone").unwrap();
    let (commit, welcome) = bob
        .add_members(GID, &[&carol.key_package().unwrap()])
        .unwrap();
    alice.apply_commit(GID, &commit).unwrap();
    alice2.apply_commit(GID, &commit).unwrap();
    carol.join(&welcome).unwrap();
    let epoch = alice.epoch(GID).unwrap();
    assert_eq!(carol.epoch(GID).unwrap(), epoch);
    assert_eq!(
        alice.typing_key(GID).unwrap(),
        carol.typing_key(GID).unwrap()
    );
}

pub fn mls_blob_rejects_wrong_key_and_tampering() {
    let alice = Device::new(b"alice/phone").unwrap();
    let blob = alice.export(&[1u8; 32]).unwrap();
    assert!(Device::import(&blob, &[2u8; 32]).is_err(), "wrong key");
    let mut bad = blob.clone();
    bad[20] ^= 1;
    assert!(Device::import(&bad, &[1u8; 32]).is_err(), "tampered");
    assert!(
        Device::import(&blob[..10], &[1u8; 32]).is_err(),
        "truncated"
    );
    assert!(Device::import(&blob, &[1u8; 32]).is_ok());
}

pub fn typing_frames_roundtrip_between_members() {
    let (alice, bob) = paired();
    let key = alice.typing_key(GID).unwrap();
    let epoch = alice.epoch(GID).unwrap();

    let frame = typing::seal(&key, epoch, GID, 7, "hello wor");
    let opened = typing::open(&bob.typing_key(GID).unwrap(), GID, &frame).unwrap();
    assert_eq!(
        (opened.seq, opened.epoch, opened.text.as_str()),
        (7, epoch, "hello wor")
    );

    // Not the plaintext, and a fresh nonce makes identical drafts encrypt differently.
    assert!(!frame.windows(5).any(|w| w == b"hello"));
    assert_ne!(frame, typing::seal(&key, epoch, GID, 7, "hello wor"));
}

pub fn typing_frames_are_padded_to_buckets() {
    let key = [5u8; 32];
    let sizes: Vec<usize> = ["", "a", "hello world", &"x".repeat(200)]
        .iter()
        .map(|t| typing::seal(&key, 1, GID, 0, t).len())
        .collect();
    assert!(
        sizes.iter().all(|s| *s == sizes[0]),
        "same bucket => same length: {sizes:?}"
    );
    let bigger = typing::seal(&key, 1, GID, 0, &"x".repeat(300)).len();
    assert!(bigger > sizes[0]);
    assert_eq!(
        bigger,
        typing::seal(&key, 1, GID, 0, &"y".repeat(500)).len()
    );
}

pub fn typing_frames_reject_tampering_wrong_key_and_wrong_conversation() {
    let key = [5u8; 32];
    let frame = typing::seal(&key, 3, GID, 1, "secret draft");
    assert!(typing::open(&key, GID, &frame).is_ok());
    assert!(typing::open(&[6u8; 32], GID, &frame).is_err(), "wrong key");
    assert!(
        typing::open(&key, b"other-conversation", &frame).is_err(),
        "wrong conversation"
    );
    let mut bad = frame.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        typing::open(&key, GID, &bad).is_err(),
        "tampered ciphertext"
    );
    let mut bad = frame.clone();
    bad[1] ^= 1; // the epoch is authenticated
    assert!(typing::open(&key, GID, &bad).is_err(), "tampered epoch");
    assert!(typing::open(&key, GID, &frame[..10]).is_err(), "truncated");
    assert!(typing::open(&key, GID, &[]).is_err(), "empty");
}

pub fn typing_long_drafts_keep_the_tail_on_a_char_boundary() {
    let key = [5u8; 32];
    let long = format!("{}{}", "é".repeat(2000), "THE END");
    let opened = typing::open(&key, GID, &typing::seal(&key, 1, GID, 0, &long)).unwrap();
    assert!(opened.text.ends_with("THE END"));
    assert!(opened.text.len() <= typing::MAX_TEXT_BYTES);
    assert!(
        opened
            .text
            .chars()
            .all(|c| c == 'é' || "THE END".contains(c))
    );
}

// ----- the byte-RPC layer the platform bindings use -----

fn arg(a: &[u8]) -> Vec<u8> {
    let mut v = (a.len() as u32).to_le_bytes().to_vec();
    v.extend(a);
    v
}

/// Call the core the way a binding does and return the result items.
fn rpc(m: u16, args: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
    let mut req = m.to_le_bytes().to_vec();
    req.extend((args.len() as u32).to_le_bytes());
    for a in args {
        req.extend(arg(a));
    }
    let resp = api::call(&req);
    let count = u32::from_le_bytes(resp[1..5].try_into().unwrap()) as usize;
    let mut items = vec![];
    let mut at = 5;
    for _ in 0..count {
        let len = u32::from_le_bytes(resp[at..at + 4].try_into().unwrap()) as usize;
        items.push(resp[at + 4..at + 4 + len].to_vec());
        at += 4 + len;
    }
    if resp[0] == 0 {
        Ok(items)
    } else {
        Err(String::from_utf8(items.remove(0)).unwrap())
    }
}

pub fn api_end_to_end_chat_and_typing() {
    let new = |name: &[u8]| rpc(method::DEVICE_NEW, &[name]).unwrap().remove(0);
    let (alice, bob) = (new(b"alice/web"), new(b"bob/linux"));

    let kp = rpc(method::KEY_PACKAGE, &[&bob]).unwrap().remove(0);
    rpc(method::CONV_CREATE, &[&alice, GID]).unwrap();
    let mut added = rpc(method::CONV_ADD_MEMBERS, &[&alice, GID, &kp]).unwrap();
    let welcome = added.remove(1);
    assert_eq!(rpc(method::CONV_JOIN, &[&bob, &welcome]).unwrap()[0], GID);

    let ct = rpc(method::CONV_ENCRYPT, &[&alice, GID, b"over the wire"])
        .unwrap()
        .remove(0);
    assert_eq!(
        rpc(method::CONV_DECRYPT, &[&bob, GID, &ct]).unwrap()[0],
        b"over the wire"
    );

    let frame = rpc(
        method::TYPING_SEAL,
        &[&alice, GID, &9u64.to_le_bytes(), "typing…".as_bytes()],
    )
    .unwrap()
    .remove(0);
    let opened = rpc(method::TYPING_OPEN, &[&bob, GID, &frame]).unwrap();
    assert_eq!(opened[0], 9u64.to_le_bytes());
    assert_eq!(opened[1], "typing…".as_bytes());

    // Persist and restore through the API.
    let key = [3u8; 32];
    let blob = rpc(method::DEVICE_EXPORT, &[&alice, &key])
        .unwrap()
        .remove(0);
    rpc(method::DEVICE_FREE, &[&alice]).unwrap();
    assert!(rpc(method::KEY_PACKAGE, &[&alice]).is_err(), "freed handle");
    let restored = rpc(method::DEVICE_IMPORT, &[&blob, &key])
        .unwrap()
        .remove(0);
    let ct = rpc(method::CONV_ENCRYPT, &[&restored, GID, b"still works"])
        .unwrap()
        .remove(0);
    assert_eq!(
        rpc(method::CONV_DECRYPT, &[&bob, GID, &ct]).unwrap()[0],
        b"still works"
    );
}

pub fn api_errors_are_returned_not_panicked() {
    assert!(rpc(method::KEY_PACKAGE, &[&1234u32.to_le_bytes()]).is_err());
    assert!(rpc(method::KEY_PACKAGE, &[]).is_err(), "missing argument");
    assert!(rpc(9999, &[]).is_err(), "unknown method");
    assert_eq!(
        rpc(method::USERNAME_CANONICALIZE, &[b"Alice_1"]).unwrap()[0],
        b"alice_1"
    );
    assert!(rpc(method::USERNAME_CANONICALIZE, &[b"no spaces"]).is_err());
}

pub fn api_password_login_through_the_byte_api() {
    let setup = ServerSetup::<YapOpaque>::new(&mut OsRng);
    let (user, pw): (&[u8], &[u8]) = (b"alice", b"correct horse battery staple");

    // Registration, with the server half done directly.
    let mut start = rpc(method::AUTH_REGISTER_START, &[pw]).unwrap();
    let request = start.remove(1);
    let response = ServerRegistration::<YapOpaque>::start(
        &setup,
        RegistrationRequest::deserialize(&request).unwrap(),
        user,
    )
    .unwrap()
    .message
    .serialize();
    let upload = rpc(
        method::AUTH_REGISTER_FINISH,
        &[&start[0], pw, user, SERVER_ID, &response],
    )
    .unwrap()
    .remove(0);
    let record =
        ServerRegistration::finish(RegistrationUpload::<YapOpaque>::deserialize(&upload).unwrap());

    // Login.
    let mut start = rpc(method::AUTH_LOGIN_START, &[pw]).unwrap();
    let request = start.remove(1);
    let server = ServerLogin::start(
        &mut OsRng,
        &setup,
        Some(record),
        CredentialRequest::deserialize(&request).unwrap(),
        user,
        ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers {
                client: Some(user),
                server: Some(SERVER_ID),
            },
        },
    )
    .unwrap();
    let out = rpc(
        method::AUTH_LOGIN_FINISH,
        &[&start[0], pw, user, SERVER_ID, &server.message.serialize()],
    )
    .unwrap();
    assert!(!out[1].is_empty(), "session key");
}
