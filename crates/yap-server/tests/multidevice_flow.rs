//! Multi-device: approving a new device, adding it to existing conversations, the encrypted
//! history archive, recovery, revocation, and the live events. Real MLS and link crypto from
//! `yap-core`, a real Postgres, and (for events) a real socket.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.

mod common;

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use common::*;
use serde_json::json;
use yap_core::{link, mls, vault};

/// Two people with an accepted conversation and two messages of history (seq 1 and 2).
async fn chatting(h: &Harness) -> (Client, Client, uuid::Uuid) {
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(h, &bob.username).await;
    bob.join_pending(h).await;
    bob.post(
        h,
        &format!("/api/v1/conversations/{conv}/accept"),
        json!({}),
    )
    .await;
    assert_eq!(alice.send(h, conv, "old message from alice").await.1, 1);
    assert_eq!(bob.read(h, conv, 0).await, vec!["old message from alice"]);
    assert_eq!(bob.send(h, conv, "old message from bob").await.1, 2);
    assert_eq!(alice.read(h, conv, 1).await, vec!["old message from bob"]);
    (alice, bob, conv)
}

#[tokio::test]
async fn a_second_device_is_pending_and_powerless_until_approved() {
    let Some(h) = harness().await else { return };
    let (alice, bob, _conv) = chatting(&h).await;
    let mut laptop = h.add_pending_device(&alice, "laptop").await;

    let (_, me) = laptop.get(&h, "/api/v1/devices/me").await;
    assert_eq!(me["status"], "pending");
    let (_, me) = alice.get(&h, "/api/v1/devices/me").await;
    assert_eq!(
        me["status"], "approved",
        "the first device is approved automatically"
    );

    // A pending device can manage its key packages (approvers consume one per conversation).
    let (s, v) = laptop
        .get(&h, "/api/v1/devices/me/key-packages/count")
        .await;
    assert_eq!((s, v["count"].as_i64()), (StatusCode::OK, Some(10)));

    // Pending: cannot read conversations, welcomes or archive, and cannot send.
    for path in [
        "/api/v1/conversations",
        "/api/v1/welcomes",
        "/api/v1/devices/pending",
    ] {
        assert_eq!(
            laptop.get(&h, path).await.0,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    // Nobody can hand it out in a new conversation: Bob only gets Alice's approved phone.
    let (_, v) = bob
        .post(
            &h,
            &format!("/api/v1/users/{}/key-packages", alice.username),
            json!({}),
        )
        .await;
    let ids: Vec<&str> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![alice.device_id.as_str()]);

    // It can announce itself; the phone then sees it (and only the phone: Bob never does).
    laptop.request_link(&h).await;
    let (_, p) = alice.get(&h, "/api/v1/devices/pending").await;
    let pending = p["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["device_id"], laptop.device_id);
    assert_eq!(pending[0]["link_pub"], B64.encode(laptop.link.unwrap().1));
    assert_eq!(
        bob.get(&h, "/api/v1/devices/pending").await.1["pending"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let (_, list) = alice.get(&h, "/api/v1/devices").await;
    assert_eq!(list["devices"].as_array().unwrap().len(), 2);
    // Someone else's pending device cannot be approved by me.
    let (s, _) = bob
        .post(
            &h,
            &format!("/api/v1/devices/{}/approve", laptop.device_id),
            json!({"bundle": B64.encode(b"x")}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approving_a_device_adds_it_to_the_conversation_and_gives_it_the_history() {
    let Some(h) = harness().await else { return };
    let (phone, bob, conv) = chatting(&h).await;
    let mut laptop = h.add_pending_device(&phone, "laptop").await;
    laptop.request_link(&h).await;
    let (laptop_secret, laptop_pub) = laptop.link.unwrap();

    // 1. The phone shows the person a fingerprint built from what the SERVER handed it; the
    //    laptop shows one built from its own keys. They match only if nothing was swapped.
    let (_, p) = phone.get(&h, "/api/v1/devices/pending").await;
    let link_pub_seen_by_phone = B64
        .decode(p["pending"][0]["link_pub"].as_str().unwrap())
        .unwrap();
    let (_, kp) = phone
        .post(
            &h,
            &format!("/api/v1/devices/{}/key-package", laptop.device_id),
            json!({}),
        )
        .await;
    let kp = B64.decode(kp["key_package"].as_str().unwrap()).unwrap();
    let fp_phone = link::fingerprint(
        &mls::key_package_signer(&kp).unwrap(),
        &link_pub_seen_by_phone,
    );
    let fp_laptop = link::fingerprint(&laptop.mls.signer_public(), &laptop_pub);
    assert_eq!(fp_phone, fp_laptop);

    // 2. The phone adds the laptop to the conversation (it has processed up to seq 2) ...
    let (s, v) = phone
        .add_with_key_package(&h, conv, &laptop.device_id, &kp, 2)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["seq"], 3, "the commit takes the next sequence number");
    // ... and approves it, sealing the account's history key to the laptop's link key.
    let history_key = [42u8; 32];
    let bundle = link::seal(&laptop_pub, &history_key).unwrap();
    let (s, _) = phone
        .post(
            &h,
            &format!("/api/v1/devices/{}/approve", laptop.device_id),
            json!({"bundle": B64.encode(bundle)}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // 3. The laptop collects the bundle (once), opens it, and joins from its Welcome.
    let (_, me) = laptop.get(&h, "/api/v1/devices/me").await;
    assert_eq!(me["status"], "approved");
    let (s, b) = laptop.get(&h, "/api/v1/devices/me/bundle").await;
    assert_eq!(s, StatusCode::OK);
    let opened = link::open(
        &laptop_secret,
        &B64.decode(b["bundle"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(opened, history_key);
    assert_eq!(laptop.delete_bundle(&h).await, StatusCode::NO_CONTENT);
    assert_eq!(
        laptop.get(&h, "/api/v1/devices/me/bundle").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(laptop.join_pending(&h).await, vec![conv]);

    // 4. Everyone converges: Bob applies the commit, then messages flow in every direction.
    let (bob_seq, _) = bob.sync(&h, conv, 2).await;
    assert_eq!(bob_seq, 3);
    assert_eq!(
        bob.send(&h, conv, "hello to both of alice's devices")
            .await
            .1,
        4
    );
    let (_, got) = laptop.sync(&h, conv, 3).await;
    assert_eq!(got.len(), 1);
    assert!(
        got[0].0.starts_with(&bob.username),
        "sender is authenticated: {}",
        got[0].0
    );
    assert_eq!(got[0].1, "hello to both of alice's devices");
    let (_, got) = phone.sync(&h, conv, 3).await;
    assert_eq!(got[0].1, "hello to both of alice's devices");

    assert_eq!(laptop.send(&h, conv, "from the laptop").await.1, 5);
    let (_, got) = bob.sync(&h, conv, 4).await;
    assert!(
        got[0].0.starts_with(&phone.username),
        "alice's laptop is recognised as alice"
    );
    assert_ne!(got[0].0, format!("{}/{}", phone.username, phone.device_id));
    assert_eq!(got[0].1, "from the laptop");
    let (_, got) = phone.sync(&h, conv, 4).await;
    assert_eq!(
        got[0].1, "from the laptop",
        "the phone reads what the laptop wrote"
    );
    assert!(
        got[0].0.starts_with(&phone.username),
        "so the app can show it as 'mine'"
    );

    // 5. Old messages are NOT readable through MLS (forward secrecy) ...
    let (_, all) = laptop
        .get(
            &h,
            &format!("/api/v1/conversations/{conv}/messages?after=0"),
        )
        .await;
    let old = B64
        .decode(all["messages"][0]["data"].as_str().unwrap())
        .unwrap();
    assert!(laptop.mls.decrypt(conv.as_bytes(), &old).is_err());

    // ... but are through the archive, sealed under the history key the server never saw.
    let entries: Vec<_> = [
        (1i64, "old message from alice", true),
        (2, "old message from bob", false),
    ]
    .into_iter()
    .map(|(seq, text, mine)| {
        let plain = json!({"f": if mine {"me"} else {"them"}, "t": 1, "x": text}).to_string();
        let sealed = vault::seal(
            &history_key,
            format!("arch:{conv}:{seq}").as_bytes(),
            plain.as_bytes(),
        );
        json!({"seq": seq, "data": B64.encode(sealed)})
    })
    .collect();
    let (s, _) = phone
        .authed_put(
            &h,
            &format!("/api/v1/archive/{conv}"),
            json!({"entries": entries}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, a) = laptop
        .get(&h, &format!("/api/v1/archive/{conv}?after=0"))
        .await;
    let got: Vec<String> = a["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let seq = e["seq"].as_i64().unwrap();
            let sealed = B64.decode(e["data"].as_str().unwrap()).unwrap();
            let plain = vault::open(
                &history_key,
                format!("arch:{conv}:{seq}").as_bytes(),
                &sealed,
            )
            .unwrap();
            serde_json::from_slice::<serde_json::Value>(&plain).unwrap()["x"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(got, ["old message from alice", "old message from bob"]);

    // The archive is per account: Bob sees none of Alice's, and an entry is bound to its seq.
    assert!(
        bob.get(&h, &format!("/api/v1/archive/{conv}")).await.1["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let sealed = B64
        .decode(a["entries"][0]["data"].as_str().unwrap())
        .unwrap();
    assert!(vault::open(&history_key, format!("arch:{conv}:2").as_bytes(), &sealed).is_err());
}

#[tokio::test]
async fn a_stale_commit_is_refused_then_succeeds_after_catching_up() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await;
    bob.post(
        &h,
        &format!("/api/v1/conversations/{conv}/accept"),
        json!({}),
    )
    .await;

    let mut laptop = h.add_pending_device(&alice, "laptop").await;
    h.approve_simple(&alice, &mut laptop).await;
    let mut bob_tablet = h.add_pending_device(&bob, "tablet").await;
    h.approve_simple(&bob, &mut bob_tablet).await;

    // Bob adds his tablet first (seq 1). Alice, still at seq 0, tries to add her laptop.
    let (s, v) = bob.add_to_conversation(&h, conv, &bob_tablet, 0).await;
    assert_eq!((s, v["seq"].as_i64()), (StatusCode::OK, Some(1)));
    let (s, _) = alice.add_to_conversation(&h, conv, &laptop, 0).await;
    assert_eq!(s, StatusCode::CONFLICT, "built on a stale group state");

    // The refused commit left Alice's group untouched: she catches up and retries.
    let (seen, _) = alice.sync(&h, conv, 0).await;
    assert_eq!(seen, 1);
    let (s, v) = alice.add_to_conversation(&h, conv, &laptop, 1).await;
    assert_eq!((s, v["seq"].as_i64()), (StatusCode::OK, Some(2)));

    // Everyone ends up on the same epoch with the same keys.
    assert_eq!(bob_tablet.join_pending(&h).await, vec![conv]);
    assert_eq!(laptop.join_pending(&h).await, vec![conv]);
    bob.sync(&h, conv, 1).await;
    bob_tablet.sync(&h, conv, 1).await;
    let key = alice.mls.typing_key(conv.as_bytes()).unwrap();
    for d in [&bob, &bob_tablet, &laptop] {
        assert_eq!(
            d.mls.typing_key(conv.as_bytes()).unwrap(),
            key,
            "{} is in sync",
            d.device_id
        );
    }
    assert_eq!(laptop.send(&h, conv, "all four devices agree").await.1, 3);
    for d in [&alice, &bob, &bob_tablet] {
        let (_, got) = d.sync(&h, conv, 2).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "all four devices agree");
    }
}

#[tokio::test]
async fn adding_devices_is_restricted() {
    let Some(h) = harness().await else { return };
    let (alice, bob, conv) = chatting(&h).await;
    let eve = h.user("eve").await;
    let mut laptop = h.add_pending_device(&alice, "laptop").await;
    h.approve_simple(&alice, &mut laptop).await;

    // A stranger cannot add devices; an unrelated person's device is not a valid recipient.
    let (s, _) = eve.post(&h, &format!("/api/v1/conversations/{conv}/devices"), json!({"commit": B64.encode(b"x"), "welcome": B64.encode(b"x"), "recipients": [laptop.device_id], "base_seq": 2})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = alice.post(&h, &format!("/api/v1/conversations/{conv}/devices"), json!({"commit": B64.encode(b"x"), "welcome": B64.encode(b"x"), "recipients": [eve.device_id], "base_seq": 2})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // A pending device of ANOTHER account cannot be added by me.
    let mut bob_pending = h.add_pending_device(&bob, "bob tablet").await;
    bob_pending.request_link(&h).await;
    let (s, _) = alice
        .post(
            &h,
            &format!("/api/v1/devices/{}/key-package", bob_pending.device_id),
            json!({}),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "key packages of someone else's device are not mine to take"
    );
    let (s, _) = alice
        .add_with_key_package(
            &h,
            conv,
            &bob_pending.device_id,
            &bob_pending.mls.key_package().unwrap(),
            2,
        )
        .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "pending devices of another account are refused"
    );

    // The same device cannot be added twice. (MLS itself would refuse a duplicate key, so this
    // posts raw bytes to exercise the server's own guard.)
    let (s, _) = alice.add_to_conversation(&h, conv, &laptop, 2).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = alice
        .post(&h, &format!("/api/v1/conversations/{conv}/devices"), json!({"commit": B64.encode(b"x"), "welcome": B64.encode(b"x"), "recipients": [laptop.device_id], "base_seq": 3}))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn the_archive_is_idempotent_private_and_validated() {
    let Some(h) = harness().await else { return };
    let (alice, bob, conv) = chatting(&h).await;
    let eve = h.user("eve").await;
    let entry = |seq: i64| json!({"seq": seq, "data": B64.encode(format!("sealed-{seq}"))});

    for _ in 0..2 {
        let (s, _) = alice
            .authed_put(
                &h,
                &format!("/api/v1/archive/{conv}"),
                json!({"entries": [entry(1), entry(2)]}),
            )
            .await;
        assert_eq!(
            s,
            StatusCode::NO_CONTENT,
            "uploading the same entries twice is harmless"
        );
    }
    let (_, a) = alice.get(&h, &format!("/api/v1/archive/{conv}")).await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 2);
    let (_, a) = alice
        .get(&h, &format!("/api/v1/archive/{conv}?after=1"))
        .await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 1);

    for (bad, why) in [
        (entry(0), "seq 0"),
        (entry(99), "beyond the log"),
        (json!({"seq": 1, "data": ""}), "empty"),
    ] {
        let (s, _) = alice
            .authed_put(
                &h,
                &format!("/api/v1/archive/{conv}"),
                json!({"entries": [bad]}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}");
    }
    let (s, _) = eve.get(&h, &format!("/api/v1/archive/{conv}")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = eve
        .authed_put(
            &h,
            &format!("/api/v1/archive/{conv}"),
            json!({"entries": [entry(1)]}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        bob.get(&h, &format!("/api/v1/archive/{conv}")).await.1["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn revoking_a_device_signs_it_out_and_stops_handing_it_out() {
    let Some(h) = harness().await else { return };
    let (phone, bob, conv) = chatting(&h).await;
    let tablet = h.add_device(&phone, "tablet").await;

    // With two approved devices, either may be removed by the other; the phone is signed out.
    let (s, _) = tablet
        .post(
            &h,
            &format!("/api/v1/devices/{}/revoke", phone.device_id),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        phone.get(&h, "/api/v1/me").await.0,
        StatusCode::UNAUTHORIZED
    );
    // The last approved device can never be removed (that would lock the account).
    let (s, v) = tablet
        .post(
            &h,
            &format!("/api/v1/devices/{}/revoke", tablet.device_id),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");

    // A removed device is no longer offered to people starting conversations, and can't read.
    let carol = h.user("carol").await;
    let (_, v) = carol
        .post(
            &h,
            &format!("/api/v1/users/{}/key-packages", tablet.username),
            json!({}),
        )
        .await;
    assert_eq!(v["devices"].as_array().unwrap().len(), 1);
    assert_eq!(v["devices"][0]["device_id"], tablet.device_id);
    let (_, list) = tablet.get(&h, "/api/v1/devices").await;
    assert_eq!(list["devices"].as_array().unwrap().len(), 1);
    // Re-attaching the removed device is refused outright.
    let session = h.login(&phone.username, PASSWORD).await.unwrap();
    let (s, _) = h
        .authed(
            Method::POST,
            "/api/v1/devices/attach",
            &session,
            Some(json!({"device_id": phone.device_id})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let _ = (bob, conv);
}

#[tokio::test]
async fn the_recovery_key_restores_history_access_and_resets_devices() {
    let Some(h) = harness().await else { return };
    let (phone, _bob, conv) = chatting(&h).await;
    let tablet = h.add_device(&phone, "tablet").await;

    // Set up at signup: the history key wrapped under a recovery key, plus an auth token.
    let (hist_key, recovery_key, recovery_auth) = ([7u8; 32], [9u8; 32], [3u8; 32]);
    let wrapped = vault::seal(&recovery_key, b"hist-key", &hist_key);
    let (s, _) = phone.authed_put(&h, "/api/v1/account/keys", json!({"wrapped_hist_key": B64.encode(&wrapped), "recovery_auth": B64.encode(recovery_auth)})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        tablet.get(&h, "/api/v1/account/keys").await.1["wrapped_hist_key"],
        B64.encode(&wrapped)
    );

    // "I lost everything": a brand-new device signs in. It is pending, and a wrong key is refused.
    let new_device = h.add_pending_device(&phone, "replacement").await;
    assert_eq!(
        new_device.get(&h, "/api/v1/devices/me").await.1["status"],
        "pending"
    );
    let (s, _) = new_device
        .post(
            &h,
            "/api/v1/devices/me/recover",
            json!({"recovery_auth": B64.encode([4u8; 32])}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        new_device.get(&h, "/api/v1/conversations").await.0,
        StatusCode::FORBIDDEN,
        "still pending"
    );

    // The right key makes it the only approved device and returns the wrapped history key.
    let (s, v) = new_device
        .post(
            &h,
            "/api/v1/devices/me/recover",
            json!({"recovery_auth": B64.encode(recovery_auth)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revoked_devices"], 2);
    let unwrapped = vault::open(
        &recovery_key,
        b"hist-key",
        &B64.decode(v["wrapped_hist_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(unwrapped, hist_key);
    assert_eq!(
        new_device.get(&h, "/api/v1/devices/me").await.1["status"],
        "approved"
    );
    for old in [&phone, &tablet] {
        assert_eq!(
            old.get(&h, "/api/v1/me").await.0,
            StatusCode::UNAUTHORIZED,
            "the old devices are signed out"
        );
    }

    // The conversation is still listed (history readable via the archive), but this device is
    // not an MLS member of it: sending needs a new conversation.
    let (_, list) = new_device.get(&h, "/api/v1/conversations").await;
    assert_eq!(list["conversations"][0]["id"], conv.to_string());
    let (s, _) = new_device
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/messages"),
            json!({"kind": 1, "data": B64.encode(b"x")}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // An account that never set a recovery key cannot use this path.
    let lonely = h.user("lonely").await;
    let pending = h.add_pending_device(&lonely, "second").await;
    let (s, _) = pending
        .post(
            &h,
            "/api/v1/devices/me/recover",
            json!({"recovery_auth": B64.encode(recovery_auth)}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn link_requests_approvals_and_removals_are_pushed_live() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let alice = h.user("alice").await;
    let mut laptop = h.add_pending_device(&alice, "laptop").await;
    let mut ws_phone = Ws::connect(addr, &alice.token).await;
    // A pending device can connect (to hear its approval) but receives no conversation data.
    let mut ws_laptop = Ws::connect(addr, &laptop.token).await;

    laptop.request_link(&h).await;
    let ask = ws_phone
        .next_of("link_request", 3000)
        .await
        .expect("the phone is told");
    assert_eq!(ask["device_id"], laptop.device_id);
    assert_eq!(ask["name"], "laptop");

    let bundle = link::seal(&laptop.link.unwrap().1, b"k").unwrap();
    alice
        .post(
            &h,
            &format!("/api/v1/devices/{}/approve", laptop.device_id),
            json!({"bundle": B64.encode(bundle)}),
        )
        .await;
    assert!(
        ws_laptop.next_of("approved", 3000).await.is_some(),
        "the laptop is told it was approved"
    );

    alice
        .post(
            &h,
            &format!("/api/v1/devices/{}/revoke", laptop.device_id),
            json!({}),
        )
        .await;
    assert!(
        ws_laptop.next_of("revoked", 3000).await.is_some(),
        "and told when it is removed"
    );
}
