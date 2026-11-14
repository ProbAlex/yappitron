//! Conversations, message requests and the encrypted log, over REST, with real MLS clients.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.

mod common;

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use common::*;
use serde_json::json;

#[tokio::test]
async fn message_request_accept_and_two_way_chat() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);

    // Alice starts a conversation: Bob gets a pending request with a Welcome.
    let conv = alice.start_conversation(&h, &bob.username).await;
    assert_eq!(bob.join_pending(&h).await, vec![conv]);

    let (_, v) = bob.get(&h, "/api/v1/conversations").await;
    let entry = &v["conversations"][0];
    assert_eq!(
        entry["state"], "invited",
        "Bob sees a request, not an open chat"
    );
    assert_eq!(entry["id"], conv.to_string());

    // Alice may send a first message; Bob can read it while it is still a request.
    let (s, seq1) = alice.send(&h, conv, "hi bob, it's alice").await;
    assert_eq!((s, seq1), (StatusCode::OK, 1));
    assert_eq!(bob.read(&h, conv, 0).await, vec!["hi bob, it's alice"]);

    // Bob cannot reply until he accepts.
    let (s, _) = bob.send(&h, conv, "too early").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = bob
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/accept"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, seq2) = bob.send(&h, conv, "hey alice!").await;
    assert_eq!((s, seq2), (StatusCode::OK, 2));
    assert_eq!(alice.read(&h, conv, 1).await, vec!["hey alice!"]);

    // Both sides now list it as an open conversation, with each other as members.
    for who in [&alice, &bob] {
        let (_, v) = who.get(&h, "/api/v1/conversations").await;
        assert_eq!(v["conversations"][0]["state"], "joined");
        assert_eq!(v["conversations"][0]["last_seq"], 2);
        assert_eq!(
            v["conversations"][0]["members"].as_array().unwrap().len(),
            2
        );
    }
}

#[tokio::test]
async fn server_stores_only_ciphertext_and_no_sender_or_time() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await;
    alice
        .send(&h, conv, "my password is hunter2-very-secret")
        .await;

    let dump: String = sqlx::query_scalar(
        "SELECT COALESCE(string_agg(row_to_json(t)::text, ' '), '') FROM messages t WHERE conversation_id = $1",
    )
    .bind(conv)
    .fetch_one(&h.db)
    .await
    .unwrap();
    assert!(!dump.contains("hunter2"));
    assert!(!dump.contains("password"));

    // Structural guarantee: the log has no column that could identify a sender or a time.
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'messages' ORDER BY ordinal_position",
    )
    .fetch_all(&h.db)
    .await
    .unwrap();
    assert_eq!(columns, ["conversation_id", "seq", "kind", "data"]);
}

#[tokio::test]
async fn requests_are_limited_until_accepted() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await;

    for i in 1..=5 {
        assert_eq!(
            alice.send(&h, conv, &format!("spam {i}")).await.0,
            StatusCode::OK
        );
    }
    let (s, _) = alice.send(&h, conv, "spam 6").await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "the sixth message waits for acceptance"
    );

    bob.post(
        &h,
        &format!("/api/v1/conversations/{conv}/accept"),
        json!({}),
    )
    .await;
    assert_eq!(
        alice.send(&h, conv, "now it's fine").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn declining_removes_the_request_and_blocks_the_sender() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(&h, &bob.username).await;

    let (s, _) = bob
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/decline"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (_, v) = bob.get(&h, "/api/v1/conversations").await;
    assert!(v["conversations"].as_array().unwrap().is_empty());
    let (_, v) = bob.get(&h, "/api/v1/welcomes").await;
    assert!(
        v["welcomes"].as_array().unwrap().is_empty(),
        "welcome is gone"
    );
    assert_eq!(
        alice.send(&h, conv, "hello?").await.0,
        StatusCode::FORBIDDEN
    );
    // Declining twice is not possible.
    let (s, _) = bob
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/decline"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn key_packages_are_single_use() {
    let Some(h) = harness().await else { return };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);

    let (_, count) = bob.get(&h, "/api/v1/devices/me/key-packages/count").await;
    assert_eq!(count["count"], 10);
    for _ in 0..10 {
        let (s, v) = alice
            .post(
                &h,
                &format!("/api/v1/users/{}/key-packages", bob.username),
                json!({}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["devices"].as_array().unwrap().len(), 1);
    }
    let (_, v) = alice
        .post(
            &h,
            &format!("/api/v1/users/{}/key-packages", bob.username),
            json!({}),
        )
        .await;
    assert!(
        v["devices"].as_array().unwrap().is_empty(),
        "all packages used up"
    );
    let (_, count) = bob.get(&h, "/api/v1/devices/me/key-packages/count").await;
    assert_eq!(count["count"], 0);
}

#[tokio::test]
async fn access_control() {
    let Some(h) = harness().await else { return };
    let (alice, bob, eve) = (
        h.user("alice").await,
        h.user("bob").await,
        h.user("eve").await,
    );
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await;
    alice.send(&h, conv, "private").await;

    // A stranger can neither read nor write.
    let (s, _) = eve
        .get(&h, &format!("/api/v1/conversations/{conv}/messages"))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = eve
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/messages"),
            json!({"kind": 1, "data": B64.encode(b"x")}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, v) = eve.get(&h, "/api/v1/conversations").await;
    assert!(v["conversations"].as_array().unwrap().is_empty());
    // ...and cannot accept someone else's request.
    let (s, _) = eve
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/accept"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A session without a registered device is turned away from chat endpoints.
    let username = unique("nodev");
    h.signup(&format!("{username}@example.test"), &username, PASSWORD)
        .await;
    let token = h.login(&username, PASSWORD).await.unwrap();
    let (s, _) = h
        .authed(Method::GET, "/api/v1/conversations", &token, None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // No token at all.
    let (s, _) = h
        .call(Method::GET, "/api/v1/conversations", None, None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Cannot attach somebody else's device.
    let (s, _) = h
        .authed(
            Method::POST,
            "/api/v1/devices/attach",
            &token,
            Some(json!({"device_id": alice.device_id})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cannot_start_a_conversation_with_yourself_or_a_ghost() {
    let Some(h) = harness().await else { return };
    let alice = h.user("alice").await;
    let (s, _) = alice
        .post(
            &h,
            &format!("/api/v1/users/{}/key-packages", unique("ghost")),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = alice
        .post(&h, "/api/v1/conversations", json!({"id": uuid::Uuid::new_v4(), "member": alice.username, "welcome": B64.encode(b"x"), "recipients": [alice.device_id]}))
        .await;
    assert_ne!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn every_device_of_both_people_joins_and_reads() {
    let Some(h) = harness().await else { return };
    let alice_phone = h.user("alice").await;
    let alice_laptop = h.add_device(&alice_phone, "laptop").await;
    let bob_phone = h.user("bob").await;
    let bob_tablet = h.add_device(&bob_phone, "tablet").await;

    // Started from Alice's phone: Alice's laptop and both of Bob's devices are added.
    let conv = alice_phone
        .start_conversation(&h, &bob_phone.username)
        .await;
    assert_eq!(alice_laptop.join_pending(&h).await, vec![conv]);
    assert_eq!(bob_phone.join_pending(&h).await, vec![conv]);
    assert_eq!(bob_tablet.join_pending(&h).await, vec![conv]);

    bob_phone
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/accept"),
            json!({}),
        )
        .await;
    assert_eq!(
        alice_phone.send(&h, conv, "to all four devices").await.0,
        StatusCode::OK
    );

    for device in [&alice_laptop, &bob_phone, &bob_tablet] {
        assert_eq!(device.read(&h, conv, 0).await, vec!["to all four devices"]);
    }
    // The sender's own echo is recognised and skipped rather than failing.
    assert!(alice_phone.read(&h, conv, 0).await.is_empty());

    // A reply from Bob's tablet reaches everyone else.
    assert_eq!(
        bob_tablet.send(&h, conv, "reply from the tablet").await.0,
        StatusCode::OK
    );
    for device in [&alice_phone, &alice_laptop, &bob_phone] {
        assert_eq!(
            device.read(&h, conv, 1).await,
            vec!["reply from the tablet"]
        );
    }
}

#[tokio::test]
async fn sequence_numbers_are_gapless_under_concurrent_sends() {
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

    // Encrypt first (MLS state is local), then post everything concurrently.
    let mut bodies = vec![];
    for i in 0..20 {
        let ct = alice
            .mls
            .encrypt(conv.as_bytes(), format!("m{i}").as_bytes())
            .unwrap();
        bodies.push(json!({"kind": 1, "data": B64.encode(ct)}));
    }
    let path = format!("/api/v1/conversations/{conv}/messages");
    let posts = bodies.into_iter().map(|b| alice.post(&h, &path, b));
    let results = futures_util::future::join_all(posts).await;
    let mut seqs: Vec<i64> = results
        .iter()
        .map(|(s, v)| {
            assert_eq!(*s, StatusCode::OK);
            v["seq"].as_i64().unwrap()
        })
        .collect();
    seqs.sort();
    assert_eq!(seqs, (1..=20).collect::<Vec<_>>());
}
