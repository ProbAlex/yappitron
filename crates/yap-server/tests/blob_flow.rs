//! Encrypted attachments over REST: who may upload, download and delete, and the limits.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};
use uuid::Uuid;

fn key() -> [u8; 32] {
    rand::random()
}

async fn upload(h: &Harness, who: &Client, conv: Uuid, bytes: Vec<u8>) -> (StatusCode, Value) {
    let (s, body) = h
        .call_raw(
            Method::PUT,
            &format!("/api/v1/conversations/{conv}/blobs"),
            bytes,
            Some(&who.token),
        )
        .await;
    (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn download(h: &Harness, who: &Client, id: &str) -> (StatusCode, Vec<u8>) {
    h.call_raw(
        Method::GET,
        &format!("/api/v1/blobs/{id}"),
        vec![],
        Some(&who.token),
    )
    .await
}

/// Alice and Bob in an accepted conversation.
async fn chatting(h: &Harness) -> (Client, Client, Uuid) {
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(h, &bob.username).await;
    bob.join_pending(h).await;
    let (s, _) = bob
        .post(
            h,
            &format!("/api/v1/conversations/{conv}/accept"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    (alice, bob, conv)
}

#[tokio::test]
async fn upload_download_round_trip_with_real_encryption() {
    let Some(h) = blob_harness(1 << 20, 1 << 30).await else {
        return;
    };
    let (alice, bob, conv) = chatting(&h).await;

    // A "photo" of 200 KB, encrypted the way the clients do.
    let photo: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let k = key();
    let sealed = yap_core::blob::seal(&k, &photo);

    let (s, v) = upload(&h, &alice, conv, sealed.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["size"], sealed.len());

    // Both members can fetch it; what comes back is exactly the ciphertext, and only the key
    // (which the server never sees) opens it.
    for who in [&alice, &bob] {
        let (s, got) = download(&h, who, &id).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(got, sealed);
        assert_eq!(yap_core::blob::open(&k, &got).unwrap(), photo);
    }
    assert!(
        !sealed.windows(32).any(|w| w == &photo[1000..1032]),
        "the stored bytes must not contain the plaintext"
    );
}

#[tokio::test]
async fn only_conversation_members_can_download() {
    let Some(h) = blob_harness(1 << 20, 1 << 30).await else {
        return;
    };
    let (alice, _bob, conv) = chatting(&h).await;
    let mallory = h.user("mallory").await;
    let sealed = yap_core::blob::seal(&key(), b"private");
    let (_, v) = upload(&h, &alice, conv, sealed).await;
    let id = v["id"].as_str().unwrap();

    // Outsiders get the same answer as for a file that does not exist.
    let (s, _) = download(&h, &mallory, id).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s2, _) = download(&h, &mallory, &Uuid::new_v4().to_string()).await;
    assert_eq!(s2, StatusCode::NOT_FOUND);
    // No token at all.
    let (s, _) = h
        .call_raw(Method::GET, &format!("/api/v1/blobs/{id}"), vec![], None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Outsiders cannot upload into the conversation either.
    let (s, _) = upload(&h, &mallory, conv, yap_core::blob::seal(&key(), b"x")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn size_cap_quota_and_garbage_are_refused() {
    // 10 KB per file, 25 KB per account.
    let Some(h) = blob_harness(10_000, 25_000).await else {
        return;
    };
    let (alice, _bob, conv) = chatting(&h).await;

    // Too big: declared up front, and also when the length is not declared honestly.
    let (s, _) = upload(&h, &alice, conv, vec![7; 10_001]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    // Empty / too short to be an encrypted file.
    let (s, _) = upload(&h, &alice, conv, vec![]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = upload(&h, &alice, conv, vec![1; 5]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Quota: 9 KB twice fits, the third does not.
    let ok = || yap_core::blob::seal(&key(), &vec![3u8; 9_000 - 25]);
    let (s, _) = upload(&h, &alice, conv, ok()).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = upload(&h, &alice, conv, ok()).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = upload(&h, &alice, conv, ok()).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    assert_eq!(v["error"], "storage quota reached");
}

#[tokio::test]
async fn only_the_uploader_can_delete() {
    let Some(h) = blob_harness(1 << 20, 1 << 30).await else {
        return;
    };
    let (alice, bob, conv) = chatting(&h).await;
    let (_, v) = upload(&h, &alice, conv, yap_core::blob::seal(&key(), b"oops")).await;
    let id = v["id"].as_str().unwrap().to_string();

    let del = |who: &Client| {
        let path = format!("/api/v1/blobs/{id}");
        let token = who.token.clone();
        let h = &h;
        async move {
            h.call_raw(Method::DELETE, &path, vec![], Some(&token))
                .await
                .0
        }
    };
    assert_eq!(
        del(&bob).await,
        StatusCode::NOT_FOUND,
        "the recipient cannot delete"
    );
    assert_eq!(download(&h, &bob, &id).await.0, StatusCode::OK);
    assert_eq!(del(&alice).await, StatusCode::NO_CONTENT);
    assert_eq!(download(&h, &bob, &id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(del(&alice).await, StatusCode::NOT_FOUND, "already gone");
}

#[tokio::test]
async fn a_stranger_cannot_flood_an_unaccepted_request() {
    let Some(h) = blob_harness(1 << 20, 1 << 30).await else {
        return;
    };
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await; // Bob has NOT accepted

    for _ in 0..5 {
        let (s, _) = upload(&h, &alice, conv, yap_core::blob::seal(&key(), b"hi")).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, _) = upload(&h, &alice, conv, yap_core::blob::seal(&key(), b"hi")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "sixth file before acceptance");
    // Bob can't upload while still only invited.
    let (s, _) = upload(&h, &bob, conv, yap_core::blob::seal(&key(), b"hi")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A declined request stops uploads altogether.
    let (s, _) = bob
        .post(
            &h,
            &format!("/api/v1/conversations/{conv}/decline"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = upload(&h, &alice, conv, yap_core::blob::seal(&key(), b"hi")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn attachments_are_off_unless_configured() {
    let Some(h) = harness().await else { return };
    let (alice, _bob, conv) = chatting(&h).await;
    let (s, _) = upload(&h, &alice, conv, yap_core::blob::seal(&key(), b"x")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_cap_holds_even_when_the_length_is_not_declared() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    let Some(h) = blob_harness(10_000, 1 << 30).await else {
        return;
    };
    let (alice, _bob, conv) = chatting(&h).await;

    // No Content-Length header at all: the server must stop reading at the cap.
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/v1/conversations/{conv}/blobs"))
        .header("authorization", format!("Bearer {}", alice.token))
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from(vec![9u8; 50_000]))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // And nothing was left behind in the database.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs WHERE conversation_id = $1")
        .bind(conv)
        .fetch_one(&h.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
