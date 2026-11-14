//! The WebSocket: live delivery, the live-typing relay, backlog replay and its safety limits,
//! over a real socket with real MLS clients.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use yap_core::typing;

struct Ws(WebSocketStream<MaybeTlsStream<TcpStream>>);

impl Ws {
    /// Connect and authenticate; panics unless the server answers `ready`.
    async fn connect(addr: SocketAddr, token: &str) -> Ws {
        let mut ws = Ws::raw(addr).await;
        ws.send(json!({"t": "auth", "token": token})).await;
        assert_eq!(ws.next(2000).await.expect("ready")["t"], "ready");
        ws
    }

    async fn raw(addr: SocketAddr) -> Ws {
        Ws(connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("ws connect")
            .0)
    }

    async fn send(&mut self, v: Value) {
        self.0
            .send(Message::Text(v.to_string().into()))
            .await
            .unwrap();
    }

    /// Next JSON frame within `ms`, or `None` on timeout / close.
    async fn next(&mut self, ms: u64) -> Option<Value> {
        loop {
            match tokio::time::timeout(Duration::from_millis(ms), self.0.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(&t).ok(),
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                _ => return None,
            }
        }
    }

    /// Next frame of type `t`, skipping others.
    async fn next_of(&mut self, t: &str, ms: u64) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        while let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) {
            let v = self.next(left.as_millis() as u64 + 1).await?;
            if v["t"] == t {
                return Some(v);
            }
        }
        None
    }

    /// Everything that arrives within `ms`.
    async fn drain(&mut self, ms: u64) -> Vec<Value> {
        let mut out = vec![];
        while let Some(v) = self.next(ms).await {
            out.push(v);
        }
        out
    }
}

async fn accepted_pair(h: &Harness) -> (Client, Client, uuid::Uuid) {
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

fn seal(c: &Client, conv: uuid::Uuid, seq: u64, text: &str) -> String {
    let key = c.mls.typing_key(conv.as_bytes()).unwrap();
    let epoch = c.mls.epoch(conv.as_bytes()).unwrap();
    B64.encode(typing::seal(&key, epoch, conv.as_bytes(), seq, text))
}

fn open(c: &Client, conv: uuid::Uuid, frame: &str) -> typing::Opened {
    let key = c.mls.typing_key(conv.as_bytes()).unwrap();
    typing::open(&key, conv.as_bytes(), &B64.decode(frame).unwrap()).unwrap()
}

#[tokio::test]
async fn live_messages_are_pushed_to_the_other_side_only() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob, conv) = accepted_pair(&h).await;
    let mut ws_alice = Ws::connect(addr, &alice.token).await;
    let mut ws_bob = Ws::connect(addr, &bob.token).await;

    let (s, seq) = alice.send(&h, conv, "pushed live").await;
    assert_eq!(s, StatusCode::OK);

    let push = ws_bob
        .next_of("msg", 2000)
        .await
        .expect("Bob gets the push");
    assert_eq!(
        (
            push["c"].as_str().unwrap(),
            push["seq"].as_i64().unwrap(),
            push["k"].as_i64().unwrap()
        ),
        (conv.to_string().as_str(), seq, 1)
    );
    let pt = bob
        .mls
        .decrypt(
            conv.as_bytes(),
            &B64.decode(push["d"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    assert_eq!(pt, b"pushed live");
    assert!(
        ws_alice.next_of("msg", 300).await.is_none(),
        "the sender gets no echo"
    );
}

#[tokio::test]
async fn live_typing_reaches_the_other_person_and_is_never_stored() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob, conv) = accepted_pair(&h).await;
    let mut ws_alice = Ws::connect(addr, &alice.token).await;
    let mut ws_bob = Ws::connect(addr, &bob.token).await;

    ws_alice
        .send(json!({"t": "typing", "c": conv, "f": seal(&alice, conv, 1, "hel")}))
        .await;
    ws_alice
        .send(json!({"t": "typing", "c": conv, "f": seal(&alice, conv, 2, "hello wor")}))
        .await;

    let first = ws_bob.next_of("typing", 2000).await.expect("first frame");
    let second = ws_bob.next_of("typing", 2000).await.expect("second frame");
    let (a, b) = (
        open(&bob, conv, first["f"].as_str().unwrap()),
        open(&bob, conv, second["f"].as_str().unwrap()),
    );
    assert_eq!((a.seq, a.text.as_str()), (1, "hel"));
    assert_eq!((b.seq, b.text.as_str()), (2, "hello wor"));
    assert!(
        ws_alice.next_of("typing", 300).await.is_none(),
        "no echo to the typist"
    );

    // Never persisted: a device that connects later sees nothing of it.
    let mut late = Ws::connect(addr, &bob.token).await;
    assert!(late.drain(300).await.iter().all(|v| v["t"] != "typing"));
}

#[tokio::test]
async fn typing_is_not_relayed_until_accepted_or_from_outsiders() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob, eve) = (
        h.user("alice").await,
        h.user("bob").await,
        h.user("eve").await,
    );
    let conv = alice.start_conversation(&h, &bob.username).await;
    bob.join_pending(&h).await;
    let mut ws_alice = Ws::connect(addr, &alice.token).await;
    let mut ws_bob = Ws::connect(addr, &bob.token).await;
    let mut ws_eve = Ws::connect(addr, &eve.token).await;

    // Bob has not accepted yet: no live typing for a pending request.
    ws_alice
        .send(json!({"t": "typing", "c": conv, "f": seal(&alice, conv, 1, "are you there")}))
        .await;
    assert!(ws_bob.next_of("typing", 400).await.is_none());

    bob.post(
        &h,
        &format!("/api/v1/conversations/{conv}/accept"),
        json!({}),
    )
    .await;
    // An outsider cannot inject frames into the conversation.
    ws_eve
        .send(json!({"t": "typing", "c": conv, "f": B64.encode(b"junk junk junk junk")}))
        .await;
    assert!(ws_bob.next_of("typing", 400).await.is_none());
    // The real member can.
    ws_alice
        .send(json!({"t": "typing", "c": conv, "f": seal(&alice, conv, 2, "now it works")}))
        .await;
    assert!(ws_bob.next_of("typing", 2000).await.is_some());
}

#[tokio::test]
async fn typing_frames_are_rate_limited() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob, conv) = accepted_pair(&h).await;
    let mut ws_alice = Ws::connect(addr, &alice.token).await;
    let mut ws_bob = Ws::connect(addr, &bob.token).await;

    for i in 0..60 {
        ws_alice
            .send(json!({"t": "typing", "c": conv, "f": seal(&alice, conv, i, "x")}))
            .await;
    }
    let received = ws_bob
        .drain(500)
        .await
        .iter()
        .filter(|v| v["t"] == "typing")
        .count();
    assert!(
        (15..=40).contains(&received),
        "expected roughly one second's worth, got {received}"
    );

    // Oversized frames are dropped outright.
    ws_alice
        .send(json!({"t": "typing", "c": conv, "f": "A".repeat(10_000)}))
        .await;
    assert!(ws_bob.next_of("typing", 300).await.is_none());
}

#[tokio::test]
async fn offline_devices_get_a_replay_and_acks_stop_it() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob, conv) = accepted_pair(&h).await;

    // Bob is offline while Alice writes three messages.
    for t in ["one", "two", "three"] {
        assert_eq!(alice.send(&h, conv, t).await.0, StatusCode::OK);
    }
    let mut ws = Ws::connect(addr, &bob.token).await;
    let mut texts = vec![];
    let mut last = 0;
    for _ in 0..3 {
        let m = ws.next_of("msg", 2000).await.expect("replayed message");
        last = m["seq"].as_i64().unwrap();
        let pt = bob
            .mls
            .decrypt(
                conv.as_bytes(),
                &B64.decode(m["d"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        texts.push(String::from_utf8(pt).unwrap());
    }
    assert_eq!(texts, ["one", "two", "three"], "in order");
    ws.send(json!({"t": "ack", "c": conv, "seq": last})).await;
    ws.send(json!({"t": "ping"})).await;
    assert_eq!(ws.next_of("pong", 2000).await.unwrap()["t"], "pong");
    drop(ws);

    // After the ack, a reconnect replays nothing.
    let mut again = Ws::connect(addr, &bob.token).await;
    assert!(again.drain(400).await.iter().all(|v| v["t"] != "msg"));
}

#[tokio::test]
async fn welcomes_and_decisions_are_pushed_live() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;
    let (alice, bob) = (h.user("alice").await, h.user("bob").await);
    let mut ws_alice = Ws::connect(addr, &alice.token).await;
    let mut ws_bob = Ws::connect(addr, &bob.token).await;

    let conv = alice.start_conversation(&h, &bob.username).await;
    let w = ws_bob
        .next_of("welcome", 2000)
        .await
        .expect("welcome pushed to Bob");
    assert_eq!(w["c"], conv.to_string());
    let gid = bob
        .mls
        .join(&B64.decode(w["d"].as_str().unwrap()).unwrap())
        .unwrap();
    assert_eq!(gid, conv.as_bytes());

    bob.post(
        &h,
        &format!("/api/v1/conversations/{conv}/decline"),
        json!({}),
    )
    .await;
    let m = ws_alice
        .next_of("member", 2000)
        .await
        .expect("Alice learns of the decision");
    assert_eq!(
        (m["u"].as_str().unwrap(), m["s"].as_str().unwrap()),
        (bob.username.as_str(), "declined")
    );
}

#[tokio::test]
async fn bad_or_missing_auth_is_refused() {
    let Some(h) = harness().await else { return };
    let addr = h.serve().await;

    let mut ws = Ws::raw(addr).await;
    ws.send(json!({"t": "auth", "token": "not-a-real-token"}))
        .await;
    assert!(ws.next(2000).await.is_none(), "closed without a ready");

    let mut ws = Ws::raw(addr).await;
    ws.send(json!({"t": "typing", "c": uuid::Uuid::new_v4(), "f": "AAAA"}))
        .await;
    assert!(
        ws.next(2000).await.is_none(),
        "anything but auth first is refused"
    );

    // A session that never registered a device cannot connect either.
    let username = unique("nodev");
    h.signup(&format!("{username}@example.test"), &username, PASSWORD)
        .await;
    let token = h.login(&username, PASSWORD).await.unwrap();
    let mut ws = Ws::raw(addr).await;
    ws.send(json!({"t": "auth", "token": token})).await;
    assert!(ws.next(2000).await.is_none());
}
