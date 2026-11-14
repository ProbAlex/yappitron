//! The WebSocket: live delivery of messages and welcomes, and the live-typing relay.
//!
//! Protocol (JSON text frames):
//! - client -> server: `{"t":"auth","token":...}` (must be first), `{"t":"typing","c":conv,"f":b64}`,
//!   `{"t":"ack","c":conv,"seq":n}`, `{"t":"ping"}`
//! - server -> client: `{"t":"ready"}`, `{"t":"msg","c","seq","k","d"}`, `{"t":"welcome","id","c","join_seq","d"}`,
//!   `{"t":"member","c","u","s"}`, `{"t":"typing","c","f"}`, `{"t":"pong"}`
//!
//! Typing frames are opaque ciphertext relayed from RAM to the other members' live connections.
//! They are never stored. Right after connecting the server replays everything the device has
//! not acknowledged; clients de-duplicate by sequence number.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth;
use crate::chat::{ack_cursor, load_members};
use crate::hub::MemberState;
use crate::state::AppState;

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Typing frames are at most ~2.1 KB; leave room for base64.
const MAX_TYPING_B64: usize = 4096;
const MAX_TYPING_PER_SECOND: u32 = 20;

pub async fn ws_handler(State(st): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(16 * 1024)
        .on_upgrade(move |socket| serve(st, socket))
}

async fn send(socket: &mut WebSocket, v: Value) -> Result<(), ()> {
    socket
        .send(Message::Text(v.to_string().into()))
        .await
        .map_err(|_| ())
}

async fn serve(st: AppState, mut socket: WebSocket) {
    let Some((account, device)) = authenticate(&st, &mut socket).await else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let (conn_id, mut rx) = st.hub.connect(device);
    // Subscribe first, then replay, so nothing slips between the two (duplicates are fine).
    let ok = send(&mut socket, json!({ "t": "ready" })).await.is_ok()
        && backlog(&st, device, &mut socket).await.is_ok();
    if ok {
        let mut typing = (Instant::now(), 0u32);
        loop {
            tokio::select! {
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(reply) = client_frame(&st, account, device, &text, &mut typing).await
                            && send(&mut socket, reply).await.is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                },
                outgoing = rx.recv() => match outgoing {
                    Some(m) => if socket.send(Message::Text(m.as_ref().into())).await.is_err() { break; },
                    None => break,
                },
            }
        }
    }
    st.hub.disconnect(device, conn_id);
}

/// First frame must be `{"t":"auth","token":...}` within a few seconds.
async fn authenticate(st: &AppState, socket: &mut WebSocket) -> Option<(Uuid, Uuid)> {
    let first = tokio::time::timeout(AUTH_TIMEOUT, socket.recv())
        .await
        .ok()??
        .ok()?;
    let Message::Text(text) = first else {
        return None;
    };
    let v: Value = serde_json::from_str(&text).ok()?;
    if v["t"] != "auth" {
        return None;
    }
    let session = auth::session_for_token(st, v["token"].as_str()?)
        .await
        .ok()?;
    Some((session.account, session.device?))
}

/// Handle one client frame; `Some(reply)` is sent straight back.
async fn client_frame(
    st: &AppState,
    account: Uuid,
    device: Uuid,
    text: &str,
    typing_window: &mut (Instant, u32),
) -> Option<Value> {
    let v: Value = serde_json::from_str(text).ok()?;
    match v["t"].as_str()? {
        "ping" => Some(json!({ "t": "pong" })),
        "ack" => {
            let conv: Uuid = v["c"].as_str()?.parse().ok()?;
            ack_cursor(st, device, conv, v["seq"].as_i64()?)
                .await
                .ok()?;
            None
        }
        "typing" => {
            let conv: Uuid = v["c"].as_str()?.parse().ok()?;
            let frame = v["f"].as_str()?;
            if frame.len() > MAX_TYPING_B64 || B64.decode(frame).is_err() {
                return None;
            }
            // Fixed one-second window; excess frames are silently dropped.
            if typing_window.0.elapsed() >= Duration::from_secs(1) {
                *typing_window = (Instant::now(), 0);
            }
            typing_window.1 += 1;
            if typing_window.1 > MAX_TYPING_PER_SECOND {
                return None;
            }
            let members = load_members(st, conv).await.ok()?;
            if !members
                .iter()
                .any(|m| m.device == device && m.state == MemberState::Joined)
            {
                return None;
            }
            // Only people who have accepted the conversation see live typing.
            let targets: Vec<Uuid> = members
                .iter()
                .filter(|m| m.account != account && m.state == MemberState::Joined)
                .map(|m| m.device)
                .collect();
            let relay: Arc<str> = json!({ "t": "typing", "c": conv, "f": frame })
                .to_string()
                .into();
            st.hub.send_to(&targets, &relay);
            None
        }
        _ => None,
    }
}

/// Replay pending welcomes and every log entry after the device's cursor.
async fn backlog(st: &AppState, device: Uuid, socket: &mut WebSocket) -> Result<(), ()> {
    let db = &st.db;
    let welcomes: Vec<(i64, Uuid, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, conversation_id, join_seq, data FROM welcomes WHERE device_id = $1 ORDER BY id",
    )
    .bind(device)
    .fetch_all(db)
    .await
    .map_err(|_| ())?;
    for (id, c, join_seq, data) in welcomes {
        send(socket, json!({ "t": "welcome", "id": id, "c": c, "join_seq": join_seq, "d": B64.encode(data) })).await?;
    }

    let cursors: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT dc.conversation_id, dc.last_seq
         FROM device_cursors dc
         JOIN devices d ON d.id = dc.device_id
         JOIN conversation_members m ON m.conversation_id = dc.conversation_id AND m.account_id = d.account_id
         WHERE dc.device_id = $1 AND m.state IN ('joined', 'invited')",
    )
    .bind(device)
    .fetch_all(db)
    .await
    .map_err(|_| ())?;
    for (conv, mut last) in cursors {
        loop {
            let rows: Vec<(i64, i16, Vec<u8>)> = sqlx::query_as(
                "SELECT seq, kind, data FROM messages WHERE conversation_id = $1 AND seq > $2 ORDER BY seq LIMIT 500",
            )
            .bind(conv)
            .bind(last)
            .fetch_all(db)
            .await
            .map_err(|_| ())?;
            let n = rows.len();
            for (seq, kind, data) in rows {
                last = seq;
                send(
                    socket,
                    json!({ "t": "msg", "c": conv, "seq": seq, "k": kind, "d": B64.encode(data) }),
                )
                .await?;
            }
            if n < 500 {
                break;
            }
        }
    }
    Ok(())
}
