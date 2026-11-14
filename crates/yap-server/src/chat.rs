//! Devices, key packages, conversations and the encrypted message log (REST half).
//!
//! The server never sees plaintext: it stores and orders opaque MLS messages. It records no
//! sender and no timestamp for a message; ordering is a per-conversation sequence number.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use yap_proto::username;

use crate::auth;
use crate::error::ApiError;
use crate::hub::{Member, MemberState};
use crate::state::AppState;

type ApiResult<T> = Result<T, ApiError>;

const MAX_KEY_PACKAGES_PER_DEVICE: i64 = 200;
const MAX_UPLOAD_KEY_PACKAGES: usize = 100;
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_WELCOME_BYTES: usize = 192 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// How many messages the inviter may send before the other person accepts.
const MAX_MESSAGES_BEFORE_ACCEPT: i64 = 5;

pub struct Caller {
    pub account: Uuid,
    pub device: Uuid,
}

/// A session bound to an APPROVED device: the only kind that may read or send messages.
pub async fn caller(st: &AppState, headers: &HeaderMap) -> ApiResult<Caller> {
    let (c, approved) = caller_any(st, headers).await?;
    if !approved {
        return Err(ApiError::Forbidden("this device is not approved yet"));
    }
    Ok(c)
}

/// A session bound to a pending or approved device; the flag says which.
pub async fn caller_any(st: &AppState, headers: &HeaderMap) -> ApiResult<(Caller, bool)> {
    let s = auth::session(st, headers).await?;
    let device = s
        .device
        .ok_or(ApiError::Forbidden("register a device first"))?;
    let approved = match s.device_status.as_deref() {
        Some("approved") => true,
        Some("pending") => false,
        _ => return Err(ApiError::Unauthorized),
    };
    Ok((
        Caller {
            account: s.account,
            device,
        },
        approved,
    ))
}

pub(crate) fn b64d(s: &str) -> ApiResult<Vec<u8>> {
    B64.decode(s)
        .map_err(|_| ApiError::BadRequest("invalid encoding"))
}

// ---------- devices ----------

#[derive(Deserialize)]
pub struct NewDevice {
    name: String,
}

pub async fn create_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<NewDevice>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = auth::session(&st, &headers).await?;
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::BadRequest("device name must be 1-64 characters"));
    }
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    // The first device of an account is trusted by definition (the person just proved they own
    // the account). Every later one must be approved by a device that is already trusted.
    let approved_devices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE account_id = $1 AND status = 'approved'",
    )
    .bind(s.account)
    .fetch_one(&mut *tx)
    .await?;
    let status = if approved_devices == 0 {
        "approved"
    } else {
        "pending"
    };
    sqlx::query("INSERT INTO devices (id, account_id, name, status) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(s.account)
        .bind(name)
        .bind(status)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET device_id = $1 WHERE token_hash = $2")
        .bind(id)
        .bind(&s.token_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "device_id": id, "status": status })),
    ))
}

#[derive(Deserialize)]
pub struct AttachDevice {
    device_id: Uuid,
}

/// Bind this session to a device the account already registered (a later login on the same
/// installation). Returns the device's status.
pub async fn attach_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<AttachDevice>,
) -> ApiResult<Json<Value>> {
    let s = auth::session(&st, &headers).await?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM devices WHERE id = $1 AND account_id = $2")
            .bind(b.device_id)
            .bind(s.account)
            .fetch_optional(&st.db)
            .await?;
    let status = status.ok_or(ApiError::NotFound("no such device"))?;
    if status == "revoked" {
        return Err(ApiError::Forbidden(
            "this device was removed from the account",
        ));
    }
    sqlx::query("UPDATE sessions SET device_id = $1 WHERE token_hash = $2")
        .bind(b.device_id)
        .bind(&s.token_hash)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "device_id": b.device_id, "status": status })))
}

// ---------- key packages ----------

#[derive(Deserialize)]
pub struct PutKeyPackages {
    key_packages: Vec<String>,
}

pub async fn put_key_packages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<PutKeyPackages>,
) -> ApiResult<StatusCode> {
    // A pending device uploads its key packages too: the approving device needs them to add it.
    let (me, _) = caller_any(&st, &headers).await?;
    if b.key_packages.is_empty() || b.key_packages.len() > MAX_UPLOAD_KEY_PACKAGES {
        return Err(ApiError::BadRequest("upload 1-100 key packages at a time"));
    }
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM key_packages WHERE device_id = $1")
        .bind(me.device)
        .fetch_one(&st.db)
        .await?;
    if have + b.key_packages.len() as i64 > MAX_KEY_PACKAGES_PER_DEVICE {
        return Err(ApiError::Conflict("too many key packages stored"));
    }
    let mut tx = st.db.begin().await?;
    for kp in &b.key_packages {
        let data = b64d(kp)?;
        if data.is_empty() || data.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(ApiError::BadRequest("invalid key package size"));
        }
        sqlx::query("INSERT INTO key_packages (device_id, data) VALUES ($1, $2)")
            .bind(me.device)
            .bind(data)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn key_package_count(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM key_packages WHERE device_id = $1")
        .bind(me.device)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({ "count": count })))
}

/// Take one key package from each of a user's devices (never the caller's own device), so the
/// caller can add them to a new conversation. Each package is handed out exactly once.
pub async fn take_key_packages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    if !st
        .limiter
        .allow(&format!("kp:{}", me.account), 30, Duration::from_secs(3600))
    {
        return Err(ApiError::TooManyRequests);
    }
    let name = username::canonicalize(&name).map_err(|_| ApiError::NotFound("no such user"))?;
    let account: Uuid = sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1")
        .bind(&name)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("no such user"))?;
    let devices: Vec<Uuid> =
        sqlx::query_scalar(
            "SELECT id FROM devices WHERE account_id = $1 AND id <> $2 AND status = 'approved' ORDER BY id",
        )
            .bind(account)
            .bind(me.device)
            .fetch_all(&st.db)
            .await?;

    let mut out = vec![];
    for device in devices {
        let kp: Option<Vec<u8>> = sqlx::query_scalar(
            "DELETE FROM key_packages WHERE id = (
                 SELECT id FROM key_packages WHERE device_id = $1
                 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING data",
        )
        .bind(device)
        .fetch_optional(&st.db)
        .await?;
        if let Some(data) = kp {
            out.push(json!({ "device_id": device, "key_package": B64.encode(data) }));
        }
    }
    Ok(Json(json!({ "username": name, "devices": out })))
}

// ---------- conversations ----------

#[derive(Deserialize)]
pub struct NewConversation {
    id: Uuid,
    /// Username of the other person.
    member: String,
    /// MLS Welcome, produced by the caller's `add_members` for all `recipients` at once.
    welcome: String,
    /// Devices that should join: the other person's devices and the caller's other devices.
    recipients: Vec<Uuid>,
}

pub async fn create_conversation(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<NewConversation>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    let other_name =
        username::canonicalize(&b.member).map_err(|_| ApiError::NotFound("no such user"))?;
    let welcome = b64d(&b.welcome)?;
    if welcome.is_empty() || welcome.len() > MAX_WELCOME_BYTES {
        return Err(ApiError::BadRequest("invalid welcome size"));
    }
    if b.recipients.is_empty() || b.recipients.len() > 40 {
        return Err(ApiError::BadRequest("invalid recipients"));
    }
    if !st.limiter.allow(
        &format!("newconv:{}", me.account),
        20,
        Duration::from_secs(3600),
    ) {
        return Err(ApiError::TooManyRequests);
    }

    let other: Uuid = sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1")
        .bind(&other_name)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("no such user"))?;
    if other == me.account {
        return Err(ApiError::BadRequest(
            "you cannot start a conversation with yourself",
        ));
    }

    // Every recipient must be a device of the caller (not this one) or of the other person.
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, account_id FROM devices WHERE id = ANY($1) AND status = 'approved'",
    )
    .bind(&b.recipients)
    .fetch_all(&st.db)
    .await?;
    let mut unique = b.recipients.clone();
    unique.sort();
    unique.dedup();
    if rows.len() != unique.len() || unique.len() != b.recipients.len() {
        return Err(ApiError::BadRequest("unknown or repeated recipient device"));
    }
    if rows
        .iter()
        .any(|(d, a)| *d == me.device || (*a != me.account && *a != other))
    {
        return Err(ApiError::BadRequest(
            "recipient is not a device of either person",
        ));
    }
    if !rows.iter().any(|(_, a)| *a == other) {
        return Err(ApiError::BadRequest(
            "the other person needs at least one device",
        ));
    }

    let mut tx = st.db.begin().await?;
    let created = sqlx::query("INSERT INTO conversations (id) VALUES ($1)")
        .bind(b.id)
        .execute(&mut *tx)
        .await;
    if let Err(e) = created {
        return Err(
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                ApiError::Conflict("conversation id already used")
            } else {
                ApiError::Internal("database")
            },
        );
    }
    for (account, state) in [(me.account, "joined"), (other, "invited")] {
        sqlx::query("INSERT INTO conversation_members (conversation_id, account_id, state) VALUES ($1, $2, $3)")
            .bind(b.id)
            .bind(account)
            .bind(state)
            .execute(&mut *tx)
            .await?;
    }
    // The creating device is a member from the start.
    sqlx::query(
        "INSERT INTO device_cursors (device_id, conversation_id, last_seq) VALUES ($1, $2, 0)",
    )
    .bind(me.device)
    .bind(b.id)
    .execute(&mut *tx)
    .await?;

    let mut pushes = vec![];
    for device in &unique {
        sqlx::query(
            "INSERT INTO device_cursors (device_id, conversation_id, last_seq) VALUES ($1, $2, 0)",
        )
        .bind(device)
        .bind(b.id)
        .execute(&mut *tx)
        .await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO welcomes (device_id, conversation_id, join_seq, data)
             VALUES ($1, $2, 0, $3) RETURNING id",
        )
        .bind(device)
        .bind(b.id)
        .bind(&welcome)
        .fetch_one(&mut *tx)
        .await?;
        pushes.push((*device, id));
    }
    tx.commit().await?;

    st.hub.invalidate(b.id);
    for (device, welcome_id) in pushes {
        let msg: Arc<str> = json!({
            "t": "welcome", "id": welcome_id, "c": b.id, "join_seq": 0, "d": B64.encode(&welcome)
        })
        .to_string()
        .into();
        st.hub.send_to(&[device], &msg);
    }
    Ok(StatusCode::CREATED)
}

pub async fn list_conversations(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let mine: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT c.id, m.state, c.last_seq
         FROM conversations c JOIN conversation_members m ON m.conversation_id = c.id
         WHERE m.account_id = $1 AND m.state IN ('joined', 'invited')
         ORDER BY c.last_seq DESC, c.id",
    )
    .bind(me.account)
    .fetch_all(&st.db)
    .await?;
    let ids: Vec<Uuid> = mine.iter().map(|(id, _, _)| *id).collect();
    let members: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT m.conversation_id, a.username, m.state
         FROM conversation_members m JOIN accounts a ON a.id = m.account_id
         WHERE m.conversation_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&st.db)
    .await?;
    let list: Vec<Value> = mine
        .into_iter()
        .map(|(id, state, last_seq)| {
            let people: Vec<Value> = members
                .iter()
                .filter(|(c, _, _)| *c == id)
                .map(|(_, u, s)| json!({ "username": u, "state": s }))
                .collect();
            json!({ "id": id, "state": state, "last_seq": last_seq, "members": people })
        })
        .collect();
    Ok(Json(json!({ "conversations": list })))
}

async fn set_member_state(
    st: &AppState,
    me: &Caller,
    conversation: Uuid,
    to: &'static str,
) -> ApiResult<StatusCode> {
    let mut tx = st.db.begin().await?;
    let updated = sqlx::query(
        "UPDATE conversation_members SET state = $3
         WHERE conversation_id = $1 AND account_id = $2 AND state = 'invited'",
    )
    .bind(conversation)
    .bind(me.account)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound("no pending request"));
    }
    if to == "declined" {
        // A declined request leaves nothing behind for this account's devices.
        sqlx::query(
            "DELETE FROM device_cursors WHERE conversation_id = $1
             AND device_id IN (SELECT id FROM devices WHERE account_id = $2)",
        )
        .bind(conversation)
        .bind(me.account)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM welcomes WHERE conversation_id = $1
             AND device_id IN (SELECT id FROM devices WHERE account_id = $2)",
        )
        .bind(conversation)
        .bind(me.account)
        .execute(&mut *tx)
        .await?;
    }
    let name: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(me.account)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;

    // Tell the other side's devices.
    let members = load_members(st, conversation).await?;
    let others: Vec<Uuid> = members
        .iter()
        .filter(|m| m.account != me.account)
        .map(|m| m.device)
        .collect();
    let msg: Arc<str> = json!({ "t": "member", "c": conversation, "u": name, "s": to })
        .to_string()
        .into();
    st.hub.invalidate(conversation);
    st.hub.send_to(&others, &msg);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn accept(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    set_member_state(&st, &me, id, "joined").await
}

pub async fn decline(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    set_member_state(&st, &me, id, "declined").await
}

/// Devices that are MLS members of a conversation, with their account's state, for accounts
/// still part of it. Cached briefly because the typing relay asks for it several times a second.
pub async fn load_members(st: &AppState, conversation: Uuid) -> ApiResult<Arc<Vec<Member>>> {
    if let Some(cached) = st.hub.cached_members(conversation) {
        return Ok(cached);
    }
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT dc.device_id, d.account_id, m.state
         FROM device_cursors dc
         JOIN devices d ON d.id = dc.device_id
         JOIN conversation_members m ON m.conversation_id = dc.conversation_id AND m.account_id = d.account_id
         WHERE dc.conversation_id = $1 AND m.state IN ('joined', 'invited')",
    )
    .bind(conversation)
    .fetch_all(&st.db)
    .await?;
    let members = rows
        .into_iter()
        .map(|(device, account, state)| Member {
            device,
            account,
            state: if state == "joined" {
                MemberState::Joined
            } else {
                MemberState::Invited
            },
        })
        .collect();
    Ok(st.hub.cache_members(conversation, members))
}

// ---------- messages ----------

#[derive(Deserialize)]
pub struct PostMessage {
    /// 0 = MLS commit, 1 = application message.
    kind: i16,
    data: String,
}

pub async fn post_message(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<PostMessage>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    if !matches!(b.kind, 0 | 1) {
        return Err(ApiError::BadRequest("kind must be 0 or 1"));
    }
    let data = b64d(&b.data)?;
    if data.is_empty() || data.len() > MAX_MESSAGE_BYTES {
        return Err(ApiError::BadRequest("invalid message size"));
    }
    if !st
        .limiter
        .allow(&format!("msg:{}", me.account), 600, Duration::from_secs(60))
    {
        return Err(ApiError::TooManyRequests);
    }

    let members = load_members(&st, id).await?;
    let mine = members.iter().find(|m| m.device == me.device);
    if !matches!(mine, Some(m) if m.state == MemberState::Joined) {
        return Err(ApiError::Forbidden("not a member of this conversation"));
    }

    let mut tx = st.db.begin().await?;
    // Taking the row lock here serializes writers, so sequence numbers are gapless and ordered.
    let seq: i64 = sqlx::query_scalar(
        "UPDATE conversations SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("no such conversation"))?;

    let others: Vec<(String,)> = sqlx::query_as(
        "SELECT state FROM conversation_members WHERE conversation_id = $1 AND account_id <> $2",
    )
    .bind(id)
    .bind(me.account)
    .fetch_all(&mut *tx)
    .await?;
    if others.iter().any(|(s,)| s == "declined") {
        return Err(ApiError::Forbidden(
            "the other person declined this conversation",
        ));
    }
    if b.kind == 1 && others.iter().any(|(s,)| s == "invited") {
        let sent: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM messages WHERE conversation_id = $1 AND kind = 1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if sent >= MAX_MESSAGES_BEFORE_ACCEPT {
            return Err(ApiError::Forbidden(
                "waiting for the other person to accept",
            ));
        }
    }

    sqlx::query("INSERT INTO messages (conversation_id, seq, kind, data) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(seq)
        .bind(b.kind)
        .bind(&data)
        .execute(&mut *tx)
        .await?;
    // The sender's cursor is NOT advanced here: that could skip another member's message that is
    // still in flight. Clients acknowledge contiguous progress themselves (their own sequence
    // numbers included), and replayed own messages are recognised and skipped.
    tx.commit().await?;

    let msg: Arc<str> =
        json!({ "t": "msg", "c": id, "seq": seq, "k": b.kind, "d": B64.encode(&data) })
            .to_string()
            .into();
    let recipients: Vec<Uuid> = members
        .iter()
        .filter(|m| m.device != me.device)
        .map(|m| m.device)
        .collect();
    st.hub.send_to(&recipients, &msg);
    Ok(Json(json!({ "seq": seq })))
}

#[derive(Deserialize)]
pub struct MessagesQuery {
    #[serde(default)]
    after: i64,
    limit: Option<i64>,
}

pub async fn get_messages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<MessagesQuery>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let members = load_members(&st, id).await?;
    if !members.iter().any(|m| m.device == me.device) {
        return Err(ApiError::Forbidden("not a member of this conversation"));
    }
    let rows: Vec<(i64, i16, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, kind, data FROM messages WHERE conversation_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(id)
    .bind(q.after)
    .bind(q.limit.unwrap_or(200).clamp(1, 500))
    .fetch_all(&st.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(seq, kind, data)| json!({ "seq": seq, "kind": kind, "data": B64.encode(data) }))
        .collect();
    Ok(Json(json!({ "messages": list })))
}

#[derive(Deserialize)]
pub struct Ack {
    seq: i64,
}

pub async fn ack(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<Ack>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    ack_cursor(&st, me.device, id, b.seq).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn ack_cursor(
    st: &AppState,
    device: Uuid,
    conversation: Uuid,
    seq: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE device_cursors SET last_seq = GREATEST(last_seq, $3)
         WHERE device_id = $1 AND conversation_id = $2
           AND $3 <= (SELECT last_seq FROM conversations WHERE id = $2)",
    )
    .bind(device)
    .bind(conversation)
    .bind(seq)
    .execute(&st.db)
    .await?;
    Ok(())
}

// ---------- welcomes ----------

pub async fn list_welcomes(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let rows: Vec<(i64, Uuid, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, conversation_id, join_seq, data FROM welcomes WHERE device_id = $1 ORDER BY id",
    )
    .bind(me.device)
    .fetch_all(&st.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(id, c, join_seq, data)| json!({ "id": id, "conversation_id": c, "join_seq": join_seq, "data": B64.encode(data) }))
        .collect();
    Ok(Json(json!({ "welcomes": list })))
}

pub async fn delete_welcome(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    sqlx::query("DELETE FROM welcomes WHERE id = $1 AND device_id = $2")
        .bind(id)
        .bind(me.device)
        .execute(&st.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
