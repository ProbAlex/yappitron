//! Multi-device: approving new devices, adding them to existing conversations, the encrypted
//! history archive, and the recovery key.
//!
//! Trust model: the server never holds any key that decrypts anything. A new device is let in by
//! one of the account's already-approved devices, which (a) shows its owner a short fingerprint to
//! compare with the new device's screen, (b) adds the new device to each conversation with an MLS
//! commit only an existing member can create, and (c) seals the account's history key to the new
//! device. The server only stores and relays those opaque blobs.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::chat::{b64d, caller, caller_any, load_members};
use crate::error::ApiError;
use crate::hub::MemberState;
use crate::state::AppState;

type ApiResult<T> = Result<T, ApiError>;

const MAX_BUNDLE_BYTES: usize = 4096;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 70 * 1024;
const MAX_ARCHIVE_BATCH: usize = 100;
const MAX_COMMIT_BYTES: usize = 64 * 1024;
const MAX_WELCOME_BYTES: usize = 192 * 1024;

/// Push a JSON event to some devices' live connections.
fn push(st: &AppState, devices: &[Uuid], event: Value) {
    let msg: Arc<str> = event.to_string().into();
    st.hub.send_to(devices, &msg);
}

async fn approved_devices_of(st: &AppState, account: Uuid) -> ApiResult<Vec<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT id FROM devices WHERE account_id = $1 AND status = 'approved'")
            .bind(account)
            .fetch_all(&st.db)
            .await?,
    )
}

// ---------- device status and list ----------

pub async fn my_device(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let (me, approved) = caller_any(&st, &headers).await?;
    Ok(Json(json!({
        "device_id": me.device,
        "status": if approved { "approved" } else { "pending" },
    })))
}

pub async fn list_devices(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (me, _) = caller_any(&st, &headers).await?;
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, name, status FROM devices
         WHERE account_id = $1 AND status <> 'revoked' ORDER BY status, name, id",
    )
    .bind(me.account)
    .fetch_all(&st.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, status)| json!({ "id": id, "name": name, "status": status, "current": id == me.device }))
        .collect();
    Ok(Json(json!({ "devices": list })))
}

// ---------- linking a new device ----------

#[derive(Deserialize)]
pub struct LinkRequest {
    /// The new device's X25519 public key (32 bytes), for sealing secrets to it.
    link_pub: String,
}

/// A pending device announces itself so the account's approved devices can offer to let it in.
pub async fn link_request(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<LinkRequest>,
) -> ApiResult<StatusCode> {
    let (me, approved) = caller_any(&st, &headers).await?;
    if approved {
        return Err(ApiError::Conflict("this device is already approved"));
    }
    let link_pub = b64d(&b.link_pub)?;
    if link_pub.len() != 32 {
        return Err(ApiError::BadRequest("link key must be 32 bytes"));
    }
    if !st.limiter.allow(
        &format!("link:{}", me.account),
        20,
        Duration::from_secs(3600),
    ) {
        return Err(ApiError::TooManyRequests);
    }
    let name: String = sqlx::query_scalar(
        "UPDATE devices SET link_pub = $1 WHERE id = $2 AND status = 'pending' RETURNING name",
    )
    .bind(&link_pub)
    .bind(me.device)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::Conflict(
        "this device is not waiting for approval",
    ))?;
    let approvers = approved_devices_of(&st, me.account).await?;
    push(
        &st,
        &approvers,
        json!({ "t": "link_request", "device_id": me.device, "name": name }),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Pending devices of this account that have published a link key.
pub async fn pending_devices(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, name, link_pub FROM devices
         WHERE account_id = $1 AND status = 'pending' AND link_pub IS NOT NULL ORDER BY name, id",
    )
    .bind(me.account)
    .fetch_all(&st.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, link_pub)| json!({ "device_id": id, "name": name, "link_pub": B64.encode(link_pub) }))
        .collect();
    Ok(Json(json!({ "pending": list })))
}

/// Take one key package of another device of the SAME account (pending or approved), for adding
/// it to a conversation. Each package is handed out once.
pub async fn take_device_key_package(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    if device == me.device {
        return Err(ApiError::BadRequest("that is this device"));
    }
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1 AND account_id = $2 AND status IN ('pending', 'approved'))",
    )
    .bind(device)
    .bind(me.account)
    .fetch_one(&st.db)
    .await?;
    if !owned {
        return Err(ApiError::NotFound("no such device"));
    }
    let kp: Option<Vec<u8>> = sqlx::query_scalar(
        "DELETE FROM key_packages WHERE id = (
             SELECT id FROM key_packages WHERE device_id = $1
             ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
         RETURNING data",
    )
    .bind(device)
    .fetch_optional(&st.db)
    .await?;
    let kp = kp.ok_or(ApiError::Conflict("that device has no key packages left"))?;
    Ok(Json(json!({ "key_package": B64.encode(kp) })))
}

#[derive(Deserialize)]
pub struct Approve {
    /// Secrets for the new device, sealed to its link key by the approving device.
    bundle: String,
}

pub async fn approve_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<Uuid>,
    Json(b): Json<Approve>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    let bundle = b64d(&b.bundle)?;
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ApiError::BadRequest("invalid bundle size"));
    }
    let mut tx = st.db.begin().await?;
    let updated = sqlx::query(
        "UPDATE devices SET status = 'approved', link_pub = NULL
         WHERE id = $1 AND account_id = $2 AND status = 'pending' AND link_pub IS NOT NULL",
    )
    .bind(device)
    .bind(me.account)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound("no such pending device"));
    }
    sqlx::query(
        "INSERT INTO link_bundles (device_id, data) VALUES ($1, $2)
         ON CONFLICT (device_id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind(device)
    .bind(&bundle)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    push(&st, &[device], json!({ "t": "approved" }));
    let others: Vec<Uuid> = approved_devices_of(&st, me.account)
        .await?
        .into_iter()
        .filter(|d| *d != device)
        .collect();
    push(&st, &others, json!({ "t": "devices_changed" }));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_bundle(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let data: Vec<u8> = sqlx::query_scalar("SELECT data FROM link_bundles WHERE device_id = $1")
        .bind(me.device)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("no bundle waiting"))?;
    Ok(Json(json!({ "bundle": B64.encode(data) })))
}

pub async fn delete_bundle(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    sqlx::query("DELETE FROM link_bundles WHERE device_id = $1")
        .bind(me.device)
        .execute(&st.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove a device's footprint on the server: sessions, key packages, memberships, Welcomes.
/// Returns the conversations it was a member of (their cached membership must be refreshed).
async fn purge_device(tx: &mut sqlx::PgConnection, device: Uuid) -> ApiResult<Vec<Uuid>> {
    let convs: Vec<Uuid> =
        sqlx::query_scalar("SELECT conversation_id FROM device_cursors WHERE device_id = $1")
            .bind(device)
            .fetch_all(&mut *tx)
            .await?;
    for table in [
        "sessions",
        "key_packages",
        "device_cursors",
        "welcomes",
        "link_bundles",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE device_id = $1"))
            .bind(device)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE devices SET status = 'revoked', link_pub = NULL WHERE id = $1")
        .bind(device)
        .execute(&mut *tx)
        .await?;
    Ok(convs)
}

/// Remove a device from the account (it is signed out everywhere and receives nothing more).
/// Note: it remains a member of existing MLS groups until another member removes it.
pub async fn revoke_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    let mut tx = st.db.begin().await?;
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM devices WHERE id = $1 AND account_id = $2 FOR UPDATE",
    )
    .bind(device)
    .bind(me.account)
    .fetch_optional(&mut *tx)
    .await?;
    let status = status.ok_or(ApiError::NotFound("no such device"))?;
    if status == "revoked" {
        return Ok(StatusCode::NO_CONTENT);
    }
    if status == "approved" {
        let approved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM devices WHERE account_id = $1 AND status = 'approved'",
        )
        .bind(me.account)
        .fetch_one(&mut *tx)
        .await?;
        if approved <= 1 {
            return Err(ApiError::Conflict(
                "you cannot remove your only approved device",
            ));
        }
    }
    let convs = purge_device(&mut tx, device).await?;
    tx.commit().await?;
    for c in convs {
        st.hub.invalidate(c);
    }
    push(&st, &[device], json!({ "t": "revoked" }));
    Ok(StatusCode::NO_CONTENT)
}

// ---------- adding a device to an existing conversation ----------

#[derive(Deserialize)]
pub struct AddDevices {
    /// MLS commit for the existing members (they apply it to learn about the new devices).
    commit: String,
    /// One MLS Welcome for all the new devices.
    welcome: String,
    recipients: Vec<Uuid>,
    /// The highest log sequence number the caller has processed. If anyone committed after it,
    /// the caller's commit was built on a stale group state and is refused (409).
    base_seq: i64,
}

pub async fn add_devices(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(conv): Path<Uuid>,
    Json(b): Json<AddDevices>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let commit = b64d(&b.commit)?;
    let welcome = b64d(&b.welcome)?;
    if commit.is_empty()
        || commit.len() > MAX_COMMIT_BYTES
        || welcome.is_empty()
        || welcome.len() > MAX_WELCOME_BYTES
    {
        return Err(ApiError::BadRequest("invalid commit or welcome size"));
    }
    let mut recipients = b.recipients.clone();
    recipients.sort();
    recipients.dedup();
    if recipients.is_empty() || recipients.len() > 20 || recipients.len() != b.recipients.len() {
        return Err(ApiError::BadRequest("invalid recipients"));
    }
    if !st.limiter.allow(
        &format!("adddev:{}", me.account),
        120,
        Duration::from_secs(3600),
    ) {
        return Err(ApiError::TooManyRequests);
    }

    let members = load_members(&st, conv).await?;
    if !members
        .iter()
        .any(|m| m.device == me.device && m.state == MemberState::Joined)
    {
        return Err(ApiError::Forbidden("not a member of this conversation"));
    }

    // Recipients: approved devices of accounts in this conversation, or a pending device of the
    // caller's own account (the one being approved right now).
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT d.id, d.account_id, d.status
         FROM devices d JOIN conversation_members m
           ON m.account_id = d.account_id AND m.conversation_id = $1 AND m.state IN ('joined', 'invited')
         WHERE d.id = ANY($2)",
    )
    .bind(conv)
    .bind(&recipients)
    .fetch_all(&st.db)
    .await?;
    if rows.len() != recipients.len() {
        return Err(ApiError::BadRequest(
            "a recipient is not a device of someone in this conversation",
        ));
    }
    for (_, account, status) in &rows {
        let ok = status == "approved" || (status == "pending" && *account == me.account);
        if !ok {
            return Err(ApiError::BadRequest("a recipient device is not approved"));
        }
    }

    let mut tx = st.db.begin().await?;
    // Serialize with other writers; the new sequence number is the commit's.
    let seq: i64 = sqlx::query_scalar(
        "UPDATE conversations SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq",
    )
    .bind(conv)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("no such conversation"))?;
    let already: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device_cursors WHERE conversation_id = $1 AND device_id = ANY($2)",
    )
    .bind(conv)
    .bind(&recipients)
    .fetch_one(&mut *tx)
    .await?;
    if already > 0 {
        return Err(ApiError::Conflict(
            "a device is already a member of this conversation",
        ));
    }
    // Commits must form a line. Application messages in between do not matter (they don't
    // change the group), but a commit since `base_seq` means the caller's is stale.
    let newer_commits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messages WHERE conversation_id = $1 AND kind = 0 AND seq > $2",
    )
    .bind(conv)
    .bind(b.base_seq)
    .fetch_one(&mut *tx)
    .await?;
    if newer_commits > 0 {
        return Err(ApiError::Conflict("conversation changed; sync and retry"));
    }
    sqlx::query("INSERT INTO messages (conversation_id, seq, kind, data) VALUES ($1, $2, 0, $3)")
        .bind(conv)
        .bind(seq)
        .bind(&commit)
        .execute(&mut *tx)
        .await?;
    let mut welcome_ids = vec![];
    for device in &recipients {
        sqlx::query(
            "INSERT INTO device_cursors (device_id, conversation_id, last_seq) VALUES ($1, $2, $3)",
        )
        .bind(device)
        .bind(conv)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO welcomes (device_id, conversation_id, join_seq, data) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(device)
        .bind(conv)
        .bind(seq)
        .bind(&welcome)
        .fetch_one(&mut *tx)
        .await?;
        welcome_ids.push((*device, id));
    }
    tx.commit().await?;

    st.hub.invalidate(conv);
    // Existing members learn of the change through the log, like any other message.
    let existing: Vec<Uuid> = members
        .iter()
        .filter(|m| m.device != me.device)
        .map(|m| m.device)
        .collect();
    push(
        &st,
        &existing,
        json!({ "t": "msg", "c": conv, "seq": seq, "k": 0, "d": B64.encode(&commit) }),
    );
    for (device, id) in welcome_ids {
        push(
            &st,
            &[device],
            json!({ "t": "welcome", "id": id, "c": conv, "join_seq": seq, "d": B64.encode(&welcome) }),
        );
    }
    Ok(Json(json!({ "seq": seq })))
}

// ---------- history archive ----------

#[derive(Deserialize)]
pub struct ArchivePut {
    entries: Vec<ArchiveEntry>,
}

#[derive(Deserialize)]
pub struct ArchiveEntry {
    seq: i64,
    data: String,
}

async fn require_member_account(st: &AppState, account: Uuid, conv: Uuid) -> ApiResult<()> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM conversation_members
                        WHERE conversation_id = $1 AND account_id = $2 AND state IN ('joined', 'invited'))",
    )
    .bind(conv)
    .bind(account)
    .fetch_one(&st.db)
    .await?;
    if ok {
        Ok(())
    } else {
        Err(ApiError::Forbidden("not a member of this conversation"))
    }
}

/// Store archive entries (sealed by the client under the account's history key). Entries are
/// per account, so devices of the same account upload the same rows; duplicates are ignored.
pub async fn put_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(conv): Path<Uuid>,
    Json(b): Json<ArchivePut>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    require_member_account(&st, me.account, conv).await?;
    if b.entries.is_empty() || b.entries.len() > MAX_ARCHIVE_BATCH {
        return Err(ApiError::BadRequest(
            "upload 1-100 archive entries at a time",
        ));
    }
    let last_seq: i64 = sqlx::query_scalar("SELECT last_seq FROM conversations WHERE id = $1")
        .bind(conv)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("no such conversation"))?;
    let mut tx = st.db.begin().await?;
    for e in &b.entries {
        let data = b64d(&e.data)?;
        if data.is_empty() || data.len() > MAX_ARCHIVE_ENTRY_BYTES || e.seq < 1 || e.seq > last_seq
        {
            return Err(ApiError::BadRequest("invalid archive entry"));
        }
        sqlx::query(
            "INSERT INTO archive (account_id, conversation_id, seq, data) VALUES ($1, $2, $3, $4)
             ON CONFLICT (account_id, conversation_id, seq) DO NOTHING",
        )
        .bind(me.account)
        .bind(conv)
        .bind(e.seq)
        .bind(data)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ArchiveQuery {
    #[serde(default)]
    after: i64,
    limit: Option<i64>,
}

pub async fn get_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(conv): Path<Uuid>,
    Query(q): Query<ArchiveQuery>,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    require_member_account(&st, me.account, conv).await?;
    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, data FROM archive WHERE account_id = $1 AND conversation_id = $2 AND seq > $3
         ORDER BY seq LIMIT $4",
    )
    .bind(me.account)
    .bind(conv)
    .bind(q.after)
    .bind(q.limit.unwrap_or(200).clamp(1, 500))
    .fetch_all(&st.db)
    .await?;
    let entries: Vec<Value> = rows
        .into_iter()
        .map(|(seq, data)| json!({ "seq": seq, "data": B64.encode(data) }))
        .collect();
    Ok(Json(json!({ "entries": entries })))
}

// ---------- history key and recovery key ----------

#[derive(Deserialize)]
pub struct PutAccountKeys {
    /// The history key sealed under the recovery key (the server cannot open it).
    wrapped_hist_key: String,
    /// A 32-byte token derived from the recovery key. Only its hash is stored.
    recovery_auth: String,
    /// Replace keys that already exist (creating a new recovery key). Without it the call only
    /// creates them: of several devices that each try to initialize an account's keys, exactly
    /// one wins and the rest get `409` (they must restore the key instead).
    #[serde(default)]
    replace: bool,
}

fn hash_auth(token: &[u8]) -> Vec<u8> {
    Sha256::new_with_prefix(b"yappitron recovery auth v1")
        .chain_update(token)
        .finalize()
        .to_vec()
}

pub async fn put_account_keys(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<PutAccountKeys>,
) -> ApiResult<StatusCode> {
    let me = caller(&st, &headers).await?;
    let wrapped = b64d(&b.wrapped_hist_key)?;
    let auth = b64d(&b.recovery_auth)?;
    if wrapped.is_empty() || wrapped.len() > 1024 || auth.len() != 32 {
        return Err(ApiError::BadRequest("invalid key material"));
    }
    let conflict = if b.replace {
        "ON CONFLICT (account_id) DO UPDATE
         SET wrapped_hist_key = EXCLUDED.wrapped_hist_key, recovery_auth_hash = EXCLUDED.recovery_auth_hash"
    } else {
        "ON CONFLICT (account_id) DO NOTHING"
    };
    let done = sqlx::query(&format!(
        "INSERT INTO account_keys (account_id, wrapped_hist_key, recovery_auth_hash) VALUES ($1, $2, $3) {conflict}"
    ))
    .bind(me.account)
    .bind(wrapped)
    .bind(hash_auth(&auth))
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "this account already has a recovery key",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct Recover {
    recovery_auth: String,
}

/// "I lost every device." Proving possession of the recovery key makes THIS device the account's
/// only approved device (every other device is removed) and returns the wrapped history key.
/// The new device is not a member of any existing conversation: those stay readable from the
/// archive, and new messages need new conversations.
pub async fn recover(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<Recover>,
) -> ApiResult<Json<Value>> {
    let (me, _) = caller_any(&st, &headers).await?;
    let auth = b64d(&b.recovery_auth)?;
    if auth.len() != 32 {
        return Err(ApiError::BadRequest("invalid recovery token"));
    }
    // Guessing is hopeless against 256 random bits, but keep the endpoint quiet anyway.
    if !st.limiter.allow(
        &format!("recover:{}", me.account),
        5,
        Duration::from_secs(3600),
    ) {
        return Err(ApiError::TooManyRequests);
    }
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT recovery_auth_hash, wrapped_hist_key FROM account_keys WHERE account_id = $1",
    )
    .bind(me.account)
    .fetch_optional(&st.db)
    .await?;
    let (stored_hash, wrapped) = row.ok_or(ApiError::NotFound(
        "no recovery key was set up for this account",
    ))?;
    if !bool::from(stored_hash.ct_eq(&hash_auth(&auth))) {
        return Err(ApiError::Forbidden("wrong recovery key"));
    }

    let mut tx = st.db.begin().await?;
    let others: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM devices WHERE account_id = $1 AND id <> $2 AND status <> 'revoked'",
    )
    .bind(me.account)
    .bind(me.device)
    .fetch_all(&mut *tx)
    .await?;
    let mut convs = vec![];
    for d in &others {
        convs.extend(purge_device(&mut tx, *d).await?);
    }
    sqlx::query("UPDATE devices SET status = 'approved', link_pub = NULL WHERE id = $1")
        .bind(me.device)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    for c in convs {
        st.hub.invalidate(c);
    }
    push(&st, &others, json!({ "t": "revoked" }));
    Ok(Json(
        json!({ "wrapped_hist_key": B64.encode(wrapped), "revoked_devices": others.len() }),
    ))
}

pub async fn get_account_keys(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let me = caller(&st, &headers).await?;
    let wrapped: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_hist_key FROM account_keys WHERE account_id = $1")
            .bind(me.account)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("no recovery key was set up"))?;
    Ok(Json(json!({ "wrapped_hist_key": B64.encode(wrapped) })))
}
