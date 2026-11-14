//! Encrypted attachments.
//!
//! Clients encrypt a file under a random key (see `yap_core::blob`) and upload only the
//! ciphertext. The key and the file's name, type and size travel inside the end-to-end encrypted
//! chat message, so the server holds opaque bytes under a random id: it cannot read, name or
//! classify them. It does record which conversation a file belongs to (needed to decide who may
//! download it) and which account uploaded it (quota, and the right to delete it), but no
//! timestamps and no file names.
//!
//! Files live on disk under `YAP_BLOB_DIR` (in production that is a NAS dataset), not in
//! Postgres, so large files never touch the database.

use std::path::{Path as FsPath, PathBuf};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::chat;
use crate::error::ApiError;
use crate::state::AppState;

type ApiResult<T> = Result<T, ApiError>;

/// A sealed file is never smaller than its header plus one authentication tag.
const MIN_BLOB_BYTES: u64 = 9 + 16;
/// Files a stranger may send into a message request that has not been accepted yet.
const MAX_BLOBS_BEFORE_ACCEPT: i64 = 5;

#[derive(Clone)]
pub struct BlobStore {
    dir: PathBuf,
    /// Largest upload, in bytes of ciphertext.
    pub max_bytes: u64,
    /// Most ciphertext one account may keep, in bytes.
    pub account_quota: u64,
}

impl BlobStore {
    pub fn new(dir: impl Into<PathBuf>, max_bytes: u64, account_quota: u64) -> Self {
        Self {
            dir: dir.into(),
            max_bytes,
            account_quota,
        }
    }

    fn path(&self, id: Uuid) -> PathBuf {
        let s = id.simple().to_string();
        self.dir.join(&s[..2]).join(s)
    }

    fn tmp_path(&self, id: Uuid) -> PathBuf {
        self.dir.join("tmp").join(id.simple().to_string())
    }
}

/// Delete half-written uploads left behind by a crash. Called at startup.
pub async fn clean_tmp(store: &BlobStore) {
    let _ = tokio::fs::remove_dir_all(store.dir.join("tmp")).await;
}

fn store(st: &AppState) -> ApiResult<&BlobStore> {
    st.blobs.as_deref().ok_or(ApiError::NotFound(
        "attachments are not enabled on this server",
    ))
}

async fn member_state(st: &AppState, conv: Uuid, account: Uuid) -> ApiResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT state FROM conversation_members WHERE conversation_id = $1 AND account_id = $2",
    )
    .bind(conv)
    .bind(account)
    .fetch_optional(&st.db)
    .await?)
}

/// `PUT /api/v1/conversations/{id}/blobs`: the body is the encrypted file. Returns its id.
pub async fn upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(conv): Path<Uuid>,
    body: Body,
) -> ApiResult<Json<Value>> {
    let me = chat::caller(&st, &headers).await?;
    let store = store(&st)?;
    if !st.limiter.allow(
        &format!("blob:{}", me.account),
        120,
        Duration::from_secs(600),
    ) {
        return Err(ApiError::TooManyRequests);
    }
    match member_state(&st, conv, me.account).await?.as_deref() {
        Some("joined") => {}
        _ => return Err(ApiError::Forbidden("not a member of this conversation")),
    }
    let others: Vec<(String,)> = sqlx::query_as(
        "SELECT state FROM conversation_members WHERE conversation_id = $1 AND account_id <> $2",
    )
    .bind(conv)
    .bind(me.account)
    .fetch_all(&st.db)
    .await?;
    if others.iter().any(|(s,)| s == "declined") {
        return Err(ApiError::Forbidden(
            "the other person declined this conversation",
        ));
    }
    if others.iter().any(|(s,)| s == "invited") {
        let sent: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM blobs WHERE conversation_id = $1 AND account_id = $2",
        )
        .bind(conv)
        .bind(me.account)
        .fetch_one(&st.db)
        .await?;
        if sent >= MAX_BLOBS_BEFORE_ACCEPT {
            return Err(ApiError::Forbidden(
                "waiting for the other person to accept",
            ));
        }
    }

    let declared: Option<u64> = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if declared.is_some_and(|n| n > store.max_bytes) {
        return Err(ApiError::TooLarge("file is too large"));
    }
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size), 0)::BIGINT FROM blobs WHERE account_id = $1",
    )
    .bind(me.account)
    .fetch_one(&st.db)
    .await?;
    let used = used.max(0) as u64;
    if used + declared.unwrap_or(0) > store.account_quota {
        return Err(ApiError::TooLarge("storage quota reached"));
    }

    let id = Uuid::new_v4();
    let tmp = store.tmp_path(id);
    let size = match write_body(
        &tmp,
        body,
        store.max_bytes,
        store.account_quota - used.min(store.account_quota),
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
    };
    if size < MIN_BLOB_BYTES {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(ApiError::BadRequest("not an encrypted file"));
    }

    let dest = store.path(id);
    let moved = async {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&tmp, &dest).await
    }
    .await;
    if moved.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(ApiError::Internal("blob store"));
    }
    let inserted = sqlx::query(
        "INSERT INTO blobs (id, conversation_id, account_id, size) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(conv)
    .bind(me.account)
    .bind(size as i64)
    .execute(&st.db)
    .await;
    if let Err(e) = inserted {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(e.into());
    }
    Ok(Json(json!({ "id": id, "size": size })))
}

/// Stream the request body to `path`, refusing more than `max` bytes (or `room` in total).
async fn write_body(path: &FsPath, body: Body, max: u64, room: u64) -> ApiResult<u64> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| ApiError::Internal("blob store"))?;
    }
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|_| ApiError::Internal("blob store"))?;
    let mut total = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::BadRequest("upload interrupted"))?;
        total += chunk.len() as u64;
        if total > max {
            return Err(ApiError::TooLarge("file is too large"));
        }
        if total > room {
            return Err(ApiError::TooLarge("storage quota reached"));
        }
        file.write_all(&chunk)
            .await
            .map_err(|_| ApiError::Internal("blob store"))?;
    }
    // Make the bytes durable before the row that points at them exists.
    file.sync_all()
        .await
        .map_err(|_| ApiError::Internal("blob store"))?;
    Ok(total)
}

/// `GET /api/v1/blobs/{id}`: the encrypted file, for members of its conversation.
pub async fn download(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let me = chat::caller(&st, &headers).await?;
    let store = store(&st)?;
    let conv: Option<Uuid> = sqlx::query_scalar("SELECT conversation_id FROM blobs WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    // Unknown file and "not yours" look the same, so ids cannot be probed.
    let not_found = ApiError::NotFound("no such file");
    let Some(conv) = conv else {
        return Err(not_found);
    };
    match member_state(&st, conv, me.account).await?.as_deref() {
        Some("joined" | "invited") => {}
        _ => return Err(not_found),
    }
    let file = tokio::fs::File::open(store.path(id))
        .await
        .map_err(|_| ApiError::NotFound("no such file"))?;
    let len = file
        .metadata()
        .await
        .map_err(|_| ApiError::Internal("blob store"))?
        .len();
    let mut resp = Body::from_stream(ReaderStream::new(file)).into_response();
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}

/// `DELETE /api/v1/blobs/{id}`: only the account that uploaded it.
pub async fn delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let me = chat::caller(&st, &headers).await?;
    let store = store(&st)?;
    let removed = sqlx::query("DELETE FROM blobs WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(me.account)
        .execute(&st.db)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound("no such file"));
    }
    let _ = tokio::fs::remove_file(store.path(id)).await;
    Ok(StatusCode::NO_CONTENT)
}
