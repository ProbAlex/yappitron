//! Account endpoints: email verification, OPAQUE signup/login, password reset, sessions.
//!
//! Privacy notes: emails are only ever hashed (HMAC) before touching the database; passwords
//! never reach the server (OPAQUE); rate-limit counters live in RAM; nothing here logs
//! request data.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use yap_proto::auth::{CONTEXT, YapOpaque, opaque_ke};
use yap_proto::username;

use crate::error::ApiError;
use crate::secrets::Secrets;
use crate::state::AppState;

const MAX_CODE_ATTEMPTS: i32 = 5;

type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone, Copy)]
enum Purpose {
    Signup,
    Reset,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::Signup => "signup",
            Purpose::Reset => "reset",
        }
    }
}

// ---------- helpers ----------

fn b64d(s: &str) -> ApiResult<Vec<u8>> {
    B64.decode(s)
        .map_err(|_| ApiError::BadRequest("invalid encoding"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Client address for in-RAM rate limiting only (never stored or logged).
///
/// The gateway sits behind exactly one trusted proxy, which appends the address it saw to
/// `X-Forwarded-For`. The LAST entry is therefore the real client; earlier entries are whatever
/// the client claimed and can be forged to dodge per-address limits.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').map(str::trim).find(|s| !s.is_empty()))
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".into())
}

fn random_token() -> (String, Vec<u8>) {
    let bytes: [u8; 32] = rand::random();
    (B64.encode(bytes), Sha256::digest(bytes).to_vec())
}

/// A malformed token is just an invalid one: always 401, never a hint about its format.
fn hash_token(token: &str) -> ApiResult<Vec<u8>> {
    let raw = B64.decode(token).map_err(|_| ApiError::Unauthorized)?;
    Ok(Sha256::digest(raw).to_vec())
}

fn login_params<'a>(domain: &'a str, username: &'a str) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(CONTEXT),
        identifiers: Identifiers {
            client: Some(username.as_bytes()),
            server: Some(domain.as_bytes()),
        },
    }
}

fn is_unique_violation(e: &sqlx::Error) -> Option<String> {
    let db = e.as_database_error()?;
    (db.code().as_deref() == Some("23505")).then(|| db.constraint().unwrap_or("").to_string())
}

// ---------- email codes ----------

#[derive(Deserialize)]
pub struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
pub struct VerifyBody {
    email: String,
    code: String,
}

async fn request_code(
    st: &AppState,
    headers: &HeaderMap,
    purpose: Purpose,
    email_in: &str,
) -> ApiResult<StatusCode> {
    let email =
        Secrets::normalize_email(email_in).ok_or(ApiError::BadRequest("invalid email address"))?;
    let email_hmac = st.secrets.email_hmac(&email);

    let ip = client_ip(headers);
    let per_ip = st
        .limiter
        .allow(&format!("code-ip:{ip}"), 10, Duration::from_secs(3600));
    let per_email = st.limiter.allow(
        &format!("code-email:{}", hex(&email_hmac)),
        3,
        Duration::from_secs(900),
    );
    if !(per_ip && per_email) {
        return Err(ApiError::TooManyRequests);
    }

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE email_hmac = $1)")
            .bind(&email_hmac)
            .fetch_one(&st.db)
            .await?;

    // The response is identical whether or not the account exists, so this endpoint cannot be
    // used to find out who has an account. The email content differs instead.
    let (subject, body) = match (purpose, exists) {
        (Purpose::Signup, false) | (Purpose::Reset, true) => {
            let code = format!("{:06}", OsRng.gen_range(0..1_000_000u32));
            sqlx::query(
                "INSERT INTO email_codes (email_hmac, purpose, code_mac, attempts, expires_at)
                 VALUES ($1, $2, $3, 0, now() + interval '10 minutes')
                 ON CONFLICT (email_hmac, purpose) DO UPDATE
                 SET code_mac = EXCLUDED.code_mac, attempts = 0, expires_at = EXCLUDED.expires_at",
            )
            .bind(&email_hmac)
            .bind(purpose.as_str())
            .bind(st.secrets.code_mac(&email_hmac, &code))
            .execute(&st.db)
            .await?;
            let what = match purpose {
                Purpose::Signup => "finish creating your Yappitron account",
                Purpose::Reset => "reset your Yappitron password",
            };
            (
                format!("Your Yappitron code: {code}"),
                format!(
                    "Use this code to {what}:\n\n    {code}\n\nIt expires in 10 minutes. \
                     If you didn't ask for it, ignore this email."
                ),
            )
        }
        (Purpose::Signup, true) => (
            "You already have a Yappitron account".to_string(),
            "Someone tried to sign up with this address, but an account already exists. \
             If it was you, log in or use \"Forgot password\". Otherwise ignore this email."
                .to_string(),
        ),
        (Purpose::Reset, false) => (
            "Yappitron password reset".to_string(),
            "Someone asked to reset a password for this address, but there is no account. \
             If it was you, sign up instead. Otherwise ignore this email."
                .to_string(),
        ),
    };

    // Send in the background so response time doesn't depend on which branch ran.
    let mailer = st.mailer.clone();
    tokio::spawn(async move {
        if mailer.send(&email, &subject, &body).await.is_err() {
            tracing::error!("failed to send email");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn verify_code(
    st: &AppState,
    headers: &HeaderMap,
    purpose: Purpose,
    email_in: &str,
    code: &str,
) -> ApiResult<Value> {
    const INVALID: ApiError = ApiError::BadRequest("invalid or expired code");

    let ip = client_ip(headers);
    if !st
        .limiter
        .allow(&format!("verify-ip:{ip}"), 30, Duration::from_secs(3600))
    {
        return Err(ApiError::TooManyRequests);
    }
    let email = Secrets::normalize_email(email_in).ok_or(INVALID)?;
    let email_hmac = st.secrets.email_hmac(&email);

    // Every attempt (right or wrong) is counted before the comparison.
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "UPDATE email_codes SET attempts = attempts + 1
         WHERE email_hmac = $1 AND purpose = $2 AND expires_at > now() AND attempts < $3
         RETURNING code_mac",
    )
    .bind(&email_hmac)
    .bind(purpose.as_str())
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_optional(&st.db)
    .await?;
    let stored = stored.ok_or(INVALID)?;

    let expected = st.secrets.code_mac(&email_hmac, code.trim());
    if !bool::from(stored.ct_eq(&expected)) {
        return Err(INVALID);
    }

    sqlx::query("DELETE FROM email_codes WHERE email_hmac = $1 AND purpose = $2")
        .bind(&email_hmac)
        .bind(purpose.as_str())
        .execute(&st.db)
        .await?;

    let (token, token_hash) = random_token();
    sqlx::query(
        "INSERT INTO tickets (token_hash, email_hmac, purpose, expires_at)
         VALUES ($1, $2, $3, now() + interval '30 minutes')",
    )
    .bind(token_hash)
    .bind(&email_hmac)
    .bind(purpose.as_str())
    .execute(&st.db)
    .await?;
    Ok(json!({ "ticket": token }))
}

pub async fn signup_request_code(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<EmailBody>,
) -> ApiResult<StatusCode> {
    request_code(&st, &headers, Purpose::Signup, &b.email).await
}

pub async fn signup_verify_code(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<VerifyBody>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        verify_code(&st, &headers, Purpose::Signup, &b.email, &b.code).await?,
    ))
}

pub async fn reset_request_code(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<EmailBody>,
) -> ApiResult<StatusCode> {
    request_code(&st, &headers, Purpose::Reset, &b.email).await
}

pub async fn reset_verify_code(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<VerifyBody>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        verify_code(&st, &headers, Purpose::Reset, &b.email, &b.code).await?,
    ))
}

// ---------- tickets ----------

/// Email hash a still-valid ticket is bound to (not consumed).
async fn ticket_email(st: &AppState, ticket: &str, purpose: Purpose) -> ApiResult<Vec<u8>> {
    sqlx::query_scalar(
        "SELECT email_hmac FROM tickets
         WHERE token_hash = $1 AND purpose = $2 AND expires_at > now()",
    )
    .bind(hash_token(ticket)?)
    .bind(purpose.as_str())
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::Unauthorized)
}

// ---------- signup ----------

#[derive(Deserialize)]
pub struct SignupStartBody {
    ticket: String,
    username: String,
    request: String,
}

#[derive(Deserialize)]
pub struct SignupFinishBody {
    ticket: String,
    username: String,
    upload: String,
}

pub async fn signup_start(
    State(st): State<AppState>,
    Json(b): Json<SignupStartBody>,
) -> ApiResult<Json<Value>> {
    ticket_email(&st, &b.ticket, Purpose::Signup).await?;
    let name =
        username::canonicalize(&b.username).map_err(|e| ApiError::BadRequest(e.message()))?;
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE username = $1)")
            .bind(&name)
            .fetch_one(&st.db)
            .await?;
    if taken {
        return Err(ApiError::Conflict("username taken"));
    }
    let request = RegistrationRequest::<YapOpaque>::deserialize(&b64d(&b.request)?)
        .map_err(|_| ApiError::BadRequest("invalid registration request"))?;
    let result = ServerRegistration::<YapOpaque>::start(&st.setup, request, name.as_bytes())
        .map_err(|_| ApiError::Internal("opaque registration start"))?;
    Ok(Json(
        json!({ "response": B64.encode(result.message.serialize()) }),
    ))
}

pub async fn signup_finish(
    State(st): State<AppState>,
    Json(b): Json<SignupFinishBody>,
) -> ApiResult<StatusCode> {
    let name =
        username::canonicalize(&b.username).map_err(|e| ApiError::BadRequest(e.message()))?;
    let upload = RegistrationUpload::<YapOpaque>::deserialize(&b64d(&b.upload)?)
        .map_err(|_| ApiError::BadRequest("invalid registration upload"))?;
    let record = ServerRegistration::<YapOpaque>::finish(upload)
        .serialize()
        .to_vec();

    let mut tx = st.db.begin().await?;
    let email_hmac: Vec<u8> = sqlx::query_scalar(
        "DELETE FROM tickets
         WHERE token_hash = $1 AND purpose = 'signup' AND expires_at > now()
         RETURNING email_hmac",
    )
    .bind(hash_token(&b.ticket)?)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let inserted = sqlx::query(
        "INSERT INTO accounts (id, username, email_hmac, opaque_record) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(&name)
    .bind(&email_hmac)
    .bind(&record)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) => {
            return Err(match is_unique_violation(&e).as_deref() {
                Some("accounts_username_key") => ApiError::Conflict("username taken"),
                Some("accounts_email_hmac_key") => ApiError::Conflict("email already registered"),
                _ => ApiError::Internal("database"),
            });
        }
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

// ---------- login ----------

#[derive(Deserialize)]
pub struct LoginStartBody {
    username: String,
    request: String,
}

#[derive(Deserialize)]
pub struct LoginFinishBody {
    login_id: Uuid,
    finalization: String,
}

pub async fn login_start(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<LoginStartBody>,
) -> ApiResult<Json<Value>> {
    // An invalid username can't exist; carry on as for an unknown user so the reply is the same.
    let name = username::canonicalize(&b.username).unwrap_or_else(|_| b.username.to_lowercase());

    let ip = client_ip(&headers);
    let ok_ip = st
        .limiter
        .allow(&format!("login-ip:{ip}"), 60, Duration::from_secs(600));
    let ok_user = st
        .limiter
        .allow(&format!("login-user:{name}"), 10, Duration::from_secs(300));
    if !(ok_ip && ok_user) {
        return Err(ApiError::TooManyRequests);
    }

    let row: Option<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT id, opaque_record FROM accounts WHERE username = $1")
            .bind(&name)
            .fetch_optional(&st.db)
            .await?;
    let account_id = row.as_ref().map(|(id, _)| *id);
    let record = row.and_then(|(_, r)| ServerRegistration::<YapOpaque>::deserialize(&r).ok());

    let request = CredentialRequest::<YapOpaque>::deserialize(&b64d(&b.request)?)
        .map_err(|_| ApiError::BadRequest("invalid login request"))?;
    // With no record this still produces a well-formed fake response (see opaque-ke docs).
    let server = ServerLogin::start(
        &mut OsRng,
        &st.setup,
        record,
        request,
        name.as_bytes(),
        login_params(&st.domain, &name),
    )
    .map_err(|_| ApiError::Internal("opaque login start"))?;

    let login_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO login_states (id, account_id, username, state, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '2 minutes')",
    )
    .bind(login_id)
    .bind(account_id)
    .bind(&name)
    .bind(server.state.serialize().to_vec())
    .execute(&st.db)
    .await?;

    Ok(Json(json!({
        "login_id": login_id,
        "response": B64.encode(server.message.serialize()),
    })))
}

pub async fn login_finish(
    State(st): State<AppState>,
    Json(b): Json<LoginFinishBody>,
) -> ApiResult<Json<Value>> {
    // Single use: the state is deleted whether or not the password was right.
    let row: Option<(Option<Uuid>, String, Vec<u8>)> = sqlx::query_as(
        "DELETE FROM login_states WHERE id = $1 AND expires_at > now()
         RETURNING account_id, username, state",
    )
    .bind(b.login_id)
    .fetch_optional(&st.db)
    .await?;
    let (account_id, name, state) = row.ok_or(ApiError::Unauthorized)?;

    let server =
        ServerLogin::<YapOpaque>::deserialize(&state).map_err(|_| ApiError::Unauthorized)?;
    let finalization = CredentialFinalization::<YapOpaque>::deserialize(&b64d(&b.finalization)?)
        .map_err(|_| ApiError::Unauthorized)?;
    server
        .finish(finalization, login_params(&st.domain, &name))
        .map_err(|_| ApiError::Unauthorized)?;
    // Unknown users never get here with a valid finalization, but make that explicit.
    let account_id = account_id.ok_or(ApiError::Unauthorized)?;

    let (token, token_hash) = random_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, expires_at)
         VALUES ($1, $2, now() + interval '30 days')",
    )
    .bind(token_hash)
    .bind(account_id)
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "session_token": token })))
}

// ---------- password reset ----------

#[derive(Deserialize)]
pub struct ResetStartBody {
    ticket: String,
    request: String,
}

#[derive(Deserialize)]
pub struct ResetFinishBody {
    ticket: String,
    upload: String,
}

pub async fn reset_start(
    State(st): State<AppState>,
    Json(b): Json<ResetStartBody>,
) -> ApiResult<Json<Value>> {
    let email_hmac = ticket_email(&st, &b.ticket, Purpose::Reset).await?;
    let name: String = sqlx::query_scalar("SELECT username FROM accounts WHERE email_hmac = $1")
        .bind(&email_hmac)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let request = RegistrationRequest::<YapOpaque>::deserialize(&b64d(&b.request)?)
        .map_err(|_| ApiError::BadRequest("invalid registration request"))?;
    let result = ServerRegistration::<YapOpaque>::start(&st.setup, request, name.as_bytes())
        .map_err(|_| ApiError::Internal("opaque registration start"))?;
    Ok(Json(json!({
        "response": B64.encode(result.message.serialize()),
        // The client needs it as the OPAQUE identifier; the caller proved they own the email.
        "username": name,
    })))
}

pub async fn reset_finish(
    State(st): State<AppState>,
    Json(b): Json<ResetFinishBody>,
) -> ApiResult<StatusCode> {
    let upload = RegistrationUpload::<YapOpaque>::deserialize(&b64d(&b.upload)?)
        .map_err(|_| ApiError::BadRequest("invalid registration upload"))?;
    let record = ServerRegistration::<YapOpaque>::finish(upload)
        .serialize()
        .to_vec();

    let mut tx = st.db.begin().await?;
    let email_hmac: Vec<u8> = sqlx::query_scalar(
        "DELETE FROM tickets
         WHERE token_hash = $1 AND purpose = 'reset' AND expires_at > now()
         RETURNING email_hmac",
    )
    .bind(hash_token(&b.ticket)?)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let account_id: Uuid = sqlx::query_scalar(
        "UPDATE accounts SET opaque_record = $1 WHERE email_hmac = $2 RETURNING id",
    )
    .bind(&record)
    .bind(&email_hmac)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    // A password reset signs out every session.
    sqlx::query("DELETE FROM sessions WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- sessions ----------

/// A resolved login session.
pub struct Session {
    pub account: Uuid,
    /// Set once the client has registered or attached a device.
    pub device: Option<Uuid>,
    pub token_hash: Vec<u8>,
}

/// Resolve a raw session token.
pub async fn session_for_token(st: &AppState, token: &str) -> ApiResult<Session> {
    let token_hash = hash_token(token)?;
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT account_id, device_id FROM sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(&token_hash)
    .fetch_optional(&st.db)
    .await?;
    let (account, device) = row.ok_or(ApiError::Unauthorized)?;
    Ok(Session {
        account,
        device,
        token_hash,
    })
}

/// Resolve `Authorization: Bearer <token>`.
pub async fn session(st: &AppState, headers: &HeaderMap) -> ApiResult<Session> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    session_for_token(st, token).await
}

/// Resolve `Authorization: Bearer <token>` to an account id.
pub async fn authenticate(st: &AppState, headers: &HeaderMap) -> ApiResult<Uuid> {
    Ok(session(st, headers).await?.account)
}

pub async fn me(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let account_id = authenticate(&st, &headers).await?;
    let name: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({ "username": name })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = xff {
            h.insert("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn client_ip_is_the_last_forwarded_entry() {
        assert_eq!(client_ip(&headers(Some("203.0.113.9"))), "203.0.113.9");
        // A forged first entry must not be trusted: the proxy appended the real one last.
        assert_eq!(
            client_ip(&headers(Some("6.6.6.6, 203.0.113.9"))),
            "203.0.113.9"
        );
        assert_eq!(
            client_ip(&headers(Some("6.6.6.6,  203.0.113.9 "))),
            "203.0.113.9"
        );
        assert_eq!(client_ip(&headers(Some("203.0.113.9, "))), "203.0.113.9");
    }

    #[test]
    fn missing_header_falls_back() {
        assert_eq!(client_ip(&headers(None)), "unknown");
        assert_eq!(client_ip(&headers(Some(""))), "unknown");
    }
}
