//! End-to-end account flows against a real Postgres, driving the router in-process with the
//! real client crypto from `yap-core`.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); the tests skip with a notice otherwise.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use yap_core::auth;
use yap_server::mail::MemoryMailer;
use yap_server::{AppState, migrate, router};

const SERVER_ID: &[u8] = b"yap.test";
const PASSWORD: &[u8] = b"correct horse battery staple";

struct Harness {
    app: Router,
    mailer: Arc<MemoryMailer>,
    db: sqlx::PgPool,
}

async fn harness() -> Option<Harness> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: set TEST_DATABASE_URL to run server integration tests");
        return None;
    };
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect to test database");
    migrate(&db).await.expect("migrate");
    let mailer = Arc::new(MemoryMailer::default());
    let state = AppState::new(db.clone(), &[9u8; 32], "yap.test", mailer.clone())
        .await
        .expect("app state");
    Some(Harness {
        app: router(state),
        mailer,
        db,
    })
}

fn unique(prefix: &str) -> String {
    let n: u64 = rand::random();
    format!("{prefix}{n:x}")
}

impl Harness {
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", "203.0.113.7");
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(body), None).await
    }

    /// How many emails have gone to `email` so far.
    fn mail_count(&self, email: &str) -> usize {
        self.mailer
            .sent()
            .iter()
            .filter(|(to, _, _)| to == email)
            .count()
    }

    /// Wait for the background mail task to deliver a NEW email (the `already`+1th to this
    /// address), then pull the 6-digit code out of it.
    async fn code_for(&self, email: &str, already: usize) -> String {
        for _ in 0..60 {
            let mails: Vec<_> = self
                .mailer
                .sent()
                .into_iter()
                .filter(|(to, _, _)| to == email)
                .collect();
            if let Some((_, subject, _)) = mails.get(already) {
                return subject
                    .strip_prefix("Your Yappitron code: ")
                    .unwrap_or_else(|| panic!("email was not a code email: {subject}"))
                    .to_string();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no new email for {email}");
    }

    async fn ticket(&self, kind: &str, email: &str) -> String {
        let already = self.mail_count(email);
        let (s, _) = self
            .post(
                &format!("/api/v1/{kind}/request-code"),
                json!({"email": email}),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let code = self.code_for(email, already).await;
        let (s, v) = self
            .post(
                &format!("/api/v1/{kind}/verify-code"),
                json!({"email": email, "code": code}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["ticket"].as_str().unwrap().to_string()
    }

    async fn signup(&self, email: &str, username: &str, password: &[u8]) {
        let ticket = self.ticket("signup", email).await;
        self.register("signup", &ticket, username, password, StatusCode::CREATED)
            .await;
    }

    /// Run the OPAQUE registration handshake against `/{kind}/start` and `/{kind}/finish`.
    async fn register(
        &self,
        kind: &str,
        ticket: &str,
        username: &str,
        password: &[u8],
        expect: StatusCode,
    ) {
        let (request, state) = auth::register_start(password).unwrap();
        let mut start = json!({"ticket": ticket, "request": B64.encode(&request)});
        if kind == "signup" {
            start["username"] = json!(username);
        }
        let (s, v) = self.post(&format!("/api/v1/{kind}/start"), start).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let response = B64.decode(v["response"].as_str().unwrap()).unwrap();
        let upload =
            auth::register_finish(state, password, username.as_bytes(), SERVER_ID, &response)
                .unwrap();
        let mut finish = json!({"ticket": ticket, "upload": B64.encode(&upload)});
        if kind == "signup" {
            finish["username"] = json!(username);
        }
        let (s, v) = self.post(&format!("/api/v1/{kind}/finish"), finish).await;
        assert_eq!(s, expect, "{v}");
    }

    /// Ok(session token), or Err("client") if the client rejected the server's reply (wrong
    /// password / unknown user), or Err("server") if the server refused the finalization.
    async fn login(&self, username: &str, password: &[u8]) -> Result<String, &'static str> {
        let (request, state) = auth::login_start(password).unwrap();
        let (s, v) = self
            .post(
                "/api/v1/login/start",
                json!({"username": username, "request": B64.encode(&request)}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let response = B64.decode(v["response"].as_str().unwrap()).unwrap();
        let out = auth::login_finish(state, password, username.as_bytes(), SERVER_ID, &response)
            .map_err(|_| "client")?;
        let (s, v) = self
            .post(
                "/api/v1/login/finish",
                json!({"login_id": v["login_id"], "finalization": B64.encode(&out.finalization)}),
            )
            .await;
        if s != StatusCode::OK {
            return Err("server");
        }
        Ok(v["session_token"].as_str().unwrap().to_string())
    }

    async fn me(&self, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, "/api/v1/me", None, Some(token))
            .await
    }
}

#[tokio::test]
async fn signup_login_and_session() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("a")), unique("alice"));
    h.signup(&email, &user, PASSWORD).await;

    let token = h.login(&user, PASSWORD).await.expect("login");
    let (s, v) = h.me(&token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["username"], user);

    // Usernames are case-insensitive: clients canonicalize before the OPAQUE exchange.
    let canonical = yap_proto::username::canonicalize(&user.to_uppercase()).unwrap();
    assert!(h.login(&canonical, PASSWORD).await.is_ok());

    // Malformed and unknown tokens are both plain 401s.
    assert_eq!(h.me("bogus").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.me(&B64.encode([0u8; 32])).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_password_and_unknown_user_look_the_same() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("b")), unique("bob"));
    h.signup(&email, &user, PASSWORD).await;

    assert_eq!(h.login(&user, b"wrong password").await, Err("client"));
    assert_eq!(h.login(&unique("ghost"), PASSWORD).await, Err("client"));
    assert_eq!(h.login("!!not valid!!", PASSWORD).await, Err("client"));
}

#[tokio::test]
async fn duplicate_username_and_email_are_rejected() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("c")), unique("carol"));
    h.signup(&email, &user, PASSWORD).await;

    // Same username, new email: rejected at /signup/start.
    let ticket = h
        .ticket("signup", &format!("{}@example.test", unique("c2")))
        .await;
    let (request, _state) = auth::register_start(PASSWORD).unwrap();
    let (s, _) = h
        .post("/api/v1/signup/start", json!({"ticket": ticket, "username": user.to_uppercase(), "request": B64.encode(&request)}))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Same email: signup is "accepted" (no enumeration) but the email says the account exists
    // and no code is issued.
    let (s, _) = h
        .post("/api/v1/signup/request-code", json!({"email": email}))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let last = h
        .mailer
        .sent()
        .into_iter()
        .rev()
        .find(|(to, _, _)| *to == email)
        .unwrap();
    assert_eq!(last.1, "You already have a Yappitron account");
}

#[tokio::test]
async fn username_rules_are_enforced() {
    let Some(h) = harness().await else { return };
    let ticket = h
        .ticket("signup", &format!("{}@example.test", unique("d")))
        .await;
    let (request, _s) = auth::register_start(PASSWORD).unwrap();
    for bad in ["ab", "has space", "_lead", "admin"] {
        let (s, _) = h
            .post(
                "/api/v1/signup/start",
                json!({"ticket": ticket, "username": bad, "request": B64.encode(&request)}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn code_locks_after_five_wrong_attempts() {
    let Some(h) = harness().await else { return };
    let email = format!("{}@example.test", unique("e"));
    h.post("/api/v1/signup/request-code", json!({"email": email}))
        .await;
    let code = h.code_for(&email, 0).await;
    let wrong = if code == "000000" { "000001" } else { "000000" };

    for _ in 0..5 {
        let (s, _) = h
            .post(
                "/api/v1/signup/verify-code",
                json!({"email": email, "code": wrong}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    // Now even the right code is refused.
    let (s, _) = h
        .post(
            "/api/v1/signup/verify-code",
            json!({"email": email, "code": code}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ticket_is_single_use() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("f")), unique("frank"));
    let ticket = h.ticket("signup", &email).await;
    h.register("signup", &ticket, &user, PASSWORD, StatusCode::CREATED)
        .await;

    let (request, state) = auth::register_start(PASSWORD).unwrap();
    let (s, _) = h
        .post(
            "/api/v1/signup/start",
            json!({"ticket": ticket, "username": unique("other"), "request": B64.encode(&request)}),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "spent ticket must not start another signup"
    );
    drop(state);
}

#[tokio::test]
async fn password_reset_changes_password_and_signs_out() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("g")), unique("gina"));
    h.signup(&email, &user, PASSWORD).await;
    let old_session = h.login(&user, PASSWORD).await.unwrap();

    let ticket = h.ticket("reset", &email).await;
    let new_password: &[u8] = b"a brand new passphrase";
    h.register(
        "reset",
        &ticket,
        &user,
        new_password,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_eq!(
        h.login(&user, PASSWORD).await,
        Err("client"),
        "old password must stop working"
    );
    assert!(h.login(&user, new_password).await.is_ok());
    assert_eq!(
        h.me(&old_session).await.0,
        StatusCode::UNAUTHORIZED,
        "reset signs out old sessions"
    );
}

#[tokio::test]
async fn reset_for_unknown_email_sends_no_code() {
    let Some(h) = harness().await else { return };
    let email = format!("{}@example.test", unique("nobody"));
    let (s, _) = h
        .post("/api/v1/reset/request-code", json!({"email": email}))
        .await;
    assert_eq!(
        s,
        StatusCode::ACCEPTED,
        "same response as for a real account"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mail = h
        .mailer
        .sent()
        .into_iter()
        .rev()
        .find(|(to, _, _)| *to == email)
        .unwrap();
    assert!(!mail.1.starts_with("Your Yappitron code"));
}

#[tokio::test]
async fn database_never_contains_plaintext_email_or_password() {
    let Some(h) = harness().await else { return };
    let (email, user) = (format!("{}@example.test", unique("priv")), unique("pat"));
    h.signup(&email, &user, PASSWORD).await;
    let _ = h
        .post(
            "/api/v1/signup/request-code",
            json!({"email": format!("{}@example.test", unique("x"))}),
        )
        .await;

    for table in [
        "accounts",
        "email_codes",
        "tickets",
        "login_states",
        "sessions",
        "server_config",
    ] {
        let sql =
            format!("SELECT COALESCE(string_agg(row_to_json(t)::text, ' '), '') FROM {table} t");
        let dump: String = sqlx::query_scalar(&sql).fetch_one(&h.db).await.unwrap();
        assert!(!dump.contains(&email), "plaintext email found in {table}");
        assert!(!dump.contains("correct horse"), "password found in {table}");
        assert!(
            !dump.to_lowercase().contains("203.0.113.7"),
            "client IP found in {table}"
        );
    }
}

#[tokio::test]
async fn code_requests_are_rate_limited_per_email() {
    let Some(h) = harness().await else { return };
    let email = format!("{}@example.test", unique("rl"));
    let mut statuses = vec![];
    for _ in 0..5 {
        statuses.push(
            h.post("/api/v1/signup/request-code", json!({"email": email}))
                .await
                .0,
        );
    }
    assert_eq!(&statuses[..3], &[StatusCode::ACCEPTED; 3]);
    assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS);
}
