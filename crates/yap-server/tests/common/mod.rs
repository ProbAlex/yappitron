//! Shared harness for the server integration tests: a real Postgres, the router driven
//! in-process (or over a real socket for WebSocket tests), and the real client crypto from
//! `yap-core`.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tower::ServiceExt;
use yap_core::auth;
use yap_core::link;
use yap_core::mls::Device;
use yap_server::blobs::BlobStore;
use yap_server::mail::MemoryMailer;
use yap_server::previews::LinkFetcher;
use yap_server::{AppState, migrate, router};

pub const SERVER_ID: &[u8] = b"yap.test";
pub const PASSWORD: &[u8] = b"correct horse battery staple";

pub struct Harness {
    pub app: Router,
    pub mailer: Arc<MemoryMailer>,
    pub db: sqlx::PgPool,
}

pub async fn harness() -> Option<Harness> {
    harness_with(None, None).await
}

/// A harness with link previews on. `fetcher` decides what it may reach.
pub async fn link_harness(fetcher: LinkFetcher) -> Option<Harness> {
    harness_with(None, Some(fetcher)).await
}

/// A harness with encrypted attachments on: files go to a fresh temp dir, with the given
/// per-file cap and per-account quota (bytes).
pub async fn blob_harness(max: u64, quota: u64) -> Option<Harness> {
    let dir = std::env::temp_dir().join(unique("yap-blobs-"));
    harness_with(Some(BlobStore::new(dir, max, quota)), None).await
}

async fn harness_with(blobs: Option<BlobStore>, links: Option<LinkFetcher>) -> Option<Harness> {
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
    let mut state = AppState::new(db.clone(), &[9u8; 32], "yap.test", mailer.clone())
        .await
        .expect("app state");
    if let Some(b) = blobs {
        state = state.with_blobs(b);
    }
    if let Some(l) = links {
        state = state.with_link_previews(l);
    }
    Some(Harness {
        app: router(state),
        mailer,
        db,
    })
}

pub fn unique(prefix: &str) -> String {
    let n: u64 = rand::random();
    format!("{prefix}{n:x}")
}

impl Harness {
    pub async fn call(
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

    pub async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(body), None).await
    }

    /// A request with a raw binary body (and response), for attachments.
    pub async fn call_raw(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        bearer: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", "203.0.113.7")
            .header("content-length", body.len());
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, bytes.to_vec())
    }

    /// How many emails have gone to `email` so far.
    pub fn mail_count(&self, email: &str) -> usize {
        self.mailer
            .sent()
            .iter()
            .filter(|(to, _, _)| to == email)
            .count()
    }

    /// Wait for the background mail task to deliver a NEW email (the `already`+1th to this
    /// address), then pull the 6-digit code out of it.
    pub async fn code_for(&self, email: &str, already: usize) -> String {
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

    pub async fn ticket(&self, kind: &str, email: &str) -> String {
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

    pub async fn signup(&self, email: &str, username: &str, password: &[u8]) {
        let ticket = self.ticket("signup", email).await;
        self.register("signup", &ticket, username, password, StatusCode::CREATED)
            .await;
    }

    /// Run the OPAQUE registration handshake against `/{kind}/start` and `/{kind}/finish`.
    pub async fn register(
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
    pub async fn login(&self, username: &str, password: &[u8]) -> Result<String, &'static str> {
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

    pub async fn me(&self, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, "/api/v1/me", None, Some(token))
            .await
    }
}

impl Harness {
    /// Serve the router on a real local port (for WebSocket tests).
    pub async fn serve(&self) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = self.app.clone();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    /// GET/POST/PUT/DELETE with a bearer token and an optional JSON body.
    pub async fn authed(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call(method, path, body, Some(token)).await
    }

    /// Sign up, log in, register a device and upload key packages: a ready-to-chat device.
    pub async fn user(&self, label: &str) -> Client {
        let username = unique(label);
        let email = format!("{username}@example.test");
        self.signup(&email, &username, PASSWORD).await;
        let session = self.login(&username, PASSWORD).await.expect("login");
        self.new_device(&username, &session, "test device").await
    }

    /// A second (or third...) device for an existing account: a fresh login on another install.
    /// It starts PENDING: it cannot read or send until an approved device lets it in.
    pub async fn add_pending_device(&self, owner: &Client, name: &str) -> Client {
        let session = self.login(&owner.username, PASSWORD).await.expect("login");
        self.new_device(&owner.username, &session, name).await
    }

    /// Ask to be approved and have `approver` approve with a placeholder bundle. This does NOT
    /// add the device to existing conversations (see `Client::add_to_conversation`).
    pub async fn approve_simple(&self, approver: &Client, pending: &mut Client) {
        pending.request_link(self).await;
        let public = pending.link.unwrap().1;
        let bundle = link::seal(&public, b"bundle").unwrap();
        let (s, v) = approver
            .post(
                self,
                &format!("/api/v1/devices/{}/approve", pending.device_id),
                json!({"bundle": B64.encode(bundle)}),
            )
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    }

    /// A second device that is already approved (for tests that are not about approval).
    pub async fn add_device(&self, owner: &Client, name: &str) -> Client {
        let mut d = self.add_pending_device(owner, name).await;
        self.approve_simple(owner, &mut d).await;
        d
    }

    async fn new_device(&self, username: &str, session: &str, name: &str) -> Client {
        let (s, v) = self
            .authed(
                Method::POST,
                "/api/v1/devices",
                session,
                Some(json!({"name": name})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let device_id = v["device_id"].as_str().unwrap().to_string();
        let mls = Device::new(format!("{username}/{device_id}").as_bytes()).unwrap();
        let kps: Vec<String> = (0..10)
            .map(|_| B64.encode(mls.key_package().unwrap()))
            .collect();
        let (s, v) = self
            .authed(
                Method::PUT,
                "/api/v1/devices/me/key-packages",
                session,
                Some(json!({"key_packages": kps})),
            )
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
        Client {
            username: username.to_string(),
            token: session.to_string(),
            device_id,
            mls,
            link: None,
        }
    }
}

/// One logged-in device with its MLS state.
pub struct Client {
    pub username: String,
    pub token: String,
    pub device_id: String,
    pub mls: Device,
    /// `(secret, public)` link key, once this device has asked to be approved.
    pub link: Option<([u8; 32], [u8; 32])>,
}

impl Client {
    pub async fn get(&self, h: &Harness, path: &str) -> (StatusCode, Value) {
        h.authed(Method::GET, path, &self.token, None).await
    }

    pub async fn post(&self, h: &Harness, path: &str, body: Value) -> (StatusCode, Value) {
        h.authed(Method::POST, path, &self.token, Some(body)).await
    }

    /// Start a conversation with `other`: take their key packages (and the caller's other
    /// devices'), build the MLS group and Welcome, and create it on the server.
    /// Returns the conversation id.
    pub async fn start_conversation(&self, h: &Harness, other: &str) -> uuid::Uuid {
        let conv = uuid::Uuid::new_v4();
        let mut recipients = vec![];
        let mut kps: Vec<Vec<u8>> = vec![];
        for who in [other, &self.username] {
            let (s, v) = self
                .post(h, &format!("/api/v1/users/{who}/key-packages"), json!({}))
                .await;
            assert_eq!(s, StatusCode::OK, "{v}");
            for d in v["devices"].as_array().unwrap() {
                recipients.push(d["device_id"].as_str().unwrap().to_string());
                kps.push(B64.decode(d["key_package"].as_str().unwrap()).unwrap());
            }
        }
        self.mls.create_conversation(conv.as_bytes()).unwrap();
        let kp_refs: Vec<&[u8]> = kps.iter().map(|k| k.as_slice()).collect();
        let (_commit, welcome) = self.mls.add_members(conv.as_bytes(), &kp_refs).unwrap();
        let (s, v) = self
            .post(
                h,
                "/api/v1/conversations",
                json!({"id": conv, "member": other, "welcome": B64.encode(welcome), "recipients": recipients}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        conv
    }

    /// Fetch pending welcomes and join each; returns the conversation ids joined.
    pub async fn join_pending(&self, h: &Harness) -> Vec<uuid::Uuid> {
        let (s, v) = self.get(h, "/api/v1/welcomes").await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let mut joined = vec![];
        for w in v["welcomes"].as_array().unwrap() {
            let gid = self
                .mls
                .join(&B64.decode(w["data"].as_str().unwrap()).unwrap())
                .unwrap();
            joined.push(uuid::Uuid::from_slice(&gid).unwrap());
            let (s, _) = h
                .authed(
                    Method::DELETE,
                    &format!("/api/v1/welcomes/{}", w["id"]),
                    &self.token,
                    None,
                )
                .await;
            assert_eq!(s, StatusCode::NO_CONTENT);
        }
        joined
    }

    /// Encrypt and post a chat message; returns the HTTP status and the sequence number.
    pub async fn send(&self, h: &Harness, conv: uuid::Uuid, text: &str) -> (StatusCode, i64) {
        let ct = self.mls.encrypt(conv.as_bytes(), text.as_bytes()).unwrap();
        let (s, v) = self
            .post(
                h,
                &format!("/api/v1/conversations/{conv}/messages"),
                json!({"kind": 1, "data": B64.encode(ct)}),
            )
            .await;
        (s, v["seq"].as_i64().unwrap_or(-1))
    }

    /// Fetch and decrypt everything after `after` (own echoes are skipped). Commits are ignored.
    pub async fn read(&self, h: &Harness, conv: uuid::Uuid, after: i64) -> Vec<String> {
        let (s, v) = self
            .get(
                h,
                &format!("/api/v1/conversations/{conv}/messages?after={after}"),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let mut out = vec![];
        for m in v["messages"].as_array().unwrap() {
            match self.mls.decrypt(
                conv.as_bytes(),
                &B64.decode(m["data"].as_str().unwrap()).unwrap(),
            ) {
                Ok(d) => out.push(String::from_utf8(d.plaintext).unwrap()),
                Err(yap_core::mls::Error::OwnMessage) => {}
                Err(e) => panic!("decrypt failed: {e}"),
            }
        }
        out
    }
}

pub struct Ws(WebSocketStream<MaybeTlsStream<TcpStream>>);

impl Ws {
    /// Connect, authenticate and wait for the replay to finish, so the test only sees what
    /// happens afterwards. Panics unless the server answers `ready` and `synced`.
    pub async fn connect(addr: SocketAddr, token: &str) -> Ws {
        let mut ws = Ws::connect_keeping_replay(addr, token).await;
        assert!(ws.next_of("synced", 5000).await.is_some(), "synced");
        ws
    }

    /// Like `connect`, but returns right after `ready`: the replay is still to be read.
    pub async fn connect_keeping_replay(addr: SocketAddr, token: &str) -> Ws {
        let mut ws = Ws::raw(addr).await;
        ws.send(json!({"t": "auth", "token": token})).await;
        assert_eq!(ws.next(2000).await.expect("ready")["t"], "ready");
        ws
    }

    pub async fn raw(addr: SocketAddr) -> Ws {
        Ws(connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("ws connect")
            .0)
    }

    pub async fn send(&mut self, v: Value) {
        self.0
            .send(Message::Text(v.to_string().into()))
            .await
            .unwrap();
    }

    /// Next JSON frame within `ms`, or `None` on timeout / close.
    pub async fn next(&mut self, ms: u64) -> Option<Value> {
        loop {
            match tokio::time::timeout(Duration::from_millis(ms), self.0.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(&t).ok(),
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                _ => return None,
            }
        }
    }

    /// Next frame of type `t`, skipping others.
    pub async fn next_of(&mut self, t: &str, ms: u64) -> Option<Value> {
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
    pub async fn drain(&mut self, ms: u64) -> Vec<Value> {
        let mut out = vec![];
        while let Some(v) = self.next(ms).await {
            out.push(v);
        }
        out
    }
}

impl Client {
    pub async fn authed_put(&self, h: &Harness, path: &str, body: Value) -> (StatusCode, Value) {
        h.authed(Method::PUT, path, &self.token, Some(body)).await
    }

    pub async fn delete_bundle(&self, h: &Harness) -> StatusCode {
        h.authed(
            Method::DELETE,
            "/api/v1/devices/me/bundle",
            &self.token,
            None,
        )
        .await
        .0
    }

    /// A pending device publishes a fresh link key and asks to be approved.
    pub async fn request_link(&mut self, h: &Harness) {
        let (secret, public) = link::keypair();
        let (s, v) = self
            .post(
                h,
                "/api/v1/devices/me/link-request",
                json!({"link_pub": B64.encode(public)}),
            )
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
        self.link = Some((secret, public));
    }

    /// Add `new_device` (a device of this account, or of the other member) to `conv`.
    /// The commit is only applied locally if the server accepted it; otherwise it is rolled back.
    pub async fn add_to_conversation(
        &self,
        h: &Harness,
        conv: uuid::Uuid,
        new_device: &Client,
        base_seq: i64,
    ) -> (StatusCode, Value) {
        let (s, v) = self
            .post(
                h,
                &format!("/api/v1/devices/{}/key-package", new_device.device_id),
                json!({}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        self.add_with_key_package(
            h,
            conv,
            &new_device.device_id,
            &B64.decode(v["key_package"].as_str().unwrap()).unwrap(),
            base_seq,
        )
        .await
    }

    pub async fn add_with_key_package(
        &self,
        h: &Harness,
        conv: uuid::Uuid,
        device_id: &str,
        key_package: &[u8],
        base_seq: i64,
    ) -> (StatusCode, Value) {
        let (commit, welcome) = self
            .mls
            .add_members_staged(conv.as_bytes(), &[key_package])
            .unwrap();
        let (s, v) = self
            .post(
                h,
                &format!("/api/v1/conversations/{conv}/devices"),
                json!({"commit": B64.encode(commit), "welcome": B64.encode(welcome), "recipients": [device_id], "base_seq": base_seq}),
            )
            .await;
        if s == StatusCode::OK {
            self.mls.confirm_pending(conv.as_bytes()).unwrap();
        } else {
            self.mls.discard_pending(conv.as_bytes()).unwrap();
        }
        (s, v)
    }

    /// Apply every log entry after `after` that is a commit (so this device's group state
    /// catches up) and decrypt the application messages. Returns the highest seq seen.
    pub async fn sync(
        &self,
        h: &Harness,
        conv: uuid::Uuid,
        after: i64,
    ) -> (i64, Vec<(String, String)>) {
        let (s, v) = self
            .get(
                h,
                &format!("/api/v1/conversations/{conv}/messages?after={after}"),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let (mut last, mut texts) = (after, vec![]);
        for m in v["messages"].as_array().unwrap() {
            let data = B64.decode(m["data"].as_str().unwrap()).unwrap();
            last = m["seq"].as_i64().unwrap();
            if m["kind"] == 0 {
                self.mls.apply_commit(conv.as_bytes(), &data).unwrap();
            } else {
                match self.mls.decrypt(conv.as_bytes(), &data) {
                    Ok(d) => texts.push((
                        String::from_utf8(d.sender).unwrap(),
                        String::from_utf8(d.plaintext).unwrap(),
                    )),
                    Err(yap_core::mls::Error::OwnMessage) => {}
                    Err(e) => panic!("decrypt failed: {e}"),
                }
            }
        }
        (last, texts)
    }
}
