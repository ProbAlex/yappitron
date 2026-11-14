//! Yappitron gateway server.

pub mod auth;
pub mod chat;
pub mod config;
pub mod error;
pub mod hub;
pub mod limiter;
pub mod mail;
pub mod secrets;
pub mod state;
pub mod ws;

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

pub use state::AppState;

pub async fn migrate(db: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(db).await
}

pub fn router(state: AppState) -> Router {
    // NOTE: no request-logging layer. Nothing about requests is logged.
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/api/v1/signup/request-code",
            post(auth::signup_request_code),
        )
        .route("/api/v1/signup/verify-code", post(auth::signup_verify_code))
        .route("/api/v1/signup/start", post(auth::signup_start))
        .route("/api/v1/signup/finish", post(auth::signup_finish))
        .route("/api/v1/login/start", post(auth::login_start))
        .route("/api/v1/login/finish", post(auth::login_finish))
        .route("/api/v1/reset/request-code", post(auth::reset_request_code))
        .route("/api/v1/reset/verify-code", post(auth::reset_verify_code))
        .route("/api/v1/reset/start", post(auth::reset_start))
        .route("/api/v1/reset/finish", post(auth::reset_finish))
        .route("/api/v1/me", get(auth::me))
        .route("/api/v1/devices", post(chat::create_device))
        .route("/api/v1/devices/attach", post(chat::attach_device))
        .route(
            "/api/v1/devices/me/key-packages",
            axum::routing::put(chat::put_key_packages),
        )
        .route(
            "/api/v1/devices/me/key-packages/count",
            get(chat::key_package_count),
        )
        .route(
            "/api/v1/users/{username}/key-packages",
            post(chat::take_key_packages),
        )
        .route(
            "/api/v1/conversations",
            get(chat::list_conversations).post(chat::create_conversation),
        )
        .route("/api/v1/conversations/{id}/accept", post(chat::accept))
        .route("/api/v1/conversations/{id}/decline", post(chat::decline))
        .route(
            "/api/v1/conversations/{id}/messages",
            get(chat::get_messages).post(chat::post_message),
        )
        .route("/api/v1/conversations/{id}/ack", post(chat::ack))
        .route("/api/v1/welcomes", get(chat::list_welcomes))
        .route(
            "/api/v1/welcomes/{id}",
            axum::routing::delete(chat::delete_welcome),
        )
        .route("/ws", get(ws::ws_handler))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

/// Periodically delete expired short-lived rows.
pub async fn sweep_forever(db: sqlx::PgPool) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        for table in ["email_codes", "tickets", "login_states", "sessions"] {
            let sql = format!("DELETE FROM {table} WHERE expires_at < now()");
            if sqlx::query(&sql).execute(&db).await.is_err() {
                tracing::warn!(table, "sweep failed");
            }
        }
    }
}
