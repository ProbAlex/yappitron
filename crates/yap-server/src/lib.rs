//! Yappitron gateway server.

pub mod auth;
pub mod config;
pub mod error;
pub mod limiter;
pub mod mail;
pub mod secrets;
pub mod state;

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
        .layer(DefaultBodyLimit::max(64 * 1024))
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
