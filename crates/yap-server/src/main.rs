use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;
use yap_server::config::Config;
use yap_server::mail::SmtpMailer;
use yap_server::{AppState, migrate, router, sweep_forever};

#[tokio::main]
async fn main() {
    // Default to warnings only. The app logs no request data, whatever the level.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_target(false)
        .without_time()
        .init();

    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await
        .map_err(|e| format!("database: {e}"))?;
    migrate(&db).await.map_err(|e| format!("migrations: {e}"))?;

    let mailer = Arc::new(SmtpMailer::new(&cfg.smtp)?);
    let state = AppState::new(db.clone(), &cfg.secret, &cfg.domain, mailer).await?;
    tokio::spawn(sweep_forever(db));

    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| format!("server: {e}"))
}
