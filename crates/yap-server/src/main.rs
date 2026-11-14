use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;
use yap_server::blobs::{BlobStore, clean_tmp};
use yap_server::config::Config;
use yap_server::mail::{FileMailer, Mailer, SmtpMailer};
use yap_server::{AppState, migrate, router, serve_web, sweep_forever};

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

    let mailer: Arc<dyn Mailer> = match (&cfg.dev_mail_file, &cfg.smtp) {
        (Some(path), _) => {
            eprintln!(
                "WARNING: YAP_DEV_MAIL_FILE is set; emails are written to {path:?} (development only)"
            );
            Arc::new(FileMailer(path.clone()))
        }
        (None, Some(smtp)) => Arc::new(SmtpMailer::new(smtp)?),
        (None, None) => unreachable!("Config::from_env requires one of them"),
    };
    let mut state = AppState::new(db.clone(), &cfg.secret, &cfg.domain, mailer)
        .await?
        .with_code_limit_per_ip(cfg.code_limit_per_ip);
    if cfg.link_previews {
        let fetcher = if cfg.dev_link_private {
            eprintln!(
                "WARNING: YAP_DEV_LINK_PREVIEW_PRIVATE is set; link previews may reach private addresses (development only)"
            );
            yap_server::previews::LinkFetcher::allowing_private_addresses()
        } else {
            yap_server::previews::LinkFetcher::new()
        };
        state = state.with_link_previews(fetcher);
    }
    if let Some(dir) = &cfg.blob_dir {
        let store = BlobStore::new(dir, cfg.max_blob_bytes, cfg.blob_quota_bytes);
        clean_tmp(&store).await;
        state = state.with_blobs(store);
    }
    tokio::spawn(sweep_forever(db));

    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    let mut app = router(state);
    if let Some(dir) = &cfg.web_dir {
        app = serve_web(app, dir);
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| format!("server: {e}"))
}
