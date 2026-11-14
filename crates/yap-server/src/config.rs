//! Configuration from environment variables (see `.env.example`).

use std::net::SocketAddr;

#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub from: String,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    /// Public hostname, bound into OPAQUE as the server identifier.
    pub domain: String,
    /// Master secret (decoded). All server-side keys are derived from it.
    pub secret: Vec<u8>,
    /// Real outbound email. Required unless `dev_mail_file` is set.
    pub smtp: Option<SmtpConfig>,
    /// DEVELOPMENT ONLY: append outgoing emails to this file instead of sending them, so tests
    /// and local runs can read verification codes. Never set this in production: it writes
    /// recipient addresses and codes to disk.
    pub dev_mail_file: Option<std::path::PathBuf>,
    /// Emailed codes one client address may request per hour (`YAP_CODE_LIMIT_PER_IP`, default 10).
    pub code_limit_per_ip: u32,
    /// If set, the gateway also serves the built Flutter web app from this directory. Production
    /// uses Caddy for that; this is for local development and end-to-end tests.
    pub web_dir: Option<std::path::PathBuf>,
    /// Where encrypted attachments are stored (`YAP_BLOB_DIR`); unset turns attachments off.
    pub blob_dir: Option<std::path::PathBuf>,
    /// Largest attachment in bytes (`YAP_MAX_BLOB_MB`, default 100).
    pub max_blob_bytes: u64,
    /// Attachment storage per account in bytes (`YAP_BLOB_QUOTA_GB`, default 20).
    pub blob_quota_bytes: u64,
    /// Whether the gateway may fetch pages for link previews (`YAP_LINK_PREVIEWS=off` disables).
    pub link_previews: bool,
    /// DEVELOPMENT ONLY (`YAP_DEV_LINK_PREVIEW_PRIVATE=1`): let link previews reach private and
    /// local addresses, so tests can use a local web server. In production this would let any
    /// user make the server fetch pages from your internal network. Never set it there.
    pub dev_link_private: bool,
}

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing environment variable {name}"))
}

/// A whole number of megabytes from the environment, as bytes.
fn mb(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        * 1024
        * 1024
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        use base64::Engine as _;
        let secret = base64::engine::general_purpose::STANDARD
            .decode(var("YAP_SERVER_SECRET")?.trim())
            .map_err(|_| "YAP_SERVER_SECRET must be base64".to_string())?;
        if secret.len() < 32 {
            return Err("YAP_SERVER_SECRET must decode to at least 32 bytes".into());
        }
        let dev_mail_file: Option<std::path::PathBuf> =
            std::env::var("YAP_DEV_MAIL_FILE").ok().map(Into::into);
        let smtp = match std::env::var("SMTP_HOST") {
            Ok(host) => Some(SmtpConfig {
                host,
                port: var("SMTP_PORT")?
                    .parse()
                    .map_err(|_| "SMTP_PORT must be a number".to_string())?,
                user: var("SMTP_USER")?,
                password: var("SMTP_PASSWORD")?,
                from: var("SMTP_FROM")?,
            }),
            Err(_) => None,
        };
        if smtp.is_none() && dev_mail_file.is_none() {
            return Err("set SMTP_HOST (and the other SMTP_* variables) to send email".into());
        }
        Ok(Self {
            bind: var("YAP_BIND")?
                .parse()
                .map_err(|_| "YAP_BIND must look like 0.0.0.0:8080".to_string())?,
            database_url: var("DATABASE_URL")?,
            domain: var("YAP_DOMAIN")?,
            secret,
            smtp,
            dev_mail_file,
            code_limit_per_ip: std::env::var("YAP_CODE_LIMIT_PER_IP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            web_dir: std::env::var("YAP_WEB_DIR").ok().map(Into::into),
            blob_dir: std::env::var("YAP_BLOB_DIR").ok().map(Into::into),
            max_blob_bytes: mb("YAP_MAX_BLOB_MB", 100),
            blob_quota_bytes: mb("YAP_BLOB_QUOTA_GB", 20) * 1024,
            dev_link_private: std::env::var("YAP_DEV_LINK_PREVIEW_PRIVATE").is_ok_and(|v| v == "1"),
            link_previews: !matches!(
                std::env::var("YAP_LINK_PREVIEWS").as_deref(),
                Ok("off" | "0" | "false")
            ),
        })
    }
}
