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
    /// If set, the gateway also serves the built Flutter web app from this directory. Production
    /// uses Caddy for that; this is for local development and end-to-end tests.
    pub web_dir: Option<std::path::PathBuf>,
}

fn var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing environment variable {name}"))
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
            web_dir: std::env::var("YAP_WEB_DIR").ok().map(Into::into),
        })
    }
}
