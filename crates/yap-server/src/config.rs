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
    pub smtp: SmtpConfig,
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
        Ok(Self {
            bind: var("YAP_BIND")?
                .parse()
                .map_err(|_| "YAP_BIND must look like 0.0.0.0:8080".to_string())?,
            database_url: var("DATABASE_URL")?,
            domain: var("YAP_DOMAIN")?,
            secret,
            smtp: SmtpConfig {
                host: var("SMTP_HOST")?,
                port: var("SMTP_PORT")?
                    .parse()
                    .map_err(|_| "SMTP_PORT must be a number".to_string())?,
                user: var("SMTP_USER")?,
                password: var("SMTP_PASSWORD")?,
                from: var("SMTP_FROM")?,
            },
        })
    }
}
