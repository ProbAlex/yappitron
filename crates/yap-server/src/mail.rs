//! Outbound email. Production uses an SMTP relay; tests capture messages in memory.

use std::sync::Mutex;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::SmtpConfig;

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    pub fn new(cfg: &SmtpConfig) -> Result<Self, String> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|e| format!("smtp setup: {e}"))?
            .port(cfg.port)
            .credentials(Credentials::new(cfg.user.clone(), cfg.password.clone()))
            .build();
        let from = cfg
            .from
            .parse()
            .map_err(|_| "SMTP_FROM is not a valid address".to_string())?;
        Ok(Self { transport, from })
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to.parse().map_err(|_| "bad recipient".to_string())?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| format!("build: {e}"))?;
        self.transport
            .send(msg)
            .await
            .map(|_| ())
            .map_err(|e| format!("send: {e}"))
    }
}

/// Captures messages instead of sending them. Used by tests.
#[derive(Default)]
pub struct MemoryMailer {
    sent: Mutex<Vec<(String, String, String)>>,
}

impl MemoryMailer {
    /// All `(to, subject, body)` captured so far.
    pub fn sent(&self) -> Vec<(String, String, String)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl Mailer for MemoryMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        self.sent
            .lock()
            .unwrap()
            .push((to.into(), subject.into(), body.into()));
        Ok(())
    }
}

/// DEVELOPMENT ONLY. Appends one JSON line per email to a file. Writes recipient addresses and
/// codes to disk, so it is only reachable through the explicit `YAP_DEV_MAIL_FILE` setting.
pub struct FileMailer(pub std::path::PathBuf);

#[async_trait]
impl Mailer for FileMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        use std::io::Write as _;
        let line = serde_json::json!({ "to": to, "subject": subject, "body": body }).to_string();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .map_err(|e| format!("open dev mail file: {e}"))?;
        writeln!(file, "{line}").map_err(|e| format!("write dev mail file: {e}"))
    }
}
