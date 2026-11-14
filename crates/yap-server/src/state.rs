use std::sync::Arc;

use opaque_ke::ServerSetup;
use opaque_ke::rand::rngs::OsRng;
use sqlx::PgPool;
use yap_proto::auth::{YapOpaque, opaque_ke};

use crate::blobs::BlobStore;
use crate::hub::Hub;
use crate::limiter::RateLimiter;
use crate::mail::Mailer;
use crate::previews::LinkFetcher;
use crate::secrets::Secrets;

pub type Setup = ServerSetup<YapOpaque>;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub secrets: Arc<Secrets>,
    pub setup: Arc<Setup>,
    pub mailer: Arc<dyn Mailer>,
    pub limiter: Arc<RateLimiter>,
    /// Live connections and the typing relay (in-process; becomes a bus across nodes).
    pub hub: Arc<Hub>,
    /// Public hostname; the OPAQUE server identifier.
    pub domain: Arc<str>,
    /// How many emailed codes one address may request per hour (in-memory counters).
    pub code_limit_per_ip: u32,
    /// Encrypted attachments; `None` turns the feature off.
    pub blobs: Option<Arc<BlobStore>>,
    /// Fetches pages for link previews; `None` turns the feature off.
    pub links: Option<Arc<LinkFetcher>>,
}

impl AppState {
    pub async fn new(
        db: PgPool,
        master_secret: &[u8],
        domain: &str,
        mailer: Arc<dyn Mailer>,
    ) -> Result<Self, String> {
        let secrets = Secrets::derive(master_secret);
        let setup = load_or_create_setup(&db, &secrets).await?;
        Ok(Self {
            db,
            secrets: Arc::new(secrets),
            setup: Arc::new(setup),
            mailer,
            limiter: Arc::new(RateLimiter::default()),
            hub: Arc::new(Hub::default()),
            domain: domain.into(),
            code_limit_per_ip: 10,
            blobs: None,
            links: None,
        })
    }

    /// Turn on encrypted attachments, stored under the store's directory.
    pub fn with_blobs(mut self, store: BlobStore) -> Self {
        self.blobs = Some(Arc::new(store));
        self
    }

    /// Turn on link previews (the gateway fetches pages on the sender's behalf).
    pub fn with_link_previews(mut self, fetcher: LinkFetcher) -> Self {
        self.links = Some(Arc::new(fetcher));
        self
    }

    /// Override how many emailed codes one address may request per hour (default 10).
    pub fn with_code_limit_per_ip(mut self, limit: u32) -> Self {
        self.code_limit_per_ip = limit;
        self
    }
}

/// The OPAQUE server setup (OPRF seed + AKE key pair) must be identical across restarts and
/// across gateway nodes, so it is stored sealed under a key derived from the master secret.
async fn load_or_create_setup(db: &PgPool, secrets: &Secrets) -> Result<Setup, String> {
    const KEY: &str = "opaque_setup_v1";
    let fetch = || async {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM server_config WHERE key = $1")
            .bind(KEY)
            .fetch_optional(db)
            .await
            .map_err(|e| format!("reading server_config: {e}"))
    };

    if fetch().await?.is_none() {
        let fresh = Setup::new(&mut OsRng);
        // ON CONFLICT: two gateways starting at once; the first insert wins.
        sqlx::query(
            "INSERT INTO server_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
        )
        .bind(KEY)
        .bind(secrets.seal(&fresh.serialize()))
        .execute(db)
        .await
        .map_err(|e| format!("writing server_config: {e}"))?;
    }
    let sealed = fetch().await?.ok_or("server_config row vanished")?;
    let bytes = secrets
        .open(&sealed)
        .ok_or("cannot open stored OPAQUE setup: wrong YAP_SERVER_SECRET?")?;
    Setup::deserialize(&bytes).map_err(|e| format!("corrupt OPAQUE setup: {e:?}"))
}
