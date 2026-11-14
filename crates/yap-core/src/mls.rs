//! MLS (RFC 9420) wrapper. A 1:1 chat is a two-member group; each device is its own member.
//!
//! This is the M0 spike surface: just enough to prove OpenMLS works on native and WASM.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving the live-typing key from the group's exporter secret.
pub const TYPING_KEY_LABEL: &str = "yappitron typing v1";

#[derive(Debug)]
pub enum Error {
    Mls(String),
    Codec(String),
    UnexpectedMessage(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Mls(e) => write!(f, "mls error: {e}"),
            Error::Codec(e) => write!(f, "codec error: {e}"),
            Error::UnexpectedMessage(w) => write!(f, "unexpected message: {w}"),
        }
    }
}

impl std::error::Error for Error {}

fn mls<E: std::fmt::Debug>(e: E) -> Error {
    Error::Mls(format!("{e:?}"))
}

fn codec<E: std::fmt::Debug>(e: E) -> Error {
    Error::Codec(format!("{e:?}"))
}

/// One device's MLS identity and state.
pub struct Device {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

/// A group (conversation) this device is a member of.
pub struct Conversation {
    group: MlsGroup,
}

impl Device {
    /// `name` identifies the device inside MLS credentials (e.g. `username/device-id`).
    pub fn new(name: &[u8]) -> Result<Self, Error> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
        })
    }

    /// A serialized key package for others to add this device to a group.
    pub fn key_package(&self) -> Result<Vec<u8>, Error> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls)?;
        bundle.key_package().tls_serialize_detached().map_err(codec)
    }

    /// Start a new conversation containing only this device.
    pub fn create_conversation(&self) -> Result<Conversation, Error> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .map_err(mls)?;
        Ok(Conversation { group })
    }

    /// Join a conversation from a serialized Welcome (the ratchet tree is inside it).
    pub fn join(&self, welcome: &[u8]) -> Result<Conversation, Error> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(codec)?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(Error::UnexpectedMessage("expected a Welcome"));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(mls)?
            .into_group(&self.provider)
            .map_err(mls)?;
        Ok(Conversation { group })
    }

    /// Add a member to the conversation. Returns `(commit, welcome)` to send via the server.
    /// The local group state is advanced immediately.
    pub fn add_member(
        &self,
        conv: &mut Conversation,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(key_package).map_err(codec)?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;
        let (commit, welcome, _group_info) = conv
            .group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(mls)?;
        conv.group
            .merge_pending_commit(&self.provider)
            .map_err(mls)?;
        Ok((
            commit.tls_serialize_detached().map_err(codec)?,
            welcome.tls_serialize_detached().map_err(codec)?,
        ))
    }

    /// Encrypt an application message (a chat message).
    pub fn encrypt(&self, conv: &mut Conversation, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let out = conv
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls)?;
        out.tls_serialize_detached().map_err(codec)
    }

    /// Decrypt an application message from another member.
    pub fn decrypt(&self, conv: &mut Conversation, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let msg = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(codec)?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| Error::UnexpectedMessage("not a protocol message"))?;
        let processed = conv
            .group
            .process_message(&self.provider, protocol)
            .map_err(mls)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err(Error::UnexpectedMessage("expected an application message")),
        }
    }

    /// Apply a commit from another member (membership/epoch changes).
    pub fn apply_commit(&self, conv: &mut Conversation, commit: &[u8]) -> Result<(), Error> {
        let msg = MlsMessageIn::tls_deserialize_exact(commit).map_err(codec)?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| Error::UnexpectedMessage("not a protocol message"))?;
        let processed = conv
            .group
            .process_message(&self.provider, protocol)
            .map_err(mls)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => conv
                .group
                .merge_staged_commit(&self.provider, *staged)
                .map_err(mls),
            _ => Err(Error::UnexpectedMessage("expected a commit")),
        }
    }

    /// 32-byte key for live-typing frames, derived from the current epoch's exporter secret.
    /// Both members derive the same key; it changes every epoch.
    pub fn typing_key(&self, conv: &Conversation) -> Result<[u8; 32], Error> {
        let secret = conv
            .group
            .export_secret(self.provider.crypto(), TYPING_KEY_LABEL, &[], 32)
            .map_err(mls)?;
        secret
            .try_into()
            .map_err(|_| Error::UnexpectedMessage("exporter returned wrong length"))
    }
}

impl Conversation {
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }
}
