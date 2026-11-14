//! MLS (RFC 9420) wrapper. A 1:1 chat is a two-member group; each device is its own member.
//!
//! A [`Device`] owns all key material and MLS state. Conversations are addressed by group id
//! and loaded from the device's storage on every call, so the whole state can be exported to
//! an encrypted blob ([`Device::export`]) and restored later ([`Device::import`]).

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto};
use std::collections::HashMap;

/// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving the live-typing key from the group's exporter secret.
pub const TYPING_KEY_LABEL: &str = "yappitron typing v1";

const BLOB_MAGIC: &[u8] = b"YAPD1";
const BLOB_AAD: &[u8] = b"yappitron-device-v1";

#[derive(Debug)]
pub enum Error {
    Mls(String),
    Codec(String),
    UnexpectedMessage(&'static str),
    NoSuchConversation,
    /// Wrong key, corrupted data, or not a device blob.
    BadBlob,
    /// This device sent the message itself. MLS cannot decrypt a sender's own ciphertext, so
    /// callers keep the plaintext when sending and skip the echo.
    OwnMessage,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Mls(e) => write!(f, "mls error: {e}"),
            Error::Codec(e) => write!(f, "codec error: {e}"),
            Error::UnexpectedMessage(w) => write!(f, "unexpected message: {w}"),
            Error::NoSuchConversation => write!(f, "no such conversation"),
            Error::BadBlob => write!(f, "cannot open device data (wrong key or corrupted)"),
            Error::OwnMessage => write!(f, "own message"),
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

/// `count(u64 BE) | { key_len(u64 BE) | value_len(u64 BE) | key | value }*` over the storage map.
fn encode_storage(storage: &MemoryStorage, out: &mut Vec<u8>) -> Result<(), Error> {
    let values = storage.values.read().map_err(|_| Error::BadBlob)?;
    out.extend((values.len() as u64).to_be_bytes());
    for (k, v) in values.iter() {
        out.extend((k.len() as u64).to_be_bytes());
        out.extend((v.len() as u64).to_be_bytes());
        out.extend(k);
        out.extend(v);
    }
    Ok(())
}

fn decode_storage(mut buf: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, Error> {
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
        if buf.len() < n {
            return Err(Error::BadBlob);
        }
        let (head, tail) = buf.split_at(n);
        *buf = tail;
        Ok(head)
    }
    fn take_u64(buf: &mut &[u8]) -> Result<usize, Error> {
        let n = u64::from_be_bytes(take(buf, 8)?.try_into().map_err(|_| Error::BadBlob)?);
        usize::try_from(n).map_err(|_| Error::BadBlob)
    }
    let count = take_u64(&mut buf)?;
    let mut map = HashMap::new();
    for _ in 0..count {
        let (k_len, v_len) = (take_u64(&mut buf)?, take_u64(&mut buf)?);
        let k = take(&mut buf, k_len)?.to_vec();
        let v = take(&mut buf, v_len)?.to_vec();
        map.insert(k, v);
    }
    Ok(map)
}

/// A decrypted application message and who sent it.
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    /// The sender's MLS credential identity (`username/device-id`), authenticated by MLS.
    pub sender: Vec<u8>,
}

/// How many past epochs keep their keys, so messages that were in flight when a device was
/// added (sent just before, delivered just after) can still be read.
const MAX_PAST_EPOCHS: usize = 5;

/// One device's MLS identity and state.
pub struct Device {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    name: Vec<u8>,
}

fn credential_for(name: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

impl Device {
    /// `name` identifies the device inside MLS credentials (e.g. `username/device-id`).
    pub fn new(name: &[u8]) -> Result<Self, Error> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;
        let credential = credential_for(name, &signer);
        Ok(Self {
            provider,
            signer,
            credential,
            name: name.to_vec(),
        })
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    // ----- persistence -----

    /// Serialize all device state and encrypt it under `key` (32 random bytes kept in the
    /// platform keystore). Call after every operation that changes state.
    pub fn export(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut plain = BLOB_MAGIC.to_vec();
        for part in [&self.name[..], self.signer.public()] {
            plain.extend((part.len() as u32).to_le_bytes());
            plain.extend(part);
        }
        encode_storage(self.provider.storage(), &mut plain)?;

        Ok(crate::vault::seal(key, BLOB_AAD, &plain))
    }

    /// Restore a device from [`Device::export`] output.
    pub fn import(blob: &[u8], key: &[u8; 32]) -> Result<Self, Error> {
        let plain = crate::vault::open(key, BLOB_AAD, blob).map_err(|_| Error::BadBlob)?;
        let mut rest = plain.strip_prefix(BLOB_MAGIC).ok_or(Error::BadBlob)?;

        let mut take = || -> Result<Vec<u8>, Error> {
            let (len, tail) = rest.split_first_chunk::<4>().ok_or(Error::BadBlob)?;
            let len = u32::from_le_bytes(*len) as usize;
            if tail.len() < len {
                return Err(Error::BadBlob);
            }
            let (part, tail) = tail.split_at(len);
            rest = tail;
            Ok(part.to_vec())
        };
        let name = take()?;
        let public = take()?;

        let loaded = decode_storage(rest)?;
        let provider = OpenMlsRustCrypto::default();
        *provider
            .storage()
            .values
            .write()
            .map_err(|_| Error::BadBlob)? = loaded;

        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(Error::BadBlob)?;
        let credential = credential_for(&name, &signer);
        Ok(Self {
            provider,
            signer,
            credential,
            name,
        })
    }

    /// This device's MLS signature public key (its stable identity inside groups).
    pub fn signer_public(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    // ----- key packages -----

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

    // ----- conversations -----

    fn group(&self, group_id: &[u8]) -> Result<MlsGroup, Error> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or(Error::NoSuchConversation)
    }

    /// Start a new conversation containing only this device, with a caller-chosen group id
    /// (the server's conversation id, so everyone agrees on it).
    pub fn create_conversation(&self, group_id: &[u8]) -> Result<(), Error> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(mls)?;
        Ok(())
    }

    /// Join a conversation from a serialized Welcome (the ratchet tree is inside it).
    /// Returns the group id.
    pub fn join(&self, welcome: &[u8]) -> Result<Vec<u8>, Error> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(codec)?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(Error::UnexpectedMessage("expected a Welcome"));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(mls)?
            .into_group(&self.provider)
            .map_err(mls)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// Add one or more devices in a single commit and apply it locally right away. Use
    /// [`Device::add_members_staged`] when the commit might be rejected by the server.
    pub fn add_members(
        &self,
        group_id: &[u8],
        key_packages: &[&[u8]],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let out = self.add_members_staged(group_id, key_packages)?;
        self.confirm_pending(group_id)?;
        Ok(out)
    }

    /// Build a commit adding devices WITHOUT applying it: the group stays on its current epoch
    /// with the commit pending. Post `(commit, welcome)` to the server, then call
    /// [`Device::confirm_pending`] if it was accepted or [`Device::discard_pending`] if not
    /// (for example because another member's commit landed first).
    pub fn add_members_staged(
        &self,
        group_id: &[u8],
        key_packages: &[&[u8]],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut group = self.group(group_id)?;
        let kps = key_packages
            .iter()
            .map(|kp| {
                KeyPackageIn::tls_deserialize_exact(kp)
                    .map_err(codec)?
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(mls)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (commit, welcome, _info) = group
            .add_members(&self.provider, &self.signer, &kps)
            .map_err(mls)?;
        Ok((
            commit.tls_serialize_detached().map_err(codec)?,
            welcome.tls_serialize_detached().map_err(codec)?,
        ))
    }

    /// Apply the commit staged by [`Device::add_members_staged`].
    pub fn confirm_pending(&self, group_id: &[u8]) -> Result<(), Error> {
        self.group(group_id)?
            .merge_pending_commit(&self.provider)
            .map_err(mls)
    }

    /// Drop the commit staged by [`Device::add_members_staged`]; the group is unchanged.
    pub fn discard_pending(&self, group_id: &[u8]) -> Result<(), Error> {
        self.group(group_id)?
            .clear_pending_commit(self.provider.storage())
            .map_err(mls)
    }

    /// Encrypt an application message (a chat message).
    pub fn encrypt(&self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut group = self.group(group_id)?;
        let out = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls)?;
        out.tls_serialize_detached().map_err(codec)
    }

    /// Decrypt an application message from another member (or another device of the same
    /// account). A device's own ciphertext cannot be decrypted: that is [`Error::OwnMessage`].
    pub fn decrypt(&self, group_id: &[u8], ciphertext: &[u8]) -> Result<Decrypted, Error> {
        let mut group = self.group(group_id)?;
        let msg = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(codec)?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| Error::UnexpectedMessage("not a protocol message"))?;
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(mls)?;
        let sender = BasicCredential::try_from(processed.credential().clone())
            .map_err(mls)?
            .identity()
            .to_vec();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Decrypted {
                plaintext: app.into_bytes(),
                sender,
            }),
            ProcessedMessageContent::OwnPrivateMessage => Err(Error::OwnMessage),
            _ => Err(Error::UnexpectedMessage("expected an application message")),
        }
    }

    /// Apply a commit from another member (membership/epoch changes).
    pub fn apply_commit(&self, group_id: &[u8], commit: &[u8]) -> Result<(), Error> {
        let mut group = self.group(group_id)?;
        let msg = MlsMessageIn::tls_deserialize_exact(commit).map_err(codec)?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| Error::UnexpectedMessage("not a protocol message"))?;
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(mls)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => group
                .merge_staged_commit(&self.provider, *staged)
                .map_err(mls),
            _ => Err(Error::UnexpectedMessage("expected a commit")),
        }
    }

    pub fn epoch(&self, group_id: &[u8]) -> Result<u64, Error> {
        Ok(self.group(group_id)?.epoch().as_u64())
    }

    pub fn member_count(&self, group_id: &[u8]) -> Result<usize, Error> {
        Ok(self.group(group_id)?.members().count())
    }

    /// 32-byte key for live-typing frames, derived from the current epoch's exporter secret.
    /// Both members derive the same key; it changes every epoch.
    pub fn typing_key(&self, group_id: &[u8]) -> Result<[u8; 32], Error> {
        let secret = self
            .group(group_id)?
            .export_secret(self.provider.crypto(), TYPING_KEY_LABEL, &[], 32)
            .map_err(mls)?;
        secret
            .try_into()
            .map_err(|_| Error::UnexpectedMessage("exporter returned wrong length"))
    }
}

/// The signature public key inside a serialized key package (the device identity it claims).
pub fn key_package_signer(key_package: &[u8]) -> Result<Vec<u8>, Error> {
    let kp = KeyPackageIn::tls_deserialize_exact(key_package).map_err(codec)?;
    // Structural parse only: the server cannot be trusted to hand out valid packages, and
    // `add_members` validates the full package (signature, lifetime, ciphersuite) before use.
    let provider = OpenMlsRustCrypto::default();
    let kp = kp
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls)?;
    Ok(kp.leaf_node().signature_key().as_slice().to_vec())
}
