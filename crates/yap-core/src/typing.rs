//! Live-typing frames: an encrypted snapshot of the sender's current draft.
//!
//! Frames are ephemeral (relayed from RAM, never stored), so each one is a full snapshot and
//! a lost frame is harmless. They are padded to fixed size buckets so the ciphertext length
//! reveals little about how much is typed.
//!
//! Layout: `version(1) | epoch(8, LE) | nonce(12) | AEAD(seq(8) | len(2) | text | zero pad)`,
//! with `version | epoch | group_id` as associated data. The key comes from the MLS exporter
//! of that epoch (see [`crate::mls::Device::typing_key`]). A random nonce is used because
//! several members share one key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;

const VERSION: u8 = 1;
const HEADER: usize = 1 + 8 + 12;
const PLAIN_HEADER: usize = 8 + 2;
/// Plaintext size buckets (header included).
pub const BUCKETS: [usize; 4] = [256, 512, 1024, 2048];
/// Longest draft, in bytes, that fits in the largest bucket.
pub const MAX_TEXT_BYTES: usize = 2048 - PLAIN_HEADER;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed, wrong key, wrong conversation, or tampered with.
    Invalid,
    UnsupportedVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid => f.write_str("invalid typing frame"),
            Error::UnsupportedVersion => f.write_str("unsupported typing frame version"),
        }
    }
}

impl std::error::Error for Error {}

/// An opened frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened {
    pub epoch: u64,
    pub seq: u64,
    pub text: String,
}

fn aad(epoch: u64, group_id: &[u8]) -> Vec<u8> {
    let mut a = vec![VERSION];
    a.extend(epoch.to_le_bytes());
    a.extend(group_id);
    a
}

/// Keep the end of the draft (what the other person is watching being typed), cut on a char
/// boundary, so it fits the largest bucket.
fn fit(text: &str) -> &str {
    if text.len() <= MAX_TEXT_BYTES {
        return text;
    }
    let mut start = text.len() - MAX_TEXT_BYTES;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

pub fn seal(key: &[u8; 32], epoch: u64, group_id: &[u8], seq: u64, text: &str) -> Vec<u8> {
    let text = fit(text).as_bytes();
    let needed = PLAIN_HEADER + text.len();
    let bucket = BUCKETS.into_iter().find(|b| *b >= needed).unwrap_or(2048);

    let mut plain = Vec::with_capacity(bucket);
    plain.extend(seq.to_le_bytes());
    plain.extend((text.len() as u16).to_le_bytes());
    plain.extend(text);
    plain.resize(bucket, 0);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad(epoch, group_id),
            },
        )
        .expect("encrypting an in-memory buffer cannot fail");

    let mut frame = vec![VERSION];
    frame.extend(epoch.to_le_bytes());
    frame.extend(nonce);
    frame.extend(ct);
    frame
}

/// The epoch a frame claims, readable without the key (so callers can pick the right key).
pub fn epoch_of(frame: &[u8]) -> Result<u64, Error> {
    if frame.first() != Some(&VERSION) {
        return Err(if frame.is_empty() {
            Error::Invalid
        } else {
            Error::UnsupportedVersion
        });
    }
    let bytes: [u8; 8] = frame
        .get(1..9)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn open(key: &[u8; 32], group_id: &[u8], frame: &[u8]) -> Result<Opened, Error> {
    let epoch = epoch_of(frame)?;
    if frame.len() < HEADER + 16 {
        return Err(Error::Invalid);
    }
    let nonce = &frame[9..HEADER];
    let plain = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &frame[HEADER..],
                aad: &aad(epoch, group_id),
            },
        )
        .map_err(|_| Error::Invalid)?;
    if plain.len() < PLAIN_HEADER {
        return Err(Error::Invalid);
    }
    let seq = u64::from_le_bytes(plain[..8].try_into().map_err(|_| Error::Invalid)?);
    let len = u16::from_le_bytes([plain[8], plain[9]]) as usize;
    let text = plain
        .get(PLAIN_HEADER..PLAIN_HEADER + len)
        .ok_or(Error::Invalid)?;
    Ok(Opened {
        epoch,
        seq,
        text: String::from_utf8(text.to_vec()).map_err(|_| Error::Invalid)?,
    })
}
