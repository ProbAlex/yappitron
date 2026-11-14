//! Authenticated encryption for data kept on the device (saved chat history, device state).
//!
//! ChaCha20-Poly1305 under a 32-byte key the platform keeps in its keystore, with a random
//! nonce prepended. `context` is authenticated but not stored, so a blob sealed for one purpose
//! (say, one conversation's history) cannot be swapped in for another.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;

const OVERHEAD: usize = 12 + 16;

/// Wrong key or context, or corrupted/truncated data.
#[derive(Debug, PartialEq, Eq)]
pub struct OpenError;

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cannot open sealed data (wrong key or corrupted)")
    }
}

impl std::error::Error for OpenError {}

pub fn seal(key: &[u8; 32], context: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .expect("encrypting an in-memory buffer cannot fail");
    let mut out = nonce.to_vec();
    out.extend(ct);
    out
}

pub fn open(key: &[u8; 32], context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
    if sealed.len() < OVERHEAD {
        return Err(OpenError);
    }
    let (nonce, ct) = sealed.split_at(12);
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: context,
            },
        )
        .map_err(|_| OpenError)
}

/// Derive a 32-byte key from a secret and a purpose label (HKDF-SHA256). Different labels give
/// unrelated keys, so one secret (the recovery key) can serve several purposes safely.
pub fn derive_key(secret: &[u8], label: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"yappitron derive v1"), secret)
        .expand(label, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}
