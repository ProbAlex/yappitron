//! Handing secrets to a newly approved device.
//!
//! A new device publishes an X25519 public key; an already-trusted device of the same account
//! seals the account's history key to it. This is a standard sealed box: an ephemeral X25519
//! key agreement, HKDF-SHA256, ChaCha20-Poly1305. The server only relays the sealed bytes.
//!
//! Layout: `ephemeral_public(32) | nonce(12) | ciphertext`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, PartialEq, Eq)]
pub struct OpenError;

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cannot open sealed link data")
    }
}

impl std::error::Error for OpenError {}

/// A fresh X25519 key pair: `(secret, public)`.
pub fn keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn derive_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"yappitron link v1"), shared);
    let mut info = ephemeral.to_vec();
    info.extend(recipient);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF length");
    key
}

fn aad(ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut a = ephemeral.to_vec();
    a.extend(recipient);
    a
}

/// Encrypt `plaintext` so only the holder of the secret for `recipient_public` can read it.
pub fn seal(recipient_public: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, OpenError> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(*recipient_public));
    if !shared.was_contributory() {
        return Err(OpenError); // a low-order public key: refuse rather than derive a fixed key
    }
    let key = derive_key(shared.as_bytes(), &ephemeral_public, recipient_public);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(&ephemeral_public, recipient_public),
            },
        )
        .map_err(|_| OpenError)?;
    let mut out = ephemeral_public.to_vec();
    out.extend(nonce);
    out.extend(ct);
    Ok(out)
}

/// Decrypt data sealed to the public key of `secret`.
pub fn open(secret: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
    if sealed.len() < 32 + 12 + 16 {
        return Err(OpenError);
    }
    let ephemeral_public: [u8; 32] = sealed[..32].try_into().map_err(|_| OpenError)?;
    let secret = StaticSecret::from(*secret);
    let recipient_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_public));
    if !shared.was_contributory() {
        return Err(OpenError);
    }
    let key = derive_key(shared.as_bytes(), &ephemeral_public, &recipient_public);
    ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(&sealed[32..44]),
            Payload {
                msg: &sealed[44..],
                aad: &aad(&ephemeral_public, &recipient_public),
            },
        )
        .map_err(|_| OpenError)
}

/// A short code both devices show during approval, binding the device's MLS signature key and
/// its link key. If a malicious server swapped either key, the two codes would differ.
/// 80 bits, as five groups of four hex digits (`A1B2-C3D4-E5F6-0718-293A`).
pub fn fingerprint(signature_public: &[u8], link_public: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"yappitron device fingerprint v1");
    for part in [signature_public, link_public] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let hex: String = digest[..10].iter().map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}
