//! Keys derived from the master secret, plus the email HMAC.
//!
//! Losing `YAP_SERVER_SECRET` means nobody can log in (the OPAQUE setup cannot be opened and
//! email lookups no longer match), so it must be backed up separately from the database.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct Secrets {
    email_key: [u8; 32],
    code_key: [u8; 32],
    seal_key: [u8; 32],
}

fn derive(hk: &Hkdf<Sha256>, label: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

impl Secrets {
    pub fn derive(master: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"yappitron-v1"), master);
        Self {
            email_key: derive(&hk, b"email-hmac"),
            code_key: derive(&hk, b"email-code-mac"),
            seal_key: derive(&hk, b"config-seal"),
        }
    }

    /// Normalize an email for hashing: trimmed and lowercased. Returns `None` if it is not
    /// plausibly an address. Deliberately loose; the verification code is the real check.
    pub fn normalize_email(input: &str) -> Option<String> {
        let email = input.trim().to_lowercase();
        if email.len() > 254 || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let (local, domain) = email.split_once('@')?;
        if local.is_empty() || local.len() > 64 || domain.contains('@') {
            return None;
        }
        if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
            return None;
        }
        Some(email)
    }

    /// Keyed hash used as the account's email identity. The address itself is never stored.
    pub fn email_hmac(&self, normalized_email: &str) -> Vec<u8> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.email_key).expect("any key length works");
        mac.update(normalized_email.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// MAC of a one-time code, bound to the email so codes cannot be moved between accounts.
    pub fn code_mac(&self, email_hmac: &[u8], code: &str) -> Vec<u8> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.code_key).expect("any key length works");
        mac.update(email_hmac);
        mac.update(code.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Encrypt a config value (random nonce prepended).
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new((&self.seal_key).into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        out.extend(
            cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext)
                .expect("encryption cannot fail for in-memory buffers"),
        );
        out
    }

    /// Decrypt a value produced by [`seal`]. `None` if tampered with or the wrong secret.
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 12 + 16 {
            return None;
        }
        let (nonce, ct) = sealed.split_at(12);
        ChaCha20Poly1305::new((&self.seal_key).into())
            .decrypt(Nonce::from_slice(nonce), ct)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization() {
        assert_eq!(
            Secrets::normalize_email("  Alice@Example.COM ").as_deref(),
            Some("alice@example.com")
        );
        for bad in [
            "",
            "alice",
            "a@b",
            "@x.com",
            "a@@x.com",
            "a b@x.com",
            "a@x.",
        ] {
            assert!(Secrets::normalize_email(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn email_hmac_is_stable_and_secret_dependent() {
        let a = Secrets::derive(&[1u8; 32]);
        let b = Secrets::derive(&[2u8; 32]);
        assert_eq!(a.email_hmac("x@y.z"), a.email_hmac("x@y.z"));
        assert_ne!(a.email_hmac("x@y.z"), b.email_hmac("x@y.z"));
        assert_ne!(a.email_hmac("x@y.z"), a.email_hmac("x@y.w"));
    }

    #[test]
    fn seal_roundtrip_and_tamper_detection() {
        let s = Secrets::derive(&[7u8; 32]);
        let sealed = s.seal(b"opaque setup bytes");
        assert_eq!(s.open(&sealed).unwrap(), b"opaque setup bytes");
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(s.open(&bad).is_none());
        assert!(Secrets::derive(&[8u8; 32]).open(&sealed).is_none());
    }
}
