//! Encryption of attachments (images, video, files, link-preview pictures).
//!
//! The sender encrypts a file under a fresh random 32-byte key and uploads only the ciphertext;
//! the server stores it without being able to read it, name it or know what it is. The key and
//! file details travel inside the end-to-end encrypted chat message, so only the people in the
//! conversation can open the file.
//!
//! Format: `version(1) | chunk_log2(1) | nonce_prefix(7) | chunk*`. Each chunk is the AEAD of up
//! to `2^chunk_log2` plaintext bytes (ChaCha20-Poly1305, the header as associated data). The nonce
//! is `nonce_prefix | chunk_index(u32, BE) | last_flag(1)` (the STREAM construction), so chunks
//! cannot be reordered, dropped from the end, or extended without detection. Chunking means a
//! streaming reader/writer can be added later without changing the format. Every chunk but the
//! last is full size; a file whose length is an exact multiple of the chunk size ends with a full
//! final chunk, and an empty file is a single empty final chunk.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;

const VERSION: u8 = 1;
const HEADER: usize = 9;
const TAG: usize = 16;
/// 64 KiB of plaintext per chunk.
const CHUNK_LOG2: u8 = 16;
const CHUNK: usize = 1 << CHUNK_LOG2 as usize;

/// Size of the ciphertext for a file of `plain_len` bytes (what gets uploaded).
pub fn sealed_len(plain_len: usize) -> usize {
    let chunks = plain_len.div_ceil(CHUNK).max(1);
    HEADER + plain_len + chunks * TAG
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong key, corrupted, truncated, reordered or extended.
    Invalid,
    UnsupportedVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid => f.write_str("cannot open file (wrong key or corrupted)"),
            Error::UnsupportedVersion => f.write_str("unsupported file format version"),
        }
    }
}

impl std::error::Error for Error {}

fn nonce(prefix: &[u8], index: u32, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&index.to_be_bytes());
    n[11] = last as u8;
    *Nonce::from_slice(&n)
}

/// Encrypt `plaintext` under `key` (which must be random and used for this one file only).
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut header = [0u8; HEADER];
    header[0] = VERSION;
    header[1] = CHUNK_LOG2;
    OsRng.fill_bytes(&mut header[2..]);

    let cipher = ChaCha20Poly1305::new(key.into());
    let mut out = Vec::with_capacity(sealed_len(plaintext.len()));
    out.extend_from_slice(&header);

    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(CHUNK).collect()
    };
    let n = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let ct = cipher
            .encrypt(
                &nonce(&header[2..], i as u32, i + 1 == n),
                Payload {
                    msg: chunk,
                    aad: &header,
                },
            )
            .expect("encrypting an in-memory buffer cannot fail");
        out.extend(ct);
    }
    out
}

/// Decrypt a file produced by [`seal`].
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < HEADER + TAG {
        return Err(Error::Invalid);
    }
    let (header, body) = sealed.split_at(HEADER);
    if header[0] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if header[1] != CHUNK_LOG2 {
        return Err(Error::Invalid);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut out = Vec::with_capacity(body.len());
    let step = CHUNK + TAG;
    let n = body.len().div_ceil(step);
    for (i, chunk) in body.chunks(step).enumerate() {
        let pt = cipher
            .decrypt(
                &nonce(&header[2..], i as u32, i + 1 == n),
                Payload {
                    msg: chunk,
                    aad: header,
                },
            )
            .map_err(|_| Error::Invalid)?;
        out.extend(pt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn round_trips_around_chunk_boundaries() {
        let k = key();
        for n in [
            0,
            1,
            100,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            3 * CHUNK,
            3 * CHUNK + 7,
        ] {
            let pt = data(n);
            let sealed = seal(&k, &pt);
            assert_eq!(sealed.len(), sealed_len(n), "length for {n}");
            assert_eq!(open(&k, &sealed).unwrap(), pt, "round trip for {n}");
        }
    }

    #[test]
    fn ciphertext_hides_the_content_and_differs_each_time() {
        let k = key();
        let pt = vec![7u8; 5000];
        let (a, b) = (seal(&k, &pt), seal(&k, &pt));
        assert_ne!(a, b, "random nonce prefix");
        assert!(!a.windows(64).any(|w| w == &pt[..64]));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&key(), b"secret picture");
        assert_eq!(open(&key(), &sealed), Err(Error::Invalid));
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let k = key();
        let sealed = seal(&k, &data(2 * CHUNK + 5));
        for at in [0usize, 1, 2, 9, 100, CHUNK + 40, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(open(&k, &bad).is_err(), "flip at {at}");
        }
    }

    #[test]
    fn truncation_reordering_and_extension_are_rejected() {
        let k = key();
        let step = CHUNK + TAG;
        let sealed = seal(&k, &data(3 * CHUNK));
        // Drop the last chunk: the new last chunk was not sealed as final.
        assert!(open(&k, &sealed[..sealed.len() - step]).is_err());
        // Cut mid-chunk.
        assert!(open(&k, &sealed[..sealed.len() - 10]).is_err());
        // Swap two chunks.
        let mut swapped = sealed.clone();
        let (a, b) = (HEADER, HEADER + step);
        let first: Vec<u8> = swapped[a..a + step].to_vec();
        let second: Vec<u8> = swapped[b..b + step].to_vec();
        swapped[a..a + step].copy_from_slice(&second);
        swapped[b..b + step].copy_from_slice(&first);
        assert!(open(&k, &swapped).is_err());
        // Append a chunk taken from the same file.
        let mut longer = sealed.clone();
        longer.extend_from_slice(&sealed[HEADER..HEADER + step]);
        assert!(open(&k, &longer).is_err());
        // Header only / empty.
        assert!(open(&k, &sealed[..HEADER]).is_err());
        assert!(open(&k, &[]).is_err());
    }

    #[test]
    fn unknown_version_is_reported() {
        let k = key();
        let mut sealed = seal(&k, b"x");
        sealed[0] = 9;
        assert_eq!(open(&k, &sealed), Err(Error::UnsupportedVersion));
    }
}
