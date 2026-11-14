//! OPAQUE (RFC 9807) cipher suite shared by clients and the server.
//!
//! Both sides MUST use the same suite. The password never leaves the client; the server
//! only stores an OPAQUE registration record.

use opaque_ke::argon2::Argon2;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};

pub use opaque_ke;

/// ristretto255 OPRF and key exchange, SHA-512, Argon2id key stretching.
pub struct YapOpaque;

impl CipherSuite for YapOpaque {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Context string mixed into every OPAQUE login so a login for another protocol/version fails.
pub const CONTEXT: &[u8] = b"yappitron-v1";
