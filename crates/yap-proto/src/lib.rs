//! Wire-level types shared by the Yappitron server and clients.

pub mod auth;
pub mod username;

/// Protocol version carried in every frame so old clients can be rejected cleanly.
pub const PROTOCOL_VERSION: u8 = 1;
