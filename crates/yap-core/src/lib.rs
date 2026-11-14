//! Yappitron client core: MLS, OPAQUE client, typing frames.
//!
//! Sans-IO by design: this crate never touches the network or disk, so it builds
//! for native targets and for WASM (browser) alike.

pub mod api;
pub mod auth;
pub mod link;
pub mod mls;
pub mod typing;
pub mod vault;
