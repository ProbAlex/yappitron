//! Client side of OPAQUE password registration and login.
//!
//! The password never leaves the device. Callers move the opaque byte blobs between this
//! module and the server (over HTTPS/WebSocket); this crate performs no I/O.
//!
//! `username` is the OPAQUE client identifier and `server_id` (the service domain) the server
//! identifier; both are bound into the protocol so a record cannot be replayed elsewhere.

use yap_proto::auth::{CONTEXT, YapOpaque, opaque_ke};

use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};

#[derive(Debug)]
pub enum Error {
    Protocol(String),
    /// Wrong password, or the server is not who it claims to be.
    LoginFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Protocol(e) => write!(f, "protocol error: {e}"),
            Error::LoginFailed => write!(f, "login failed"),
        }
    }
}

impl std::error::Error for Error {}

fn protocol<E: std::fmt::Debug>(e: E) -> Error {
    Error::Protocol(format!("{e:?}"))
}

fn ids<'a>(username: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(username),
        server: Some(server_id),
    }
}

/// In-progress registration. Keep it until the server's response arrives.
pub struct RegistrationInProgress(ClientRegistration<YapOpaque>);

/// Step 1 of registration. Returns the request to send and the state to keep.
pub fn register_start(password: &[u8]) -> Result<(Vec<u8>, RegistrationInProgress), Error> {
    let r = ClientRegistration::<YapOpaque>::start(&mut OsRng, password).map_err(protocol)?;
    Ok((
        r.message.serialize().to_vec(),
        RegistrationInProgress(r.state),
    ))
}

/// Step 2 of registration. Returns the upload to send; the server stores it as the record.
pub fn register_finish(
    state: RegistrationInProgress,
    password: &[u8],
    username: &[u8],
    server_id: &[u8],
    server_response: &[u8],
) -> Result<Vec<u8>, Error> {
    let response = RegistrationResponse::deserialize(server_response).map_err(protocol)?;
    let params = ClientRegistrationFinishParameters::new(ids(username, server_id), None);
    let finished = state
        .0
        .finish(&mut OsRng, password, response, params)
        .map_err(protocol)?;
    Ok(finished.message.serialize().to_vec())
}

/// In-progress login. Keep it until the server's response arrives.
pub struct LoginInProgress(ClientLogin<YapOpaque>);

/// Step 1 of login. Returns the request to send and the state to keep.
pub fn login_start(password: &[u8]) -> Result<(Vec<u8>, LoginInProgress), Error> {
    let r = ClientLogin::<YapOpaque>::start(&mut OsRng, password).map_err(protocol)?;
    Ok((r.message.serialize().to_vec(), LoginInProgress(r.state)))
}

/// What a successful login yields.
pub struct LoginOutput {
    /// Send to the server to complete the exchange.
    pub finalization: Vec<u8>,
    /// Shared with the server; proves both sides completed the same login.
    pub session_key: Vec<u8>,
}

/// Step 2 of login. Fails with [`Error::LoginFailed`] on a wrong password.
pub fn login_finish(
    state: LoginInProgress,
    password: &[u8],
    username: &[u8],
    server_id: &[u8],
    server_response: &[u8],
) -> Result<LoginOutput, Error> {
    let response = CredentialResponse::deserialize(server_response).map_err(protocol)?;
    let params = ClientLoginFinishParameters::new(Some(CONTEXT), ids(username, server_id), None);
    let finished = state
        .0
        .finish(&mut OsRng, password, response, params)
        .map_err(|_| Error::LoginFailed)?;
    Ok(LoginOutput {
        finalization: finished.message.serialize().to_vec(),
        session_key: finished.session_key.to_vec(),
    })
}
