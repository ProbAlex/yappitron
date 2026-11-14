//! Byte-oriented RPC over the core. Every platform binding (C ABI for native, wasm-bindgen for
//! the browser) is a thin wrapper around [`call`], so there is one definition of the API.
//!
//! Request:  `method(u16 LE) | argc(u32 LE) | { len(u32 LE) | bytes }*`
//! Response: `status(u8: 0 ok, 1 error) | count(u32 LE) | { len(u32 LE) | bytes }*`
//! (on error there is one item, a UTF-8 message). Integers inside arguments are little-endian.
//! Objects (devices, in-progress OPAQUE exchanges) live in the core and are named by `u32`
//! handles. See `docs/CORE_API.md` for the method table.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use yap_proto::username;

use crate::auth::{self, LoginInProgress, RegistrationInProgress};
use crate::link;
use crate::mls::Device;
use crate::typing;
use crate::vault;

/// Method ids. Keep in sync with `docs/CORE_API.md` and the Dart client.
pub mod method {
    pub const DEVICE_NEW: u16 = 1;
    pub const DEVICE_IMPORT: u16 = 2;
    pub const DEVICE_EXPORT: u16 = 3;
    pub const DEVICE_FREE: u16 = 4;
    pub const KEY_PACKAGE: u16 = 5;
    pub const CONV_CREATE: u16 = 6;
    pub const CONV_ADD_MEMBERS: u16 = 7;
    pub const CONV_JOIN: u16 = 8;
    pub const CONV_ENCRYPT: u16 = 9;
    pub const CONV_DECRYPT: u16 = 10;
    pub const CONV_APPLY_COMMIT: u16 = 11;
    pub const CONV_EPOCH: u16 = 12;
    pub const CONV_ADD_MEMBERS_STAGED: u16 = 15;
    pub const CONV_COMMIT_CONFIRM: u16 = 16;
    pub const CONV_COMMIT_DISCARD: u16 = 17;
    pub const KEY_PACKAGE_SIGNER: u16 = 18;
    pub const DEVICE_SIGNER: u16 = 19;
    pub const TYPING_SEAL: u16 = 13;
    pub const TYPING_OPEN: u16 = 14;
    pub const AUTH_REGISTER_START: u16 = 20;
    pub const AUTH_REGISTER_FINISH: u16 = 21;
    pub const AUTH_LOGIN_START: u16 = 22;
    pub const AUTH_LOGIN_FINISH: u16 = 23;
    pub const USERNAME_CANONICALIZE: u16 = 30;
    pub const LINK_KEYPAIR: u16 = 42;
    pub const LINK_SEAL: u16 = 43;
    pub const LINK_OPEN: u16 = 44;
    pub const FINGERPRINT: u16 = 45;
    pub const VAULT_SEAL: u16 = 40;
    pub const VAULT_OPEN: u16 = 41;
}

enum Obj {
    Device(Box<Device>),
    Register(Box<RegistrationInProgress>),
    Login(Box<LoginInProgress>),
}

struct Registry {
    next: u32,
    objects: HashMap<u32, Obj>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        next: 1,
        objects: HashMap::new(),
    })
});

type Items = Vec<Vec<u8>>;
type Res = Result<Items, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

struct Args(Vec<Vec<u8>>);

impl Args {
    fn parse(mut buf: &[u8]) -> Result<Self, String> {
        let mut take = |n: usize| -> Result<&[u8], String> {
            if buf.len() < n {
                return Err("truncated request".into());
            }
            let (head, tail) = buf.split_at(n);
            buf = tail;
            Ok(head)
        };
        let argc = u32::from_le_bytes(take(4)?.try_into().map_err(err)?) as usize;
        let mut args = Vec::new();
        for _ in 0..argc {
            let len = u32::from_le_bytes(take(4)?.try_into().map_err(err)?) as usize;
            args.push(take(len)?.to_vec());
        }
        Ok(Args(args))
    }

    fn bytes(&self, i: usize) -> Result<&[u8], String> {
        self.0
            .get(i)
            .map(|v| v.as_slice())
            .ok_or_else(|| format!("missing argument {i}"))
    }

    fn str(&self, i: usize) -> Result<&str, String> {
        std::str::from_utf8(self.bytes(i)?).map_err(|_| format!("argument {i} is not UTF-8"))
    }

    fn u32(&self, i: usize) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.bytes(i)?
                .try_into()
                .map_err(|_| format!("argument {i} is not a u32"))?,
        ))
    }

    fn u64(&self, i: usize) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.bytes(i)?
                .try_into()
                .map_err(|_| format!("argument {i} is not a u64"))?,
        ))
    }

    fn key32(&self, i: usize) -> Result<[u8; 32], String> {
        self.bytes(i)?
            .try_into()
            .map_err(|_| format!("argument {i} must be 32 bytes"))
    }
}

/// An error response, for bindings that must report a failure the core could not (a panic).
pub fn error_response(message: &str) -> Vec<u8> {
    encode(1, &[message.as_bytes().to_vec()])
}

fn encode(status: u8, items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![status];
    out.extend((items.len() as u32).to_le_bytes());
    for item in items {
        out.extend((item.len() as u32).to_le_bytes());
        out.extend(item);
    }
    out
}

fn insert(obj: Obj) -> u32 {
    let mut reg = REGISTRY.lock().unwrap();
    let id = reg.next;
    reg.next += 1;
    reg.objects.insert(id, obj);
    id
}

fn with_device<T>(handle: u32, f: impl FnOnce(&Device) -> Result<T, String>) -> Result<T, String> {
    let reg = REGISTRY.lock().unwrap();
    match reg.objects.get(&handle) {
        Some(Obj::Device(d)) => f(d),
        _ => Err("no such device".into()),
    }
}

fn take(handle: u32) -> Option<Obj> {
    REGISTRY.lock().unwrap().objects.remove(&handle)
}

/// Run one request. Never panics on malformed input; errors come back in the response.
pub fn call(request: &[u8]) -> Vec<u8> {
    let result = (|| -> Res {
        let (m, rest) = request
            .split_first_chunk::<2>()
            .ok_or("truncated request")?;
        dispatch(u16::from_le_bytes(*m), &Args::parse(rest)?)
    })();
    match result {
        Ok(items) => encode(0, &items),
        Err(e) => encode(1, &[e.into_bytes()]),
    }
}

fn dispatch(m: u16, a: &Args) -> Res {
    use method::*;
    match m {
        DEVICE_NEW => Ok(vec![
            insert(Obj::Device(Box::new(
                Device::new(a.bytes(0)?).map_err(err)?,
            )))
            .to_le_bytes()
            .to_vec(),
        ]),
        DEVICE_IMPORT => {
            let device = Device::import(a.bytes(0)?, &a.key32(1)?).map_err(err)?;
            Ok(vec![
                insert(Obj::Device(Box::new(device))).to_le_bytes().to_vec(),
            ])
        }
        DEVICE_EXPORT => {
            let key = a.key32(1)?;
            with_device(a.u32(0)?, |d| Ok(vec![d.export(&key).map_err(err)?]))
        }
        DEVICE_FREE => {
            take(a.u32(0)?);
            Ok(vec![])
        }
        KEY_PACKAGE => with_device(a.u32(0)?, |d| Ok(vec![d.key_package().map_err(err)?])),
        CONV_CREATE => with_device(a.u32(0)?, |d| {
            d.create_conversation(a.bytes(1)?).map_err(err)?;
            Ok(vec![])
        }),
        // args: handle, group id, then one or more key packages
        CONV_ADD_MEMBERS => with_device(a.u32(0)?, |d| {
            let kps = (2..a.0.len())
                .map(|i| a.bytes(i))
                .collect::<Result<Vec<_>, _>>()?;
            let (commit, welcome) = d.add_members(a.bytes(1)?, &kps).map_err(err)?;
            Ok(vec![commit, welcome])
        }),
        CONV_JOIN => with_device(a.u32(0)?, |d| Ok(vec![d.join(a.bytes(1)?).map_err(err)?])),
        CONV_ENCRYPT => with_device(a.u32(0)?, |d| {
            Ok(vec![d.encrypt(a.bytes(1)?, a.bytes(2)?).map_err(err)?])
        }),
        // result: plaintext, sender identity (`username/device-id`)
        CONV_DECRYPT => with_device(a.u32(0)?, |d| {
            let out = d.decrypt(a.bytes(1)?, a.bytes(2)?).map_err(err)?;
            Ok(vec![out.plaintext, out.sender])
        }),
        CONV_APPLY_COMMIT => with_device(a.u32(0)?, |d| {
            d.apply_commit(a.bytes(1)?, a.bytes(2)?).map_err(err)?;
            Ok(vec![])
        }),
        CONV_EPOCH => with_device(a.u32(0)?, |d| {
            Ok(vec![
                d.epoch(a.bytes(1)?).map_err(err)?.to_le_bytes().to_vec(),
            ])
        }),
        // args: handle, group id, key package... ; builds a commit WITHOUT applying it
        CONV_ADD_MEMBERS_STAGED => with_device(a.u32(0)?, |d| {
            let kps = (2..a.0.len())
                .map(|i| a.bytes(i))
                .collect::<Result<Vec<_>, _>>()?;
            let (commit, welcome) = d.add_members_staged(a.bytes(1)?, &kps).map_err(err)?;
            Ok(vec![commit, welcome])
        }),
        CONV_COMMIT_CONFIRM => with_device(a.u32(0)?, |d| {
            d.confirm_pending(a.bytes(1)?).map_err(err)?;
            Ok(vec![])
        }),
        CONV_COMMIT_DISCARD => with_device(a.u32(0)?, |d| {
            d.discard_pending(a.bytes(1)?).map_err(err)?;
            Ok(vec![])
        }),
        KEY_PACKAGE_SIGNER => Ok(vec![
            crate::mls::key_package_signer(a.bytes(0)?).map_err(err)?,
        ]),
        DEVICE_SIGNER => with_device(a.u32(0)?, |d| Ok(vec![d.signer_public()])),
        LINK_KEYPAIR => {
            let (secret, public) = link::keypair();
            Ok(vec![secret.to_vec(), public.to_vec()])
        }
        LINK_SEAL => {
            let public: [u8; 32] = a
                .bytes(0)?
                .try_into()
                .map_err(|_| "public key must be 32 bytes".to_string())?;
            Ok(vec![link::seal(&public, a.bytes(1)?).map_err(err)?])
        }
        LINK_OPEN => Ok(vec![link::open(&a.key32(0)?, a.bytes(1)?).map_err(err)?]),
        FINGERPRINT => Ok(vec![
            link::fingerprint(a.bytes(0)?, a.bytes(1)?).into_bytes(),
        ]),
        TYPING_SEAL => with_device(a.u32(0)?, |d| {
            let gid = a.bytes(1)?;
            let key = d.typing_key(gid).map_err(err)?;
            let epoch = d.epoch(gid).map_err(err)?;
            Ok(vec![typing::seal(&key, epoch, gid, a.u64(2)?, a.str(3)?)])
        }),
        TYPING_OPEN => with_device(a.u32(0)?, |d| {
            let (gid, frame) = (a.bytes(1)?, a.bytes(2)?);
            // Frames from another epoch (a commit we haven't applied yet, or an old one) are
            // simply dropped by the caller.
            if typing::epoch_of(frame).map_err(err)? != d.epoch(gid).map_err(err)? {
                return Err("typing frame from a different epoch".into());
            }
            let opened = typing::open(&d.typing_key(gid).map_err(err)?, gid, frame).map_err(err)?;
            Ok(vec![
                opened.seq.to_le_bytes().to_vec(),
                opened.text.into_bytes(),
            ])
        }),
        AUTH_REGISTER_START => {
            let (request, state) = auth::register_start(a.bytes(0)?).map_err(err)?;
            Ok(vec![
                insert(Obj::Register(Box::new(state)))
                    .to_le_bytes()
                    .to_vec(),
                request,
            ])
        }
        AUTH_REGISTER_FINISH => match take(a.u32(0)?) {
            Some(Obj::Register(state)) => {
                let upload = auth::register_finish(
                    *state,
                    a.bytes(1)?,
                    a.bytes(2)?,
                    a.bytes(3)?,
                    a.bytes(4)?,
                )
                .map_err(err)?;
                Ok(vec![upload])
            }
            _ => Err("no such registration".into()),
        },
        AUTH_LOGIN_START => {
            let (request, state) = auth::login_start(a.bytes(0)?).map_err(err)?;
            Ok(vec![
                insert(Obj::Login(Box::new(state))).to_le_bytes().to_vec(),
                request,
            ])
        }
        AUTH_LOGIN_FINISH => match take(a.u32(0)?) {
            Some(Obj::Login(state)) => {
                let out =
                    auth::login_finish(*state, a.bytes(1)?, a.bytes(2)?, a.bytes(3)?, a.bytes(4)?)
                        .map_err(err)?;
                Ok(vec![out.finalization, out.session_key])
            }
            _ => Err("no such login".into()),
        },
        USERNAME_CANONICALIZE => username::canonicalize(a.str(0)?)
            .map(|n| vec![n.into_bytes()])
            .map_err(|e| e.message().to_string()),
        // args: key32, context, plaintext / sealed
        VAULT_SEAL => Ok(vec![vault::seal(&a.key32(0)?, a.bytes(1)?, a.bytes(2)?)]),
        VAULT_OPEN => Ok(vec![
            vault::open(&a.key32(0)?, a.bytes(1)?, a.bytes(2)?).map_err(err)?,
        ]),
        other => Err(format!("unknown method {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_requests_return_errors_not_panics() {
        for req in [
            &[][..],
            &[1],
            &[1, 0, 255, 255, 255, 255],
            &[99, 0, 0, 0, 0, 0],
            &[5, 0, 1, 0, 0, 0, 200, 0, 0, 0],
        ] {
            let resp = call(req);
            assert_eq!(resp[0], 1, "request {req:?} should be an error");
        }
    }
}
