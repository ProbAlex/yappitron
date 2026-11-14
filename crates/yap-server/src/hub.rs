//! Live connections and fan-out. Everything here is RAM-only: nothing about who is connected
//! is ever persisted.
//!
//! This is the single-node implementation. When a second gateway is added, `send_to` becomes a
//! publish on a message bus (NATS) and each node delivers to its own connections; callers do
//! not change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use uuid::Uuid;

/// Per-connection outbound queue. A client that cannot keep up loses live pushes and must
/// notice the gap (sequence numbers) and refetch over REST.
const QUEUE: usize = 256;
const MEMBERS_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberState {
    Joined,
    Invited,
}

/// One MLS-member device of a conversation.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    pub device: Uuid,
    pub account: Uuid,
    pub state: MemberState,
}

type Conns = HashMap<Uuid, Vec<(u64, mpsc::Sender<Arc<str>>)>>;
type MemberCache = HashMap<Uuid, (Instant, Arc<Vec<Member>>)>;

#[derive(Default)]
pub struct Hub {
    next_id: AtomicU64,
    conns: Mutex<Conns>,
    members: Mutex<MemberCache>,
}

impl Hub {
    /// Register a connection for `device`. Returns its id and the receiving end.
    pub fn connect(&self, device: Uuid) -> (u64, mpsc::Receiver<Arc<str>>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(QUEUE);
        self.conns
            .lock()
            .unwrap()
            .entry(device)
            .or_default()
            .push((id, tx));
        (id, rx)
    }

    pub fn disconnect(&self, device: Uuid, id: u64) {
        let mut conns = self.conns.lock().unwrap();
        if let Some(list) = conns.get_mut(&device) {
            list.retain(|(i, _)| *i != id);
            if list.is_empty() {
                conns.remove(&device);
            }
        }
    }

    /// Push `msg` to every live connection of the given devices. Full queues drop the push.
    pub fn send_to(&self, devices: &[Uuid], msg: &Arc<str>) {
        let conns = self.conns.lock().unwrap();
        for device in devices {
            for (_, tx) in conns.get(device).into_iter().flatten() {
                let _ = tx.try_send(msg.clone());
            }
        }
    }

    pub fn cached_members(&self, conversation: Uuid) -> Option<Arc<Vec<Member>>> {
        let cache = self.members.lock().unwrap();
        let (at, members) = cache.get(&conversation)?;
        (at.elapsed() < MEMBERS_TTL).then(|| members.clone())
    }

    pub fn cache_members(&self, conversation: Uuid, members: Vec<Member>) -> Arc<Vec<Member>> {
        let members = Arc::new(members);
        let mut cache = self.members.lock().unwrap();
        if cache.len() > 10_000 {
            cache.retain(|_, (at, _)| at.elapsed() < MEMBERS_TTL);
        }
        cache.insert(conversation, (Instant::now(), members.clone()));
        members
    }

    /// Drop the cached membership after it changes.
    pub fn invalidate(&self, conversation: Uuid) {
        self.members.lock().unwrap().remove(&conversation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivers_only_to_connected_devices_and_cleans_up() {
        let hub = Hub::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (id_a, mut rx_a) = hub.connect(a);
        let (_id_b, mut rx_b) = hub.connect(b);

        hub.send_to(&[a], &Arc::from("hello"));
        assert_eq!(&*rx_a.recv().await.unwrap(), "hello");
        assert!(rx_b.try_recv().is_err());

        hub.disconnect(a, id_a);
        hub.send_to(&[a], &Arc::from("nobody home"));
        assert!(rx_a.recv().await.is_none());
    }

    #[test]
    fn membership_cache_expires_and_invalidates() {
        let hub = Hub::default();
        let c = Uuid::new_v4();
        assert!(hub.cached_members(c).is_none());
        hub.cache_members(c, vec![]);
        assert!(hub.cached_members(c).is_some());
        hub.invalidate(c);
        assert!(hub.cached_members(c).is_none());
    }
}
