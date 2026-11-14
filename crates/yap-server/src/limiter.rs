//! In-memory fixed-window rate limiter. Counters live in RAM only and vanish on restart, so
//! no IP address or username is ever persisted for rate limiting.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// Count one hit for `key`. Returns `false` once more than `max` hits land in `window`.
    pub fn allow(&self, key: &str, max: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.windows.lock().unwrap();
        if map.len() > 50_000 {
            map.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(3600));
        }
        let entry = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_and_resets() {
        let l = RateLimiter::default();
        let w = Duration::from_millis(50);
        assert!(l.allow("k", 2, w));
        assert!(l.allow("k", 2, w));
        assert!(!l.allow("k", 2, w));
        assert!(l.allow("other", 2, w));
        std::thread::sleep(Duration::from_millis(60));
        assert!(l.allow("k", 2, w));
    }
}
