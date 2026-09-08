//! Per-connection transport limits. These are Rust host defaults, never renderer input.

use std::time::Duration;

use openbot_computer::screen::SCREEN_VIEWER_MAX_BINARY_BYTES;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) struct SocketLimits {
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
    pub ping_interval: Duration,
    pub idle: Duration,
    pub write: Duration,
}

pub(super) const SOCKET_LIMITS: SocketLimits = SocketLimits {
    bytes_per_second: 8 * 1024 * 1024,
    burst_bytes: SCREEN_VIEWER_MAX_BINARY_BYTES as u64,
    ping_interval: Duration::from_secs(10),
    idle: Duration::from_secs(30),
    write: Duration::from_secs(1),
};
pub(super) const CLOSE_TIMEOUT: Duration = Duration::from_millis(100);

/// Integer nanosecond credits preserve fractional refill without rounding up or accumulating debt.
struct Bucket {
    credits: u128,
    capacity: u128,
    rate: u64,
    at: Instant,
}

impl Bucket {
    fn new(capacity: u64, rate: u64, at: Instant) -> Self {
        let capacity = u128::from(capacity) * 1_000_000_000;
        Self {
            credits: capacity,
            capacity,
            rate,
            at,
        }
    }

    fn take(&mut self, units: u64, now: Instant) -> bool {
        let Some(elapsed) = now.checked_duration_since(self.at) else {
            return false;
        };
        self.credits = self
            .credits
            .saturating_add(elapsed.as_nanos().saturating_mul(u128::from(self.rate)))
            .min(self.capacity);
        self.at = now;
        let charge = u128::from(units) * 1_000_000_000;
        if charge > self.credits {
            return false;
        }
        self.credits -= charge;
        true
    }
}

pub(super) struct DeliveryBudget {
    outbound: Bucket,
    inbound: Bucket,
    limits: SocketLimits,
    idle_at: Instant,
    ping_at: Instant,
    challenge: u64,
    pending_pong: Option<[u8; 8]>,
}

impl DeliveryBudget {
    pub fn new(limits: SocketLimits, now: Instant) -> Self {
        Self {
            outbound: Bucket::new(limits.burst_bytes, limits.bytes_per_second, now),
            // RFC6455 control frames are <=125 bytes. Bound floods independently of image bytes.
            inbound: Bucket::new(20, 10, now),
            limits,
            idle_at: now + limits.idle,
            ping_at: now + limits.ping_interval,
            challenge: 0,
            pending_pong: None,
        }
    }

    pub fn frame(&mut self, bytes: usize, now: Instant) -> bool {
        bytes <= SCREEN_VIEWER_MAX_BINARY_BYTES
            && u64::try_from(bytes).is_ok_and(|bytes| self.outbound.take(bytes, now))
    }

    pub fn incoming(&mut self, now: Instant) -> bool {
        self.inbound.take(1, now)
    }

    pub fn idle(&self, now: Instant) -> bool {
        now >= self.idle_at
    }

    pub fn wake_at(&self) -> Instant {
        if self.pending_pong.is_some() {
            self.idle_at
        } else {
            self.ping_at.min(self.idle_at)
        }
    }

    pub fn ping(&mut self, now: Instant) -> Option<[u8; 8]> {
        if now < self.ping_at || self.pending_pong.is_some() || self.idle(now) {
            return None;
        }
        let Some(challenge) = self.challenge.checked_add(1) else {
            self.idle_at = now;
            return None;
        };
        self.challenge = challenge;
        let payload = self.challenge.to_be_bytes();
        self.pending_pong = Some(payload);
        Some(payload)
    }

    pub fn pong(&mut self, payload: &[u8], now: Instant) {
        // Traffic and old/unsolicited pongs cannot keep a dead viewer alive. Only the current
        // host challenge, once, proves the peer is still consuming this connection.
        if !self.idle(now)
            && self
                .pending_pong
                .as_ref()
                .is_some_and(|sent| sent == payload)
        {
            self.pending_pong = None;
            self.idle_at = now + self.limits.idle;
            self.ping_at = now + self.limits.ping_interval;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_has_one_bounded_burst_exact_refill_and_no_rounding_credit() {
        let now = Instant::now();
        let mut budget = DeliveryBudget::new(SOCKET_LIMITS, now);
        assert!(!budget.frame(SCREEN_VIEWER_MAX_BINARY_BYTES + 1, now));
        assert!(budget.frame(SCREEN_VIEWER_MAX_BINARY_BYTES, now));
        assert!(!budget.frame(1, now));
        assert!(!budget.frame(1, now + Duration::from_nanos(1)));
        assert!(budget.frame(8 * 1024 * 1024, now + Duration::from_secs(1)));
        assert!(!budget.frame(1, now + Duration::from_secs(1)));
        assert!(budget.frame(
            SCREEN_VIEWER_MAX_BINARY_BYTES,
            now + Duration::from_secs(100)
        ));
        assert!(!budget.frame(1, now + Duration::from_secs(100)));
    }

    #[test]
    fn traffic_wrong_and_replayed_pong_never_renew_idle_deadline() {
        let now = Instant::now();
        let mut budget = DeliveryBudget::new(SOCKET_LIMITS, now);
        assert!(budget.ping(now).is_none());
        let ping = budget
            .ping(now + Duration::from_secs(10))
            .expect("challenge");
        assert!(budget.ping(now + Duration::from_secs(20)).is_none());
        budget.pong(b"wrong", now + Duration::from_secs(20));
        assert!(budget.incoming(now + Duration::from_secs(20)));
        assert!(budget.frame(1, now + Duration::from_secs(20)));
        assert_eq!(budget.wake_at(), now + Duration::from_secs(30));
        budget.pong(&ping, now + Duration::from_secs(25));
        assert_eq!(budget.wake_at(), now + Duration::from_secs(35));
        let next = budget.ping(now + Duration::from_secs(35)).expect("next");
        assert_ne!(ping, next);
        budget.pong(&ping, now + Duration::from_secs(50));
        assert!(budget.idle(now + Duration::from_secs(55)));
        budget.pong(&next, now + Duration::from_secs(55));
        assert!(budget.idle(now + Duration::from_secs(55)));
    }

    #[test]
    fn control_flood_is_bounded_and_time_regression_cannot_refill() {
        let now = Instant::now();
        let mut budget = DeliveryBudget::new(SOCKET_LIMITS, now);
        for _ in 0..20 {
            assert!(budget.incoming(now));
        }
        assert!(!budget.incoming(now));
        assert!(!budget.incoming(now - Duration::from_secs(1)));
        assert!(budget.incoming(now + Duration::from_millis(100)));
        assert!(!budget.incoming(now + Duration::from_millis(100)));
    }
}
