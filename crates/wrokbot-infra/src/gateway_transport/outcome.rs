use super::{GatewayFenceError, GatewayRequestDescriptor};
use std::sync::{Arc, Mutex};

/// Finite transport failure facts, without backend text, URLs, headers or secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayFailure {
    /// Request framing was invalid.
    InvalidRequest,
    /// Policy or current authority rejected the request.
    Rejected,
    /// The operation was cancelled or its response body was dropped.
    Cancelled,
    /// A bounded wait expired.
    Timeout,
    /// An authority dependency failed before dispatch.
    Unavailable,
    /// A response read or network exchange failed.
    Body,
    /// Authority cleanup could not be confirmed.
    CleanupUnknown,
}
/// Read-only facts for exactly one execute, including headers received before SDK retry/drop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayAttemptSnapshot {
    may_have_sent: bool,
    response_status: Option<u16>,
    permit_released: bool,
    complete: bool,
    failure: Option<GatewayFailure>,
}
impl GatewayAttemptSnapshot {
    /// SafeDialer was entered; its API does not expose the precise byte-send boundary.
    pub const fn may_have_sent(self) -> bool {
        self.may_have_sent
    }
    /// First HTTP response status, preserved even when SDK drops a 401 body.
    pub const fn response_status(self) -> Option<u16> {
        self.response_status
    }
    /// Host confirmed release of this execute's authority lease.
    pub const fn permit_released(self) -> bool {
        self.permit_released
    }
    /// Body reached EOF successfully.
    pub const fn complete(self) -> bool {
        self.complete
    }
    /// Final finite failure, if any.
    pub const fn failure(self) -> Option<GatewayFailure> {
        self.failure
    }
}
/// Transport-minted read handle. Observers cannot alter facts or supply a shared mutable slot.
#[derive(Clone)]
pub struct GatewayAttempt {
    state: Arc<Mutex<AttemptState>>,
    request: Option<GatewayRequestDescriptor>,
}

#[derive(Default)]
struct AttemptState {
    snapshot: GatewayAttemptSnapshot,
    settled: bool,
}
impl GatewayAttempt {
    /// None means framing failed before a closed destination could be established.
    pub const fn request(&self) -> Option<GatewayRequestDescriptor> {
        self.request
    }
    /// Copy current facts; no identity or request data is retained here.
    pub fn snapshot(&self) -> GatewayAttemptSnapshot {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
    }
}
impl std::fmt::Debug for GatewayAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayAttempt")
            .field("request", &self.request)
            .field("facts", &self.snapshot())
            .finish()
    }
}
/// Required operation-owned observation sink; each execute receives a distinct read handle.
pub trait GatewayHttpOutcomes: Send + Sync {
    /// Called synchronously once. Implementations must not block or retain unbounded history.
    fn started(&self, attempt: GatewayAttempt);
}
pub(super) struct AttemptGuard {
    state: Arc<Mutex<AttemptState>>,
}

pub(super) struct AttemptWatch {
    state: Arc<Mutex<AttemptState>>,
}
impl AttemptGuard {
    pub(super) fn new(
        request: Option<GatewayRequestDescriptor>,
        sink: &dyn GatewayHttpOutcomes,
    ) -> Self {
        let state = Arc::new(Mutex::new(AttemptState::default()));
        let attempt = GatewayAttempt {
            state: state.clone(),
            request,
        };
        sink.started(attempt.clone());
        Self { state }
    }
    fn update(&self, f: impl FnOnce(&mut GatewayAttemptSnapshot)) {
        f(&mut self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot);
    }
    fn settle(&self, f: impl FnOnce(&mut GatewayAttemptSnapshot)) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.settled {
            return false;
        }
        f(&mut state.snapshot);
        state.settled = true;
        true
    }
    pub(super) fn watch(&self) -> AttemptWatch {
        AttemptWatch {
            state: self.state.clone(),
        }
    }
    pub(super) fn dispatched(&self) {
        self.update(|s| s.may_have_sent = true);
    }
    pub(super) fn headers(&self, status: u16) {
        self.update(|s| s.response_status = Some(status));
    }
    pub(super) fn released(&self) {
        self.update(|s| s.permit_released = true);
    }
    pub(super) fn completed(&self) -> bool {
        self.settle(|s| s.complete = true)
    }
    pub(super) fn fail(&self, failure: GatewayFailure) -> bool {
        self.settle(|s| s.failure = Some(failure))
    }
    pub(super) fn fence_failed(&self, error: GatewayFenceError) {
        self.fail(match error {
            GatewayFenceError::Refused => GatewayFailure::Rejected,
            GatewayFenceError::Unavailable => GatewayFailure::Unavailable,
            GatewayFenceError::CleanupUnknown => GatewayFailure::CleanupUnknown,
        });
    }
}
impl AttemptWatch {
    pub(super) fn fail(&self, failure: GatewayFailure) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.settled {
            return false;
        }
        state.snapshot.failure = Some(failure);
        state.settled = true;
        true
    }
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.fail(GatewayFailure::Cancelled);
    }
}
