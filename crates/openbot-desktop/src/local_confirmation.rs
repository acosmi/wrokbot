//! R228 local-confirmation coordination. No OS, database, window lookup or wire codec.
//!
//! The host owns one coordinator per app instance and registers only its already admitted
//! bindings. A grant is shared by all clones of that binding. The only lock order is
//! coordinator then binding; no caller callback, native call or await runs under either.
//! Clock samples must be captured by the host immediately before each operation. Either
//! clock expiring or moving backwards denies authority. Lock-out-of-order samples are
//! rejected without confusing thread scheduling with wall-clock rollback. These checks do not replace native
//! sleep/session invalidation: simultaneous unobserved sleep and wall-clock adjustment
//! cannot be proved absent by this module.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::desktop::local_confirmation::{
    LOCAL_CONFIRMATION_WAIT_SECONDS, LocalConfirmationOutcome, LocalConfirmationReceipt,
    LocalConfirmationState, LocalConfirmationStatus, MAX_LOCAL_CONFIRMATION_FRESHNESS_SECONDS,
};

use crate::CancellationToken;

const WAIT: Duration = Duration::from_secs(LOCAL_CONFIRMATION_WAIT_SECONDS as u64);
const FRESH: Duration = Duration::from_secs(MAX_LOCAL_CONFIRMATION_FRESHNESS_SECONDS as u64);

/// Trusted host clock observations; never accepted from the renderer.
#[derive(Clone, Copy)]
pub(crate) struct ClockSample {
    monotonic: Instant,
    wall: SystemTime,
}

impl ClockSample {
    pub(crate) const fn new(monotonic: Instant, wall: SystemTime) -> Self {
        Self { monotonic, wall }
    }

    fn elapsed_since(self, earlier: Self) -> Result<Duration, ConfirmationError> {
        let monotonic = self
            .monotonic
            .checked_duration_since(earlier.monotonic)
            .ok_or(ConfirmationError::ClockRegression)?;
        let wall = self
            .wall
            .duration_since(earlier.wall)
            .map_err(|_| ConfirmationError::ClockRegression)?;
        Ok(monotonic.max(wall))
    }
}

impl fmt::Debug for ClockSample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClockSample(<host clocks>)")
    }
}

/// Closed internal failures; the transport supplies its fixed HTTP projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfirmationError {
    InvalidScope,
    NotCurrent,
    Busy,
    Unavailable,
    Expired,
    ClockRegression,
    StaleClockSample,
    InvalidState,
    Exhausted,
    Poisoned,
}

/// A native observation is not itself a grant. Success still requires host postchecks.
#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeOutcome {
    Succeeded { at: ClockSample },
    Cancelled,
    Unavailable,
}

/// Closed callback disposition; only NeedsPostcheck can proceed toward installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeDisposition {
    NeedsPostcheck,
    Cancelled,
    Unavailable,
    Rejected,
}

/// Unique application owner. Dropping it revokes all surviving handles and attempts.
pub(crate) struct LocalConfirmationCoordinator {
    shared: Arc<Shared>,
}

struct Shared {
    // Rust-only installation scope, never logged or serialized. Arc identity additionally
    // separates two coordinators even if a caller accidentally repeats this string.
    _instance_id: Box<str>,
    state: Mutex<CoordinatorState>,
}

struct CoordinatorState {
    available: bool,
    shutdown: bool,
    epoch: u64,
    grant_epoch: u64,
    next_attempt: u64,
    last_observation: Option<ClockSample>,
    pending: Option<Pending>,
}

struct Binding {
    _binding_id: u64,
    auth: AuthContext,
    state: Mutex<BindingState>,
}

#[derive(Default)]
struct BindingState {
    revoked: bool,
    grant: Option<Grant>,
}

#[derive(Clone, Copy)]
struct Grant {
    epoch: u64,
    grant_epoch: u64,
    succeeded_at: ClockSample,
}

struct Pending {
    id: u64,
    binding: Arc<Binding>,
    epoch: u64,
    began_at: ClockSample,
    cancellation: CancellationToken,
    native_started: bool,
    native_stopped: bool,
    phase: Phase,
}

#[derive(Clone, Copy)]
enum Phase {
    Prepared,
    Waiting,
    Succeeded(ClockSample),
    Aborted(ConfirmationError),
    Completed,
}

impl Phase {
    fn active(self) -> bool {
        matches!(self, Self::Prepared | Self::Waiting | Self::Succeeded(_))
    }
}

/// A binding's shared, private authority. Cloning never copies a deadline by value.
#[derive(Clone)]
pub(crate) struct GrantHandle {
    shared: Arc<Shared>,
    binding: Arc<Binding>,
}

/// Non-cloneable logical POST ownership. Drop cancels, but does not fake native stop.
pub(crate) struct ConfirmationAttempt {
    grant: GrantHandle,
    id: u64,
}

/// Exact logical cancellation shared with a request owner after an attempt moves to a
/// queued host job. It never acknowledges native stop or grants authority on its own.
#[derive(Clone)]
pub(crate) struct AttemptCancellation {
    shared: Arc<Shared>,
    id: u64,
}

/// Independent, non-cloneable native ownership. Keep it after the POST is cancelled.
/// Only `native_stopped` acknowledges actual native cleanup. Drop deliberately does not
/// release a native slot; a lost owner fails closed with at most one unresolved request.
pub(crate) struct NativeCompletionToken {
    shared: Arc<Shared>,
    id: u64,
    cancellation: CancellationToken,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {
        $(impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<private state>)"))
            }
        })+
    };
}

redacted_debug!(
    LocalConfirmationCoordinator,
    GrantHandle,
    ConfirmationAttempt,
    AttemptCancellation,
    NativeCompletionToken,
);

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ConfirmationError> {
    mutex.lock().map_err(|_| ConfirmationError::Poisoned)
}

// Revocation/cleanup may recover a poisoned guard, but authority-granting paths never do.
fn cleanup_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl CoordinatorState {
    fn release_terminal(&mut self) {
        if self.pending.as_ref().is_some_and(|pending| {
            !pending.phase.active() && (!pending.native_started || pending.native_stopped)
        }) {
            self.pending = None;
        }
    }

    fn abort(&mut self, error: ConfirmationError) {
        if let Some(pending) = &mut self.pending {
            if pending.phase.active() {
                pending.phase = Phase::Aborted(error);
            }
            pending.cancellation.cancel();
        }
        self.release_terminal();
    }

    fn abort_id(&mut self, id: u64, error: ConfirmationError) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == id)
        {
            self.abort(error);
        }
    }

    fn invalidate(&mut self, error: ConfirmationError) {
        if let Some(epoch) = self.epoch.checked_add(1) {
            self.epoch = epoch;
        } else {
            self.shutdown = true;
        }
        self.abort(error);
    }

    fn observe(&mut self, now: ClockSample) -> Result<(), ConfirmationError> {
        if let Some(previous) = self.last_observation {
            // Sampling occurs outside the mutex: an earlier caller can acquire it later.
            // Reject that operation, but do not revoke unrelated valid grants or move
            // the observation backwards. A forward monotonic sample with a backward
            // wall sample is the actual rollback condition we can observe here.
            if now.monotonic < previous.monotonic
                || (now.monotonic == previous.monotonic && now.wall < previous.wall)
            {
                return Err(ConfirmationError::StaleClockSample);
            }
            if now.wall < previous.wall {
                self.invalidate(ConfirmationError::ClockRegression);
                self.last_observation = Some(now);
                return Err(ConfirmationError::ClockRegression);
            }
        }
        self.last_observation = Some(now);
        if let Some(pending) = &self.pending
            && pending.phase.active()
        {
            match now.elapsed_since(pending.began_at) {
                Ok(elapsed) if elapsed < WAIT => {}
                Ok(_) => self.abort(ConfirmationError::Expired),
                Err(error) => {
                    self.invalidate(error);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn usable(&self) -> Result<(), ConfirmationError> {
        if self.shutdown {
            Err(ConfirmationError::NotCurrent)
        } else if !self.available {
            Err(ConfirmationError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn live_attempt(&self, id: u64) -> Result<&Pending, ConfirmationError> {
        self.usable()?;
        let pending = self
            .pending
            .as_ref()
            .filter(|pending| pending.id == id)
            .ok_or(ConfirmationError::InvalidState)?;
        if pending.epoch != self.epoch {
            return Err(ConfirmationError::NotCurrent);
        }
        if let Phase::Aborted(error) = pending.phase {
            return Err(error);
        }
        if !pending.phase.active() || pending.cancellation.is_cancelled() {
            return Err(ConfirmationError::InvalidState);
        }
        if lock(&pending.binding.state)?.revoked {
            return Err(ConfirmationError::NotCurrent);
        }
        Ok(pending)
    }
}

impl LocalConfirmationCoordinator {
    pub(crate) fn new(instance_id: &str, available: bool) -> Result<Self, ConfirmationError> {
        if instance_id.is_empty() {
            return Err(ConfirmationError::InvalidScope);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                _instance_id: instance_id.into(),
                state: Mutex::new(CoordinatorState {
                    available,
                    shutdown: false,
                    epoch: 1,
                    grant_epoch: 1,
                    next_attempt: 1,
                    last_observation: None,
                    pending: None,
                }),
            }),
        })
    }

    /// Root must pass an existing nonzero native binding and verified local admin scope.
    /// This neither registers a window nor proves canonical PG sole-admin authority.
    pub(crate) fn register_binding(
        &self,
        binding_id: u64,
        auth: &AuthContext,
    ) -> Result<GrantHandle, ConfirmationError> {
        if binding_id == 0 || !auth.is_single_user() || !auth.has_role(Role::Admin) {
            return Err(ConfirmationError::InvalidScope);
        }
        if lock(&self.shared.state)?.shutdown {
            return Err(ConfirmationError::NotCurrent);
        }
        Ok(GrantHandle {
            shared: Arc::clone(&self.shared),
            binding: Arc::new(Binding {
                _binding_id: binding_id,
                auth: auth.clone(),
                state: Mutex::new(BindingState::default()),
            }),
        })
    }

    /// `prechecked` is the host's fresh PG result. Equality includes all roles and tuple
    /// fields; this method never upgrades a binding to a new generation.
    pub(crate) fn begin(
        &self,
        grant: &GrantHandle,
        prechecked: &AuthContext,
        now: ClockSample,
    ) -> Result<ConfirmationAttempt, ConfirmationError> {
        if !Arc::ptr_eq(&self.shared, &grant.shared) {
            return Err(ConfirmationError::NotCurrent);
        }
        if grant.binding.auth != *prechecked {
            grant.revoke();
            return Err(ConfirmationError::NotCurrent);
        }
        let mut state = lock(&self.shared.state)?;
        state.observe(now)?;
        state.usable()?;
        if lock(&grant.binding.state)?.revoked {
            return Err(ConfirmationError::NotCurrent);
        }
        if state.pending.is_some() {
            return Err(ConfirmationError::Busy);
        }
        let id = state.next_attempt;
        state.next_attempt = id.checked_add(1).ok_or(ConfirmationError::Exhausted)?;
        state.pending = Some(Pending {
            id,
            binding: Arc::clone(&grant.binding),
            epoch: state.epoch,
            began_at: now,
            cancellation: CancellationToken::new(),
            native_started: false,
            native_stopped: false,
            phase: Phase::Prepared,
        });
        Ok(ConfirmationAttempt {
            grant: grant.clone(),
            id,
        })
    }

    /// Host timer hook. Timeout requests cancellation but cannot acknowledge OS stop.
    #[cfg(test)]
    pub(crate) fn expire(&self, now: ClockSample) -> Result<(), ConfirmationError> {
        lock(&self.shared.state)?.observe(now)
    }

    /// Native lock/sleep/session events must call this independently of clock checks.
    pub(crate) fn invalidate_all(&self) {
        cleanup_lock(&self.shared.state).invalidate(ConfirmationError::NotCurrent);
    }

    /// Clear grants across this instance without acquiring any host windows registry lock.
    /// Ordinary app blur must not cancel the system dialog's original pending attempt.
    pub(crate) fn clear_existing_grants(&self) {
        let mut state = cleanup_lock(&self.shared.state);
        if let Some(epoch) = state.grant_epoch.checked_add(1) {
            state.grant_epoch = epoch;
        } else {
            state.shutdown = true;
            state.available = false;
            state.invalidate(ConfirmationError::Exhausted);
        }
    }

    /// Recovery to available never revives an old grant or an old attempt.
    pub(crate) fn set_available(&self, available: bool) {
        let mut state = cleanup_lock(&self.shared.state);
        if !available {
            state.invalidate(ConfirmationError::Unavailable);
        }
        state.available = available;
    }

    pub(crate) fn shutdown(&self) {
        let mut state = cleanup_lock(&self.shared.state);
        state.shutdown = true;
        state.available = false;
        state.invalidate(ConfirmationError::NotCurrent);
    }
}

impl Drop for LocalConfirmationCoordinator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl GrantHandle {
    /// Compare private coordinator and binding identities, never numeric IDs or auth fields.
    /// This does not prove that either binding is live/current and does not replace the
    /// host's current-window guard or its final authority check at grant installation.
    pub(crate) fn is_same_binding(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared) && Arc::ptr_eq(&self.binding, &other.binding)
    }

    /// Clear only this binding's existing grant, including all shared clones. Ordinary
    /// native focus loss may use this without cancelling an in-progress confirmation.
    /// It does not revoke the binding, change epochs or extend either deadline. Sleep,
    /// session invalidation and destruction must still use the stronger revocation hooks.
    pub(crate) fn clear_existing_grant(&self) {
        let _coordinator = cleanup_lock(&self.shared.state);
        cleanup_lock(&self.binding.state).grant = None;
    }

    /// Permanently revoke this binding and all old clones. Rebind needs a new handle.
    pub(crate) fn revoke(&self) {
        let mut state = cleanup_lock(&self.shared.state);
        let mut binding = cleanup_lock(&self.binding.state);
        binding.revoked = true;
        binding.grant = None;
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| Arc::ptr_eq(&pending.binding, &self.binding))
        {
            state.abort(ConfirmationError::NotCurrent);
        }
    }

    fn remaining(
        &self,
        state: &CoordinatorState,
        now: ClockSample,
    ) -> Result<u32, ConfirmationError> {
        let mut binding = lock(&self.binding.state)?;
        if binding.revoked || state.shutdown {
            return Err(ConfirmationError::NotCurrent);
        }
        let Some(grant) = binding.grant else {
            return Ok(0);
        };
        if grant.epoch != state.epoch || grant.grant_epoch != state.grant_epoch || !state.available
        {
            binding.grant = None;
            return Ok(0);
        }
        let elapsed = match now.elapsed_since(grant.succeeded_at) {
            Ok(elapsed) => elapsed,
            Err(error) => {
                binding.grant = None;
                return Err(error);
            }
        };
        if elapsed >= FRESH {
            binding.grant = None;
            return Ok(0);
        }
        let remaining = FRESH - elapsed;
        // Ceiling is display-only. Authorization used the strict duration comparison.
        Ok(remaining.as_secs() as u32 + u32::from(remaining.subsec_nanos() != 0))
    }

    pub(crate) fn status(
        &self,
        now: ClockSample,
    ) -> Result<LocalConfirmationStatus, ConfirmationError> {
        let mut state = lock(&self.shared.state)?;
        state.observe(now)?;
        let remaining_seconds = self.remaining(&state, now)?;
        let status = if !state.available {
            LocalConfirmationState::Unavailable
        } else if state.pending.as_ref().is_some_and(|pending| {
            pending.phase.active()
                && !pending.cancellation.is_cancelled()
                && Arc::ptr_eq(&pending.binding, &self.binding)
        }) {
            LocalConfirmationState::Pending
        } else if remaining_seconds > 0 {
            LocalConfirmationState::Fresh
        } else {
            LocalConfirmationState::Required
        };
        Ok(LocalConfirmationStatus {
            state: status,
            remaining_seconds: if status == LocalConfirmationState::Fresh {
                remaining_seconds
            } else {
                0
            },
        })
    }

    /// Independent of the pending UI projection: retry cancellation preserves a valid
    /// prior grant without extending it. Business writes must still run their PG ACL.
    pub(crate) fn is_fresh(&self, now: ClockSample) -> bool {
        let Ok(mut state) = lock(&self.shared.state) else {
            return false;
        };
        state.observe(now).is_ok() && self.remaining(&state, now).is_ok_and(|seconds| seconds > 0)
    }
}

impl ConfirmationAttempt {
    pub(crate) fn cancellation_handle(&self) -> AttemptCancellation {
        AttemptCancellation {
            shared: Arc::clone(&self.grant.shared),
            id: self.id,
        }
    }

    /// Reserve native ownership before calling the OS. A launch failure must also call
    /// the returned token's native_stopped after the native owner has actually stopped.
    pub(crate) fn start_native(
        &mut self,
        now: ClockSample,
    ) -> Result<NativeCompletionToken, ConfirmationError> {
        let mut state = lock(&self.grant.shared.state)?;
        state.observe(now)?;
        if !matches!(state.live_attempt(self.id)?.phase, Phase::Prepared) {
            return Err(ConfirmationError::InvalidState);
        }
        let pending = state
            .pending
            .as_mut()
            .ok_or(ConfirmationError::InvalidState)?;
        pending.native_started = true;
        pending.phase = Phase::Waiting;
        Ok(NativeCompletionToken {
            shared: Arc::clone(&self.grant.shared),
            id: self.id,
            cancellation: pending.cancellation.clone(),
        })
    }

    /// Consume only after Root re-fetches the current binding and postchecks PG/runtime.
    /// The 120-second budget includes this final CAS; 900 seconds starts at native success.
    pub(crate) fn install(
        self,
        current: &GrantHandle,
        postchecked: &AuthContext,
        now: ClockSample,
    ) -> Result<LocalConfirmationReceipt, ConfirmationError> {
        if !Arc::ptr_eq(&self.grant.shared, &current.shared)
            || !Arc::ptr_eq(&self.grant.binding, &current.binding)
            || self.grant.binding.auth != *postchecked
        {
            self.grant.revoke();
            return Err(ConfirmationError::NotCurrent);
        }
        let mut state = lock(&self.grant.shared.state)?;
        state.observe(now)?;
        let pending = state.live_attempt(self.id)?;
        let Phase::Succeeded(succeeded_at) = pending.phase else {
            return Err(ConfirmationError::InvalidState);
        };
        if now.elapsed_since(succeeded_at)? >= FRESH {
            return Err(ConfirmationError::Expired);
        }
        let epoch = state.epoch;
        let grant_epoch = state.grant_epoch;
        let mut binding = lock(&self.grant.binding.state)?;
        // The coordinator lock excludes revoke/invalidate between live_attempt and CAS.
        binding.grant = Some(Grant {
            epoch,
            grant_epoch,
            succeeded_at,
        });
        drop(binding);
        let remaining_seconds = self.grant.remaining(&state, now)?;
        state
            .pending
            .as_mut()
            .ok_or(ConfirmationError::InvalidState)?
            .phase = Phase::Completed;
        state.release_terminal();
        Ok(LocalConfirmationReceipt {
            outcome: LocalConfirmationOutcome::Confirmed,
            remaining_seconds,
        })
    }

    /// Logical cancellation retains only a still-valid older grant, with no renewal.
    pub(crate) fn cancel(
        self,
        now: ClockSample,
    ) -> Result<LocalConfirmationReceipt, ConfirmationError> {
        let mut state = lock(&self.grant.shared.state)?;
        state.abort_id(self.id, ConfirmationError::InvalidState);
        state.observe(now)?;
        Ok(LocalConfirmationReceipt {
            outcome: LocalConfirmationOutcome::Cancelled,
            remaining_seconds: self.grant.remaining(&state, now)?,
        })
    }
}

impl Drop for ConfirmationAttempt {
    fn drop(&mut self) {
        cleanup_lock(&self.grant.shared.state).abort_id(self.id, ConfirmationError::InvalidState);
    }
}

impl AttemptCancellation {
    /// Linearizes with install under the same coordinator mutex, and only aborts this id.
    pub(crate) fn cancel(&self) {
        cleanup_lock(&self.shared.state).abort_id(self.id, ConfirmationError::InvalidState);
    }
}

impl NativeCompletionToken {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Call once with the native callback's captured success time and a new host sample.
    /// Duplicate, stopped, cancelled or obsolete native results cannot create authority.
    pub(crate) fn record_outcome(
        &self,
        outcome: NativeOutcome,
        observed_now: ClockSample,
    ) -> Result<NativeDisposition, ConfirmationError> {
        let mut state = lock(&self.shared.state)?;
        if let Err(error) = state.observe(observed_now) {
            state.abort_id(self.id, error);
            return Err(error);
        }
        let Ok(pending) = state.live_attempt(self.id) else {
            return Ok(NativeDisposition::Rejected);
        };
        if !pending.native_started
            || pending.native_stopped
            || !matches!(pending.phase, Phase::Waiting)
        {
            return Ok(NativeDisposition::Rejected);
        }
        let (phase, disposition) = match outcome {
            NativeOutcome::Succeeded { at } => {
                // Neither a future timestamp nor a delayed post-timeout callback is usable.
                let elapsed = at.elapsed_since(pending.began_at);
                if elapsed.is_err() || observed_now.elapsed_since(at).is_err() {
                    state.abort(ConfirmationError::ClockRegression);
                    return Err(ConfirmationError::ClockRegression);
                }
                if elapsed? >= WAIT {
                    state.abort(ConfirmationError::Expired);
                    return Err(ConfirmationError::Expired);
                }
                (Phase::Succeeded(at), NativeDisposition::NeedsPostcheck)
            }
            NativeOutcome::Cancelled => (
                Phase::Aborted(ConfirmationError::InvalidState),
                NativeDisposition::Cancelled,
            ),
            NativeOutcome::Unavailable => (
                Phase::Aborted(ConfirmationError::Unavailable),
                NativeDisposition::Unavailable,
            ),
        };
        let pending = state
            .pending
            .as_mut()
            .ok_or(ConfirmationError::InvalidState)?;
        pending.phase = phase;
        if !phase.active() {
            pending.cancellation.cancel();
        }
        state.release_terminal();
        Ok(disposition)
    }

    /// Invoke only after the original native owner stopped, even after POST drop/timeout.
    /// A success awaiting PG postcheck keeps logical singleflight until install/cancel.
    pub(crate) fn native_stopped(self) {
        let mut state = cleanup_lock(&self.shared.state);
        if let Some(pending) = &mut state.pending
            && pending.id == self.id
        {
            pending.native_stopped = true;
            if matches!(pending.phase, Phase::Prepared | Phase::Waiting) {
                pending.phase = Phase::Aborted(ConfirmationError::InvalidState);
                pending.cancellation.cancel();
            }
        }
        state.release_terminal();
    }
}

#[cfg(test)]
#[path = "local_confirmation_tests.rs"]
mod tests;
