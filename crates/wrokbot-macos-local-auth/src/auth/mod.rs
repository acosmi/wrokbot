//! R228 QA candidate: one owned native authentication thread, without product authority.
#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod native;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime};

pub const SYSTEM_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(120);
static NEXT_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);

/// Fixed host-selected language; never an arbitrary authentication reason or policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationLocale {
    English,
    SimplifiedChinese,
}

/// An opaque native attempt identity. This is not a product actor or bearer credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptId(u64);

/// An observed OS policy result, not permission to perform a product operation.
pub struct LocalAuthConfirmation {
    attempt_id: AttemptId,
    monotonic: Instant,
    wall: SystemTime,
}

impl LocalAuthConfirmation {
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    pub const fn confirmed_at(&self) -> Instant {
        self.monotonic
    }

    pub const fn confirmed_at_wall(&self) -> SystemTime {
        self.wall
    }
}

impl std::fmt::Debug for LocalAuthConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAuthConfirmation")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum LocalAuthOutcome {
    Confirmed(LocalAuthConfirmation),
    Cancelled,
    TimedOut,
    Stopped,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAuthStartError {
    Busy,
    Stopped,
    Unavailable,
}

/// Own this once per application instance. Drop signals stop; it never blocks PG cleanup.
pub struct MacLocalAuthOwner {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<OwnerState>,
    changed: Condvar,
    timeout: Duration,
}

struct OwnerState {
    stopping: bool,
    worker_done: bool,
    pending: Option<Arc<Attempt>>,
}

/// One handle owns delivery of an outcome; an outcome can be taken only once.
/// Outcome availability does not imply `is_stopped()`. Keep the host slot until native retirement.
pub struct LocalAuthAttempt {
    inner: Arc<Attempt>,
}

struct Attempt {
    id: AttemptId,
    locale: ConfirmationLocale,
    deadline: Instant,
    state: Mutex<AttemptState>,
    changed: Condvar,
    owner: Weak<Shared>,
    outcome_taken: AtomicBool,
}

struct AttemptState {
    terminal: bool,
    outcome: Option<LocalAuthOutcome>,
    cancel_requested: bool,
    native_done: bool,
    native_stopped: bool,
}

// Internal locks never encompass FFI, callback code, user closures, or a wait on another owner.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl MacLocalAuthOwner {
    /// Current Rust owner health, not native preflight, an empty slot, or a retirement receipt.
    /// A normal pending attempt is allowed; poisoned state never reports running.
    pub fn is_running(&self) -> bool {
        self.shared
            .state
            .lock()
            .is_ok_and(|state| !state.stopping && !state.worker_done)
    }

    pub fn new() -> Result<Self, LocalAuthStartError> {
        #[cfg(target_os = "macos")]
        {
            let gate = native::NativeGate::acquire()?;
            Self::spawn(
                native::NativeBackend,
                SYSTEM_CONFIRMATION_TIMEOUT,
                Some(gate),
            )
        }
        #[cfg(not(target_os = "macos"))]
        Err(LocalAuthStartError::Unavailable)
    }

    pub fn begin(
        &self,
        locale: ConfirmationLocale,
    ) -> Result<LocalAuthAttempt, LocalAuthStartError> {
        let mut owner = match self.shared.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                self.stop();
                return Err(LocalAuthStartError::Unavailable);
            }
        };
        if owner.stopping || owner.worker_done {
            return Err(LocalAuthStartError::Stopped);
        }
        if owner.pending.is_some() {
            return Err(LocalAuthStartError::Busy);
        }
        let id = NEXT_ATTEMPT_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| LocalAuthStartError::Unavailable)?;
        let deadline = Instant::now()
            .checked_add(self.shared.timeout)
            .ok_or(LocalAuthStartError::Unavailable)?;
        let inner = Arc::new(Attempt {
            id: AttemptId(id),
            locale,
            deadline,
            state: Mutex::new(AttemptState {
                terminal: false,
                outcome: None,
                cancel_requested: false,
                native_done: false,
                native_stopped: false,
            }),
            changed: Condvar::new(),
            owner: Arc::downgrade(&self.shared),
            outcome_taken: AtomicBool::new(false),
        });
        owner.pending = Some(inner.clone());
        self.shared.changed.notify_all();
        Ok(LocalAuthAttempt { inner })
    }

    pub fn stop(&self) {
        let pending = {
            let mut state = lock(&self.shared.state);
            state.stopping = true;
            self.shared.changed.notify_all();
            state.pending.clone()
        };
        if let Some(pending) = pending {
            pending.cancel(LocalAuthOutcome::Stopped);
        }
    }

    /// True after this worker's cleanup marker and native slot retirement, with unpoisoned state.
    /// This is not an acknowledgement of framework callback-stack or UI quiescence.
    pub fn is_stopped(&self) -> bool {
        self.shared
            .state
            .lock()
            .is_ok_and(|state| state.worker_done && state.pending.is_none())
    }

    /// Bounded observation only. A false result is not successful native cleanup.
    /// Call on an appropriate host worker, never while holding PG/window/runtime locks.
    pub fn wait_stopped(&self, timeout: Duration) -> bool {
        let Ok(state) = self.shared.state.lock() else {
            return false;
        };
        self.shared
            .changed
            .wait_timeout_while(state, timeout, |s| !s.worker_done || s.pending.is_some())
            .is_ok_and(|(state, _)| state.worker_done && state.pending.is_none())
    }

    fn spawn<B: Backend>(
        backend: B,
        timeout: Duration,
        gate: Option<NativeGate>,
    ) -> Result<Self, LocalAuthStartError> {
        let shared = Arc::new(Shared {
            state: Mutex::new(OwnerState {
                stopping: false,
                worker_done: false,
                pending: None,
            }),
            changed: Condvar::new(),
            timeout,
        });
        let worker_shared = shared.clone();
        std::thread::Builder::new()
            .name("wrok-local-auth".into())
            .spawn(move || worker(worker_shared, backend, gate))
            .map_err(|_| LocalAuthStartError::Unavailable)?;
        Ok(Self { shared })
    }
}

impl Drop for MacLocalAuthOwner {
    fn drop(&mut self) {
        self.stop();
    }
}

impl LocalAuthAttempt {
    pub fn id(&self) -> AttemptId {
        self.inner.id
    }

    pub fn cancel(&self) {
        self.inner.cancel(LocalAuthOutcome::Cancelled);
    }

    pub fn is_cancelled(&self) -> bool {
        let Some(owner) = self.inner.owner.upgrade() else {
            return true;
        };
        let Ok(owner_state) = owner.state.lock() else {
            return true;
        };
        if owner_state.stopping || owner_state.worker_done {
            return true;
        }
        self.inner
            .state
            .lock()
            .map_or(true, |state| state.cancel_requested)
    }

    /// A terminal native reply was observed (or evaluation never started), and the worker has
    /// invalidated and released its own context/block references. Framework references may remain.
    /// Poisoned owner/attempt state cannot produce this receipt.
    pub fn is_stopped(&self) -> bool {
        let Some(owner) = self.inner.owner.upgrade() else {
            return false;
        };
        let Ok(_owner_state) = owner.state.lock() else {
            return false;
        };
        self.inner
            .state
            .lock()
            .is_ok_and(|state| state.native_stopped)
    }

    pub fn try_take_outcome(&self) -> Option<LocalAuthOutcome> {
        let Some(owner) = self.inner.owner.upgrade() else {
            return self.unavailable();
        };
        // Hold both normal locks through delivery: an earlier is_poisoned snapshot is insufficient.
        let owner_state = match owner.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                return self.unavailable();
            }
        };
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                return self.unavailable();
            }
        };
        self.inner.expire(&mut state);
        if (owner_state.stopping || owner_state.worker_done)
            && (!state.terminal || matches!(state.outcome, Some(LocalAuthOutcome::Confirmed(_))))
        {
            state.terminal = true;
            state.cancel_requested = true;
            state.outcome = Some(LocalAuthOutcome::Stopped);
            self.inner.changed.notify_all();
        }
        let outcome = state.outcome.take()?;
        if self.inner.outcome_taken.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(outcome)
        }
    }

    fn unavailable(&self) -> Option<LocalAuthOutcome> {
        // Poison recovery is cleanup only. Discard any old proof and never read it as authority.
        let mut state = lock(&self.inner.state);
        state.terminal = true;
        state.cancel_requested = true;
        state.outcome = None;
        self.inner.changed.notify_all();
        if self.inner.outcome_taken.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(LocalAuthOutcome::Unavailable)
        }
    }

    /// Wait at most the supplied duration; this never extends the 120-second native attempt budget.
    /// None means no deliverable outcome (including an outcome already taken by this handle).
    pub fn wait_timeout(&self, timeout: Duration) -> Option<LocalAuthOutcome> {
        let stop_waiting = Instant::now().checked_add(timeout)?;
        loop {
            if let Some(outcome) = self.try_take_outcome() {
                return Some(outcome);
            }
            if self.inner.outcome_taken.load(Ordering::SeqCst) {
                return None;
            }
            let state = match self.inner.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    drop(error.into_inner());
                    return self.unavailable();
                }
            };
            if state.terminal {
                drop(state);
                continue;
            }
            let now = Instant::now();
            if now >= stop_waiting {
                return None;
            }
            let until = stop_waiting.min(self.inner.deadline);
            let result = self
                .inner
                .changed
                .wait_timeout(state, until.saturating_duration_since(now));
            match result {
                Ok((state, _)) => drop(state),
                Err(error) => {
                    drop(error.into_inner());
                    return self.unavailable();
                }
            }
        }
    }
}

impl Drop for LocalAuthAttempt {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl Attempt {
    fn expire(&self, state: &mut AttemptState) {
        if !state.terminal && Instant::now() >= self.deadline {
            state.terminal = true;
            state.outcome = Some(LocalAuthOutcome::TimedOut);
            state.cancel_requested = true;
            self.changed.notify_all();
        }
    }

    fn cancel(&self, outcome: LocalAuthOutcome) {
        let mut state = lock(&self.state);
        state.cancel_requested = true;
        // Cancellation dominates a success not yet delivered. A consumed proof is an OS fact;
        // the host must still check its exact attempt/window/PG cancellation before granting.
        if !state.terminal || matches!(state.outcome, Some(LocalAuthOutcome::Confirmed(_))) {
            state.terminal = true;
            state.outcome = Some(outcome);
        }
        self.changed.notify_all();
    }
}

#[derive(Clone)]
struct Completion(Arc<Attempt>);

#[derive(Clone, Copy)]
enum NativeResult {
    Confirmed,
    Cancelled,
    Unavailable,
}

impl Completion {
    fn is_live(&self) -> bool {
        let Some(owner) = self.0.owner.upgrade() else {
            return false;
        };
        let Ok(owner_state) = owner.state.lock() else {
            return false;
        };
        if owner_state.stopping || owner_state.worker_done {
            return false;
        }
        let Ok(mut state) = self.0.state.lock() else {
            return false;
        };
        self.0.expire(&mut state);
        !state.terminal && !state.cancel_requested
    }

    fn finish(&self, result: NativeResult, monotonic: Instant, wall: SystemTime) {
        let owner = self.0.owner.upgrade();
        let owner_state = owner.as_ref().map(|owner| owner.state.lock());
        let owner_bad = !matches!(&owner_state, Some(Ok(_)));
        let owner_stopping = owner_state
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .is_none_or(|state| state.stopping || state.worker_done);
        let (mut state, attempt_bad) = match self.0.state.lock() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        };
        if owner_bad || attempt_bad {
            // Actual callback is observed, but poisoned state must not publish any old/new proof.
            state.native_done = true;
            state.terminal = true;
            state.cancel_requested = true;
            state.outcome = if self.0.outcome_taken.load(Ordering::SeqCst) {
                None
            } else {
                Some(LocalAuthOutcome::Unavailable)
            };
            self.0.changed.notify_all();
            return;
        }
        if state.native_done {
            return;
        }
        state.native_done = true;
        self.0.expire(&mut state);
        if matches!(result, NativeResult::Cancelled) {
            state.cancel_requested = true;
        }
        if !state.terminal {
            state.terminal = true;
            state.outcome = Some(if owner_stopping {
                LocalAuthOutcome::Stopped
            } else {
                match result {
                    NativeResult::Confirmed => LocalAuthOutcome::Confirmed(LocalAuthConfirmation {
                        attempt_id: self.0.id,
                        monotonic,
                        wall,
                    }),
                    NativeResult::Cancelled => LocalAuthOutcome::Cancelled,
                    NativeResult::Unavailable => LocalAuthOutcome::Unavailable,
                }
            });
        }
        self.0.changed.notify_all();
    }
}

trait Evaluation {
    fn invalidate(&mut self);
}

trait Backend: Send + 'static {
    fn start(
        &mut self,
        locale: ConfirmationLocale,
        completion: Completion,
    ) -> Result<Box<dyn Evaluation>, NativeResult>;
}

#[cfg(target_os = "macos")]
type NativeGate = native::NativeGate;
#[cfg(not(target_os = "macos"))]
struct NativeGate;

struct WorkerEnd {
    shared: Arc<Shared>,
    gate: Option<NativeGate>,
}

impl Drop for WorkerEnd {
    fn drop(&mut self) {
        let (pending, owner_bad) = {
            let (mut state, owner_bad) = match self.shared.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            state.stopping = true;
            state.worker_done = true;
            self.shared.changed.notify_all();
            (state.pending.clone(), owner_bad)
        };
        if let Some(pending) = &pending {
            pending.cancel(LocalAuthOutcome::Unavailable);
        }
        if pending.is_some() || owner_bad {
            // Unexpected/poisoned state cannot prove native retirement. Preserve process gate.
            if let Some(gate) = self.gate.take() {
                std::mem::forget(gate);
            }
        }
    }
}

fn worker<B: Backend>(shared: Arc<Shared>, mut backend: B, gate: Option<NativeGate>) {
    let _end = WorkerEnd {
        shared: shared.clone(),
        gate,
    };
    loop {
        let pending = {
            let mut state = lock(&shared.state);
            while state.pending.is_none() && !state.stopping {
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            match &state.pending {
                Some(pending) => pending.clone(),
                None => return,
            }
        };
        let completion = Completion(pending.clone());
        let mut evaluation = if completion.is_live() {
            match backend.start(pending.locale, completion.clone()) {
                Ok(evaluation) => Some(evaluation),
                Err(error) => {
                    completion.finish(error, Instant::now(), SystemTime::now());
                    None
                }
            }
        } else {
            completion.finish(NativeResult::Cancelled, Instant::now(), SystemTime::now());
            None
        };
        let mut invalidated = false;
        let mut native_unknown = false;
        loop {
            let (mut state, attempt_bad) = match pending.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            if attempt_bad {
                state.terminal = true;
                state.cancel_requested = true;
                state.outcome = if pending.outcome_taken.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(LocalAuthOutcome::Unavailable)
                };
                pending.changed.notify_all();
                native_unknown = true;
                break;
            }
            pending.expire(&mut state);
            if state.native_done {
                break;
            }
            if state.cancel_requested && !invalidated {
                drop(state);
                if let Some(evaluation) = evaluation.as_mut() {
                    evaluation.invalidate();
                }
                invalidated = true;
                continue;
            }
            if state.cancel_requested {
                // An outcome/timeout is not native completion. Keep the one slot until callback.
                drop(
                    pending
                        .changed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            } else {
                let until = pending.deadline.saturating_duration_since(Instant::now());
                drop(
                    pending
                        .changed
                        .wait_timeout(state, until)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            }
        }
        if !invalidated && let Some(evaluation) = evaluation.as_mut() {
            evaluation.invalidate();
        }
        drop(evaluation); // Release our own context/block references on this worker thread.
        let (mut state, owner_bad) = match shared.state.lock() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        };
        {
            let (mut attempt_state, attempt_bad) = match pending.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            if native_unknown || owner_bad || attempt_bad {
                attempt_state.native_stopped = false;
                state.stopping = true;
            } else {
                attempt_state.native_stopped = true;
                if state
                    .pending
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &pending))
                {
                    state.pending = None;
                }
            }
            pending.changed.notify_all();
        }
        shared.changed.notify_all();
        if state.stopping {
            return;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod health_tests;
