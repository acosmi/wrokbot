//! Isolated R228 candidate. Notification receipt is not proof of full lock-screen coverage.
#![deny(unsafe_code)]

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod native;

/// Fixed public native events; no notification payload or user-selected name escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    AppResignedActive,
    SystemWillSleep,
    SystemDidWake,
    ScreensDidSleep,
    ScreensDidWake,
    SessionResignedActive,
    SessionBecameActive,
}

/// The host applies this action to its existing shared grant coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    ClearExistingGrant,
    InvalidateAll,
}

impl SessionEvent {
    pub fn invalidation(self) -> Invalidation {
        match self {
            Self::AppResignedActive => Invalidation::ClearExistingGrant,
            _ => Invalidation::InvalidateAll,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorError {
    WrongThread,
    Busy,
    NotCurrent,
    Failed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorStatus {
    Starting,
    Live,
    Closing,
    Failed,
    Removed,
}

/// All fixed observers were removed and our callback flights/references have retired.
/// This does not assert that every framework-internal callback stack has returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleanupReceipt(());

struct State {
    registered: bool,
    native_removed: bool,
    removed: bool,
    flights: usize,
}

struct Shared {
    closed: AtomicBool,
    failed: AtomicBool,
    state: Mutex<State>,
    callback: Arc<dyn Fn(SessionEvent) + Send + Sync>,
}

impl Shared {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.close();
    }

    fn status(&self) -> MonitorStatus {
        let Ok(state) = self.state.lock() else {
            self.fail();
            return MonitorStatus::Failed;
        };
        if self.failed.load(Ordering::SeqCst) {
            MonitorStatus::Failed
        } else if state.removed {
            MonitorStatus::Removed
        } else if self.closed.load(Ordering::SeqCst) {
            MonitorStatus::Closing
        } else if state.registered {
            MonitorStatus::Live
        } else {
            MonitorStatus::Starting
        }
    }

    fn deliver(&self, event: SessionEvent) {
        let Ok(mut state) = self.state.lock() else {
            self.fail();
            return;
        };
        if self.closed.load(Ordering::SeqCst) || self.failed.load(Ordering::SeqCst) {
            return;
        }
        let Some(next) = state.flights.checked_add(1) else {
            self.fail();
            return;
        };
        state.flights = next;
        drop(state);
        let _flight = CallbackFlight(self);
        // No TLS borrow or monitor mutex is held across host code. Reentrant close is safe.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| (self.callback)(event))) {
            // Mark failure while this flight is still counted. Cleanup must not observe zero
            // flights and report success in the gap between unwind and the outer FFI catch.
            self.fail();
            std::mem::forget(payload);
        }
    }
}

struct CallbackFlight<'a>(&'a Shared);
impl Drop for CallbackFlight<'_> {
    fn drop(&mut self) {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(poison) => {
                self.0.fail();
                poison.into_inner()
            }
        };
        match state.flights.checked_sub(1) {
            Some(next) => state.flights = next,
            None => self.0.fail(),
        }
    }
}

/// Called directly by the fixed native block. Never allow a Rust panic to unwind into FFI.
fn callback_boundary(shared: &Shared, event: SessionEvent) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| shared.deliver(event))) {
        shared.fail();
        // A user-defined panic payload can itself panic in Drop. Retain no payload in state;
        // leak this exceptional payload instead of permitting a second unwind across FFI.
        std::mem::forget(payload);
    }
}

trait ObserverOwner {
    /// Must remove every originally registered observer before reporting success.
    fn remove_all(&mut self) -> Result<(), MonitorError>;
}

struct Slot {
    shared: Arc<Shared>,
    native: Option<Box<dyn ObserverOwner>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        // TLS teardown also suppresses delivery before its native fields are destroyed.
        // Only explicit cleanup may issue a removal receipt.
        self.shared.close();
    }
}

thread_local! {
    // Production entry points require the real main thread, making this one process slot.
    // ObjC observers and blocks never enter a Send/Sync container.
    static SLOT: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

/// Opaque Rust-only owner. Keep a cleanup ticket before transferring/dropping this owner.
/// Drop closes delivery; it does not remove native observers or release the TLS slot.
pub struct MonitorHandle {
    shared: Arc<Shared>,
}

/// Exact-instance cleanup capability; clones do not affect liveness when dropped.
#[derive(Clone)]
pub struct CleanupTicket {
    shared: Arc<Shared>,
}

impl MonitorHandle {
    pub fn close_callbacks(&self) {
        self.shared.close();
    }

    pub fn status(&self) -> MonitorStatus {
        self.shared.status()
    }

    /// A current snapshot, not an irrevocable authorization proof.
    pub fn is_live(&self) -> bool {
        self.status() == MonitorStatus::Live
    }

    pub fn is_removed(&self) -> bool {
        self.status() == MonitorStatus::Removed
    }

    pub fn cleanup_ticket(&self) -> CleanupTicket {
        CleanupTicket {
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn cleanup_on_main_thread(&self) -> Result<CleanupReceipt, MonitorError> {
        self.cleanup_ticket().cleanup_on_main_thread()
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl CleanupTicket {
    pub fn is_removed(&self) -> bool {
        self.shared.status() == MonitorStatus::Removed
    }

    pub fn cleanup_on_main_thread(&self) -> Result<CleanupReceipt, MonitorError> {
        #[cfg(target_os = "macos")]
        {
            native::main_thread()?;
            cleanup_inner(&self.shared)
        }
        #[cfg(not(target_os = "macos"))]
        Err(MonitorError::Unsupported)
    }
}

/// Install only from the real application main thread. The callback must only invalidate
/// Rust state; it must not wait on PG, windows or dispatch back to the main thread.
pub fn start<F>(callback: F) -> Result<MonitorHandle, MonitorError>
where
    F: Fn(SessionEvent) + Send + Sync + 'static,
{
    #[cfg(target_os = "macos")]
    {
        let main = native::main_thread()?;
        start_inner(Arc::new(callback), |shared| native::register(main, shared))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = callback;
        Err(MonitorError::Unsupported)
    }
}

/// Read the existing NSApplication's active fact on the actual main thread. Never activates
/// the app or changes focus. A false/unknown result cannot grant freshness.
pub fn current_app_is_active() -> Result<bool, MonitorError> {
    #[cfg(target_os = "macos")]
    {
        native::main_thread()?;
        let live = SLOT.with(|slot| {
            slot.try_borrow()
                .ok()
                .and_then(|slot| {
                    slot.as_ref()
                        .map(|s| s.shared.status() == MonitorStatus::Live)
                })
                .unwrap_or(false)
        });
        if !live {
            return Err(MonitorError::NotCurrent);
        }
        native::current_app_is_active()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MonitorError::Unsupported)
    }
}

fn start_inner(
    callback: Arc<dyn Fn(SessionEvent) + Send + Sync>,
    build: impl FnOnce(Arc<Shared>) -> Box<dyn ObserverOwner>,
) -> Result<MonitorHandle, MonitorError> {
    let shared = Arc::new(Shared {
        closed: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        state: Mutex::new(State {
            registered: false,
            native_removed: false,
            removed: false,
            flights: 0,
        }),
        callback,
    });
    SLOT.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| MonitorError::Busy)?;
        if slot.is_some() {
            return Err(MonitorError::Busy);
        }
        *slot = Some(Slot {
            shared: Arc::clone(&shared),
            native: None,
        });
        Ok(())
    })?;
    // Registration can synchronously invoke a native block. Do not hold a TLS borrow here.
    let native = build(Arc::clone(&shared));
    SLOT.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| MonitorError::Busy)?;
        let current = slot
            .as_mut()
            .filter(|s| Arc::ptr_eq(&s.shared, &shared))
            .ok_or(MonitorError::NotCurrent)?;
        current.native = Some(native);
        Ok(())
    })?;
    if let Ok(mut state) = shared.state.lock() {
        state.registered = true;
    } else {
        shared.fail();
    }
    if shared.status() != MonitorStatus::Live {
        let _ = cleanup_inner(&shared);
        return Err(MonitorError::Failed);
    }
    Ok(MonitorHandle { shared })
}

fn cleanup_inner(shared: &Arc<Shared>) -> Result<CleanupReceipt, MonitorError> {
    shared.close();
    if shared.status() == MonitorStatus::Removed {
        return Ok(CleanupReceipt(()));
    }
    let owner = SLOT.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| MonitorError::Busy)?;
        let current = slot
            .as_mut()
            .filter(|s| Arc::ptr_eq(&s.shared, shared))
            .ok_or(MonitorError::NotCurrent)?;
        Ok(current.native.take())
    })?;
    if let Some(mut owner) = owner {
        // Native calls and native object/block destruction happen with no TLS/monitor lock.
        if let Err(error) = owner.remove_all() {
            shared.fail();
            SLOT.with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut()
                    && let Some(current) = slot.as_mut().filter(|s| Arc::ptr_eq(&s.shared, shared))
                {
                    current.native = Some(owner);
                }
            });
            return Err(error);
        }
        drop(owner);
        match shared.state.lock() {
            Ok(mut state) => state.native_removed = true,
            Err(poison) => {
                shared.fail();
                poison.into_inner().native_removed = true;
            }
        }
    }
    {
        let mut state = shared.state.lock().map_err(|_| {
            shared.fail();
            MonitorError::Failed
        })?;
        if shared.failed.load(Ordering::SeqCst) {
            return Err(MonitorError::Failed);
        }
        if !state.native_removed || state.flights != 0 {
            return Err(MonitorError::Busy);
        }
        state.removed = true;
    }
    let removed = SLOT.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| MonitorError::Busy)?;
        if slot
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.shared, shared))
        {
            Ok(slot.take())
        } else {
            Err(MonitorError::NotCurrent)
        }
    })?;
    drop(removed);
    Ok(CleanupReceipt(()))
}

#[cfg(test)]
mod tests;
