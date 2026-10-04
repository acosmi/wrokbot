//! Actual finite read inventory. Bare legacy Vec lifetime is expressly excluded.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::{ArtifactReadOperation, CurrentArtifactReadBlock};
use openbot_contracts::artifact_read::{ArtifactReadAllocationLease, PendingArtifactReadBuffer};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    ArtifactReadCurrentError, HostRequestBindingIdentity, RequestBindingIssuer,
};
use tokio::sync::Notify;
use tracing::instrument::WithSubscriber;

use super::artifact_read_authority::PostgresArtifactReadAuthority;
use crate::artifact_store::StoreBoundArtifactReader;

pub struct ArtifactReadLifecycle {
    gate: Mutex<Vec<Weak<ReadOperationState>>>,
    closed: AtomicBool,
    unavailable: AtomicBool,
    jobs: AtomicUsize,
    resources: AtomicUsize,
    changed: Notify,
}
pub struct ArtifactReadDrainAck {
    _actual_closed_inventory: (),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReadDrainError {
    Elapsed,
    Unavailable,
}
impl ArtifactReadLifecycle {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            jobs: AtomicUsize::new(0),
            resources: AtomicUsize::new(0),
            changed: Notify::new(),
        })
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.close_matching(|_| true);
    }
    pub fn close_issuer(&self, issuer: &RequestBindingIssuer) {
        self.close_matching(|state| {
            state
                .auth
                .request_binding()
                .is_some_and(|binding| issuer.owns_identity(binding.identity()))
        });
    }
    pub fn close_binding(&self, binding: &HostRequestBindingIdentity) {
        self.close_matching(|state| {
            state
                .auth
                .request_binding()
                .is_some_and(|original| original.identity().same_binding(binding))
        });
    }
    fn close_matching(&self, matches: impl Fn(&ReadOperationState) -> bool) {
        match self.gate.try_lock() {
            Ok(mut gate) => {
                gate.retain(|entry| {
                    if let Some(state) = entry.upgrade() {
                        if matches(&state) {
                            state.close();
                        }
                        true
                    } else {
                        false
                    }
                });
            }
            Err(_) => {
                self.unavailable.store(true, Ordering::SeqCst);
            }
        }
        self.changed.notify_waiters();
    }
    pub(super) fn register(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
    ) -> Result<(), ArtifactReadCurrentError> {
        let mut gate = self
            .gate
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if self.closed.load(Ordering::SeqCst) || self.unavailable.load(Ordering::SeqCst) {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        gate.retain(|entry| entry.strong_count() != 0);
        gate.push(Arc::downgrade(state));
        Ok(())
    }
    pub(super) fn admit(
        self: &Arc<Self>,
        operation_stopped: &AtomicBool,
    ) -> Result<JobPermit, ArtifactReadCurrentError> {
        let _gate = self
            .gate
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if self.closed.load(Ordering::SeqCst)
            || self.unavailable.load(Ordering::SeqCst)
            || operation_stopped.load(Ordering::SeqCst)
        {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        self.jobs.fetch_add(1, Ordering::SeqCst);
        Ok(JobPermit {
            lifecycle: Arc::clone(self),
        })
    }
    pub(super) fn resource(self: &Arc<Self>) -> PhysicalResourceLease {
        // Created only inside an already admitted job. Jobs cannot reach zero until its
        // actual worker result/resource has either transferred or actually ended.
        self.resources.fetch_add(1, Ordering::SeqCst);
        PhysicalResourceLease {
            lifecycle: Arc::clone(self),
        }
    }
    fn is_drained(&self) -> Result<bool, ArtifactReadDrainError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ArtifactReadDrainError::Unavailable);
        }
        match self.gate.try_lock() {
            Ok(_gate) => Ok(self.closed.load(Ordering::SeqCst)
                && self.jobs.load(Ordering::SeqCst) == 0
                && self.resources.load(Ordering::SeqCst) == 0),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(ArtifactReadDrainError::Unavailable),
            Err(std::sync::TryLockError::WouldBlock) => Ok(false),
        }
    }
    pub async fn drain(&self) -> ArtifactReadDrainAck {
        loop {
            let changed = self.changed.notified();
            if self.is_drained() == Ok(true) {
                return ArtifactReadDrainAck {
                    _actual_closed_inventory: (),
                };
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(5)) => {} }
        }
    }
    pub async fn drain_before(
        &self,
        deadline: Instant,
    ) -> Result<ArtifactReadDrainAck, ArtifactReadDrainError> {
        loop {
            let changed = self.changed.notified();
            if Instant::now() >= deadline {
                return Err(ArtifactReadDrainError::Elapsed);
            }
            if self.is_drained()? {
                return Ok(ArtifactReadDrainAck {
                    _actual_closed_inventory: (),
                });
            }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return Err(ArtifactReadDrainError::Elapsed),
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            }
        }
    }
}
pub(super) struct JobPermit {
    lifecycle: Arc<ArtifactReadLifecycle>,
}
impl Drop for JobPermit {
    fn drop(&mut self) {
        self.lifecycle.jobs.fetch_sub(1, Ordering::SeqCst);
        self.lifecycle.changed.notify_waiters();
    }
}
pub(super) struct PhysicalResourceLease {
    lifecycle: Arc<ArtifactReadLifecycle>,
}
impl PhysicalResourceLease {
    pub(super) fn is_closed(&self) -> bool {
        self.lifecycle.closed.load(Ordering::SeqCst)
            || self.lifecycle.unavailable.load(Ordering::SeqCst)
    }
}
impl Drop for PhysicalResourceLease {
    fn drop(&mut self) {
        self.lifecycle.resources.fetch_sub(1, Ordering::SeqCst);
        self.lifecycle.changed.notify_waiters();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadPhase {
    Idle,
    Working,
    FinalJoint,
    Pending,
    Leased,
    Terminal,
}
pub(super) struct ReadOperationData {
    pub(super) reader: Option<StoreBoundArtifactReader>,
    pub(super) resource: Option<PhysicalResourceLease>,
    pub(super) phase: ReadPhase,
    pub(super) position: u64,
    pub(super) eof: bool,
}
pub(super) struct ReadOperationState {
    pub(super) authority: Arc<PostgresArtifactReadAuthority>,
    pub(super) lifecycle: Arc<ArtifactReadLifecycle>,
    pub(super) auth: AuthContext,
    pub(super) artifact_id: String,
    pub(super) data: Mutex<ReadOperationData>,
    pub(super) stopped: AtomicBool,
}
impl ReadOperationState {
    pub(super) fn new(
        authority: Arc<PostgresArtifactReadAuthority>,
        auth: AuthContext,
        artifact_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            lifecycle: authority.read_lifecycle(),
            authority,
            auth,
            artifact_id,
            data: Mutex::new(ReadOperationData {
                reader: None,
                resource: None,
                phase: ReadPhase::Idle,
                position: 0,
                eof: false,
            }),
            stopped: AtomicBool::new(false),
        })
    }
    pub(super) fn begin(&self) -> Result<(), ArtifactReadCurrentError> {
        let mut data = self
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if self.is_stopped() || data.phase != ReadPhase::Idle {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        data.phase = ReadPhase::Working;
        Ok(())
    }
    pub(super) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
            || self.lifecycle.closed.load(Ordering::SeqCst)
            || self.lifecycle.unavailable.load(Ordering::SeqCst)
    }
    pub(super) fn close(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        // This private data lock never crosses body IO or await; its physical tail is bounded
        // synchronous metadata/root/marker verification. Serialize against lease Drop so
        // a last lease cannot write Idle just after a failed closing try_lock and strand its FD.
        match self.data.lock() {
            Ok(mut data) => {
                if matches!(data.phase, ReadPhase::Idle | ReadPhase::Terminal) {
                    data.phase = ReadPhase::Terminal;
                    drop(data.reader.take());
                    drop(data.resource.take());
                }
            }
            Err(_) => {
                self.lifecycle.unavailable.store(true, Ordering::SeqCst);
            }
        }
        self.lifecycle.changed.notify_waiters();
    }
    pub(super) fn finish_failed(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut data) = self.data.lock() {
            data.phase = ReadPhase::Terminal;
            drop(data.reader.take());
            drop(data.resource.take());
        } else {
            self.lifecycle.unavailable.store(true, Ordering::SeqCst);
        }
        self.lifecycle.changed.notify_waiters();
    }
}
impl Drop for ReadOperationState {
    fn drop(&mut self) {
        // Reader field precedes resource field; no ACK while its original File is alive.
        if let Ok(data) = self.data.get_mut() {
            drop(data.reader.take());
            drop(data.resource.take());
        } else {
            self.lifecycle.unavailable.store(true, Ordering::SeqCst);
        }
    }
}
pub(super) struct AllocationLease {
    state: Arc<ReadOperationState>,
    handed_off: AtomicBool,
}
impl AllocationLease {
    pub(super) fn new(state: Arc<ReadOperationState>) -> Self {
        Self {
            state,
            handed_off: AtomicBool::new(false),
        }
    }
}
impl ArtifactReadAllocationLease for AllocationLease {
    fn mark_handed_off(&self) -> Result<(), ArtifactReadCurrentError> {
        let mut data = self
            .state
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if self.state.is_stopped() || data.phase != ReadPhase::Pending {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        data.phase = ReadPhase::Leased;
        self.handed_off.store(true, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for AllocationLease {
    fn drop(&mut self) {
        if let Ok(mut data) = self.state.data.lock() {
            if !self.handed_off.load(Ordering::SeqCst) || self.state.is_stopped() || data.eof {
                self.state.stopped.store(true, Ordering::SeqCst);
                data.phase = ReadPhase::Terminal;
                drop(data.reader.take());
                drop(data.resource.take());
            } else {
                data.phase = ReadPhase::Idle;
            }
        } else {
            self.state
                .lifecycle
                .unavailable
                .store(true, Ordering::SeqCst);
        }
        self.state.lifecycle.changed.notify_waiters();
    }
}
pub(super) struct PendingReadOwnership {
    pub(super) pending: Option<PendingArtifactReadBuffer>,
    pub(super) lease: Option<Box<dyn ArtifactReadAllocationLease>>,
}
impl Drop for PendingReadOwnership {
    fn drop(&mut self) {
        if let Some(pending) = &mut self.pending {
            pending.wipe();
        }
        drop(self.pending.take());
        drop(self.lease.take());
    }
}
pub(super) struct LifecycleReadOperation {
    pub(super) state: Arc<ReadOperationState>,
}
struct CancelAttempt {
    state: Arc<ReadOperationState>,
    completed: bool,
}
impl Drop for CancelAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.state.close();
        }
    }
}
#[async_trait]
impl ArtifactReadOperation for LifecycleReadOperation {
    async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError> {
        if auth != &self.state.auth
            || !auth
                .request_binding()
                .zip(self.state.auth.request_binding())
                .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
        {
            self.state.close();
            return Err(AppError::Unauthenticated);
        }
        let job = self.state.lifecycle.admit(&self.state.stopped)?;
        self.state.begin()?;
        let state = Arc::clone(&self.state);
        let dispatcher = tracing::dispatcher::get_default(Clone::clone);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(
            async move {
                let result = state.authority.read_operation_block(&state).await;
                if result.is_err() {
                    state.finish_failed();
                }
                // A failed send drops coupled pending/lease before the actual job permit ends.
                drop(sender.send(result));
                drop(job);
            }
            .with_subscriber(dispatcher),
        );
        let mut attempt = CancelAttempt {
            state: Arc::clone(&self.state),
            completed: false,
        };
        let result = receiver
            .await
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?;
        attempt.completed = true;
        result
    }
    fn close(&mut self) {
        self.state.close();
    }
}
impl Drop for LifecycleReadOperation {
    fn drop(&mut self) {
        self.state.close();
    }
}

#[cfg(test)]
#[path = "artifact_read_lifecycle/tests.rs"]
mod tests;
