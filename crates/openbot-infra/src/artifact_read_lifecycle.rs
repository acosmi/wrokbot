//! Actual finite read inventory. Bare legacy Vec lifetime is expressly excluded.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::artifact_read_protocol::{
    ArtifactReadEntryStop, ArtifactReadOperationCompletion,
};
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
use crate::artifact_administration::ObservedArtifactReadRecord;
use crate::artifact_store::{
    DatasetBoundArtifactStore, StoreBoundArtifactReader, StoreReadEnrollment, StoreReadJobLease,
    StoreReadQueryLease,
};

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
        let mut original_stops = Vec::new();
        match self.gate.try_lock() {
            Ok(mut gate) => {
                gate.retain(|entry| {
                    if let Some(state) = entry.upgrade() {
                        if matches(&state) {
                            state.close();
                            if let Some(stop) = state.entry_stop.get() {
                                original_stops.push(Arc::clone(stop));
                            }
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
        // The original port holds only a weak Entry. Stop cached allocations outside this
        // inventory gate; neither the callback nor close substitutes a query/resource ACK.
        for stop in original_stops {
            stop.request_stop();
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
    #[cfg(test)]
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
            operation: None,
            shared: None,
        })
    }
    pub(super) fn admit_operation(
        self: &Arc<Self>,
        operation: &Arc<ReadOperationState>,
    ) -> Result<JobPermit, ArtifactReadCurrentError> {
        let _gate = self
            .gate
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if operation.is_stopped() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let shared = operation
            .shared
            .get()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .begin_job()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        // Both inventories become visible before close can inspect the same admission gate.
        self.jobs.fetch_add(1, Ordering::SeqCst);
        operation.jobs.fetch_add(1, Ordering::SeqCst);
        Ok(JobPermit {
            lifecycle: Arc::clone(self),
            operation: Some(Arc::clone(operation)),
            shared: Some(shared),
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
    // Kept outside State.data: no State -> resource -> State ownership cycle.
    operation: Option<Arc<ReadOperationState>>,
    shared: Option<StoreReadJobLease>,
}
impl Drop for JobPermit {
    fn drop(&mut self) {
        if let Some(operation) = &self.operation {
            operation.jobs.fetch_sub(1, Ordering::SeqCst);
            operation.notify_shared_changed();
        }
        drop(self.shared.take());
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
pub(crate) struct ReadOperationState {
    pub(super) authority: Arc<PostgresArtifactReadAuthority>,
    pub(super) lifecycle: Arc<ArtifactReadLifecycle>,
    pub(super) auth: AuthContext,
    pub(super) artifact_id: String,
    pub(super) data: Mutex<ReadOperationData>,
    pub(super) stopped: AtomicBool,
    pub(super) original_deadline: Option<Instant>,
    closure_unproven: AtomicBool,
    jobs: AtomicUsize,
    allocations: AtomicUsize,
    shared: OnceLock<StoreReadEnrollment>,
    entry_stop: OnceLock<Arc<dyn ArtifactReadEntryStop>>,
    #[cfg(test)]
    pub(super) public_prepare_probe:
        Mutex<Option<Arc<super::artifact_read_authority::public_read_prepare::PublicPrepareProbe>>>,
}
impl ReadOperationState {
    pub(super) fn new(
        authority: Arc<PostgresArtifactReadAuthority>,
        auth: AuthContext,
        artifact_id: String,
    ) -> Arc<Self> {
        Self::with_deadline(authority, auth, artifact_id, None)
    }
    pub(super) fn with_deadline(
        authority: Arc<PostgresArtifactReadAuthority>,
        auth: AuthContext,
        artifact_id: String,
        original_deadline: Option<Instant>,
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
            original_deadline,
            closure_unproven: AtomicBool::new(false),
            jobs: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            shared: OnceLock::new(),
            entry_stop: OnceLock::new(),
            #[cfg(test)]
            public_prepare_probe: Mutex::new(None),
        })
    }

    /// Register the same physical Store and original Entry port before any preparation await.
    /// The data lock only serializes this one-time metadata enrollment, never IO or callbacks.
    pub(super) fn enroll_store(
        self: &Arc<Self>,
        store: Arc<DatasetBoundArtifactStore>,
        entry_stop: Option<Arc<dyn ArtifactReadEntryStop>>,
    ) -> Result<(), ArtifactReadCurrentError> {
        let data = self
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if self.shared.get().is_some() || data.phase != ReadPhase::Idle {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let original_entry_stop = entry_stop.clone();
        let enrollment = store
            .enroll_read(self, &self.artifact_id, entry_stop)
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        self.shared
            .set(enrollment)
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        if let Some(stop) = original_entry_stop {
            self.entry_stop
                .set(stop)
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        }
        Ok(())
    }

    pub(super) fn bind_observed_record(
        &self,
        record: &ObservedArtifactReadRecord,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.shared
            .get()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .bind_observed_record(record)
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }

    /// Only physical workers use this check. No-body host/source classification may still run.
    pub(super) fn body_is_admitted(&self) -> Result<(), ArtifactReadCurrentError> {
        self.shared
            .get()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .body_is_admitted()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }

    pub(super) fn begin_query(
        self: &Arc<Self>,
    ) -> Result<ReadQueryReservation, ArtifactReadCurrentError> {
        let lease = self
            .shared
            .get()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .begin_query()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        Ok(ReadQueryReservation {
            state: Arc::clone(self),
            lease: Some(lease),
        })
    }

    fn notify_shared_changed(&self) {
        if let Some(shared) = self.shared.get() {
            shared.notify_changed();
        }
    }

    /// A finite proof from real operation owners, not the old instance-wide ACK/count alone.
    pub(crate) fn shared_inventory_drained(&self) -> Result<bool, ArtifactReadDrainError> {
        if self.closure_unproven.load(Ordering::SeqCst)
            || self.lifecycle.unavailable.load(Ordering::SeqCst)
        {
            return Err(ArtifactReadDrainError::Unavailable);
        }
        let data = match self.data.try_lock() {
            Ok(data) => data,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(ArtifactReadDrainError::Unavailable);
            }
        };
        // Legacy raw Vec has no allocation-release receipt. Its coupled target/FD and actual
        // worker are separately retained; only the new leased path uses these phase witnesses.
        let phase_closed = self.original_deadline.is_none() || data.phase == ReadPhase::Terminal;
        Ok(self.stopped.load(Ordering::SeqCst)
            && self.jobs.load(Ordering::SeqCst) == 0
            && self.allocations.load(Ordering::SeqCst) == 0
            && data.reader.is_none()
            && data.resource.is_none()
            && phase_closed)
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
            || self
                .original_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || self
                .shared
                .get()
                .is_some_and(StoreReadEnrollment::original_admission_closed)
    }
    pub(super) fn check_current(&self) -> Result<(), ArtifactReadCurrentError> {
        if self.is_stopped() {
            Err(ArtifactReadCurrentError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(super) fn mark_closure_unproven(&self) {
        self.closure_unproven.store(true, Ordering::SeqCst);
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(shared) = self.shared.get() {
            shared.mark_unproven();
        }
        self.lifecycle.changed.notify_waiters();
    }
    pub(super) fn joint_deadline(&self) -> Result<Instant, ArtifactReadCurrentError> {
        self.check_current()?;
        let five_seconds = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        Ok(self
            .original_deadline
            .map_or(five_seconds, |original| original.min(five_seconds)))
    }
    #[cfg(test)]
    pub(super) fn actual_jobs(&self) -> usize {
        self.jobs.load(Ordering::SeqCst)
    }
    fn try_close_idle(&self) {
        match self.data.try_lock() {
            Ok(mut data) => {
                if matches!(data.phase, ReadPhase::Idle | ReadPhase::Terminal) {
                    data.phase = ReadPhase::Terminal;
                    drop(data.reader.take());
                    drop(data.resource.take());
                }
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.lifecycle.unavailable.store(true, Ordering::SeqCst);
            }
        }
    }
    fn is_operation_drained(&self) -> Result<bool, AppError> {
        if self.original_deadline.is_none()
            || self.lifecycle.unavailable.load(Ordering::SeqCst)
            || self.closure_unproven.load(Ordering::SeqCst)
        {
            return Err(operation_unavailable());
        }
        let _gate = match self.lifecycle.gate.try_lock() {
            Ok(gate) => gate,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(operation_unavailable()),
        };
        let data = match self.data.try_lock() {
            Ok(data) => data,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(operation_unavailable()),
        };
        // Pending/Leased cannot reach Terminal before their full allocation actually drops.
        Ok(self.stopped.load(Ordering::SeqCst)
            && self.jobs.load(Ordering::SeqCst) == 0
            && data.phase == ReadPhase::Terminal
            && data.reader.is_none()
            && data.resource.is_none())
    }
    pub(crate) fn close(&self) {
        if self
            .shared
            .get()
            .is_some_and(StoreReadEnrollment::mark_waiter_cancellation)
        {
            self.closure_unproven.store(true, Ordering::SeqCst);
        }
        self.stopped.store(true, Ordering::SeqCst);
        if self.original_deadline.is_some() {
            self.try_close_idle();
            self.lifecycle.changed.notify_waiters();
            self.notify_shared_changed();
            return;
        }
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
        self.notify_shared_changed();
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
        self.notify_shared_changed();
    }
}

/// The same original schema/PG future. Only a real original rollback ACK may consume it.
pub(super) struct ReadQueryReservation {
    state: Arc<ReadOperationState>,
    lease: Option<StoreReadQueryLease>,
}
impl ReadQueryReservation {
    pub(super) fn complete(mut self) {
        if let Some(lease) = self.lease.take() {
            lease.complete();
        }
    }
}
impl Drop for ReadQueryReservation {
    fn drop(&mut self) {
        if self.lease.is_some() {
            // This persists on the original Store/key even with no public total deadline.
            self.state.mark_closure_unproven();
        }
        drop(self.lease.take());
    }
}

const fn operation_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifacts",
    }
}

pub(super) struct OperationCompletion {
    pub(super) state: Arc<ReadOperationState>,
}
#[async_trait]
impl ArtifactReadOperationCompletion for OperationCompletion {
    fn close(&self) {
        self.state.close();
    }
    async fn drain_before(&self, deadline: Instant) -> Result<(), AppError> {
        self.state.close();
        loop {
            let changed = self.state.lifecycle.changed.notified();
            if Instant::now() >= deadline {
                return Err(operation_unavailable());
            }
            self.state.try_close_idle();
            if self.state.is_operation_drained()? {
                return Ok(());
            }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    return Err(operation_unavailable());
                },
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            }
        }
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
            if let Some(shared) = self.shared.get() {
                shared.mark_unproven();
            }
        }
    }
}
pub(super) struct AllocationLease {
    state: Arc<ReadOperationState>,
    handed_off: AtomicBool,
}
impl AllocationLease {
    pub(super) fn new(state: Arc<ReadOperationState>) -> Self {
        state.allocations.fetch_add(1, Ordering::SeqCst);
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
        // Existing pending/leased RAII wipes and ends the full allocation before this Drop.
        self.state.allocations.fetch_sub(1, Ordering::SeqCst);
        self.state.notify_shared_changed();
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
        let job = match self.state.lifecycle.admit_operation(&self.state) {
            Ok(job) => job,
            Err(error) => {
                if self.state.body_is_admitted().is_err() {
                    self.state
                        .authority
                        .classify_requested_refusal(&self.state)
                        .await?;
                }
                return Err(error.into());
            }
        };
        // Freeze this original phase/overall deadline while the admitted State is still idle.
        let receive_deadline = if self.state.original_deadline.is_some() {
            Some(self.state.joint_deadline()?)
        } else {
            None
        };
        if let Err(error) = self.state.begin() {
            drop(job);
            if self.state.body_is_admitted().is_err() {
                self.state
                    .authority
                    .classify_requested_refusal(&self.state)
                    .await?;
            }
            return Err(error.into());
        }
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
        let result = if let Some(deadline) = receive_deadline {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver)
                .await
                .map_err(|_| operation_unavailable())?
                .map_err(|_| operation_unavailable())?
        } else {
            receiver.await.map_err(|_| operation_unavailable())?
        };
        if let Some(deadline) = receive_deadline {
            if Instant::now() >= deadline {
                return Err(operation_unavailable());
            }
            // finish_failed stops this original owner before sending its classified error.
            // Only successful data may use stopped/body-admission state as an additional tail.
            if result.is_ok() {
                self.state.check_current()?;
            }
        }
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
