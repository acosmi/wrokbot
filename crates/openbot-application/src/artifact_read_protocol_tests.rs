//! Pure Core ownership/state-machine tests. The counted guards, targets and completions below
//! are trusted synthetic ports, never evidence of a real PG transaction, FD, Session or Window.
//! The pending buffers and Core transport allocations are real. Short real monotonic windows
//! exercise deadline logic without claiming elapsed production five-second/600-second budgets.

use std::collections::VecDeque;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Waker};

use openbot_contracts::artifact_read::{ArtifactReadAllocationLease, PendingArtifactReadBuffer};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, MAX_ARTIFACT_READ_CHUNK_BYTES,
    SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    ArtifactReadCurrentCheck, ArtifactReadCurrentError, ArtifactReadRecordFacts,
    ArtifactReadTailWitness, HostRequestBindingError, HostRequestBindingGuard,
    RequestBindingOwnerLease, ServerSessionBindingIdentity,
};

use super::*;
use crate::ArtifactAdministrationError;
use crate::artifact_read_lifecycle::ArtifactReadOperation;

const ARTIFACT_ID: &str = "01900000-0000-7000-8000-000000000001";
const TEST_WAIT: Duration = Duration::from_secs(2);

struct Counts {
    authority: Arc<()>,
    joint_calls: AtomicUsize,
    physical_calls: AtomicUsize,
    producer_calls: AtomicUsize,
    preparations: AtomicUsize,
    enrollments: AtomicUsize,
    allocated: AtomicUsize,
    live_allocations: AtomicUsize,
    lease_drops: AtomicUsize,
    close_calls: AtomicUsize,
    drain_calls: AtomicUsize,
    completed_drains: AtomicUsize,
    stopped: AtomicBool,
    drain_permitted: AtomicBool,
    witness_window_millis: AtomicUsize,
    last_witness_deadline: Mutex<Option<Instant>>,
    allocations: Mutex<Vec<Arc<AllocationTrace>>>,
    changed: Notify,
}
impl Counts {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            authority: Arc::new(()),
            joint_calls: AtomicUsize::new(0),
            physical_calls: AtomicUsize::new(0),
            producer_calls: AtomicUsize::new(0),
            preparations: AtomicUsize::new(0),
            enrollments: AtomicUsize::new(0),
            allocated: AtomicUsize::new(0),
            live_allocations: AtomicUsize::new(0),
            lease_drops: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            drain_calls: AtomicUsize::new(0),
            completed_drains: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            drain_permitted: AtomicBool::new(true),
            witness_window_millis: AtomicUsize::new(0),
            last_witness_deadline: Mutex::new(None),
            allocations: Mutex::new(Vec::new()),
            changed: Notify::new(),
        })
    }
    fn stop(&self) {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        self.stopped.store(true, Ordering::SeqCst);
        self.notify();
    }
    fn notify(&self) {
        self.changed.notify_waiters();
        self.changed.notify_one();
    }
    fn permit_drain(&self) {
        self.drain_permitted.store(true, Ordering::SeqCst);
        self.notify();
    }
    fn observation_counts(&self) -> (usize, usize, usize) {
        (
            self.joint_calls.load(Ordering::SeqCst),
            self.physical_calls.load(Ordering::SeqCst),
            self.producer_calls.load(Ordering::SeqCst),
        )
    }
}

struct CountedGuard(Arc<Counts>);
impl HostRequestBindingGuard for CountedGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        _: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> ArtifactReadCurrentCheck<'a> {
        self.0.joint_calls.fetch_add(1, Ordering::SeqCst);
        let millis = self.0.witness_window_millis.load(Ordering::SeqCst);
        let actual_deadline = if millis == 0 {
            deadline
        } else {
            deadline.min(Instant::now() + Duration::from_millis(u64::try_from(millis).unwrap()))
        };
        *self.0.last_witness_deadline.lock().unwrap() = Some(actual_deadline);
        let tail = CountedTail {
            auth: auth.clone(),
            original_deadline: actual_deadline,
        };
        Box::pin(async move { Ok(Box::new(tail) as Box<dyn ArtifactReadTailWitness>) })
    }
}
struct CountedTail {
    auth: AuthContext,
    original_deadline: Instant,
}
impl ArtifactReadTailWitness for CountedTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        if auth != &self.auth {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        if Instant::now() >= self.original_deadline || Instant::now() >= deadline {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        Ok(())
    }
}
struct CountedTarget {
    auth: AuthContext,
    counts: Arc<Counts>,
}
impl ArtifactReadCurrentTarget for CountedTarget {
    fn lookup_id(&self) -> &str {
        ARTIFACT_ID
    }
    fn matches_authority(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.counts.authority, authority)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.auth == *auth
            && self
                .auth
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(original, current)| {
                    original.identity().same_binding(current.identity())
                })
    }
    fn matches_current_record(&self, _: ArtifactReadRecordFacts<'_>) -> bool {
        true
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        self.counts.physical_calls.fetch_add(1, Ordering::SeqCst);
        if self.counts.stopped.load(Ordering::SeqCst) {
            Err(ArtifactReadCurrentError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct Scenario {
    owner: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    auth: AuthContext,
    counts: Arc<Counts>,
}
impl Scenario {
    fn new() -> Self {
        let (owner, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let counts = Counts::new();
        let auth = session_auth(&issuer, Arc::clone(&counts), "synthetic-original-session");
        Self {
            owner,
            issuer,
            auth,
            counts,
        }
    }
}
impl Drop for Scenario {
    fn drop(&mut self) {
        self.owner.close();
        self.counts.permit_drain();
    }
}
fn session_auth(issuer: &RequestBindingIssuer, counts: Arc<Counts>, session: &str) -> AuthContext {
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new("public-read-core-only"),
        TenantId::new("public-read-core-only"),
        ActorId::new("same-original-actor"),
        AuthGeneration::new(7),
        false,
    )
    .with_role(Role::User)
    .build();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        session.to_owned(),
        auth.actor().clone(),
        "synthetic-test-column".into(),
        time::OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(CountedGuard(counts)))
        .unwrap();
    auth.with_verified_request_binding(binding).unwrap()
}

struct AllocationTrace {
    dropped: AtomicBool,
    handed: AtomicBool,
    release_probe: Mutex<Option<Weak<ActualRelease>>>,
    release_still_pending_at_lease_drop: AtomicBool,
}
struct CountedLease {
    counts: Arc<Counts>,
    trace: Arc<AllocationTrace>,
    eof: bool,
}
impl ArtifactReadAllocationLease for CountedLease {
    fn mark_handed_off(&self) -> Result<(), ArtifactReadCurrentError> {
        self.trace.handed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for CountedLease {
    fn drop(&mut self) {
        if let Some(release) = self
            .trace
            .release_probe
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
        {
            // This callback runs from the real LeasedArtifactReadBlock Drop, after its actual
            // full allocation disposal. Never read freed memory to claim a wipe observation.
            self.trace
                .release_still_pending_at_lease_drop
                .store(!release.released.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        self.trace.dropped.store(true, Ordering::SeqCst);
        self.counts.lease_drops.fetch_add(1, Ordering::SeqCst);
        let previous = self.counts.live_allocations.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 0, "one real allocation has one lease Drop");
        if self.eof || !self.trace.handed.load(Ordering::SeqCst) {
            self.counts.stop();
        }
        self.counts.notify();
    }
}
fn actual_memory_block(
    auth: &AuthContext,
    counts: &Arc<Counts>,
    prefix: &[u8],
    original_deadline: Instant,
) -> Result<CurrentArtifactReadBlock, AppError> {
    let mut pending = PendingArtifactReadBuffer::new_initialized()?;
    assert_eq!(
        pending.initialized_mut().len(),
        MAX_ARTIFACT_READ_CHUNK_BYTES
    );
    pending.initialized_mut().fill(0xa5);
    pending.initialized_mut()[..prefix.len()].copy_from_slice(prefix);
    pending.record_actual_length(prefix.len())?;
    let trace = Arc::new(AllocationTrace {
        dropped: AtomicBool::new(false),
        handed: AtomicBool::new(false),
        release_probe: Mutex::new(None),
        release_still_pending_at_lease_drop: AtomicBool::new(false),
    });
    counts.allocations.lock().unwrap().push(Arc::clone(&trace));
    counts.allocated.fetch_add(1, Ordering::SeqCst);
    counts.live_allocations.fetch_add(1, Ordering::SeqCst);
    let deadline = original_deadline.min(Instant::now() + CONTROL_BUDGET);
    CurrentArtifactReadBlock::from_trusted_observation(
        pending,
        auth.clone(),
        Arc::new(CountedTarget {
            auth: auth.clone(),
            counts: Arc::clone(counts),
        }),
        Box::new(CountedTail {
            auth: auth.clone(),
            original_deadline: deadline,
        }),
        deadline,
        Box::new(CountedLease {
            counts: Arc::clone(counts),
            trace,
            eof: prefix.is_empty(),
        }),
    )
}
struct CountedOperation {
    counts: Arc<Counts>,
    original_deadline: Instant,
    remaining_prefixes: VecDeque<Vec<u8>>,
}
#[async_trait]
impl ArtifactReadOperation for CountedOperation {
    async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError> {
        if self.counts.stopped.load(Ordering::SeqCst) {
            return Err(artifacts_unavailable());
        }
        self.counts.producer_calls.fetch_add(1, Ordering::SeqCst);
        let prefix = self
            .remaining_prefixes
            .pop_front()
            .ok_or_else(artifacts_unavailable)?;
        actual_memory_block(auth, &self.counts, &prefix, self.original_deadline)
    }
    fn close(&mut self) {
        self.counts.stop();
    }
}
struct CountedCompletion(Arc<Counts>);
#[async_trait]
impl ArtifactReadOperationCompletion for CountedCompletion {
    fn close(&self) {
        self.0.stop();
    }
    async fn drain_before(&self, deadline: Instant) -> Result<(), AppError> {
        self.close();
        self.0.drain_calls.fetch_add(1, Ordering::SeqCst);
        self.0.notify();
        loop {
            let changed = self.0.changed.notified();
            if Instant::now() >= deadline {
                return Err(artifacts_unavailable());
            }
            if self.0.stopped.load(Ordering::SeqCst)
                && self.0.drain_permitted.load(Ordering::SeqCst)
                && self.0.live_allocations.load(Ordering::SeqCst) == 0
            {
                self.0.completed_drains.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), changed)
                .await
                .map_err(|_| artifacts_unavailable())?;
        }
    }
}
struct CountedAdministration {
    counts: Arc<Counts>,
    first_prefix: Vec<u8>,
    pause_after_enrollment: bool,
}
impl CountedAdministration {
    fn new(counts: Arc<Counts>, first_prefix: &[u8]) -> Self {
        Self {
            counts,
            first_prefix: first_prefix.to_vec(),
            pause_after_enrollment: false,
        }
    }
}
#[async_trait]
impl ArtifactAdministration for CountedAdministration {
    async fn prepare_host_bound_artifact_read(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        original_deadline: Instant,
        observer: Arc<dyn ArtifactReadPreparationObserver>,
    ) -> Result<PreparedArtifactRead, AppError> {
        self.counts.preparations.fetch_add(1, Ordering::SeqCst);
        let completion: Arc<dyn ArtifactReadOperationCompletion> =
            Arc::new(CountedCompletion(Arc::clone(&self.counts)));
        self.counts.enrollments.fetch_add(1, Ordering::SeqCst);
        observer.enrolled(Arc::clone(&completion))?;
        // The cancel case stops before any pending allocation or producer call. The held
        // completion gate models only an unproved synthetic outcome, never PG rollback.
        if self.pause_after_enrollment {
            pending::<()>().await;
        }
        self.counts.producer_calls.fetch_add(1, Ordering::SeqCst);
        let first = actual_memory_block(auth, &self.counts, &self.first_prefix, original_deadline)?;
        let operation = CurrentArtifactReadOperation::from_trusted_operation(
            auth.clone(),
            Box::new(CountedOperation {
                counts: Arc::clone(&self.counts),
                original_deadline,
                remaining_prefixes: VecDeque::from([Vec::new()]),
            }),
        )?;
        PreparedArtifactRead::from_trusted_preparation(
            auth.clone(),
            PreparedArtifactReadFacts {
                artifact_id: artifact_id.to_owned(),
                sha256: "a".repeat(64),
                byte_length: u64::try_from(self.first_prefix.len()).unwrap(),
            },
            original_deadline,
            operation,
            first,
            completion,
        )
    }
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
}
struct UnsupportedAdministration;
#[async_trait]
impl ArtifactAdministration for UnsupportedAdministration {
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + TEST_WAIT;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "finite pure test did not observe its original outcome"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
async fn wait_removed(registry: &PublicArtifactReadRegistry, id: &str) {
    wait_until(|| !registry.inner.entries.lock().unwrap().contains_key(id)).await;
}
async fn wait_empty(registry: &PublicArtifactReadRegistry) {
    wait_until(|| registry.inner.entries.lock().unwrap().is_empty()).await;
}
fn consume_control(registry: &PublicArtifactReadRegistry, auth: &AuthContext, reply: AppReply) {
    let delivery = registry.take_control(auth, reply).unwrap();
    delivery.verify_current_tail(auth).unwrap();
    drop(delivery);
}
async fn open_ready(
    registry: &PublicArtifactReadRegistry,
    auth: &AuthContext,
    counts: Arc<Counts>,
    prefix: &[u8],
) -> ArtifactReadOpened {
    let administration = CountedAdministration::new(counts, prefix);
    let opened = registry
        .open(
            &administration,
            auth,
            OpenArtifactRead {
                artifact_id: ARTIFACT_ID.into(),
            },
        )
        .await
        .unwrap();
    consume_control(registry, auth, AppReply::ArtifactReadOpened(opened.clone()));
    opened
}
async fn handoff_data(
    registry: &PublicArtifactReadRegistry,
    auth: &AuthContext,
    handle: &str,
) -> PublicArtifactReadTransportBlock {
    let input = ReadArtifactReadBlock {
        handle_id: handle.into(),
        sequence: 0,
    };
    let descriptor = registry.next(auth, input.clone()).await.unwrap();
    assert_eq!(descriptor.byte_length, 3);
    assert!(!descriptor.eof);
    let delivery = registry.take_delivery(auth, input).unwrap();
    assert_eq!(delivery.descriptor(), &descriptor);
    let block = delivery.handoff(auth).unwrap().unwrap();
    assert_eq!(block.as_ref(), b"abc");
    block
}

#[tokio::test]
async fn completed_ack_retry_keeps_original_tail_and_performs_zero_io() {
    let scenario = Scenario::new();
    let registry = PublicArtifactReadRegistry::new();
    let opened = open_ready(
        &registry,
        &scenario.auth,
        Arc::clone(&scenario.counts),
        b"abc",
    )
    .await;
    let entry = registry
        .original_entry(&scenario.auth, &opened.handle_id)
        .unwrap();
    let block = handoff_data(&registry, &scenario.auth, &opened.handle_id).await;
    drop(block);
    // The actual first ACK creates this tighter synthetic witness once. Its real short
    // monotonic window must not be refreshed by a response-loss retry; production stays 5s.
    scenario
        .counts
        .witness_window_millis
        .store(120, Ordering::SeqCst);
    let input = AcknowledgeArtifactReadBlock {
        handle_id: opened.handle_id.clone(),
        sequence: 0,
    };
    let original = registry
        .acknowledge(&scenario.auth, input.clone())
        .await
        .unwrap();
    let short_original_deadline = scenario
        .counts
        .last_witness_deadline
        .lock()
        .unwrap()
        .unwrap();
    let (original_tail, original_valid_before, original_sequence) = {
        let data = entry.data.lock().await;
        let completed = data.last_ack.as_ref().unwrap();
        (
            Arc::clone(&completed.tail),
            completed.valid_before,
            data.sequence,
        )
    };
    consume_control(
        &registry,
        &scenario.auth,
        AppReply::ArtifactReadAcknowledged(original.clone()),
    );
    let io_before_retry = scenario.counts.observation_counts();
    let drops_before_retry = scenario.counts.lease_drops.load(Ordering::SeqCst);
    let retried = registry
        .acknowledge(&scenario.auth, input.clone())
        .await
        .unwrap();
    assert_eq!(retried, original);
    {
        let data = entry.data.lock().await;
        let completed = data.last_ack.as_ref().unwrap();
        let record = entry.control.lock().unwrap();
        let control = record.as_ref().unwrap();
        assert!(Arc::ptr_eq(&original_tail, &completed.tail));
        assert!(Arc::ptr_eq(&original_tail, &control.tail));
        assert_eq!(completed.valid_before, original_valid_before);
        assert_eq!(control.valid_before, original_valid_before);
        assert_eq!(data.sequence, original_sequence);
        assert_eq!(data.sequence, 1);
    }
    consume_control(
        &registry,
        &scenario.auth,
        AppReply::ArtifactReadAcknowledged(retried),
    );
    assert_eq!(scenario.counts.observation_counts(), io_before_retry);
    assert_eq!(
        scenario.counts.lease_drops.load(Ordering::SeqCst),
        drops_before_retry
    );
    tokio::time::sleep_until(tokio::time::Instant::from_std(short_original_deadline)).await;
    assert!(matches!(
        registry.acknowledge(&scenario.auth, input).await,
        Err(AppError::DependencyUnavailable { .. })
    ));
    assert_eq!(scenario.counts.observation_counts(), io_before_retry);
    assert_eq!(
        scenario.counts.lease_drops.load(Ordering::SeqCst),
        drops_before_retry
    );
    assert!(entry.stopped.load(Ordering::SeqCst));
    wait_removed(&registry, &opened.handle_id).await;
    assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ordinary_notifications_do_not_cancel_original_reader_expiry() {
    let scenario = Scenario::new();
    let registry = PublicArtifactReadRegistry::new();
    let original_deadline = Instant::now() + Duration::from_millis(80);
    let completion: Arc<dyn ArtifactReadOperationCompletion> =
        Arc::new(CountedCompletion(Arc::clone(&scenario.counts)));
    // This private Entry injects only a short actual deadline. The same extracted production
    // loop is used; HANDLE_LIFETIME and production admission remain the original 600s.
    let entry = Arc::new(Entry {
        id: "01900000-0000-7000-8000-000000000002".into(),
        auth: scenario.auth.clone(),
        original_deadline,
        registry: Arc::downgrade(&registry.inner),
        runtime: tokio::runtime::Handle::current(),
        stopped: AtomicBool::new(false),
        preparation_finished: AtomicBool::new(true),
        cleanup_started: AtomicBool::new(false),
        changed: Notify::new(),
        completion: Mutex::new(Some(completion)),
        control: Mutex::new(None),
        data: AsyncMutex::new(EntryData::opening()),
    });
    registry
        .inner
        .entries
        .lock()
        .unwrap()
        .insert(entry.id.clone(), Arc::clone(&entry));
    let mut timer = Box::pin(expire_original_reader(Arc::clone(&entry)));
    assert!(matches!(
        timer.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    // Drive actual Notify wakeups, not a scheduler-dependent notification count. Either wake
    // must return to the same pending original timer, with no completion/stop of its reader.
    for _ in 0..2 {
        entry.changed.notify_one();
        assert!(matches!(
            timer.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        assert!(!entry.stopped.load(Ordering::SeqCst));
        assert_eq!(scenario.counts.close_calls.load(Ordering::SeqCst), 0);
    }
    tokio::time::timeout(TEST_WAIT, timer).await.unwrap();
    assert!(Instant::now() >= original_deadline);
    assert!(entry.stopped.load(Ordering::SeqCst));
    assert!(scenario.counts.stopped.load(Ordering::SeqCst));
    assert!(scenario.counts.close_calls.load(Ordering::SeqCst) > 0);
    wait_removed(&registry, &entry.id).await;
    assert!(scenario.counts.completed_drains.load(Ordering::SeqCst) > 0);
    assert_eq!(scenario.counts.observation_counts(), (0, 0, 0));
    assert_eq!(HANDLE_LIFETIME, Duration::from_secs(600));
}

#[tokio::test]
async fn canceled_opening_keeps_same_completion_and_capacity_until_actual_drain() {
    let scenario = Scenario::new();
    let registry = PublicArtifactReadRegistry::new();
    scenario
        .counts
        .drain_permitted
        .store(false, Ordering::SeqCst);
    let mut administration = CountedAdministration::new(Arc::clone(&scenario.counts), b"abc");
    administration.pause_after_enrollment = true;
    let mut waiter = Box::pin(registry.open(
        &administration,
        &scenario.auth,
        OpenArtifactRead {
            artifact_id: ARTIFACT_ID.into(),
        },
    ));
    assert!(matches!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    assert_eq!(scenario.counts.enrollments.load(Ordering::SeqCst), 1);
    assert_eq!(scenario.counts.observation_counts(), (0, 0, 0));
    let entry = registry
        .inner
        .entries
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let original_completion = entry.actual_completion().unwrap();
    drop(waiter);
    assert!(entry.preparation_finished.load(Ordering::SeqCst));
    assert!(entry.stopped.load(Ordering::SeqCst));
    assert!(Arc::ptr_eq(
        &original_completion,
        &entry.actual_completion().unwrap()
    ));
    wait_until(|| scenario.counts.drain_calls.load(Ordering::SeqCst) > 0).await;
    assert!(entry.data.lock().await.phase == Phase::Closing);
    assert_eq!(scenario.counts.completed_drains.load(Ordering::SeqCst), 0);
    assert!(
        registry
            .inner
            .entries
            .lock()
            .unwrap()
            .contains_key(&entry.id)
    );
    // Include the original Closing reservation in both implementation caps. These additional
    // private admissions start no factory/IO; preparation_finished marks their known zeroIO.
    let mut zero_io_entries = Vec::new();
    for _ in 1..MAX_BINDING_READERS {
        let additional = registry.admit(&scenario.auth).unwrap();
        additional
            .preparation_finished
            .store(true, Ordering::SeqCst);
        zero_io_entries.push(additional);
    }
    assert!(matches!(
        registry.admit(&scenario.auth),
        Err(AppError::RequestConflict { .. })
    ));
    for binding in 1..(MAX_OPEN_READERS / MAX_BINDING_READERS) {
        let peer = session_auth(
            &scenario.issuer,
            Counts::new(),
            &format!("synthetic-capacity-{binding}"),
        );
        for _ in 0..MAX_BINDING_READERS {
            let additional = registry.admit(&peer).unwrap();
            additional
                .preparation_finished
                .store(true, Ordering::SeqCst);
            zero_io_entries.push(additional);
        }
    }
    assert_eq!(
        registry.inner.entries.lock().unwrap().len(),
        MAX_OPEN_READERS
    );
    let overflow = session_auth(&scenario.issuer, Counts::new(), "synthetic-global-overflow");
    assert!(matches!(
        registry.admit(&overflow),
        Err(AppError::RequestConflict { .. })
    ));
    assert_eq!(scenario.counts.enrollments.load(Ordering::SeqCst), 1);
    assert_eq!(scenario.counts.allocated.load(Ordering::SeqCst), 0);
    scenario.counts.permit_drain();
    wait_removed(&registry, &entry.id).await;
    assert!(scenario.counts.completed_drains.load(Ordering::SeqCst) > 0);
    for additional in zero_io_entries {
        additional.stop();
    }
    wait_empty(&registry).await;
    // Unsupported default preparation has no enrolled producer; its reservation can retire
    // without pretending the canceled original completion already acknowledged anything.
    assert!(matches!(
        registry
            .open(
                &UnsupportedAdministration,
                &scenario.auth,
                OpenArtifactRead {
                    artifact_id: ARTIFACT_ID.into()
                }
            )
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts"
        })
    ));
    wait_empty(&registry).await;
    assert_eq!(scenario.counts.enrollments.load(Ordering::SeqCst), 1);
    assert_eq!(scenario.counts.observation_counts(), (0, 0, 0));
}

#[tokio::test]
async fn acknowledgment_advances_only_after_original_carrier_lease_drop() {
    let scenario = Scenario::new();
    let registry = PublicArtifactReadRegistry::new();
    let opened = open_ready(
        &registry,
        &scenario.auth,
        Arc::clone(&scenario.counts),
        b"abc",
    )
    .await;
    let entry = registry
        .original_entry(&scenario.auth, &opened.handle_id)
        .unwrap();
    let carrier = Arc::new(handoff_data(&registry, &scenario.auth, &opened.handle_id).await);
    let last_carrier = Arc::clone(&carrier);
    let release = entry.data.lock().await.released.as_ref().unwrap().clone();
    let trace = scenario
        .counts
        .allocations
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    *trace.release_probe.lock().unwrap() = Some(Arc::downgrade(&release));
    let input = AcknowledgeArtifactReadBlock {
        handle_id: opened.handle_id.clone(),
        sequence: 0,
    };
    let mut acknowledgment = Box::pin(registry.acknowledge(&scenario.auth, input));
    assert!(matches!(
        acknowledgment
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    // The original waiter has removed the registry owner and is holding the Entry mutex
    // while waiting. Inspect by pending/marker/counters, not by awaiting that held mutex.
    assert!(!release.released.load(Ordering::SeqCst));
    assert!(!trace.dropped.load(Ordering::SeqCst));
    assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 1);
    drop(carrier);
    assert!(!release.released.load(Ordering::SeqCst));
    assert!(!trace.dropped.load(Ordering::SeqCst));
    assert!(matches!(
        acknowledgment
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(last_carrier);
    assert!(trace.dropped.load(Ordering::SeqCst));
    assert!(
        trace
            .release_still_pending_at_lease_drop
            .load(Ordering::SeqCst)
    );
    assert!(release.released.load(Ordering::SeqCst));
    assert_eq!(scenario.counts.lease_drops.load(Ordering::SeqCst), 1);
    assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 0);
    let accepted = tokio::time::timeout(TEST_WAIT, acknowledgment)
        .await
        .unwrap()
        .unwrap();
    {
        let data = entry.data.lock().await;
        assert_eq!(data.sequence, 1);
        assert_eq!(data.last_ack.as_ref().unwrap().sequence, 0);
        assert!(data.phase == Phase::Ready);
        assert!(data.registry_block.is_none());
    }
    consume_control(
        &registry,
        &scenario.auth,
        AppReply::ArtifactReadAcknowledged(accepted),
    );
    entry.stop();
    wait_removed(&registry, &entry.id).await;
}

#[tokio::test]
async fn terminal_control_delivery_survives_cleanup_without_byte_authority() {
    // Select the real typed proof, let cleanup retire registry membership, then perform the
    // same final Core handoff. A synthetic owner close must still withhold the retained proof.
    for revoke_owner in [false, true] {
        let scenario = Scenario::new();
        let registry = PublicArtifactReadRegistry::new();
        let opened = open_ready(&registry, &scenario.auth, Arc::clone(&scenario.counts), b"").await;
        let input = ReadArtifactReadBlock {
            handle_id: opened.handle_id.clone(),
            sequence: 0,
        };
        let descriptor = registry.next(&scenario.auth, input.clone()).await.unwrap();
        assert!(descriptor.eof);
        assert_eq!(descriptor.byte_length, 0);
        assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 0);
        assert_eq!(scenario.counts.lease_drops.load(Ordering::SeqCst), 1);
        assert!(scenario.counts.completed_drains.load(Ordering::SeqCst) > 0);
        let delivery = registry.take_delivery(&scenario.auth, input).unwrap();
        wait_removed(&registry, &opened.handle_id).await;
        let no_byte_observations = scenario.counts.observation_counts();
        if revoke_owner {
            scenario.owner.close();
        }
        let handed = delivery.handoff(&scenario.auth);
        if revoke_owner {
            assert!(matches!(handed, Err(AppError::Unauthenticated)));
        } else {
            assert!(handed.unwrap().is_none());
        }
        assert_eq!(scenario.counts.observation_counts(), no_byte_observations);
    }
    for revoke_owner in [false, true] {
        let scenario = Scenario::new();
        let registry = PublicArtifactReadRegistry::new();
        let opened = open_ready(
            &registry,
            &scenario.auth,
            Arc::clone(&scenario.counts),
            b"abc",
        )
        .await;
        let closed = registry
            .close(
                &scenario.auth,
                CloseArtifactRead {
                    handle_id: opened.handle_id.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 0);
        assert!(scenario.counts.completed_drains.load(Ordering::SeqCst) > 0);
        let delivery = registry
            .take_control(&scenario.auth, AppReply::ArtifactReadClosed(closed))
            .unwrap();
        wait_removed(&registry, &opened.handle_id).await;
        let no_byte_observations = scenario.counts.observation_counts();
        if revoke_owner {
            scenario.owner.close();
        }
        if revoke_owner {
            assert!(matches!(
                delivery.verify_current_tail(&scenario.auth),
                Err(AppError::Unauthenticated)
            ));
        } else {
            delivery.verify_current_tail(&scenario.auth).unwrap();
            assert!(matches!(delivery.reply(), AppReply::ArtifactReadClosed(_)));
        }
        drop(delivery);
        assert_eq!(scenario.counts.observation_counts(), no_byte_observations);
    }
}

#[tokio::test]
async fn foreign_original_bindings_cannot_select_or_close_peer() {
    let scenario = Scenario::new();
    let registry = PublicArtifactReadRegistry::new();
    let peer_counts = Counts::new();
    let peer = session_auth(
        &scenario.issuer,
        Arc::clone(&peer_counts),
        "synthetic-peer-session",
    );
    let replacement = Scenario::new();
    assert_eq!(scenario.auth, peer);
    assert_eq!(scenario.auth, replacement.auth);
    let administration = CountedAdministration::new(Arc::clone(&scenario.counts), b"abc");
    let opened = registry
        .open(
            &administration,
            &scenario.auth,
            OpenArtifactRead {
                artifact_id: ARTIFACT_ID.into(),
            },
        )
        .await
        .unwrap();
    let peer_opened = open_ready(&registry, &peer, Arc::clone(&peer_counts), b"abc").await;
    let entry = registry
        .original_entry(&scenario.auth, &opened.handle_id)
        .unwrap();
    let peer_entry = registry
        .original_entry(&peer, &peer_opened.handle_id)
        .unwrap();
    let observations_before = scenario.counts.observation_counts();
    for foreign in [&peer, &replacement.auth] {
        assert!(matches!(
            registry.take_control(foreign, AppReply::ArtifactReadOpened(opened.clone())),
            Err(AppError::NotVisible)
        ));
        assert!(matches!(
            registry
                .next(
                    foreign,
                    ReadArtifactReadBlock {
                        handle_id: opened.handle_id.clone(),
                        sequence: 0
                    }
                )
                .await,
            Err(AppError::NotVisible)
        ));
        assert!(matches!(
            registry
                .acknowledge(
                    foreign,
                    AcknowledgeArtifactReadBlock {
                        handle_id: opened.handle_id.clone(),
                        sequence: 0
                    }
                )
                .await,
            Err(AppError::NotVisible)
        ));
        assert!(matches!(
            registry
                .close(
                    foreign,
                    CloseArtifactRead {
                        handle_id: opened.handle_id.clone()
                    }
                )
                .await,
            Err(AppError::NotVisible)
        ));
    }
    assert_eq!(scenario.counts.observation_counts(), observations_before);
    assert!(!entry.stopped.load(Ordering::SeqCst));
    assert!(entry.control.lock().unwrap().is_some());
    consume_control(
        &registry,
        &scenario.auth,
        AppReply::ArtifactReadOpened(opened.clone()),
    );
    let selected = ReadArtifactReadBlock {
        handle_id: opened.handle_id.clone(),
        sequence: 0,
    };
    registry
        .next(&scenario.auth, selected.clone())
        .await
        .unwrap();
    assert!(matches!(
        registry.take_delivery(&peer, selected.clone()),
        Err(AppError::NotVisible)
    ));
    assert!(matches!(
        registry.take_delivery(&replacement.auth, selected.clone()),
        Err(AppError::NotVisible)
    ));
    assert!(entry.data.lock().await.phase == Phase::DescriptorReady);
    assert!(!entry.stopped.load(Ordering::SeqCst));
    let own_carrier = registry
        .take_delivery(&scenario.auth, selected)
        .unwrap()
        .handoff(&scenario.auth)
        .unwrap()
        .unwrap();
    let peer_carrier = handoff_data(&registry, &peer, &peer_opened.handle_id).await;
    registry.close_for_issuer(&replacement.issuer).unwrap();
    assert!(!entry.stopped.load(Ordering::SeqCst));
    assert!(!peer_entry.stopped.load(Ordering::SeqCst));
    registry
        .close_for_binding(scenario.auth.request_binding().unwrap().identity())
        .unwrap();
    assert!(entry.stopped.load(Ordering::SeqCst));
    assert!(!peer_entry.stopped.load(Ordering::SeqCst));
    assert!(!peer_counts.stopped.load(Ordering::SeqCst));
    assert!(peer_entry.data.lock().await.phase == Phase::AwaitingAcknowledgment);
    peer_carrier.verify_current_tail(&peer).unwrap();
    assert_eq!(peer_carrier.as_ref(), b"abc");
    drop(own_carrier);
    wait_removed(&registry, &opened.handle_id).await;
    assert_eq!(scenario.counts.live_allocations.load(Ordering::SeqCst), 0);
    assert_eq!(peer_counts.live_allocations.load(Ordering::SeqCst), 1);
    drop(peer_carrier);
    peer_entry.stop();
    wait_removed(&registry, &peer_opened.handle_id).await;
    peer_counts.permit_drain();
    assert_eq!(peer_counts.live_allocations.load(Ordering::SeqCst), 0);
}
