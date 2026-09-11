use super::*;
use crate::local_confirmation::NativeOutcome;
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::desktop::local_confirmation::{
    LocalConfirmationOutcome, LocalConfirmationState,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn auth(generation: u64) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [Role::Admin],
        AuthGeneration::new(generation),
        true,
    )
}

struct AuthorityGate {
    entered: Semaphore,
    release: Semaphore,
    dropped: AtomicBool,
}

impl AuthorityGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            dropped: AtomicBool::new(false),
        })
    }

    async fn entered(&self) {
        self.entered.acquire().await.unwrap().forget();
    }
}

enum VerifyAction {
    Current,
    Different(AuthContext),
    Denied,
    Gate(Arc<AuthorityGate>),
}

struct TestAuthority {
    actions: Mutex<VecDeque<VerifyAction>>,
    calls: AtomicUsize,
}

impl TestAuthority {
    fn push(&self, action: VerifyAction) {
        self.actions.lock().unwrap().push_back(action);
    }
}

#[async_trait]
impl LocalConfirmationAuthority for TestAuthority {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let action = self
            .actions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(VerifyAction::Current);
        match action {
            VerifyAction::Current => Ok(expected.clone()),
            VerifyAction::Different(auth) => Ok(auth),
            VerifyAction::Denied => Err(AppError::Unauthenticated),
            VerifyAction::Gate(gate) => {
                struct MarkDrop<'a>(&'a AtomicBool);
                impl Drop for MarkDrop<'_> {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _drop = MarkDrop(&gate.dropped);
                gate.entered.add_permits(1);
                gate.release.acquire().await.unwrap().forget();
                Ok(expected.clone())
            }
        }
    }
}

struct NativeSlot {
    completion: NativeCompletionToken,
    sender: Option<oneshot::Sender<NativeDisposition>>,
}

impl NativeSlot {
    fn record(&self, outcome: NativeOutcome) -> NativeDisposition {
        self.completion
            .record_outcome(outcome, sample_now())
            .unwrap()
    }

    fn deliver(&mut self, result: NativeDisposition) -> bool {
        self.sender.take().unwrap().send(result).is_ok()
    }

    fn stop(self) {
        self.completion.native_stopped();
    }
}

struct TestNative {
    available: AtomicBool,
    starts: AtomicUsize,
    started: Semaphore,
    slots: Mutex<VecDeque<NativeSlot>>,
}

impl TestNative {
    async fn take(&self) -> NativeSlot {
        self.started.acquire().await.unwrap().forget();
        self.slots.lock().unwrap().pop_front().unwrap()
    }
}

impl LocalConfirmationNative for TestNative {
    fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    fn start(
        &self,
        _: UiLocale,
        completion: NativeCompletionToken,
    ) -> Result<oneshot::Receiver<NativeDisposition>, AppError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = oneshot::channel();
        self.slots.lock().unwrap().push_back(NativeSlot {
            completion,
            sender: Some(sender),
        });
        self.started.add_permits(1);
        Ok(receiver)
    }

    fn stop(&self) {
        self.available.store(false, Ordering::SeqCst);
        for slot in self.slots.lock().unwrap().drain(..) {
            slot.stop();
        }
    }
}

type PreparedJob = (
    PrepareLocalConfirmation,
    oneshot::Sender<Result<ConfirmationAttempt, AppError>>,
);
type FinishedJob = (
    FinishLocalConfirmation,
    oneshot::Sender<Result<LocalConfirmationReceipt, AppError>>,
);

struct TestWindow {
    current: Mutex<GrantHandle>,
    foreground: AtomicBool,
    queue_prepare: AtomicBool,
    queue_finish: AtomicBool,
    prepares: Mutex<VecDeque<PreparedJob>>,
    finishes: Mutex<VecDeque<FinishedJob>>,
    prepare_ready: Semaphore,
    finish_ready: Semaphore,
}

impl TestWindow {
    fn run_prepare(&self, job: PrepareLocalConfirmation) -> Result<ConfirmationAttempt, AppError> {
        if !self.foreground.load(Ordering::SeqCst) {
            return Err(unavailable());
        }
        let current = self.current.lock().unwrap();
        job.execute(&current)
    }

    fn run_finish(
        &self,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        if job.requires_foreground() && !self.foreground.load(Ordering::SeqCst) {
            return Err(unavailable());
        }
        let current = self.current.lock().unwrap();
        job.execute(&current)
    }

    async fn take_prepare(&self) -> PreparedJob {
        self.prepare_ready.acquire().await.unwrap().forget();
        self.prepares.lock().unwrap().pop_front().unwrap()
    }

    async fn take_finish(&self) -> FinishedJob {
        self.finish_ready.acquire().await.unwrap().forget();
        self.finishes.lock().unwrap().pop_front().unwrap()
    }
}

#[async_trait]
impl LocalConfirmationWindow for TestWindow {
    async fn prepare(
        &self,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        if !self.queue_prepare.load(Ordering::SeqCst) {
            return self.run_prepare(job);
        }
        let (sender, receiver) = oneshot::channel();
        self.prepares.lock().unwrap().push_back((job, sender));
        self.prepare_ready.add_permits(1);
        receiver.await.map_err(|_| unavailable())?
    }

    async fn finish(
        &self,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        if !self.queue_finish.load(Ordering::SeqCst) {
            return self.run_finish(job);
        }
        let (sender, receiver) = oneshot::channel();
        self.finishes.lock().unwrap().push_back((job, sender));
        self.finish_ready.add_permits(1);
        receiver.await.map_err(|_| unavailable())?
    }
}

struct Rig {
    service: Arc<LocalConfirmationService>,
    authority: Arc<TestAuthority>,
    native: Arc<TestNative>,
    window: Arc<TestWindow>,
    grant: GrantHandle,
    auth: AuthContext,
    closed: CancellationToken,
}

impl Rig {
    fn new() -> Self {
        Self::with_wait(POST_WAIT)
    }

    fn with_wait(wait: Duration) -> Self {
        let authority = Arc::new(TestAuthority {
            actions: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        });
        let native = Arc::new(TestNative {
            available: AtomicBool::new(true),
            starts: AtomicUsize::new(0),
            started: Semaphore::new(0),
            slots: Mutex::new(VecDeque::new()),
        });
        let mut service =
            LocalConfirmationService::new("installation", authority.clone(), Some(native.clone()))
                .unwrap();
        service.test_wait = wait;
        let auth = auth(0); // Real initial Desktop generation zero is valid.
        let grant = service.register_binding(1, &auth).unwrap();
        let window = Arc::new(TestWindow {
            current: Mutex::new(grant.clone()),
            foreground: AtomicBool::new(true),
            queue_prepare: AtomicBool::new(false),
            queue_finish: AtomicBool::new(false),
            prepares: Mutex::new(VecDeque::new()),
            finishes: Mutex::new(VecDeque::new()),
            prepare_ready: Semaphore::new(0),
            finish_ready: Semaphore::new(0),
        });
        Self {
            service: Arc::new(service),
            authority,
            native,
            window,
            grant,
            auth,
            closed: CancellationToken::new(),
        }
    }

    fn confirm(&self) -> tokio::task::JoinHandle<Result<LocalConfirmationReceipt, AppError>> {
        let service = self.service.clone();
        let grant = self.grant.clone();
        let auth = self.auth.clone();
        let closed = self.closed.clone();
        let window = self.window.clone();
        tokio::spawn(async move {
            service
                .confirm(&grant, &auth, &closed, UiLocale::En, window.as_ref())
                .await
        })
    }

    async fn success(&self) -> LocalConfirmationReceipt {
        let request = self.confirm();
        let mut slot = self.native.take().await;
        let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
        assert_eq!(disposition, NativeDisposition::NeedsPostcheck);
        assert!(slot.deliver(disposition));
        slot.stop();
        request.await.unwrap().unwrap()
    }

    fn replace_without_old_revoke(&self) {
        // Deliberately model the old host's map-remove -> closed/revoke gap.
        let replacement = self.service.register_binding(1, &self.auth).unwrap();
        *self.window.current.lock().unwrap() = replacement;
    }
}

fn expire_job_budget(budget: &RequestBudget, wall_only: bool) {
    let mut clocks = budget.clocks.lock().unwrap();
    if wall_only {
        clocks.began_wall = SystemTime::now() - POST_WAIT;
    } else {
        clocks.began_monotonic = Instant::now() - POST_WAIT;
    }
}

#[tokio::test]
async fn cancelled_prepare_reply_drops_its_attempt_without_starting_native() {
    let rig = Rig::new();
    rig.window.queue_prepare.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let (job, sender) = rig.window.take_prepare().await;
    let prepared = rig.window.run_prepare(job).unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    // The real host must let send's returned value drop, rather than leak a prepared attempt.
    let undelivered = sender.send(Ok(prepared));
    assert!(undelivered.is_err());
    drop(undelivered);
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        rig.grant.status(sample_now()).unwrap().state,
        LocalConfirmationState::Required
    );
}

#[tokio::test]
async fn whole_request_async_deadline_cancels_a_finish_still_in_host_queue() {
    let rig = Rig::with_wait(Duration::from_millis(80));
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    let (job, sender) = rig.window.take_finish().await;
    assert_eq!(request.await.unwrap(), Err(unavailable()));
    assert!(slot.completion.cancellation().is_cancelled());
    assert_eq!(rig.window.run_finish(job), Err(AppError::Unauthenticated));
    drop(sender);
    assert!(!rig.grant.is_fresh(sample_now()));
    slot.stop();
}

#[tokio::test]
async fn cancelled_final_job_respects_whole_request_deadline() {
    let rig = Rig::new();
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Cancelled);
    slot.deliver(disposition);
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    assert!(!job.requires_foreground());
    expire_job_budget(&job.context.budget, true);
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(request.await.unwrap(), Err(unavailable()));
}

#[tokio::test]
async fn explicit_status_authority_error_revokes_old_grant_without_native_call() {
    let rig = Rig::new();
    rig.success().await;
    rig.authority.push(VerifyAction::Denied);
    assert_eq!(
        rig.service.status(&rig.grant, &rig.auth, &rig.closed).await,
        Err(AppError::Unauthenticated)
    );
    assert!(!rig.grant.is_fresh(sample_now()));
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn genuine_generation_zero_flow_requires_pre_and_postcheck() {
    let rig = Rig::new();
    let receipt = rig.success().await;
    assert_eq!(receipt.outcome, LocalConfirmationOutcome::Confirmed);
    assert!((899..=900).contains(&receipt.remaining_seconds));
    assert_eq!(rig.authority.calls.load(Ordering::SeqCst), 2);
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 1);
    assert!(rig.grant.is_fresh(sample_now()));
}

#[tokio::test]
async fn binding_replacement_while_pg_precheck_waits_makes_zero_native_calls() {
    let rig = Rig::new();
    let gate = AuthorityGate::new();
    rig.authority.push(VerifyAction::Gate(gate.clone()));
    let request = rig.confirm();
    gate.entered().await;
    rig.replace_without_old_revoke();
    gate.release.add_permits(1);
    assert_eq!(request.await.unwrap(), Err(AppError::Unauthenticated));
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropped_request_cannot_execute_queued_prepare_or_start_native() {
    let rig = Rig::new();
    rig.window.queue_prepare.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let (job, sender) = rig.window.take_prepare().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(matches!(
        rig.window.run_prepare(job),
        Err(AppError::Unauthenticated)
    ));
    drop(sender);
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        rig.grant.status(sample_now()).unwrap().state,
        LocalConfirmationState::Required
    );
}

#[tokio::test]
async fn dropped_request_cancels_queued_finish_under_coordinator_lock() {
    let rig = Rig::new();
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    let (job, sender) = rig.window.take_finish().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(slot.completion.cancellation().is_cancelled());
    assert!(matches!(
        rig.window.run_finish(job),
        Err(AppError::Unauthenticated)
    ));
    drop(sender);
    assert!(!rig.grant.is_fresh(sample_now()));
    slot.stop();
}

#[tokio::test]
async fn final_window_replacement_is_rejected_without_waiting_for_closed_token() {
    let rig = Rig::new();
    rig.success().await;
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    rig.replace_without_old_revoke();
    assert!(!rig.closed.is_cancelled());
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(request.await.unwrap(), Err(AppError::Unauthenticated));
    assert!(!rig.grant.is_fresh(sample_now()));
}

#[tokio::test]
async fn final_foreground_failure_denies_confirmation_in_host_job() {
    let rig = Rig::new();
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    assert!(job.requires_foreground());
    rig.window.foreground.store(false, Ordering::SeqCst);
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(request.await.unwrap(), Err(unavailable()));
    assert!(!rig.grant.is_fresh(sample_now()));
}

#[tokio::test]
async fn generation_or_explicit_pg_error_rejects_and_revokes_old_clones() {
    for precheck in [true, false] {
        for changed in [true, false] {
            let rig = Rig::new();
            rig.success().await;
            if !precheck {
                rig.authority.push(VerifyAction::Current);
            }
            rig.authority.push(if changed {
                VerifyAction::Different(auth(1))
            } else {
                VerifyAction::Denied
            });
            let request = rig.confirm();
            if !precheck {
                let mut slot = rig.native.take().await;
                let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
                slot.deliver(disposition);
                slot.stop();
            }
            assert_eq!(request.await.unwrap(), Err(AppError::Unauthenticated));
            assert!(!rig.grant.is_fresh(sample_now()));
            assert_eq!(
                rig.native.starts.load(Ordering::SeqCst),
                if precheck { 1 } else { 2 }
            );
        }
    }
}

#[tokio::test]
async fn pg_timeout_in_status_precheck_and_postcheck_revokes_old_clones() {
    for stage in [0, 1, 2] {
        // Shorten only the test service's whole-request budget; production uses exact POST_WAIT.
        let rig = Rig::with_wait(Duration::from_millis(80));
        rig.success().await;
        let old_clone = rig.grant.clone();
        let gate = AuthorityGate::new();
        if stage == 2 {
            rig.authority.push(VerifyAction::Current);
        }
        rig.authority.push(VerifyAction::Gate(gate.clone()));
        if stage == 0 {
            assert_eq!(
                rig.service.status(&rig.grant, &rig.auth, &rig.closed).await,
                Err(unavailable())
            );
        } else {
            let request = rig.confirm();
            let mut unresolved = None;
            if stage == 2 {
                let mut slot = rig.native.take().await;
                let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
                slot.deliver(disposition);
                unresolved = Some(slot);
            }
            assert_eq!(request.await.unwrap(), Err(unavailable()));
            if let Some(slot) = unresolved {
                assert!(slot.completion.cancellation().is_cancelled());
                slot.stop();
            }
        }
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert!(!old_clone.is_fresh(sample_now()));
    }
}

#[tokio::test]
async fn dropping_pg_wait_cancels_only_request_not_previously_valid_grant() {
    let rig = Rig::new();
    rig.success().await;
    let gate = AuthorityGate::new();
    rig.authority.push(VerifyAction::Gate(gate.clone()));
    let request = rig.confirm();
    gate.entered().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(gate.dropped.load(Ordering::SeqCst));
    assert!(rig.grant.is_fresh(sample_now()));
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn normal_cancel_signal_can_precede_disposition_and_needs_no_pg_postcheck_or_foreground() {
    let rig = Rig::new();
    rig.success().await;
    let calls_before = rig.authority.calls.load(Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Cancelled);
    assert_eq!(disposition, NativeDisposition::Cancelled);
    assert!(slot.completion.cancellation().is_cancelled());
    tokio::task::yield_now().await;
    assert!(!request.is_finished());
    rig.window.foreground.store(false, Ordering::SeqCst);
    assert!(slot.deliver(disposition));
    slot.stop();
    let receipt = request.await.unwrap().unwrap();
    assert_eq!(receipt.outcome, LocalConfirmationOutcome::Cancelled);
    assert!((899..=900).contains(&receipt.remaining_seconds));
    assert_eq!(rig.authority.calls.load(Ordering::SeqCst), calls_before + 1);
}

#[tokio::test]
async fn cancelled_receipt_still_uses_final_current_binding_guard() {
    let rig = Rig::new();
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Cancelled);
    slot.deliver(disposition);
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    assert!(!job.requires_foreground());
    rig.replace_without_old_revoke();
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(request.await.unwrap(), Err(AppError::Unauthenticated));
}

#[tokio::test]
async fn complete_post_budget_applies_to_prepare_and_final_queue_including_wall_clock() {
    for prepare in [true, false] {
        for wall_only in [true, false] {
            let rig = Rig::new();
            if prepare {
                rig.window.queue_prepare.store(true, Ordering::SeqCst);
            } else {
                rig.window.queue_finish.store(true, Ordering::SeqCst);
            }
            let request = rig.confirm();
            if prepare {
                let (job, sender) = rig.window.take_prepare().await;
                assert_eq!(job.context.budget.wait, POST_WAIT);
                expire_job_budget(&job.context.budget, wall_only);
                assert!(sender.send(rig.window.run_prepare(job)).is_ok());
                assert_eq!(rig.native.starts.load(Ordering::SeqCst), 0);
            } else {
                let mut slot = rig.native.take().await;
                let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
                slot.deliver(disposition);
                slot.stop();
                let (job, sender) = rig.window.take_finish().await;
                expire_job_budget(&job.context.budget, wall_only);
                assert!(sender.send(rig.window.run_finish(job)).is_ok());
            }
            assert_eq!(request.await.unwrap(), Err(unavailable()));
            assert!(!rig.grant.is_fresh(sample_now()));
        }
    }
}

#[tokio::test]
async fn native_health_loss_revokes_and_recovery_does_not_restore_grant() {
    let rig = Rig::new();
    rig.success().await;
    rig.native.available.store(false, Ordering::SeqCst);
    assert!(!rig.service.is_native_available());
    assert!(!rig.grant.is_fresh(sample_now()));
    rig.native.available.store(true, Ordering::SeqCst);
    assert!(rig.service.is_native_available());
    assert_eq!(
        rig.service
            .status(&rig.grant, &rig.auth, &rig.closed)
            .await
            .unwrap()
            .state,
        LocalConfirmationState::Unavailable
    );
    rig.success().await;
    assert!(rig.grant.is_fresh(sample_now()));
}

#[tokio::test]
async fn status_rechecks_native_health_after_pg_wait_before_projecting_fresh() {
    let rig = Rig::new();
    rig.success().await;
    let old_clone = rig.grant.clone();
    let gate = AuthorityGate::new();
    rig.authority.push(VerifyAction::Gate(gate.clone()));

    let service = Arc::clone(&rig.service);
    let grant = rig.grant.clone();
    let auth = rig.auth.clone();
    let closed = rig.closed.clone();
    let status = tokio::spawn(async move { service.status(&grant, &auth, &closed).await });
    gate.entered().await;

    // Model the owner or monitor failing while the canonical PG read is in flight, before
    // its native notification callback has had a chance to invalidate the coordinator.
    rig.native.available.store(false, Ordering::SeqCst);
    gate.release.add_permits(1);

    assert_eq!(
        status.await.unwrap().unwrap(),
        LocalConfirmationStatus {
            state: LocalConfirmationState::Unavailable,
            remaining_seconds: 0,
        }
    );
    assert!(!old_clone.is_fresh(sample_now()));
}

#[tokio::test]
async fn native_health_loss_while_final_job_is_queued_cannot_grant() {
    let rig = Rig::new();
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    rig.native.available.store(false, Ordering::SeqCst);
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(request.await.unwrap(), Err(unavailable()));
    assert!(!rig.grant.is_fresh(sample_now()));
}

#[tokio::test]
async fn ordinary_request_drop_retains_native_slot_until_actual_owner_retirement() {
    let rig = Rig::new();
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(slot.completion.cancellation().is_cancelled());
    assert!(matches!(
        rig.confirm().await.unwrap(),
        Err(AppError::RequestConflict { .. })
    ));
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 1);
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    assert_eq!(disposition, NativeDisposition::Rejected);
    assert!(!slot.deliver(disposition));
    slot.stop();
    rig.success().await;
    assert_eq!(rig.native.starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn admission_prevents_multiple_pg_prechecks() {
    let rig = Rig::new();
    let gate = AuthorityGate::new();
    rig.authority.push(VerifyAction::Gate(gate.clone()));
    let first = rig.confirm();
    gate.entered().await;
    assert!(matches!(
        rig.confirm().await.unwrap(),
        Err(AppError::RequestConflict { .. })
    ));
    assert_eq!(rig.authority.calls.load(Ordering::SeqCst), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
}

#[test]
fn whole_request_budget_denies_wall_rollback_and_uses_exact_constant() {
    let budget = RequestBudget::new(POST_WAIT).unwrap();
    let mut clocks = budget.clocks.lock().unwrap();
    assert_eq!(
        budget
            .deadline
            .into_std()
            .duration_since(clocks.began_monotonic),
        Duration::from_secs(120)
    );
    clocks.last_wall = SystemTime::now() + Duration::from_secs(1);
    drop(clocks);
    assert!(budget.sample().is_err());
}

#[tokio::test]
async fn job_observed_wall_rollback_revokes_even_when_coordinator_clock_never_regressed() {
    for prepare in [true, false] {
        let rig = Rig::new();
        rig.success().await;
        let old_clone = rig.grant.clone();
        if prepare {
            rig.window.queue_prepare.store(true, Ordering::SeqCst);
        } else {
            rig.window.queue_finish.store(true, Ordering::SeqCst);
        }
        let request = rig.confirm();
        if prepare {
            let (job, sender) = rig.window.take_prepare().await;
            job.context.budget.clocks.lock().unwrap().last_wall =
                SystemTime::now() + Duration::from_secs(1);
            // Only the POST budget saw a later wall time. All pure coordinator samples are real,
            // current and increasing, so pure clock-regression detection cannot mask this gap.
            assert!(old_clone.is_fresh(sample_now()));
            assert!(sender.send(rig.window.run_prepare(job)).is_ok());
            assert_eq!(rig.native.starts.load(Ordering::SeqCst), 1);
        } else {
            let mut slot = rig.native.take().await;
            let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
            slot.deliver(disposition);
            slot.stop();
            let (job, sender) = rig.window.take_finish().await;
            job.context.budget.clocks.lock().unwrap().last_wall =
                SystemTime::now() + Duration::from_secs(1);
            assert!(old_clone.is_fresh(sample_now()));
            assert!(sender.send(rig.window.run_finish(job)).is_ok());
        }
        assert_eq!(request.await.unwrap(), Err(unavailable()));
        assert!(!old_clone.is_fresh(sample_now()));
    }
}

#[tokio::test]
async fn final_status_budget_rollback_or_poison_revokes_previous_grant() {
    for poison in [false, true] {
        let rig = Rig::new();
        rig.success().await;
        let budget = RequestBudget::new(POST_WAIT).unwrap();
        if poison {
            let clocks = budget.clocks.clone();
            assert!(
                std::thread::spawn(move || {
                    let _held = clocks.lock().unwrap();
                    panic!("synthetic POST clock-state poison");
                })
                .join()
                .is_err()
            );
        } else {
            budget.clocks.lock().unwrap().last_wall = SystemTime::now() + Duration::from_secs(1);
        }
        assert!(rig.grant.is_fresh(sample_now()));
        // This is exactly the private final read called by status after PG verification.
        assert_eq!(
            rig.service.read_status(&rig.grant, &rig.closed, &budget),
            Err(unavailable())
        );
        assert!(!rig.grant.is_fresh(sample_now()));
    }
}

#[tokio::test]
async fn service_instance_clear_does_not_need_window_registry_or_cancel_queued_confirmation() {
    let rig = Rig::new();
    rig.success().await;
    rig.window.queue_finish.store(true, Ordering::SeqCst);
    let request = rig.confirm();
    let mut slot = rig.native.take().await;
    let disposition = slot.record(NativeOutcome::Succeeded { at: sample_now() });
    slot.deliver(disposition);
    let cancellation = slot.completion.cancellation();
    slot.stop();
    let (job, sender) = rig.window.take_finish().await;
    {
        let _registry = rig.window.current.lock().unwrap();
        rig.service.clear_existing_grants();
        assert!(!rig.grant.is_fresh(sample_now()));
        assert!(!cancellation.is_cancelled());
    }
    assert!(sender.send(rig.window.run_finish(job)).is_ok());
    assert_eq!(
        request.await.unwrap().unwrap().outcome,
        LocalConfirmationOutcome::Confirmed
    );
    assert!(rig.grant.is_fresh(sample_now()));
}
