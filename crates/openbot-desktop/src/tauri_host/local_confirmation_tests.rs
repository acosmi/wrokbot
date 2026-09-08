//! Actual protocol framing/registry tests with fake PG and native owners. The dispatcher only
//! controls queuing; every admission/final job executes the production protocol guard. No Wry
//! window, AppKit foreground getter, system authentication or PostgreSQL connection is exercised.

use super::{
    AppCommand, AppError, AppReply, DesktopTauriProtocol, Method, Request, Response,
    SensitiveWriteReason, StatusCode, SubscriptionRequest, TauriHostError, VerifiedUiAssets,
    WindowAuthority,
};
use crate::local_confirmation::{
    ConfirmationAttempt, NativeCompletionToken, NativeDisposition, NativeOutcome,
};
use crate::local_confirmation_authority::LocalConfirmationAuthority;
use crate::local_confirmation_host::{LocalConfirmationDispatcher, LocalConfirmationHost};
use crate::local_confirmation_service::{
    FinishLocalConfirmation, LocalConfirmationNative, LocalConfirmationService,
    PrepareLocalConfirmation, sample_now,
};
use crate::{DesktopWindowLifecycle, InProcessTransport};
use async_trait::async_trait;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::desktop::local_confirmation::{
    LOCAL_CONFIRMATION_PATH, LocalConfirmationOutcome, LocalConfirmationReceipt,
    LocalConfirmationState, LocalConfirmationStatus,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::ui::UiLocale;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};

const MAIN: &str = "main";
const TEST_WAIT: Duration = Duration::from_secs(2);
const SYNTHETIC_SECRET: &str = "LOCAL_CONFIRMATION_FRAMING_CANARY";

fn local_auth(single_user: bool) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("confirmation-deployment"),
        TenantId::new("confirmation-tenant"),
        ActorId::new("confirmation-admin"),
        [Role::Admin],
        AuthGeneration::new(0),
        single_user,
    )
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "confirmation_test_fixture",
    }
}

#[derive(Default)]
struct ApplicationProbe {
    calls: AtomicUsize,
}

#[async_trait]
impl ApplicationService for ApplicationProbe {
    async fn execute(&self, _: AuthContext, _: AppCommand) -> Result<AppReply, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // No business backend or secret storage exists in this fixture.
        Err(unavailable())
    }

    async fn subscribe(
        &self,
        _: AuthContext,
        _: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        Err(unavailable())
    }
}

fn protocol(application: Arc<ApplicationProbe>) -> Arc<DesktopTauriProtocol> {
    let files = BTreeMap::from([
        ("index.html".to_owned(), b"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>".to_vec()),
        ("openbot-bootstrap.mjs".to_owned(), b"export {};".to_vec()),
    ]);
    Arc::new(DesktopTauriProtocol::from_verified_assets(
        VerifiedUiAssets::from_verified_release(files).unwrap(),
        Arc::new(InProcessTransport::new(application)),
    ))
}

#[derive(Default)]
struct AuthorityProbe {
    calls: AtomicUsize,
}

#[async_trait]
impl LocalConfirmationAuthority for AuthorityProbe {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(expected.clone())
    }
}

// A test-only scheduling pause at a pure health read lets the test inspect the *actual*
// registry lock held by protocol.finish_local_confirmation. It simulates thread preemption,
// not a native preflight, and times out instead of leaving a failed test thread parked forever.
struct HealthPause {
    entered: Semaphore,
    released: Mutex<bool>,
    changed: Condvar,
}

impl HealthPause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    fn pause(&self) -> bool {
        self.entered.add_permits(1);
        let released = self.released.lock().unwrap();
        let (released, _) = self
            .changed
            .wait_timeout_while(released, TEST_WAIT, |released| !*released)
            .unwrap();
        *released
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct NativeEvaluation {
    completion: NativeCompletionToken,
    sender: Option<oneshot::Sender<NativeDisposition>>,
}

impl NativeEvaluation {
    fn record(&self, outcome: NativeOutcome) -> NativeDisposition {
        self.completion
            .record_outcome(outcome, sample_now())
            .unwrap()
    }

    fn deliver(&mut self, disposition: NativeDisposition) -> bool {
        self.sender.take().unwrap().send(disposition).is_ok()
    }

    fn retire(self) {
        self.completion.native_stopped();
    }
}

struct NativeProbe {
    healthy: AtomicBool,
    starts: AtomicUsize,
    ready: Semaphore,
    evaluations: Mutex<VecDeque<NativeEvaluation>>,
    next_health_pause: Mutex<Option<Arc<HealthPause>>>,
}

impl NativeProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            healthy: AtomicBool::new(true),
            starts: AtomicUsize::new(0),
            ready: Semaphore::new(0),
            evaluations: Mutex::new(VecDeque::new()),
            next_health_pause: Mutex::new(None),
        })
    }

    async fn take(&self) -> NativeEvaluation {
        tokio::time::timeout(TEST_WAIT, self.ready.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        self.evaluations.lock().unwrap().pop_front().unwrap()
    }
}

impl LocalConfirmationNative for NativeProbe {
    fn is_available(&self) -> bool {
        let pause = self.next_health_pause.lock().unwrap().take();
        if let Some(pause) = pause
            && !pause.pause()
        {
            return false;
        }
        self.healthy.load(Ordering::SeqCst)
    }

    fn start(
        &self,
        _: UiLocale,
        completion: NativeCompletionToken,
    ) -> Result<oneshot::Receiver<NativeDisposition>, AppError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = oneshot::channel();
        self.evaluations
            .lock()
            .unwrap()
            .push_back(NativeEvaluation {
                completion,
                sender: Some(sender),
            });
        self.ready.add_permits(1);
        Ok(receiver)
    }

    fn stop(&self) {
        self.healthy.store(false, Ordering::SeqCst);
        for evaluation in self.evaluations.lock().unwrap().drain(..) {
            evaluation.retire();
        }
    }
}

struct QueuedFinish {
    label: String,
    binding_id: u64,
    job: FinishLocalConfirmation,
    sender: oneshot::Sender<Result<LocalConfirmationReceipt, AppError>>,
}

struct DispatcherProbe {
    protocol: Weak<DesktopTauriProtocol>,
    prepares: AtomicUsize,
    finishes: AtomicUsize,
    queue_finishes: AtomicBool,
    queued: Mutex<VecDeque<QueuedFinish>>,
    finish_ready: Semaphore,
}

impl DispatcherProbe {
    fn new(protocol: &Arc<DesktopTauriProtocol>) -> Arc<Self> {
        Arc::new(Self {
            protocol: Arc::downgrade(protocol),
            prepares: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
            queue_finishes: AtomicBool::new(false),
            queued: Mutex::new(VecDeque::new()),
            finish_ready: Semaphore::new(0),
        })
    }

    async fn take_finish(&self) -> QueuedFinish {
        tokio::time::timeout(TEST_WAIT, self.finish_ready.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        self.queued.lock().unwrap().pop_front().unwrap()
    }
}

#[async_trait]
impl LocalConfirmationDispatcher for DispatcherProbe {
    fn cleanup_on_main_thread(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn is_native_stopped(&self) -> bool {
        true
    }

    async fn prepare(
        &self,
        label: &str,
        binding_id: u64,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        self.protocol
            .upgrade()
            .ok_or(AppError::Unauthenticated)?
            .prepare_local_confirmation(label, binding_id, job)
    }

    async fn finish(
        &self,
        label: &str,
        binding_id: u64,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        if self.queue_finishes.load(Ordering::SeqCst) {
            let (sender, receiver) = oneshot::channel();
            self.queued.lock().unwrap().push_back(QueuedFinish {
                label: label.to_owned(),
                binding_id,
                job,
                sender,
            });
            self.finish_ready.add_permits(1);
            receiver.await.map_err(|_| unavailable())?
        } else {
            self.protocol
                .upgrade()
                .ok_or(AppError::Unauthenticated)?
                .finish_local_confirmation(label, binding_id, job)
        }
    }
}

struct Fixture {
    protocol: Arc<DesktopTauriProtocol>,
    application: Arc<ApplicationProbe>,
    authority: Arc<AuthorityProbe>,
    native: Arc<NativeProbe>,
    dispatcher: Arc<DispatcherProbe>,
}

impl Fixture {
    fn new() -> Self {
        let application = Arc::new(ApplicationProbe::default());
        let protocol = protocol(application.clone());
        let authority = Arc::new(AuthorityProbe::default());
        let native = NativeProbe::new();
        let dispatcher = DispatcherProbe::new(&protocol);
        let service = Arc::new(
            LocalConfirmationService::new(
                "protocol-test-installation",
                authority.clone(),
                Some(native.clone()),
            )
            .unwrap(),
        );
        protocol
            .install_local_confirmation(LocalConfirmationHost {
                service,
                dispatcher: dispatcher.clone(),
            })
            .unwrap();
        protocol.bind_window(MAIN, local_auth(true), None).unwrap();
        Self {
            protocol,
            application,
            authority,
            native,
            dispatcher,
        }
    }

    fn bound(&self) -> WindowAuthority {
        self.protocol.authority(MAIN).unwrap().unwrap()
    }

    async fn send(&self, method: Method, path: &str, body: Vec<u8>) -> Response<Vec<u8>> {
        self.protocol
            .handle(MAIN, request(method, path, body))
            .await
    }

    fn begin(&self) -> tokio::task::JoinHandle<Response<Vec<u8>>> {
        let protocol = self.protocol.clone();
        tokio::spawn(async move {
            protocol
                .handle(
                    MAIN,
                    request(Method::POST, LOCAL_CONFIRMATION_PATH, Vec::new()),
                )
                .await
        })
    }

    async fn confirm(&self) -> LocalConfirmationReceipt {
        let running = self.begin();
        let mut evaluation = self.native.take().await;
        let disposition = evaluation.record(NativeOutcome::Succeeded { at: sample_now() });
        assert_eq!(disposition, NativeDisposition::NeedsPostcheck);
        assert!(evaluation.deliver(disposition));
        evaluation.retire();
        let response = completed(running).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        serde_json::from_slice(response.body()).unwrap()
    }
}

fn request(method: Method, path: &str, body: Vec<u8>) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(body)
        .unwrap()
}

async fn completed(running: tokio::task::JoinHandle<Response<Vec<u8>>>) -> Response<Vec<u8>> {
    tokio::time::timeout(TEST_WAIT, running)
        .await
        .unwrap()
        .unwrap()
}

fn assert_no_store(response: &Response<Vec<u8>>) {
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert!(!String::from_utf8_lossy(response.body()).contains(SYNTHETIC_SECRET));
}

fn assert_error(response: &Response<Vec<u8>>, status: StatusCode, expected: AppError) {
    assert_eq!(response.status(), status);
    assert_no_store(response);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body()).unwrap(),
        json!({"code": expected.code().as_str()})
    );
}

#[tokio::test]
async fn get_reads_current_status_without_native_start_or_application_effect() {
    let fixture = Fixture::new();
    let response = fixture
        .send(Method::GET, LOCAL_CONFIRMATION_PATH, Vec::new())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    assert_no_store(&response);
    assert_eq!(
        serde_json::from_slice::<LocalConfirmationStatus>(response.body()).unwrap(),
        LocalConfirmationStatus {
            state: LocalConfirmationState::Required,
            remaining_seconds: 0
        }
    );
    assert_eq!(fixture.authority.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.dispatcher.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 0);
    fixture.confirm().await;
    let starts = fixture.native.starts.load(Ordering::SeqCst);
    let response = fixture
        .send(Method::GET, LOCAL_CONFIRMATION_PATH, Vec::new())
        .await;
    let status: LocalConfirmationStatus = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(status.state, LocalConfirmationState::Fresh);
    assert!((1..=900).contains(&status.remaining_seconds));
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), starts);
}

#[tokio::test]
async fn confirmation_framing_rejects_nonempty_body_any_query_and_unsupported_method() {
    let fixture = Fixture::new();
    for method in [Method::GET, Method::POST] {
        for body in [
            b"{}".to_vec(),
            b"null".to_vec(),
            vec![0],
            SYNTHETIC_SECRET.as_bytes().to_vec(),
        ] {
            let response = fixture
                .send(method.clone(), LOCAL_CONFIRMATION_PATH, body)
                .await;
            assert_error(
                &response,
                StatusCode::BAD_REQUEST,
                AppError::MalformedPayload { field: "body" },
            );
        }
        for suffix in ["?", "?action=confirm", "?fresh=true&actor=other"] {
            let response = fixture
                .send(
                    method.clone(),
                    &format!("{LOCAL_CONFIRMATION_PATH}{suffix}"),
                    Vec::new(),
                )
                .await;
            assert_error(
                &response,
                StatusCode::BAD_REQUEST,
                AppError::MalformedPayload { field: "query" },
            );
        }
    }
    for method in [Method::PUT, Method::PATCH, Method::DELETE, Method::HEAD] {
        let response = fixture
            .send(method, LOCAL_CONFIRMATION_PATH, Vec::new())
            .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_no_store(&response);
    }
    for path in [
        format!("{LOCAL_CONFIRMATION_PATH}/"),
        format!("{LOCAL_CONFIRMATION_PATH}/confirm"),
    ] {
        assert_eq!(
            fixture.send(Method::POST, &path, Vec::new()).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(fixture.authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unbound_and_remote_mode_cannot_use_local_confirmation() {
    let fixture = Fixture::new();
    for method in [Method::GET, Method::POST] {
        let response = fixture
            .protocol
            .handle(
                "unbound",
                request(method, LOCAL_CONFIRMATION_PATH, Vec::new()),
            )
            .await;
        assert_error(
            &response,
            StatusCode::UNAUTHORIZED,
            AppError::Unauthenticated,
        );
    }
    let application = Arc::new(ApplicationProbe::default());
    let remote = protocol(application.clone());
    remote
        .bind_window("remote", local_auth(false), Some(Duration::from_secs(60)))
        .unwrap();
    for method in [Method::GET, Method::POST] {
        let response = remote
            .handle(
                "remote",
                request(method, LOCAL_CONFIRMATION_PATH, Vec::new()),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_no_store(&response);
    }
    assert_eq!(fixture.authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), 0);
    assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        fixture.protocol.bind_window(
            "forged-local-fresh",
            local_auth(true),
            Some(Duration::from_secs(60))
        ),
        Err(TauriHostError::InvalidFreshness)
    ));
}

#[tokio::test]
async fn host_freshness_precedes_secret_decoding_and_clears_without_reactivation() {
    let fixture = Fixture::new();
    let path = "/api/me/model-connections";
    let malformed = format!("{{\"apiKey\":\"{SYNTHETIC_SECRET}\", invalid").into_bytes();
    let stale = fixture.send(Method::POST, path, malformed.clone()).await;
    assert_error(
        &stale,
        StatusCode::UNAUTHORIZED,
        AppError::SensitiveWriteRefused {
            reason: SensitiveWriteReason::SessionNotFresh,
        },
    );
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 0);
    fixture.confirm().await;
    let fresh = fixture.send(Method::POST, path, malformed.clone()).await;
    assert_error(
        &fresh,
        StatusCode::BAD_REQUEST,
        AppError::MalformedPayload { field: "body" },
    );
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 0);
    let valid = serde_json::to_vec(&json!({"name":"fixture", "protocol":"openai_chat_completions", "endpoint":"https://example.test/v1", "model":"fixture", "enabled":true, "apiKey":SYNTHETIC_SECRET})).unwrap();
    let reached_application = fixture.send(Method::POST, path, valid).await;
    assert_error(
        &reached_application,
        StatusCode::SERVICE_UNAVAILABLE,
        unavailable(),
    );
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 1);
    fixture.protocol.clear_window_confirmation(MAIN).unwrap();
    let cleared = fixture.send(Method::POST, path, malformed).await;
    assert_error(
        &cleared,
        StatusCode::UNAUTHORIZED,
        AppError::SensitiveWriteRefused {
            reason: SensitiveWriteReason::SessionNotFresh,
        },
    );
    assert_eq!(fixture.application.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn second_post_conflicts_before_another_pg_or_native_start() {
    let fixture = Fixture::new();
    let first = fixture.begin();
    let mut evaluation = fixture.native.take().await;
    let second = fixture
        .send(Method::POST, LOCAL_CONFIRMATION_PATH, Vec::new())
        .await;
    assert_error(
        &second,
        StatusCode::CONFLICT,
        AppError::RequestConflict {
            resource: "desktop_local_confirmation",
        },
    );
    assert_eq!(fixture.authority.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), 1);
    let disposition = evaluation.record(NativeOutcome::Cancelled);
    assert!(evaluation.deliver(disposition));
    evaluation.retire();
    let response = completed(first).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<LocalConfirmationReceipt>(response.body())
            .unwrap()
            .outcome,
        LocalConfirmationOutcome::Cancelled
    );
    assert_eq!(fixture.authority.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn same_label_same_auth_replacement_rejects_already_queued_final_receipt() {
    let fixture = Fixture::new();
    fixture
        .dispatcher
        .queue_finishes
        .store(true, Ordering::SeqCst);
    let old = fixture.bound();
    let running = fixture.begin();
    let mut evaluation = fixture.native.take().await;
    let disposition = evaluation.record(NativeOutcome::Succeeded { at: sample_now() });
    evaluation.deliver(disposition);
    evaluation.retire();
    let queued = fixture.dispatcher.take_finish().await;
    assert_eq!(queued.binding_id, old.binding_id);
    // Real registry APIs perform replacement and revocation; the fake never pre-revokes.
    assert!(fixture.protocol.unbind_window(MAIN).unwrap());
    fixture
        .protocol
        .bind_window(MAIN, old.auth.clone(), None)
        .unwrap();
    let current = fixture.bound();
    assert_eq!(current.auth, old.auth);
    assert_ne!(current.binding_id, old.binding_id);
    let result =
        fixture
            .protocol
            .finish_local_confirmation(&queued.label, queued.binding_id, queued.job);
    assert_eq!(result, Err(AppError::Unauthenticated));
    let _ = queued.sender.send(result);
    assert_error(
        &completed(running).await,
        StatusCode::UNAUTHORIZED,
        AppError::Unauthenticated,
    );
    assert!(!old.is_fresh());
    assert!(!current.is_fresh());
}

#[tokio::test]
async fn actual_registry_guard_is_held_through_cas_and_unbind_revokes_all_old_clones() {
    let fixture = Fixture::new();
    fixture
        .dispatcher
        .queue_finishes
        .store(true, Ordering::SeqCst);
    let old = fixture.bound();
    let old_clone = old.clone();
    let running = fixture.begin();
    let mut evaluation = fixture.native.take().await;
    let disposition = evaluation.record(NativeOutcome::Succeeded { at: sample_now() });
    evaluation.deliver(disposition);
    evaluation.retire();
    let queued = fixture.dispatcher.take_finish().await;
    let QueuedFinish {
        label,
        binding_id,
        job,
        sender,
    } = queued;
    let pause = HealthPause::new();
    *fixture.native.next_health_pause.lock().unwrap() = Some(pause.clone());
    let protocol = fixture.protocol.clone();
    let execute =
        std::thread::spawn(move || protocol.finish_local_confirmation(&label, binding_id, job));
    let entered = tokio::time::timeout(TEST_WAIT, pause.entered.acquire()).await;
    let was_entered = entered.is_ok();
    if let Ok(Ok(permit)) = entered {
        permit.forget();
    }
    let writer_was_blocked = matches!(
        fixture.protocol.windows.try_write(),
        Err(std::sync::TryLockError::WouldBlock)
    );
    pause.release();
    let receipt = execute.join().unwrap();
    assert!(was_entered);
    assert!(writer_was_blocked);
    assert_eq!(
        receipt.as_ref().unwrap().outcome,
        LocalConfirmationOutcome::Confirmed
    );
    assert!(old_clone.is_fresh());
    // CAS won first. Hold its reply until the real unbind/rebind finishes: the HTTP layer must
    // reject delivery to the replaced window, and its old authority clone must already be stale.
    fixture.protocol.unbind_window(MAIN).unwrap();
    fixture
        .protocol
        .bind_window(MAIN, old.auth.clone(), None)
        .unwrap();
    let _ = sender.send(receipt);
    assert_error(
        &completed(running).await,
        StatusCode::UNAUTHORIZED,
        AppError::Unauthenticated,
    );
    assert!(!old.is_fresh());
    assert!(!old_clone.is_fresh());
    assert!(!fixture.bound().is_fresh());
}

#[tokio::test]
async fn native_window_blur_clears_old_grant_without_cancelling_pending_confirmation() {
    let fixture = Fixture::new();
    fixture.confirm().await;
    let old = fixture.bound();
    assert!(old.is_fresh());
    let lifecycle = DesktopWindowLifecycle::new("wrok", fixture.protocol.clone()).unwrap();
    let running = fixture.begin();
    let mut evaluation = fixture.native.take().await;
    assert!(
        !lifecycle
            .handle_window_event(MAIN, &tauri::WindowEvent::Focused(false))
            .unwrap()
    );
    assert!(!old.is_fresh());
    assert!(!evaluation.completion.cancellation().is_cancelled());
    assert!(fixture.protocol.is_window_bound(MAIN).unwrap());
    assert!(
        !lifecycle
            .handle_window_event(MAIN, &tauri::WindowEvent::Focused(true))
            .unwrap()
    );
    assert!(!old.is_fresh()); // Focus restoration alone never reissues the previous grant.
    let disposition = evaluation.record(NativeOutcome::Succeeded { at: sample_now() });
    evaluation.deliver(disposition);
    evaluation.retire();
    let response = completed(running).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<LocalConfirmationReceipt>(response.body())
            .unwrap()
            .outcome,
        LocalConfirmationOutcome::Confirmed
    );
    assert!(old.is_fresh()); // Only the new, checked proof made this same shared binding fresh.
}

#[tokio::test]
async fn closing_native_health_denies_old_authority_and_status_without_revival() {
    let fixture = Fixture::new();
    fixture.confirm().await;
    let old = fixture.bound();
    assert!(old.is_fresh());
    fixture.native.healthy.store(false, Ordering::SeqCst);
    assert!(!old.is_fresh());
    let starts = fixture.native.starts.load(Ordering::SeqCst);
    let response = fixture
        .send(Method::GET, LOCAL_CONFIRMATION_PATH, Vec::new())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<LocalConfirmationStatus>(response.body())
            .unwrap()
            .state,
        LocalConfirmationState::Unavailable
    );
    fixture.native.healthy.store(true, Ordering::SeqCst);
    assert!(!old.is_fresh());
    assert_eq!(fixture.native.starts.load(Ordering::SeqCst), starts);
    fixture.confirm().await;
    assert!(old.is_fresh());
}

#[tokio::test]
async fn cancelled_queued_receipt_is_also_rejected_after_real_unbind() {
    let fixture = Fixture::new();
    fixture
        .dispatcher
        .queue_finishes
        .store(true, Ordering::SeqCst);
    let running = fixture.begin();
    let mut evaluation = fixture.native.take().await;
    let disposition = evaluation.record(NativeOutcome::Cancelled);
    evaluation.deliver(disposition);
    evaluation.retire();
    let queued = fixture.dispatcher.take_finish().await;
    assert!(!queued.job.requires_foreground());
    fixture.protocol.unbind_window(MAIN).unwrap();
    let result =
        fixture
            .protocol
            .finish_local_confirmation(&queued.label, queued.binding_id, queued.job);
    assert_eq!(result, Err(AppError::Unauthenticated));
    let _ = queued.sender.send(result);
    assert_error(
        &completed(running).await,
        StatusCode::UNAUTHORIZED,
        AppError::Unauthenticated,
    );
}
