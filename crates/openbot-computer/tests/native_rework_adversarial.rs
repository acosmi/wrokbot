//! Independent second review. Synthetic ports only: no OS input, capture, network or secrets.
use async_trait::async_trait;
use openbot_computer::native::*;
use openbot_computer::native::{NativeActionGate, NativeCleanupGate};
use openbot_computer::native::{ObservationGeneration, PixelDeliveryGate, PixelFrameOrigin};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

const CANARY: &str = "SYNTHETIC_UNKNOWN_CANARY_NO_REAL_SECRET";
struct Platform {
    query_block: bool,
    injection_block: bool,
    fail_release: bool,
    unknown: bool,
    query_started: Semaphore,
    query_gate: Semaphore,
    injection_started: Semaphore,
    injection_gate: Semaphore,
    calls: AtomicUsize,
    releases: AtomicUsize,
    wrong_target_releases: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    pressed: AtomicBool,
    injected_target_start: Mutex<Option<OffsetDateTime>>,
}
impl Platform {
    fn new(query_block: bool, injection_block: bool, fail_release: bool, unknown: bool) -> Self {
        Self {
            query_block,
            injection_block,
            fail_release,
            unknown,
            query_started: Semaphore::new(0),
            query_gate: Semaphore::new(0),
            injection_started: Semaphore::new(0),
            injection_gate: Semaphore::new(0),
            calls: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            wrong_target_releases: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            pressed: AtomicBool::new(false),
            injected_target_start: Mutex::new(None),
        }
    }
}
#[async_trait]
impl NativePlatformPort for Platform {
    fn with_current_action(
        &self,
        _: &ActionCapability,
        _: &NativeTarget,
        _: &NativeAction,
        effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        effect()
    }
    fn with_current_cleanup(
        &self,
        _: &NativeTarget,
        effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        effect()
    }

    async fn query_session_state(
        &self,
        _: &OsSessionId,
    ) -> Result<NativeSessionState, NativePlatformError> {
        self.query_started.add_permits(1);
        if self.query_block {
            self.query_gate.acquire().await.unwrap().forget();
        }
        Ok(NativeSessionState::Active)
    }
    async fn inject_action(
        &self,
        target: &NativeTarget,
        action: &NativeAction,
        dispatch_gate: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError> {
        dispatch_gate.dispatch(|| {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            *self.injected_target_start.lock().unwrap() = Some(target.process_start_time());
            if matches!(action, NativeAction::KeyDown { .. }) {
                self.pressed.store(true, Ordering::SeqCst);
            }
            self.injection_started.add_permits(1);
        })?;
        if self.injection_block {
            self.injection_gate.acquire().await.unwrap().forget();
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        if self.unknown {
            Ok(NativeInjectionOutcome::Unknown {
                reason: CANARY.into(),
            })
        } else {
            Ok(NativeInjectionOutcome::Success)
        }
    }
    async fn release_inputs(
        &self,
        target: &NativeTarget,
        _: &[NativeKey],
        _: &[MouseButton],
        dispatch_gate: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError> {
        if *self.injected_target_start.lock().unwrap() != Some(target.process_start_time()) {
            self.wrong_target_releases.fetch_add(1, Ordering::SeqCst);
            return Err(NativePlatformError("test-only wrong target".into()));
        }
        if self.fail_release {
            return Err(NativePlatformError("test-only cleanup refused".into()));
        }
        dispatch_gate.dispatch(|| {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.pressed.store(false, Ordering::SeqCst);
        })?;
        Ok(())
    }
}
fn target(session: &OsSessionId, start: i64) -> NativeTarget {
    NativeTarget::from_trusted_host(
        "test-install",
        "test-user",
        session.clone(),
        BootId::new("test-boot"),
        123,
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(start),
        NativeWindowId::new("window-a"),
        NativeDisplayId::new("display-a"),
        CoordinateTransform {
            scale_factor: 1.0,
            bounds: LogicalRect {
                x: 0.0,
                y: 0.0,
                width: 100.0,
                height: 100.0,
            },
        },
        ObservationGeneration::new(1),
    )
}
fn capability(id: &str, target: NativeTargetHandle) -> ActionCapability {
    ActionCapability::new(
        CapabilityId::new(id),
        ActorId::new("test-actor"),
        RunId::new("test-run"),
        PolicyDecisionId::new("test-durable-decision"),
        target,
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    )
}
async fn setup(port: Arc<Platform>) -> (NativeSessionHandle, NativeTargetHandle) {
    let registry = NativeSessionRegistry::new();
    let session = OsSessionId::new(format!("test-session-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "owner-a", port)
        .await
        .unwrap();
    handle.acquire_acting().await.unwrap();
    let target = handle.register_target(target(&session, 100)).await;
    (handle, target)
}
async fn wait_started(semaphore: &Semaphore) {
    tokio::time::timeout(StdDuration::from_secs(2), semaphore.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}
async fn act(
    handle: &NativeSessionHandle,
    target: NativeTargetHandle,
    id: &str,
) -> Result<NativeReceipt, NativeControlError> {
    let now = OffsetDateTime::now_utc();
    handle
        .perform_action(
            (capability(id, target)).with_action(
                (NativeAction::KeyDown {
                    key: NativeKey::Space,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Space,
            },
            now,
            now,
        )
        .await
}

#[tokio::test]
async fn positive_native_success_and_confirmed_owned_cleanup() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    act(&h, t, "positive").await.unwrap();
    h.stop().await.unwrap();
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
    assert!(!port.pressed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn r01_failed_cleanup_must_not_report_stop_success_or_forget_obligation() {
    let port = Arc::new(Platform::new(false, false, true, false));
    let (h, t) = setup(port.clone()).await;
    act(&h, t, "cleanup-fails").await.unwrap();
    let first = h.stop().await;
    let second = h.stop().await;
    println!(
        "first={first:?} second={second:?} pressed={} releases={}",
        port.pressed.load(Ordering::SeqCst),
        port.releases.load(Ordering::SeqCst)
    );
    assert!(
        first.is_err() && second.is_err(),
        "cleanup failure was reported as Stop success and the obligation was discarded"
    );
}

#[tokio::test]
async fn r02_cleanup_must_not_target_a_recycled_process() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    act(&h, t, "original-process").await.unwrap();
    h.register_target(target(h.session_id(), 200)).await;
    let result = h.stop().await;
    println!(
        "stop={result:?} wrong_target_releases={}",
        port.wrong_target_releases.load(Ordering::SeqCst)
    );
    assert_eq!(
        port.wrong_target_releases.load(Ordering::SeqCst),
        0,
        "cleanup was sent to the replacement process instead of retaining the original input obligation"
    );
}

#[tokio::test]
async fn r03_stop_during_session_query_must_prevent_new_injection() {
    let port = Arc::new(Platform::new(true, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let task = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "stop-during-query").await })
    };
    wait_started(&port.query_started).await;
    let stopping = {
        let h = h.clone();
        tokio::spawn(async move { h.stop().await })
    };
    tokio::time::timeout(StdDuration::from_secs(2), async {
        while h.current_epoch().await.get() == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    port.query_gate.add_permits(1);
    let action = task.await.unwrap();
    let stopped = stopping.await.unwrap();
    println!(
        "action={action:?} stop={stopped:?} injections_after_stop_epoch={}",
        port.calls.load(Ordering::SeqCst)
    );
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        0,
        "query returned after Stop revoked the action, but a new injection still began"
    );
}

#[tokio::test]
async fn r04_target_replaced_during_query_must_prevent_old_action() {
    let port = Arc::new(Platform::new(true, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let task = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "target-during-query").await })
    };
    wait_started(&port.query_started).await;
    h.register_target(target(h.session_id(), 200)).await;
    port.query_gate.add_permits(1);
    let result = task.await.unwrap();
    println!(
        "result={result:?} injections={}",
        port.calls.load(Ordering::SeqCst)
    );
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        0,
        "invalidated target was not rechecked after an asynchronous session query"
    );
}

#[tokio::test]
async fn r05_session_query_is_inside_the_five_second_action_budget() {
    let port = Arc::new(Platform::new(true, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let result =
        tokio::time::timeout(StdDuration::from_millis(5500), act(&h, t, "query-timeout")).await;
    println!("bounded_result={result:?}");
    assert!(
        result.is_ok(),
        "the formal action remained pending beyond its five-second budget because query_session_state has no deadline"
    );
}

#[tokio::test]
async fn r06_cancelled_unsent_query_must_not_leak_in_flight_reservation() {
    let port = Arc::new(Platform::new(true, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let task = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "cancel-query").await })
    };
    wait_started(&port.query_started).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let stop = tokio::time::timeout(StdDuration::from_millis(5500), h.stop()).await;
    println!(
        "stop_after_cancel={stop:?} injections={}",
        port.calls.load(Ordering::SeqCst)
    );
    assert!(
        matches!(stop, Ok(Ok(()))),
        "cancelled read-only query leaked an in-flight slot and made Stop time out"
    );
}

#[tokio::test]
async fn r07_unknown_reason_must_be_redacted_in_receipt_and_reconciliation() {
    let port = Arc::new(Platform::new(false, false, false, true));
    let (h, t) = setup(port).await;
    let receipt = act(&h, t, "unknown").await;
    let later = h.acquire_acting().await;
    assert!(
        !format!("{receipt:?} {later:?}").contains(CANARY),
        "raw adapter Unknown prose leaked through receipt and ReconciliationRequired"
    );
}

#[tokio::test]
async fn r08_second_registry_must_not_create_a_parallel_os_session_owner() {
    let port = Arc::new(Platform::new(false, true, false, false));
    let (a, ta) = setup(port.clone()).await;
    let b = NativeSessionRegistry::new()
        .get_or_create(a.session_id().clone(), "owner-a", port.clone())
        .await
        .unwrap();
    assert_eq!(
        b.acquire_acting().await,
        Err(NativeControlError::SessionBusy)
    );
    let tb = ta.clone();
    let first = tokio::spawn(async move { act(&a, ta, "registry-one").await });
    wait_started(&port.injection_started).await;
    let second = tokio::spawn(async move { act(&b, tb, "registry-two").await });
    let _ = tokio::time::timeout(
        StdDuration::from_millis(100),
        port.injection_started.acquire(),
    )
    .await;
    port.injection_gate.add_permits(2);
    let _ = first.await;
    let _ = second.await;
    println!(
        "two_registry_injection_peak={}",
        port.peak.load(Ordering::SeqCst)
    );
    assert_eq!(
        port.peak.load(Ordering::SeqCst),
        1,
        "two registry instances independently authorized the same OS session"
    );
}

struct Sink {
    block: bool,
    fail_call: usize,
    started: Semaphore,
    gate: Semaphore,
    calls: AtomicUsize,
    bytes: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    finishes: AtomicUsize,
}
impl Sink {
    fn new(block: bool, fail_call: usize) -> Self {
        Self {
            block,
            fail_call,
            started: Semaphore::new(0),
            gate: Semaphore::new(0),
            calls: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl PixelSinkPort for Sink {
    fn with_current_egress(
        &self,
        _: &PixelConsent,
        _: &PixelFrame,
        _: &EgressContext<'_>,
        effect: &mut dyn FnMut() -> Result<(), SinkError>,
    ) -> Result<(), SinkError> {
        effect()
    }

    async fn deliver_chunk(
        &self,
        chunk: &[u8],
        dispatch_gate: &PixelDeliveryGate<'_>,
    ) -> Result<(), SinkError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_call {
            return Err(SinkError(
                "test-only failed before accepting this chunk".into(),
            ));
        }
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.started.add_permits(1);
        if self.block {
            self.gate.acquire().await.unwrap().forget();
        }
        dispatch_gate.dispatch(|| {
            self.bytes.fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
    async fn finish(&self, dispatch_gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        dispatch_gate.dispatch(|| {
            self.finishes.fetch_add(1, Ordering::SeqCst);
        })?;
        Ok(())
    }
}
fn grant(now: OffsetDateTime, lifetime: Duration) -> PixelConsent {
    PixelConsentGrant {
        consent_id: "test-consent".into(),
        actor: ActorId::new("test-actor"),
        auth_generation: AuthGeneration::new(1),
        os_session: OsSessionId::new("test-session"),
        target_handle: NativeTargetHandle::new("test-target"),
        region: PixelRegion::new(0, 0, 1, 1),
        run_id: RunId::new("test-run"),
        receiver: ModelReceiver::new(
            "test-connection",
            "test-model",
            1,
            "test-account",
            "https://receiver.invalid",
        ),
        consent_epoch: ConsentEpoch::new(1),
        granted_at: now,
        expires_at: now + lifetime,
    }
    .issue()
    .unwrap()
}
async fn send(
    c: &PixelEgressCoordinator,
    consent: &PixelConsent,
    bytes: usize,
    now: OffsetDateTime,
) -> Result<EgressReceipt, PixelEgressError> {
    let actor = ActorId::new("test-actor");
    let session = OsSessionId::new("test-session");
    let region = consent.region();
    let ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: consent.target_handle(),
        requested_region: &region,
        run_id: consent.run_id(),
        receiver: consent.receiver(),
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: false,
            pixel_consent_granted: true,
        },
        now,
    };
    let frame = PixelFrame {
        origin: None,
        width: 1,
        height: 1,
        data: vec![0x31; bytes],
        classification: ScreenSecurityClassification::Normal,
    };
    c.send_frame(consent, &observed_frame(&frame, &ctx), &ctx)
        .await
}

#[tokio::test]
async fn positive_pixel_success_and_revoke_before_send() {
    let sink = Arc::new(Sink::new(false, 0));
    let c = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, Duration::minutes(1));
    assert_eq!(send(&c, &consent, 4, now).await.unwrap().bytes_delivered, 4);
    c.revoke().await;
    assert!(
        send(&c, &consent, 4, now + Duration::seconds(1))
            .await
            .is_err()
    );
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn r09_consent_expiry_during_first_chunk_must_prevent_subsequent_chunk() {
    let sink = Arc::new(Sink::new(true, 0));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, Duration::milliseconds(100));
    let expiry = consent.expires_at();
    let job = {
        let c = c.clone();
        tokio::spawn(async move { send(&c, &consent, STREAM_CHUNK_SIZE + 1, now).await })
    };
    wait_started(&sink.started).await;
    while OffsetDateTime::now_utc() < expiry {
        tokio::time::sleep(StdDuration::from_millis(20)).await;
    }
    sink.gate.add_permits(2);
    let result = job.await.unwrap();
    println!(
        "result={result:?} chunk_calls={} delivered={}",
        sink.calls.load(Ordering::SeqCst),
        sink.bytes.load(Ordering::SeqCst)
    );
    assert_eq!(
        sink.calls.load(Ordering::SeqCst),
        1,
        "expired consent permitted a new second chunk after the first returned"
    );
}

#[tokio::test]
async fn r10_concurrent_frames_must_not_overlap_on_the_same_sink() {
    let sink = Arc::new(Sink::new(true, 0));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, Duration::minutes(1));
    let first = {
        let c = c.clone();
        let grant = consent.clone();
        tokio::spawn(async move { send(&c, &grant, 4, now).await })
    };
    wait_started(&sink.started).await;
    tokio::time::sleep(StdDuration::from_millis(250)).await;
    let second = {
        let c = c.clone();
        tokio::spawn(async move { send(&c, &consent, 4, OffsetDateTime::now_utc()).await })
    };
    let _ = tokio::time::timeout(StdDuration::from_millis(100), sink.started.acquire()).await;
    sink.gate.add_permits(2);
    let _ = first.await;
    let _ = second.await;
    println!(
        "sink_parallel_delivery_peak={}",
        sink.peak.load(Ordering::SeqCst)
    );
    assert_eq!(
        sink.peak.load(Ordering::SeqCst),
        1,
        "two formal send_frame calls retained and delivered separate frames concurrently"
    );
}

#[tokio::test]
async fn r11_partial_delivery_failure_must_be_distinguishable_from_zero_bytes() {
    let zero = Arc::new(Sink::new(false, 1));
    let partial = Arc::new(Sink::new(false, 2));
    let a = PixelEgressCoordinator::new(zero.clone());
    let b = PixelEgressCoordinator::new(partial.clone());
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, Duration::minutes(1));
    let z = send(&a, &consent, STREAM_CHUNK_SIZE + 1, now).await;
    let p = send(&b, &consent, STREAM_CHUNK_SIZE + 1, now).await;
    assert_eq!(zero.bytes.load(Ordering::SeqCst), 0);
    assert_eq!(partial.bytes.load(Ordering::SeqCst), STREAM_CHUNK_SIZE);
    println!(
        "zero={z:?} partial={p:?} actual_partial_bytes={}",
        partial.bytes.load(Ordering::SeqCst)
    );
    assert_ne!(
        z, p,
        "zero-byte failure and a 65536-byte confirmed prefix have identical public outcomes; no progress receipt is retained"
    );
}

fn fresh_session_id() -> usize {
    static ID: AtomicUsize = AtomicUsize::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}

fn observed_frame(frame: &PixelFrame, ctx: &EgressContext<'_>) -> PixelFrame {
    let mut frame = frame.clone();
    frame.origin = Some(PixelFrameOrigin {
        capture_id: "synthetic-capture".into(),
        session: ctx.session.clone(),
        target: ctx.target.clone(),
        region: *ctx.requested_region,
        observation: ObservationGeneration::new(1),
        captured_at: OffsetDateTime::now_utc(),
    });
    frame
}
