//! Independent controller regressions against the frozen AG-03/04 candidate.
//! Only synthetic ports and bytes; no OS input, screen capture, network, or secrets.
use openbot_computer::native::{NativeActionGate, NativeCleanupGate};
use openbot_computer::native::{ObservationGeneration, PixelDeliveryGate, PixelFrameOrigin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use openbot_computer::native::*;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

struct Platform {
    started: Semaphore,
    gate: Semaphore,
    block: bool,
    locked: bool,
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    releases: AtomicUsize,
    queries: AtomicUsize,
    pressed: AtomicBool,
}

impl Platform {
    fn new(block: bool, locked: bool) -> Self {
        Self {
            started: Semaphore::new(0),
            gate: Semaphore::new(0),
            block,
            locked,
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            pressed: AtomicBool::new(false),
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

    async fn inject_action(
        &self,
        _: &NativeTarget,
        action: &NativeAction,
        dispatch_gate: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError> {
        dispatch_gate.dispatch(|| {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            if matches!(action, NativeAction::KeyDown { .. }) {
                self.pressed.store(true, Ordering::SeqCst);
            }
            self.started.add_permits(1);
        })?;
        if self.block {
            self.gate.acquire().await.unwrap().forget();
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(NativeInjectionOutcome::Success)
    }
    async fn release_inputs(
        &self,
        _: &NativeTarget,
        _: &[NativeKey],
        _: &[MouseButton],
        dispatch_gate: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError> {
        dispatch_gate.dispatch(|| {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.pressed.store(false, Ordering::SeqCst);
        })?;
        Ok(())
    }
    async fn query_session_state(
        &self,
        _: &OsSessionId,
    ) -> Result<NativeSessionState, NativePlatformError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        Ok(if self.locked {
            NativeSessionState::Locked
        } else {
            NativeSessionState::Active
        })
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
async fn setup(
    port: Arc<Platform>,
) -> (
    NativeSessionRegistry,
    NativeSessionHandle,
    NativeTargetHandle,
) {
    let registry = NativeSessionRegistry::new();
    let session = OsSessionId::new(format!("test-session-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "owner-a", port)
        .await
        .unwrap();
    handle.acquire_acting().await.unwrap();
    let target = handle.register_target(target(&session, 100)).await;
    (registry, handle, target)
}
fn key_down() -> NativeAction {
    NativeAction::KeyDown {
        key: NativeKey::Space,
    }
}
async fn wait_started(semaphore: &Semaphore) {
    tokio::time::timeout(StdDuration::from_secs(2), semaphore.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}

#[tokio::test]
async fn positive_native_normal_action_and_confirmed_cleanup() {
    let port = Arc::new(Platform::new(false, false));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    handle
        .perform_action(
            (capability("positive", target)).with_action((key_down()).clone()),
            key_down(),
            now,
            now,
        )
        .await
        .unwrap();
    assert!(port.pressed.load(Ordering::SeqCst));
    handle.stop().await.unwrap();
    assert!(!port.pressed.load(Ordering::SeqCst));
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn n01_recycled_process_cannot_reuse_old_target_capability() {
    let port = Arc::new(Platform::new(false, false));
    let (_, handle, old_target) = setup(port.clone()).await;
    let old_cap = capability("old-target", old_target.clone());
    let replacement = handle
        .register_target(target(handle.session_id(), 200))
        .await;
    let now = OffsetDateTime::now_utc();
    let result = handle
        .perform_action(
            (old_cap).with_action((key_down()).clone()),
            key_down(),
            now,
            now,
        )
        .await;
    println!(
        "handle_reused={} result={result:?} injections={}",
        old_target == replacement,
        port.calls.load(Ordering::SeqCst)
    );
    assert!(
        result.is_err() && port.calls.load(Ordering::SeqCst) == 0,
        "recycled PID/window accepted an old capability"
    );
}

#[tokio::test]
async fn n02_release_cannot_admit_second_owner_while_first_in_flight() {
    let port = Arc::new(Platform::new(true, false));
    let (registry, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    let first = {
        let h = handle.clone();
        let cap = capability("first", target.clone());
        tokio::spawn(async move {
            h.perform_action(
                (cap).with_action((key_down()).clone()),
                key_down(),
                now,
                now,
            )
            .await
        })
    };
    wait_started(&port.started).await;
    // A secure implementation may return Busy or wait for the pending effect to settle.
    let _ = tokio::time::timeout(StdDuration::from_millis(100), handle.release_acting()).await;
    let second = registry
        .get_or_create(handle.session_id().clone(), "owner-b", port.clone())
        .await
        .unwrap();
    let second_acquired = matches!(
        tokio::time::timeout(StdDuration::from_millis(100), second.acquire_acting()).await,
        Ok(Ok(()))
    );
    let task = if second_acquired {
        let cap = capability("second", target);
        Some(tokio::spawn(async move {
            second
                .perform_action(
                    (cap).with_action((key_down()).clone()),
                    key_down(),
                    now,
                    now,
                )
                .await
        }))
    } else {
        None
    };
    if task.is_some() {
        wait_started(&port.started).await;
    }
    let peak = port.peak.load(Ordering::SeqCst);
    port.gate.add_permits(2);
    let _ = first.await.unwrap();
    if let Some(task) = task {
        let _ = task.await.unwrap();
    }
    println!("second_acquired={second_acquired} active_injections_peak={peak}");
    assert!(
        !second_acquired && peak == 1,
        "ownership released before in-flight input/cleanup settled"
    );
}

#[tokio::test]
async fn n03_stop_cannot_report_success_while_pressed_effect_is_unconfirmed() {
    let port = Arc::new(Platform::new(true, false));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    let task = {
        let h = handle.clone();
        tokio::spawn(async move {
            h.perform_action(
                (capability("blocked", target)).with_action((key_down()).clone()),
                key_down(),
                now,
                now,
            )
            .await
        })
    };
    wait_started(&port.started).await;
    let early = tokio::time::timeout(StdDuration::from_millis(100), handle.stop()).await;
    let early_success = matches!(early, Ok(Ok(())));
    let still_pressed_at_stop = port.pressed.load(Ordering::SeqCst);
    port.gate.add_permits(1);
    let late = task.await.unwrap();
    println!(
        "stop_success={early_success} still_pressed={still_pressed_at_stop} release_calls={} late={late:?}",
        port.releases.load(Ordering::SeqCst)
    );
    assert!(
        !early_success || !still_pressed_at_stop,
        "Stop returned success before release/Unknown reconciliation"
    );
}

#[tokio::test]
async fn n04_sleep_cannot_discard_injected_state_and_reopen_acting() {
    let port = Arc::new(Platform::new(false, false));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    handle
        .perform_action(
            (capability("sleep", target)).with_action((key_down()).clone()),
            key_down(),
            now,
            now,
        )
        .await
        .unwrap();
    let change = handle
        .notify_environment_change(NativeEnvironmentChange::Sleep)
        .await;
    let reacquired = handle.acquire_acting().await.is_ok();
    let pressed = port.pressed.load(Ordering::SeqCst);
    println!(
        "event={change:?} reacquired={reacquired} pressed={pressed} releases={}",
        port.releases.load(Ordering::SeqCst)
    );
    assert!(
        !pressed || (!reacquired && change.is_err()),
        "environment change lost pending key cleanup and allowed a new owner"
    );
}

#[tokio::test]
async fn n05_locked_session_must_be_rechecked_before_injection() {
    let port = Arc::new(Platform::new(false, true));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    let result = handle
        .perform_action(
            (capability("locked", target)).with_action((key_down()).clone()),
            key_down(),
            now,
            now,
        )
        .await;
    println!(
        "result={result:?} session_queries={} injections={}",
        port.queries.load(Ordering::SeqCst),
        port.calls.load(Ordering::SeqCst)
    );
    assert!(
        result.is_err() && port.calls.load(Ordering::SeqCst) == 0,
        "locked OS session was never checked"
    );
}

#[tokio::test]
async fn n06_recorded_observation_age_cannot_be_overridden_by_call_argument() {
    let port = Arc::new(Platform::new(false, false));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    handle
        .update_observation(
            &target,
            ObservationGeneration::new(1),
            now - Duration::seconds(10),
        )
        .await
        .unwrap();
    let result = handle
        .perform_action(
            (capability("old-observation", target)).with_action((key_down()).clone()),
            key_down(),
            now,
            now,
        )
        .await;
    println!(
        "result={result:?} injections={}",
        port.calls.load(Ordering::SeqCst)
    );
    assert!(
        result.is_err() && port.calls.load(Ordering::SeqCst) == 0,
        "stored stale observation replaced by caller timestamp"
    );
}

#[tokio::test]
async fn n07_nonfinite_coordinate_rejected_before_platform() {
    let port = Arc::new(Platform::new(false, false));
    let (_, handle, target) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    let result = handle
        .perform_action(
            (capability("bad-coordinate", target)).with_action(
                (NativeAction::MouseMove {
                    x: f64::NAN,
                    y: f64::INFINITY,
                })
                .clone(),
            ),
            NativeAction::MouseMove {
                x: f64::NAN,
                y: f64::INFINITY,
            },
            now,
            now,
        )
        .await;
    assert!(
        result.is_err() && port.calls.load(Ordering::SeqCst) == 0,
        "nonfinite unbounded input was injected"
    );
}

struct Sink {
    started: Semaphore,
    gate: Semaphore,
    block: bool,
    error_after_first: bool,
    calls: AtomicUsize,
    bytes: AtomicUsize,
    finishes: AtomicUsize,
}
impl Sink {
    fn new(block: bool, error_after_first: bool) -> Self {
        Self {
            started: Semaphore::new(0),
            gate: Semaphore::new(0),
            block,
            error_after_first,
            calls: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
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
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.error_after_first && call == 1 {
            return Err(SinkError("SYNTHETIC_CANARY_NO_REAL_SECRET".into()));
        }
        dispatch_gate.dispatch(|| {
            self.bytes.fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        self.started.add_permits(1);
        if self.block {
            self.gate.acquire().await.unwrap().forget();
        }
        Ok(())
    }
    async fn finish(&self, dispatch_gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        dispatch_gate.dispatch(|| {
            self.finishes.fetch_add(1, Ordering::SeqCst);
        })?;
        Ok(())
    }
}
fn grant(now: OffsetDateTime, region: PixelRegion) -> PixelConsent {
    PixelConsentGrant {
        consent_id: "test-consent".into(),
        actor: ActorId::new("test-actor"),
        auth_generation: AuthGeneration::new(1),
        os_session: OsSessionId::new("test-session"),
        target_handle: NativeTargetHandle::new("test-target"),
        region,
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
        expires_at: now + Duration::minutes(1),
    }
    .issue()
    .unwrap()
}
async fn send(
    coordinator: &PixelEgressCoordinator,
    consent: &PixelConsent,
    frame: &PixelFrame,
    now: OffsetDateTime,
) -> Result<EgressReceipt, PixelEgressError> {
    let actor = ActorId::new("test-actor");
    let session = OsSessionId::new("test-session");
    let region = consent.region();
    let context = EgressContext {
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
    coordinator
        .send_frame(consent, &observed_frame(frame, &context), &context)
        .await
}
fn frame(width: u32, height: u32, bytes: usize) -> PixelFrame {
    PixelFrame {
        origin: None,
        width,
        height,
        data: vec![0x31; bytes],
        classification: ScreenSecurityClassification::Normal,
    }
}

#[tokio::test]
async fn positive_pixel_send_and_pre_send_revocation() {
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, PixelRegion::new(0, 0, 1, 1));
    let image = frame(1, 1, 4);
    assert_eq!(
        send(&c, &consent, &image, now)
            .await
            .unwrap()
            .bytes_delivered,
        4
    );
    c.revoke().await;
    assert!(send(&c, &consent, &image, now).await.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn n08_small_region_consent_does_not_authorize_full_frame() {
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, PixelRegion::new(0, 0, 1, 1));
    let result = send(&c, &consent, &frame(1280, 800, 4096), now).await;
    println!(
        "result={result:?} bytes={}",
        sink.bytes.load(Ordering::SeqCst)
    );
    assert!(
        result.is_err() && sink.bytes.load(Ordering::SeqCst) == 0,
        "1x1 consent allowed full-frame bytes without crop/identity binding"
    );
}

#[tokio::test]
async fn n09_revoke_during_last_chunk_must_not_finish_successfully() {
    let sink = Arc::new(Sink::new(true, false));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, PixelRegion::new(0, 0, 1, 1));
    let task = {
        let c = c.clone();
        tokio::spawn(async move { send(&c, &consent, &frame(1, 1, 1024), now).await })
    };
    wait_started(&sink.started).await;
    c.revoke().await;
    sink.gate.add_permits(1);
    let result = task.await.unwrap();
    let finished = sink.finishes.load(Ordering::SeqCst);
    println!("result={result:?} finishes_after_revoke={finished}");
    let success = matches!(
        result,
        Ok(EgressReceipt {
            status: EgressStatus::Success,
            ..
        })
    );
    assert!(
        !success && finished == 0,
        "last chunk acknowledged after revoke still finalized Success"
    );
}

#[tokio::test]
async fn n10_sink_errors_must_be_closed_and_redacted() {
    let sink = Arc::new(Sink::new(false, true));
    let c = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = grant(now, PixelRegion::new(0, 0, 1, 1));
    let result = send(&c, &consent, &frame(1, 1, STREAM_CHUNK_SIZE + 1), now).await;
    println!(
        "prefix_bytes={} result={result:?}",
        sink.bytes.load(Ordering::SeqCst)
    );
    assert!(result.is_err());
    assert!(
        !format!("{result:?}").contains("SYNTHETIC_CANARY_NO_REAL_SECRET"),
        "adapter error prose leaked through public error"
    );
}

#[test]
fn n11_region_overflow_must_reject_without_panicking() {
    let result = std::panic::catch_unwind(|| {
        PixelRegion::new(u32::MAX, 0, 1, 1).is_within(&PixelRegion::new(0, 0, 1, 1))
    });
    assert!(
        matches!(result, Ok(false)),
        "unchecked region edge arithmetic panics or accepts wrapped coordinates"
    );
}

#[test]
fn n12_key_debug_must_not_expose_character_content() {
    let debug = format!(
        "{:?}",
        NativeAction::KeyDown {
            key: NativeKey::Char('界')
        }
    );
    assert!(
        !debug.contains('界'),
        "raw key content present in Debug: {debug}"
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
