//! Independent second review. Synthetic ports only: no OS input, capture, network or secrets.
use async_trait::async_trait;
use openbot_computer::native::*;
use openbot_computer::native::{NativeActionGate, NativeCleanupGate};
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
async fn s01_consumed_capability_never_becomes_replayable_at_capacity() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let a = NativeAction::MouseMove { x: 1.0, y: 1.0 };
    for i in 0..=1024 {
        let now = OffsetDateTime::now_utc();
        h.update_observation(&t, ObservationGeneration::new(1), now)
            .await
            .unwrap();
        let _ = h
            .perform_action(
                (capability(&format!("many-{i}"), t.clone()).with_action(a.clone()))
                    .with_action((a.clone()).clone()),
                a.clone(),
                now,
                now,
            )
            .await;
    }
    let now = OffsetDateTime::now_utc();
    assert!(
        h.perform_action(
            (capability("many-0", t).with_action(a.clone())).with_action((a).clone()),
            a,
            now,
            now
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn s02_abort_after_injection_retains_cleanup_obligation() {
    let port = Arc::new(Platform::new(false, true, false, false));
    let (h, t) = setup(port.clone()).await;
    let task = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "abort-after-send").await })
    };
    wait_started(&port.injection_started).await;
    task.abort();
    let _ = task.await;
    let result = h.stop().await;
    assert!(
        !port.pressed.load(Ordering::SeqCst) || result.is_err(),
        "Stop falsely succeeded after losing injected key obligation"
    );
    assert_eq!(
        port.releases.load(Ordering::SeqCst),
        1,
        "known press must be offered for checked cleanup"
    );
}
#[tokio::test]
async fn s03_same_handle_cannot_inject_concurrently() {
    let port = Arc::new(Platform::new(false, true, false, false));
    let (h, t) = setup(port.clone()).await;
    let first = {
        let h = h.clone();
        let t = t.clone();
        tokio::spawn(async move { act(&h, t, "same-one").await })
    };
    wait_started(&port.injection_started).await;
    let second = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "same-two").await })
    };
    let _ = tokio::time::timeout(
        StdDuration::from_millis(100),
        port.injection_started.acquire(),
    )
    .await;
    port.injection_gate.add_permits(2);
    let _ = first.await;
    let _ = second.await;
    assert_eq!(port.peak.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn s04_observation_expiry_during_query_prevents_effect() {
    let port = Arc::new(Platform::new(true, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let task = {
        let h = h.clone();
        tokio::spawn(async move { act(&h, t, "expired-in-query").await })
    };
    wait_started(&port.query_started).await;
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    port.query_gate.add_permits(1);
    let _ = task.await;
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn s05_human_takeover_must_report_cleanup_failure() {
    let port = Arc::new(Platform::new(false, false, true, false));
    let (h, t) = setup(port.clone()).await;
    act(&h, t, "human-cleanup").await.unwrap();
    assert!(h.notify_human_takeover().await.is_err());
}
#[tokio::test]
async fn s06_unbound_action_cannot_use_a_capability() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let now = OffsetDateTime::now_utc();
    assert!(
        h.perform_action(
            capability("unbound", t),
            NativeAction::InsertText {
                text: "synthetic".into()
            },
            now,
            now
        )
        .await
        .is_err()
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

fn fresh_session_id() -> usize {
    static ID: AtomicUsize = AtomicUsize::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}

struct AuthorityPlatform {
    inner: Arc<Platform>,
    allowed: Mutex<bool>,
    checked: bool,
}
#[async_trait]
impl NativePlatformPort for AuthorityPlatform {
    async fn query_session_state(
        &self,
        s: &OsSessionId,
    ) -> Result<NativeSessionState, NativePlatformError> {
        self.inner.query_session_state(s).await
    }
    async fn inject_action(
        &self,
        t: &NativeTarget,
        a: &NativeAction,
        g: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError> {
        self.inner.inject_action(t, a, g).await
    }
    async fn release_inputs(
        &self,
        t: &NativeTarget,
        k: &[NativeKey],
        b: &[MouseButton],
        g: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError> {
        self.inner.release_inputs(t, k, b, g).await
    }
    fn with_current_action(
        &self,
        c: &ActionCapability,
        _: &NativeTarget,
        _: &NativeAction,
        e: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        let allowed = self.allowed.lock().unwrap();
        if !self.checked
            || !*allowed
            || c.actor().as_str() != "test-actor"
            || c.run_id().as_str() != "test-run"
            || c.auth_generation() != AuthGeneration::new(1)
            || c.decision_id().as_str() != "test-durable-decision"
        {
            return Err(NativePlatformError(
                "synthetic_current_authority_refused".into(),
            ));
        }
        e()
    }
    fn with_current_cleanup(
        &self,
        _: &NativeTarget,
        e: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        e()
    }
}
#[tokio::test]
async fn s07_missing_current_authority_never_dispatches() {
    let inner = Arc::new(Platform::new(false, false, false, false));
    let port = Arc::new(AuthorityPlatform {
        inner: inner.clone(),
        allowed: Mutex::new(true),
        checked: false,
    });
    let session = OsSessionId::new(format!("authority-missing-{}", fresh_session_id()));
    let h = NativeSessionRegistry::new()
        .get_or_create(session.clone(), "owner-a", port)
        .await
        .unwrap();
    h.acquire_acting().await.unwrap();
    let t = h.register_target(target(&session, 100)).await;
    assert!(act(&h, t, "without-authority").await.is_err());
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn s08_current_authority_revoked_while_querying_sends_zero() {
    let inner = Arc::new(Platform::new(true, false, false, false));
    let port = Arc::new(AuthorityPlatform {
        inner: inner.clone(),
        allowed: Mutex::new(true),
        checked: true,
    });
    let session = OsSessionId::new(format!("authority-revoked-{}", fresh_session_id()));
    let h = NativeSessionRegistry::new()
        .get_or_create(session.clone(), "owner-a", port.clone())
        .await
        .unwrap();
    h.acquire_acting().await.unwrap();
    let t = h.register_target(target(&session, 100)).await;
    let job = tokio::spawn(async move { act(&h, t, "current-authority").await });
    wait_started(&inner.query_started).await;
    *port.allowed.lock().unwrap() = false;
    inner.query_gate.add_permits(1);
    assert!(job.await.unwrap().is_err());
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn s09_dropping_all_handles_does_not_erase_pressed_inputs() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let session = h.session_id().clone();
    act(&h, t, "dropped-owner").await.unwrap();
    drop(h);
    let next = NativeSessionRegistry::new()
        .get_or_create(session, "owner-b", port.clone())
        .await
        .unwrap();
    assert!(next.acquire_acting().await.is_err());
    next.stop().await.unwrap();
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
    assert!(!port.pressed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn s10_clean_stopped_lifecycle_can_restart_without_accepting_old_handles() {
    let port = Arc::new(Platform::new(false, false, false, false));
    let (h, t) = setup(port.clone()).await;
    let session = h.session_id().clone();
    h.stop().await.unwrap();
    drop(h);
    let next = NativeSessionRegistry::new()
        .get_or_create(session.clone(), "owner-next", port.clone())
        .await
        .unwrap();
    next.acquire_acting().await.unwrap();
    let new_target = next.register_target(target(&session, 100)).await;
    assert_ne!(new_target, t);
    assert!(act(&next, t, "old-lifecycle-handle").await.is_err());
    act(&next, new_target, "new-lifecycle-action")
        .await
        .unwrap();
    next.stop().await.unwrap();
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
}
