//! GK-08 native lifecycle faults. Synthetic ports only; no OS input, Keychain or user apps.
//!
//! Existing coverage (native_control / primary / rework / controller): missing authority,
//! revoke-while-await, recycled PID, Stop cleanup failure, same-handle mutex, query budget,
//! cancelled unsent query, parallel registry owner, clean restart rejecting old handles.
//!
//! This file adds: dual gate re-entry (N1), two in-flight stages + Stop (N2), and dirty/clean
//! session interleaving plus capacity that must not evict obligations (N3).

use async_trait::async_trait;
use openbot_computer::native::{
    ActionCapability, BootId, CoordinateTransform, LogicalRect, MouseButton, NativeAction,
    NativeActionGate, NativeCleanupGate, NativeControlError, NativeDisplayId,
    NativeInjectionOutcome, NativeKey, NativePlatformError, NativePlatformPort, NativeReceipt,
    NativeSessionEpoch, NativeSessionHandle, NativeSessionRegistry, NativeSessionState,
    NativeTarget, NativeTargetHandle, NativeWindowId, ObservationGeneration, OsSessionId,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

fn next_session() -> OsSessionId {
    static ID: AtomicU64 = AtomicU64::new(1);
    OsSessionId::new(format!("gk08-native-{}", ID.fetch_add(1, Ordering::SeqCst)))
}

struct Port {
    query_block: bool,
    pre_dispatch_block: bool,
    double_action_dispatch: bool,
    reenter_action_effect: bool,
    reenter_cleanup_effect: bool,
    double_cleanup_dispatch: bool,
    fail_release: bool,
    query_started: Semaphore,
    query_gate: Semaphore,
    pre_dispatch_started: Semaphore,
    pre_dispatch_gate: Semaphore,
    injects: AtomicUsize,
    releases: AtomicUsize,
    action_second_dispatch: Mutex<Option<Result<(), String>>>,
    cleanup_second_dispatch: Mutex<Option<Result<(), String>>>,
    last_release_pid: Mutex<Option<u32>>,
    pressed: AtomicBool,
}

impl Port {
    fn new() -> Self {
        Self {
            query_block: false,
            pre_dispatch_block: false,
            double_action_dispatch: false,
            reenter_action_effect: false,
            reenter_cleanup_effect: false,
            double_cleanup_dispatch: false,
            fail_release: false,
            query_started: Semaphore::new(0),
            query_gate: Semaphore::new(0),
            pre_dispatch_started: Semaphore::new(0),
            pre_dispatch_gate: Semaphore::new(0),
            injects: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            action_second_dispatch: Mutex::new(None),
            cleanup_second_dispatch: Mutex::new(None),
            last_release_pid: Mutex::new(None),
            pressed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl NativePlatformPort for Port {
    fn with_current_action(
        &self,
        _: &ActionCapability,
        _: &NativeTarget,
        _: &NativeAction,
        effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        let first = effect();
        if self.reenter_action_effect {
            let second = effect();
            *self.action_second_dispatch.lock().unwrap() =
                Some(second.as_ref().map(|_| ()).map_err(|e| e.0.clone()));
            first.and(second)
        } else {
            first
        }
    }

    fn with_current_cleanup(
        &self,
        _: &NativeTarget,
        effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        let first = effect();
        if self.reenter_cleanup_effect {
            let second = effect();
            *self.cleanup_second_dispatch.lock().unwrap() =
                Some(second.as_ref().map(|_| ()).map_err(|e| e.0.clone()));
            first.and(second)
        } else {
            first
        }
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
        _: &NativeTarget,
        action: &NativeAction,
        gate: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError> {
        if self.pre_dispatch_block {
            self.pre_dispatch_started.add_permits(1);
            self.pre_dispatch_gate.acquire().await.unwrap().forget();
        }
        let first = gate.dispatch(|| {
            self.injects.fetch_add(1, Ordering::SeqCst);
            if matches!(action, NativeAction::KeyDown { .. }) {
                self.pressed.store(true, Ordering::SeqCst);
            }
        });
        if self.double_action_dispatch {
            let second = gate.dispatch(|| {
                self.injects.fetch_add(1, Ordering::SeqCst);
            });
            *self.action_second_dispatch.lock().unwrap() =
                Some(second.as_ref().map(|_| ()).map_err(|e| e.0.clone()));
        }
        first?;
        Ok(NativeInjectionOutcome::Success)
    }

    async fn release_inputs(
        &self,
        target: &NativeTarget,
        _: &[NativeKey],
        _: &[MouseButton],
        gate: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError> {
        if self.fail_release {
            return Err(NativePlatformError("synthetic_cleanup_refused".into()));
        }
        let first = gate.dispatch(|| {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.pressed.store(false, Ordering::SeqCst);
            *self.last_release_pid.lock().unwrap() = Some(target.pid());
        });
        if self.double_cleanup_dispatch {
            let second = gate.dispatch(|| {
                self.releases.fetch_add(1, Ordering::SeqCst);
            });
            *self.cleanup_second_dispatch.lock().unwrap() =
                Some(second.as_ref().map(|_| ()).map_err(|e| e.0.clone()));
        }
        first
    }
}

fn target(session: &OsSessionId, pid: u32) -> NativeTarget {
    NativeTarget::from_trusted_host(
        "gk08-install",
        "gk08-user",
        session.clone(),
        BootId::new("gk08-boot"),
        pid,
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(100),
        NativeWindowId::new(format!("window-{pid}")),
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

fn capability(id: &str, handle: NativeTargetHandle) -> ActionCapability {
    ActionCapability::new(
        CapabilityId::new(id),
        ActorId::new("gk08-actor"),
        RunId::new("gk08-run"),
        PolicyDecisionId::new("gk08-decision"),
        handle,
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    )
    .with_action(NativeAction::KeyDown {
        key: NativeKey::Space,
    })
}

async fn setup(port: Arc<Port>, pid: u32) -> (NativeSessionHandle, NativeTargetHandle) {
    let registry = NativeSessionRegistry::new();
    let session = next_session();
    let handle = registry
        .get_or_create(session.clone(), "gk08-owner", port)
        .await
        .unwrap();
    handle.acquire_acting().await.unwrap();
    let target = handle.register_target(target(&session, pid)).await;
    (handle, target)
}

async fn act(
    handle: &NativeSessionHandle,
    target: NativeTargetHandle,
    id: &str,
) -> Result<NativeReceipt, NativeControlError> {
    let now = OffsetDateTime::now_utc();
    handle
        .perform_action(
            capability(id, target),
            NativeAction::KeyDown {
                key: NativeKey::Space,
            },
            now,
            now,
        )
        .await
}

async fn wait_permit(semaphore: &Semaphore) {
    tokio::time::timeout(StdDuration::from_secs(2), semaphore.acquire())
        .await
        .expect("started")
        .expect("permit")
        .forget();
}

fn is_confirmed(result: &Result<NativeReceipt, NativeControlError>) -> bool {
    matches!(
        result,
        Ok(r) if matches!(r.status(), openbot_computer::native::NativeActionStatus::Confirmed)
    )
}

#[tokio::test]
async fn n1_single_dispatch_confirms_one_inject_and_stop_releases_once() {
    let port = Arc::new(Port::new());
    let (handle, t) = setup(port.clone(), 11).await;
    let receipt = act(&handle, t, "n1-ok").await.unwrap();
    assert!(matches!(
        receipt.status(),
        openbot_computer::native::NativeActionStatus::Confirmed
    ));
    assert_eq!(port.injects.load(Ordering::SeqCst), 1);
    handle.stop().await.unwrap();
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
    assert!(!port.pressed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn n1_second_action_dispatch_is_rejected_without_double_inject() {
    let mut port = Port::new();
    port.double_action_dispatch = true;
    let port = Arc::new(port);
    let (handle, t) = setup(port.clone(), 12).await;
    let result = act(&handle, t, "n1-double").await;
    let second = port.action_second_dispatch.lock().unwrap().clone();
    assert_eq!(
        port.injects.load(Ordering::SeqCst),
        1,
        "second dispatch injected"
    );
    assert!(
        matches!(second, Some(Err(ref code)) if code.contains("dispatch_already_used")),
        "second={second:?}"
    );
    assert!(
        is_confirmed(&result),
        "first dispatch should still confirm, got {result:?}"
    );
    handle.stop().await.unwrap();
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn n1_with_current_action_reentry_does_not_drop_cleanup_obligation() {
    let mut port = Port::new();
    port.reenter_action_effect = true;
    let port = Arc::new(port);
    let (handle, t) = setup(port.clone(), 13).await;
    let result = act(&handle, t, "n1-reenter").await;
    assert_eq!(port.injects.load(Ordering::SeqCst), 1);
    let second = port.action_second_dispatch.lock().unwrap().clone();
    assert!(matches!(second, Some(Err(_))), "reentry second={second:?}");
    assert!(
        !is_confirmed(&result),
        "reentry must not report Confirmed after authority callback failed, got {result:?}"
    );
    let stop = handle.stop().await;
    assert!(
        stop.is_err() || port.releases.load(Ordering::SeqCst) == 1,
        "obligation lost: stop={stop:?} releases={}",
        port.releases.load(Ordering::SeqCst)
    );
    assert_ne!(
        port.releases.load(Ordering::SeqCst),
        2,
        "cleanup dispatched twice"
    );
}

#[tokio::test]
async fn n1_cleanup_gate_rejects_second_dispatch_without_double_release() {
    let mut port = Port::new();
    port.double_cleanup_dispatch = true;
    let port = Arc::new(port);
    let (handle, t) = setup(port.clone(), 14).await;
    act(&handle, t, "n1-cleanup").await.unwrap();
    let stop = handle.stop().await;
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
    let second = port.cleanup_second_dispatch.lock().unwrap().clone();
    assert!(
        matches!(second, Some(Err(ref code)) if code.contains("cleanup_already_used")),
        "second={second:?} stop={stop:?}"
    );
}

#[tokio::test]
async fn n2_querying_and_unstarted_requests_stop_without_success_or_inject() {
    let mut port = Port::new();
    port.query_block = true;
    let port = Arc::new(port);
    let (handle, t) = setup(port.clone(), 21).await;
    let first = {
        let handle = handle.clone();
        let t = t.clone();
        tokio::spawn(async move { act(&handle, t, "n2-query").await })
    };
    wait_permit(&port.query_started).await;
    let second = {
        let handle = handle.clone();
        let t = t.clone();
        tokio::spawn(async move { act(&handle, t, "n2-queued").await })
    };
    let start = tokio::time::Instant::now();
    while handle.pending_actions() < 2 && start.elapsed() < StdDuration::from_secs(2) {
        tokio::task::yield_now().await;
    }
    assert_eq!(handle.pending_actions(), 2);
    let stop = handle.stop().await;
    port.query_gate.add_permits(4);
    let a = tokio::time::timeout(StdDuration::from_secs(7), first)
        .await
        .expect("first terminates")
        .unwrap();
    let b = tokio::time::timeout(StdDuration::from_secs(7), second)
        .await
        .expect("second terminates")
        .unwrap();
    assert_eq!(handle.pending_actions(), 0);
    assert_eq!(port.injects.load(Ordering::SeqCst), 0);
    assert!(!is_confirmed(&a), "querying request became success {a:?}");
    assert!(!is_confirmed(&b), "queued request became success {b:?}");
    assert!(
        a.is_err() && b.is_err(),
        "Unknown must not be rewritten as Ok: {a:?} {b:?}"
    );
    assert!(stop.is_ok(), "no inject so Stop should be clean: {stop:?}");
}

#[tokio::test]
async fn n2_pre_effect_and_queued_requests_are_accounted_separately() {
    let mut port = Port::new();
    port.pre_dispatch_block = true;
    let port = Arc::new(port);
    let (handle, t) = setup(port.clone(), 22).await;
    let first = {
        let handle = handle.clone();
        let t = t.clone();
        tokio::spawn(async move { act(&handle, t, "n2-pre").await })
    };
    wait_permit(&port.pre_dispatch_started).await;
    let second = {
        let handle = handle.clone();
        let t = t.clone();
        tokio::spawn(async move { act(&handle, t, "n2-pre-queued").await })
    };
    let start = tokio::time::Instant::now();
    while handle.pending_actions() < 2 && start.elapsed() < StdDuration::from_secs(2) {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        handle.pending_actions(),
        2,
        "both requests must reach the intended fault point"
    );
    let stop = handle.stop().await;
    port.pre_dispatch_gate.add_permits(4);
    let a = tokio::time::timeout(StdDuration::from_secs(7), first)
        .await
        .expect("first terminates")
        .unwrap();
    let b = tokio::time::timeout(StdDuration::from_secs(7), second)
        .await
        .expect("second terminates")
        .unwrap();
    assert_eq!(handle.pending_actions(), 0);
    assert_eq!(port.injects.load(Ordering::SeqCst), 0);
    assert!(!is_confirmed(&a), "pre-effect request succeeded {a:?}");
    assert!(!is_confirmed(&b), "queued request succeeded {b:?}");
    assert!(a.is_err() && b.is_err());
    assert!(stop.is_ok(), "stop={stop:?}");
}

#[tokio::test]
async fn n3_dirty_session_stop_does_not_release_another_session_keys() {
    let dirty = Arc::new({
        let mut p = Port::new();
        p.fail_release = true;
        p
    });
    let clean = Arc::new(Port::new());
    let registry = NativeSessionRegistry::new();
    let session_a = next_session();
    let session_b = next_session();
    let a = registry
        .get_or_create(session_a.clone(), "owner-a", dirty.clone())
        .await
        .unwrap();
    let b = registry
        .get_or_create(session_b.clone(), "owner-b", clean.clone())
        .await
        .unwrap();
    a.acquire_acting().await.unwrap();
    b.acquire_acting().await.unwrap();
    let ta = a.register_target(target(&session_a, 31)).await;
    let tb = b.register_target(target(&session_b, 32)).await;
    act(&a, ta, "n3-a").await.unwrap();
    act(&b, tb, "n3-b").await.unwrap();
    assert!(a.stop().await.is_err());
    assert_eq!(dirty.releases.load(Ordering::SeqCst), 0);
    b.stop().await.unwrap();
    assert_eq!(clean.releases.load(Ordering::SeqCst), 1);
    assert_eq!(*clean.last_release_pid.lock().unwrap(), Some(32));
    assert_eq!(dirty.injects.load(Ordering::SeqCst), 1);
    assert_eq!(clean.injects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn n3_old_handle_cannot_act_after_clean_stop_new_lifecycle() {
    let port = Arc::new(Port::new());
    let registry = NativeSessionRegistry::new();
    let session = next_session();
    let first = registry
        .get_or_create(session.clone(), "owner-1", port.clone())
        .await
        .unwrap();
    first.acquire_acting().await.unwrap();
    let t = first.register_target(target(&session, 41)).await;
    act(&first, t.clone(), "n3-old").await.unwrap();
    first.stop().await.unwrap();
    let replay = act(&first, t.clone(), "n3-replay").await;
    assert!(replay.is_err(), "old handle acted after Stop: {replay:?}");
    let overlapping = registry
        .get_or_create(session.clone(), "owner-1", port.clone())
        .await
        .unwrap();
    assert!(
        overlapping.acquire_acting().await.is_err(),
        "a second handle must not start a new lifecycle while the stopped handle still occupies the session"
    );
    drop(first);
    drop(overlapping);
    let restarted = registry
        .get_or_create(session, "owner-1", port.clone())
        .await
        .unwrap();
    restarted.acquire_acting().await.unwrap();
    let t2 = restarted
        .register_target(target(restarted.session_id(), 41))
        .await;
    assert_ne!(t2, t);
    assert!(act(&restarted, t, "n3-stale-target").await.is_err());
    act(&restarted, t2, "n3-new").await.unwrap();
    restarted.stop().await.unwrap();
}

#[tokio::test]
async fn n3_capacity_retains_dirty_session_instead_of_evicting_obligation() {
    let dirty_port = Arc::new({
        let mut p = Port::new();
        p.fail_release = true;
        p
    });
    let registry = NativeSessionRegistry::new();
    let dirty_session = next_session();
    let dirty = registry
        .get_or_create(dirty_session.clone(), "dirty-owner", dirty_port.clone())
        .await
        .unwrap();
    dirty.acquire_acting().await.unwrap();
    let t = dirty.register_target(target(&dirty_session, 51)).await;
    act(&dirty, t, "n3-dirty").await.unwrap();
    assert!(dirty.stop().await.is_err());
    drop(dirty);

    let mut held = Vec::new();
    let mut saw_full = false;
    for i in 0..80 {
        let port = Arc::new(Port::new());
        match registry
            .get_or_create(next_session(), format!("cap-{i}"), port)
            .await
        {
            Ok(handle) => held.push(handle),
            Err(NativeControlError::BoundedQueueFull) => {
                saw_full = true;
                break;
            }
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert!(saw_full, "never hit registry capacity");
    let same = NativeSessionRegistry::new()
        .get_or_create(dirty_session, "dirty-owner", dirty_port.clone())
        .await;
    assert!(
        same.is_ok(),
        "dirty session was evicted under capacity pressure"
    );
    let same = same.unwrap();
    assert!(
        same.acquire_acting().await.is_err(),
        "retained dirty lifecycle must still block acting"
    );
    assert_eq!(dirty_port.injects.load(Ordering::SeqCst), 1);
    assert_eq!(dirty_port.releases.load(Ordering::SeqCst), 0);
    drop(held);
}

#[tokio::test]
async fn controller_cleanup_authority_callback_reentry_preserves_unknown() {
    let mut p = Port::new();
    p.reenter_cleanup_effect = true;
    let port = Arc::new(p);
    let (handle, target) = setup(port.clone(), 61).await;
    act(&handle, target, "cleanup-authority-reentry")
        .await
        .unwrap();
    assert!(handle.stop().await.is_err());
    assert_eq!(port.releases.load(Ordering::SeqCst), 1);
    assert!(matches!(
        *port.cleanup_second_dispatch.lock().unwrap(),
        Some(Err(_))
    ));
    assert!(handle.acquire_acting().await.is_err());
}
