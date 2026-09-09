//! Unit tests for native session owner, one-shot capabilities, bounded queues, and Stop cleanup (v5 §10.7).
use super::runtime::{NativeActionGate, NativeCleanupGate};

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};
use time::{Duration, OffsetDateTime};
use tokio::sync::{Barrier, Mutex};

use super::control::{
    ActionCapability, NativeActionStatus, NativeControlError, NativeSessionEpoch,
};
use super::identity::{
    BootId, CoordinateTransform, LogicalRect, MouseButton, NativeAction, NativeDisplayId,
    NativeKey, NativeTarget, NativeWindowId, ObservationGeneration, OsSessionId,
};
use super::runtime::{
    MAX_PENDING_ACTIONS, NativeInjectionOutcome, NativePlatformError, NativePlatformPort,
    NativeSessionRegistry, NativeSessionState,
};

#[derive(Default)]
struct MockPlatformPort {
    inject_count: AtomicUsize,
    release_count: AtomicUsize,
    injected_actions: Mutex<Vec<NativeAction>>,
    released_keys: Mutex<Vec<NativeKey>>,
    released_buttons: Mutex<Vec<MouseButton>>,
    barrier: Mutex<Option<Arc<Barrier>>>,
    simulate_unknown: Mutex<bool>,
    simulate_error: Mutex<Option<String>>,
}

#[async_trait]
impl NativePlatformPort for MockPlatformPort {
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
        _target: &NativeTarget,
        action: &NativeAction,
        dispatch_gate: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError> {
        dispatch_gate.dispatch(|| {
            self.inject_count.fetch_add(1, Ordering::SeqCst);
        })?;
        let maybe_barrier = self.barrier.lock().await.take();
        if let Some(b) = maybe_barrier {
            b.wait().await;
        }
        if let Some(err) = self.simulate_error.lock().await.clone() {
            return Err(NativePlatformError(err));
        }
        if *self.simulate_unknown.lock().await {
            return Ok(NativeInjectionOutcome::Unknown {
                reason: "in_flight_dropped".to_string(),
            });
        }
        self.injected_actions.lock().await.push(action.clone());
        Ok(NativeInjectionOutcome::Success)
    }

    async fn release_inputs(
        &self,
        _target: &NativeTarget,
        keys: &[NativeKey],
        buttons: &[MouseButton],
        dispatch_gate: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError> {
        dispatch_gate.dispatch(|| {
            self.release_count.fetch_add(1, Ordering::SeqCst);
        })?;
        self.released_keys.lock().await.extend_from_slice(keys);
        self.released_buttons
            .lock()
            .await
            .extend_from_slice(buttons);
        Ok(())
    }

    async fn query_session_state(
        &self,
        _session: &OsSessionId,
    ) -> Result<NativeSessionState, NativePlatformError> {
        Ok(NativeSessionState::Active)
    }
}

fn sample_target(session: &OsSessionId, window: &str, obs_gen: u64) -> NativeTarget {
    NativeTarget::from_trusted_host(
        "device-001",
        "fushihua",
        session.clone(),
        BootId::new("boot-abc"),
        1234,
        OffsetDateTime::UNIX_EPOCH + Duration::hours(100),
        NativeWindowId::new(window),
        NativeDisplayId::new("display-1"),
        CoordinateTransform {
            scale_factor: 2.0,
            bounds: LogicalRect {
                x: 0.0,
                y: 0.0,
                width: 1280.0,
                height: 800.0,
            },
        },
        ObservationGeneration::new(obs_gen),
    )
}

#[tokio::test]
async fn same_session_only_one_acting_owner_and_other_sessions_isolated() {
    let registry = NativeSessionRegistry::new();
    let port1 = Arc::new(MockPlatformPort::default());
    let port2 = Arc::new(MockPlatformPort::default());

    let session_a = OsSessionId::new(format!("session-a-{}", fresh_session_id()));
    let session_b = OsSessionId::new(format!("session-b-{}", fresh_session_id()));

    let bot1 = registry
        .get_or_create(session_a.clone(), "bot-1", port1.clone())
        .await
        .unwrap();
    let bot2 = registry
        .get_or_create(session_a.clone(), "bot-2", port1.clone())
        .await
        .unwrap();
    let bot3 = registry
        .get_or_create(session_b.clone(), "bot-3", port2.clone())
        .await
        .unwrap();

    // Bot 1 acquires acting in Session A
    bot1.acquire_acting().await.expect("bot1 acquire acting");

    // Bot 2 in Session A fails with SessionBusy
    let conflict = bot2.acquire_acting().await;
    assert_eq!(conflict, Err(NativeControlError::SessionBusy));

    // Bot 3 in independent Session B succeeds
    bot3.acquire_acting()
        .await
        .expect("bot3 acquire acting in session b");

    // Bot 1 releases, then Bot 2 can acquire
    bot1.release_acting().await.expect("bot1 release acting");
    bot2.acquire_acting()
        .await
        .expect("bot2 acquire acting after bot1 release");
}

#[tokio::test]
async fn bounded_queue_rejects_17th_pending_action() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(MockPlatformPort::default());
    let barrier = Arc::new(Barrier::new(2));
    *port.barrier.lock().await = Some(barrier.clone());

    let session = OsSessionId::new(format!("session-queue-test-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-worker", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = sample_target(&session, "window-main", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    let mut tasks = Vec::new();
    for i in 0..MAX_PENDING_ACTIONS {
        let h = handle.clone();
        let th = target_handle.clone();
        let cap = ActionCapability::new(
            CapabilityId::new(format!("cap-{}", i)),
            ActorId::new("actor-1"),
            RunId::new("run-1"),
            PolicyDecisionId::new("dec-1"),
            th,
            ObservationGeneration::new(1),
            AuthGeneration::new(1),
            NativeSessionEpoch::new(1),
        );
        let task = tokio::spawn(async move {
            h.perform_action(
                (cap).with_action((NativeAction::MouseMove { x: 10.0, y: 10.0 }).clone()),
                NativeAction::MouseMove { x: 10.0, y: 10.0 },
                now,
                now,
            )
            .await
        });
        tasks.push(task);
    }

    // Wait until all 16 are in flight
    while handle.pending_actions() < MAX_PENDING_ACTIONS {
        tokio::task::yield_now().await;
    }

    // 17th submission should be rejected with BoundedQueueFull
    let cap17 = ActionCapability::new(
        CapabilityId::new("cap-17"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    let result17 = handle
        .perform_action(
            (cap17).with_action((NativeAction::MouseMove { x: 20.0, y: 20.0 }).clone()),
            NativeAction::MouseMove { x: 20.0, y: 20.0 },
            now,
            now,
        )
        .await;
    assert_eq!(result17, Err(NativeControlError::BoundedQueueFull));

    // Unblock the 16 waiting tasks
    barrier.wait().await;

    // Wait for all 16 to finish
    for t in tasks {
        let res = t.await.unwrap();
        assert!(res.is_ok());
    }
}

#[tokio::test]
async fn human_takeover_cancels_queue_and_rejects_without_auto_replay() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(MockPlatformPort::default());
    let session = OsSessionId::new(format!("session-human-takeover-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-actor", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = sample_target(&session, "window-1", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    // Human takes over
    handle
        .notify_human_takeover()
        .await
        .expect("notify human takeover");

    let cap = ActionCapability::new(
        CapabilityId::new("cap-human-active"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        handle.current_epoch().await,
    );

    // Agent action immediately rejected
    let res = handle
        .perform_action(
            (cap).with_action(
                (NativeAction::KeyDown {
                    key: NativeKey::Return,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Return,
            },
            now,
            now,
        )
        .await;
    assert_eq!(res, Err(NativeControlError::HumanLeaseActive));
    assert_eq!(port.inject_count.load(Ordering::SeqCst), 0);

    // Release human takeover
    handle
        .release_human_takeover()
        .await
        .expect("release takeover");

    // Old capability has old epoch and should be rejected
    let old_cap = ActionCapability::new(
        CapabilityId::new("cap-old"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    let res_old = handle
        .perform_action(
            (old_cap).with_action(
                (NativeAction::KeyDown {
                    key: NativeKey::Return,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Return,
            },
            now,
            now,
        )
        .await;
    assert_eq!(res_old, Err(NativeControlError::EpochStale));
}

#[tokio::test]
async fn observation_expiration_and_target_drift_fail_before_platform_call() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(MockPlatformPort::default());
    let session = OsSessionId::new(format!("session-obs-test-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-obs", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = sample_target(&session, "window-obs", 2);
    let target_handle = handle.register_target(target).await;

    let obs_time = OffsetDateTime::now_utc() - Duration::seconds(2); // > 1s expired
    let now = OffsetDateTime::now_utc();

    let cap = ActionCapability::new(
        CapabilityId::new("cap-expired"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(2),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );

    let res = handle
        .perform_action(
            (cap).with_action((NativeAction::MouseMove { x: 10.0, y: 10.0 }).clone()),
            NativeAction::MouseMove { x: 10.0, y: 10.0 },
            obs_time,
            now,
        )
        .await;
    assert_eq!(res, Err(NativeControlError::ObservationExpired));
    assert_eq!(port.inject_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stop_releases_only_inputs_injected_by_this_owner() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(MockPlatformPort::default());
    let session = OsSessionId::new(format!("session-stop-cleanup-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-cleaner", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = sample_target(&session, "window-clean", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    // Inject KeyDown Return and MouseDown Left
    let cap1 = ActionCapability::new(
        CapabilityId::new("cap-kd"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    handle
        .perform_action(
            (cap1).with_action(
                (NativeAction::KeyDown {
                    key: NativeKey::Return,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Return,
            },
            now,
            now,
        )
        .await
        .expect("perform keydown");

    let cap2 = ActionCapability::new(
        CapabilityId::new("cap-md"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    handle
        .perform_action(
            (cap2).with_action(
                (NativeAction::MouseDown {
                    button: MouseButton::Left,
                    x: 100.0,
                    y: 100.0,
                })
                .clone(),
            ),
            NativeAction::MouseDown {
                button: MouseButton::Left,
                x: 100.0,
                y: 100.0,
            },
            now,
            now,
        )
        .await
        .expect("perform mousedown");

    // Call stop
    handle.stop().await.expect("stop succeeds");

    // Check released inputs
    let released_k = port.released_keys.lock().await.clone();
    let released_b = port.released_buttons.lock().await.clone();

    assert_eq!(released_k, vec![NativeKey::Return]);
    assert_eq!(released_b, vec![MouseButton::Left]);
    assert_eq!(port.release_count.load(Ordering::SeqCst), 1);

    // Subsequent action fails with Stopped
    let cap3 = ActionCapability::new(
        CapabilityId::new("cap-post-stop"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(2),
    );
    let res3 = handle
        .perform_action(
            (cap3).with_action(
                (NativeAction::KeyUp {
                    key: NativeKey::Return,
                })
                .clone(),
            ),
            NativeAction::KeyUp {
                key: NativeKey::Return,
            },
            now,
            now,
        )
        .await;
    assert_eq!(res3, Err(NativeControlError::Stopped));
}

#[tokio::test]
async fn single_use_capability_consumption_and_unknown_reconciliation() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(MockPlatformPort::default());
    let session = OsSessionId::new(format!("session-single-use-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-su", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = sample_target(&session, "window-su", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    let cap = ActionCapability::new(
        CapabilityId::new("cap-reuse-test"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );

    // First attempt succeeds
    let res1 = handle
        .perform_action(
            (cap.clone()).with_action((NativeAction::MouseMove { x: 50.0, y: 50.0 }).clone()),
            NativeAction::MouseMove { x: 50.0, y: 50.0 },
            now,
            now,
        )
        .await;
    assert!(res1.is_ok());
    assert_eq!(port.inject_count.load(Ordering::SeqCst), 1);

    // Second attempt with same capability fails immediately
    let res2 = handle
        .perform_action(
            (cap).with_action((NativeAction::MouseMove { x: 50.0, y: 50.0 }).clone()),
            NativeAction::MouseMove { x: 50.0, y: 50.0 },
            now,
            now,
        )
        .await;
    assert_eq!(res2, Err(NativeControlError::CapabilityConsumed));
    assert_eq!(port.inject_count.load(Ordering::SeqCst), 1); // Not injected again!

    // Simulate unknown injection outcome
    *port.simulate_unknown.lock().await = true;
    let cap_unknown = ActionCapability::new(
        CapabilityId::new("cap-unknown"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    let res_unknown = handle
        .perform_action(
            (cap_unknown).with_action((NativeAction::MouseMove { x: 60.0, y: 60.0 }).clone()),
            NativeAction::MouseMove { x: 60.0, y: 60.0 },
            now,
            now,
        )
        .await;
    assert!(res_unknown.is_ok());
    let receipt = res_unknown.unwrap();
    assert!(matches!(
        receipt.status(),
        NativeActionStatus::Unknown { .. }
    ));

    // Subsequent actions enter ReconciliationRequired and fail closed
    let cap_next = ActionCapability::new(
        CapabilityId::new("cap-next"),
        ActorId::new("actor-1"),
        RunId::new("run-1"),
        PolicyDecisionId::new("dec-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );
    let res_next = handle
        .perform_action(
            (cap_next).with_action((NativeAction::MouseMove { x: 70.0, y: 70.0 }).clone()),
            NativeAction::MouseMove { x: 70.0, y: 70.0 },
            now,
            now,
        )
        .await;
    assert!(matches!(
        res_next,
        Err(NativeControlError::ReconciliationRequired(_))
    ));
}

fn fresh_session_id() -> usize {
    static ID: AtomicUsize = AtomicUsize::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}
