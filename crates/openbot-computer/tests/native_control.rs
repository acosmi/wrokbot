//! Integration tests for native computer control coordination (v5 §10.7 / PA-04 / V5-NATIVE-01).
use openbot_computer::native::{NativeActionGate, NativeCleanupGate};

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use openbot_computer::native::{
    ActionCapability, BootId, CoordinateTransform, LogicalRect, MouseButton, NativeAction,
    NativeActionCategory, NativeActionStatus, NativeControlError, NativeDisplayId,
    NativeInjectionOutcome, NativeKey, NativePlatformError, NativePlatformPort, NativeSessionEpoch,
    NativeSessionRegistry, NativeSessionState, NativeTarget, NativeWindowId, ObservationGeneration,
    OsSessionId,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

#[derive(Default)]
struct TestPlatformPort {
    inject_count: AtomicUsize,
    release_count: AtomicUsize,
    injected_actions: Mutex<Vec<NativeAction>>,
    released_keys: Mutex<Vec<NativeKey>>,
    released_buttons: Mutex<Vec<MouseButton>>,
    simulate_release_error: Mutex<Option<String>>,
}

#[async_trait]
impl NativePlatformPort for TestPlatformPort {
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
        if let Some(err) = self.simulate_release_error.lock().await.clone() {
            return Err(NativePlatformError(err));
        }
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

fn create_test_target(session: &OsSessionId, win: &str, obs_gen: u64) -> NativeTarget {
    NativeTarget::from_trusted_host(
        "device-install-01",
        "fushihua",
        session.clone(),
        BootId::new("boot-test-01"),
        9876,
        OffsetDateTime::UNIX_EPOCH + Duration::hours(50),
        NativeWindowId::new(win),
        NativeDisplayId::new("disp-0"),
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
async fn test_same_session_acting_exclusivity_and_independent_sessions() {
    let registry = NativeSessionRegistry::new();
    let port_a = Arc::new(TestPlatformPort::default());
    let port_b = Arc::new(TestPlatformPort::default());

    let session_1 = OsSessionId::new(format!("os-session-1-{}", fresh_session_id()));
    let session_2 = OsSessionId::new(format!("os-session-2-{}", fresh_session_id()));

    let handle_1a = registry
        .get_or_create(session_1.clone(), "bot-instance-alpha", port_a.clone())
        .await
        .unwrap();
    let handle_1b = registry
        .get_or_create(session_1.clone(), "bot-instance-beta", port_a.clone())
        .await
        .unwrap();
    let handle_2 = registry
        .get_or_create(session_2.clone(), "bot-instance-gamma", port_b.clone())
        .await
        .unwrap();

    // Instance Alpha acquires acting in session 1
    handle_1a
        .acquire_acting()
        .await
        .expect("alpha acquires acting");

    // Instance Beta attempts to acquire in same session 1 -> must fail with SessionBusy
    let conflict = handle_1b.acquire_acting().await;
    assert_eq!(conflict, Err(NativeControlError::SessionBusy));

    // Instance Gamma in independent session 2 succeeds without interference
    handle_2
        .acquire_acting()
        .await
        .expect("gamma acquires acting in session 2");

    // Alpha stops: session 1 epoch advances and acting owner clears
    handle_1a.stop().await.expect("alpha stops");

    // Session 2 is completely unaffected
    assert_eq!(handle_2.current_epoch().await, NativeSessionEpoch::new(1));
}

#[tokio::test]
async fn test_full_injection_receipt_and_redaction() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(TestPlatformPort::default());
    let session = OsSessionId::new(format!("os-session-receipt-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-executor", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = create_test_target(&session, "win-primary", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    let cap = ActionCapability::new(
        CapabilityId::new("cap-text-insert"),
        ActorId::new("actor-test"),
        RunId::new("run-test"),
        PolicyDecisionId::new("decision-1"),
        target_handle.clone(),
        ObservationGeneration::new(1),
        AuthGeneration::new(1),
        NativeSessionEpoch::new(1),
    );

    let secret_text = "super_secret_password_123".to_string();
    let action = NativeAction::InsertText {
        text: secret_text.clone(),
    };
    assert_eq!(action.category(), NativeActionCategory::Text);

    // Verify debug representation does NOT leak the text
    let debug_repr = format!("{:?}", action);
    assert!(!debug_repr.contains(&secret_text));
    assert!(debug_repr.contains("[REDACTED_TEXT]"));

    let receipt = handle
        .perform_action((cap).with_action((action).clone()), action, now, now)
        .await
        .expect("perform action");

    assert_eq!(receipt.operation_id(), "op-cap-text-insert");
    assert_eq!(receipt.target_handle(), &target_handle);
    assert_eq!(receipt.category(), NativeActionCategory::Text);
    assert_eq!(receipt.status(), &NativeActionStatus::Confirmed);
    assert_eq!(receipt.epoch(), NativeSessionEpoch::new(1));

    // Receipt Debug format must also not leak text
    let receipt_debug = format!("{:?}", receipt);
    assert!(!receipt_debug.contains(&secret_text));
}

#[tokio::test]
async fn test_scoped_stop_cleanup_releases_only_injected_inputs() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(TestPlatformPort::default());
    let session = OsSessionId::new(format!("os-session-scoped-cleanup-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-keys", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = create_test_target(&session, "win-editor", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    // 1. Inject KeyDown Return
    let cap1 = ActionCapability::new(
        CapabilityId::new("cap-ret"),
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
        .expect("perform keydown return");

    // 2. Inject KeyDown Tab
    let cap2 = ActionCapability::new(
        CapabilityId::new("cap-tab"),
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
                (NativeAction::KeyDown {
                    key: NativeKey::Tab,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Tab,
            },
            now,
            now,
        )
        .await
        .expect("perform keydown tab");

    // 3. Inject KeyUp Tab (Tab is no longer pressed)
    let cap3 = ActionCapability::new(
        CapabilityId::new("cap-tab-up"),
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
            (cap3).with_action(
                (NativeAction::KeyUp {
                    key: NativeKey::Tab,
                })
                .clone(),
            ),
            NativeAction::KeyUp {
                key: NativeKey::Tab,
            },
            now,
            now,
        )
        .await
        .expect("perform keyup tab");

    // 4. Inject MouseDown Middle
    let cap4 = ActionCapability::new(
        CapabilityId::new("cap-mmb"),
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
            (cap4).with_action(
                (NativeAction::MouseDown {
                    button: MouseButton::Middle,
                    x: 200.0,
                    y: 300.0,
                })
                .clone(),
            ),
            NativeAction::MouseDown {
                button: MouseButton::Middle,
                x: 200.0,
                y: 300.0,
            },
            now,
            now,
        )
        .await
        .expect("perform mousedown middle");

    // Stop session
    handle.stop().await.expect("stop session");

    // Only Return (still down) and Middle (still down) should be released; Tab was already released!
    let released_keys = port.released_keys.lock().await.clone();
    let released_buttons = port.released_buttons.lock().await.clone();

    assert_eq!(released_keys, vec![NativeKey::Return]);
    assert_eq!(released_buttons, vec![MouseButton::Middle]);
    assert_eq!(port.release_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_release_failure_retains_reconciliation_required() {
    let registry = NativeSessionRegistry::new();
    let port = Arc::new(TestPlatformPort::default());
    *port.simulate_release_error.lock().await = Some("os_io_failure_during_release".to_string());

    let session = OsSessionId::new(format!("os-session-reconcile-{}", fresh_session_id()));
    let handle = registry
        .get_or_create(session.clone(), "bot-reconcile", port.clone())
        .await
        .unwrap();
    handle.acquire_acting().await.expect("acquire acting");

    let target = create_test_target(&session, "win-reconcile", 1);
    let target_handle = handle.register_target(target).await;
    let now = OffsetDateTime::now_utc();

    let cap = ActionCapability::new(
        CapabilityId::new("cap-down"),
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
            (cap).with_action(
                (NativeAction::KeyDown {
                    key: NativeKey::Escape,
                })
                .clone(),
            ),
            NativeAction::KeyDown {
                key: NativeKey::Escape,
            },
            now,
            now,
        )
        .await
        .expect("keydown");

    // Stop will attempt release, which fails and returns error per AR-01/RV-03
    assert!(handle.stop().await.is_err());

    // Next attempt to acquire acting must fail with ReconciliationRequired
    let acquire_err = handle.acquire_acting().await;
    assert!(matches!(
        acquire_err,
        Err(NativeControlError::ReconciliationRequired(_))
    ));
}

fn fresh_session_id() -> usize {
    static ID: AtomicUsize = AtomicUsize::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}
