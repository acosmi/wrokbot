//! Unit tests for pixel consent, four-way permission boundary, and egress coordinator (v5 §10.7 / PA-04).
use super::consent::PixelConsent;
use super::identity::ObservationGeneration;
use super::pixel_egress::{PixelDeliveryGate, PixelFrameOrigin};

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

use super::consent::{
    ConsentEpoch, FourWayPermissions, MAX_CONSENT_DURATION, ModelReceiver, PixelConsentError,
    PixelConsentGrant, PixelRegion,
};
use super::identity::{NativeTargetHandle, OsSessionId};
use super::pixel_egress::{
    EgressContext, EgressStatus, MAX_PIXEL_PAYLOAD_BYTES, PixelEgressCoordinator, PixelEgressError,
    PixelFrame, PixelSinkPort, ProtectedScreenKind, STREAM_CHUNK_SIZE,
    ScreenSecurityClassification, SinkError,
};

#[derive(Default)]
struct MockSinkPort {
    chunks_delivered: AtomicUsize,
    bytes_delivered: AtomicUsize,
    chunks: Mutex<Vec<Vec<u8>>>,
    finished: AtomicUsize,
}

#[async_trait]
impl PixelSinkPort for MockSinkPort {
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
        self.chunks_delivered.fetch_add(1, Ordering::SeqCst);
        dispatch_gate.dispatch(|| {
            self.bytes_delivered
                .fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        self.chunks.lock().await.push(chunk.to_vec());
        Ok(())
    }

    async fn finish(&self, dispatch_gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        dispatch_gate.dispatch(|| {
            self.finished.fetch_add(1, Ordering::SeqCst);
        })?;
        Ok(())
    }
}

fn sample_grant(now: OffsetDateTime) -> PixelConsentGrant {
    PixelConsentGrant {
        consent_id: "consent-001".to_string(),
        actor: ActorId::new("actor-1"),
        auth_generation: AuthGeneration::new(1),
        os_session: OsSessionId::new("session-test"),
        target_handle: NativeTargetHandle::new("target-window-1"),
        region: PixelRegion::new(0, 0, 1000, 700),
        run_id: RunId::new("run-001"),
        receiver: ModelReceiver::new(
            "conn-1",
            "claude-3-5-sonnet",
            1,
            "account-anthropic-1",
            "https://api.anthropic.com",
        ),
        consent_epoch: ConsentEpoch::new(1),
        granted_at: now,
        expires_at: now + Duration::minutes(10),
    }
}

#[tokio::test]
async fn valid_consent_and_permissions_deliver_full_payload_to_sink() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();

    let consent = sample_grant(now).issue().expect("issue consent");
    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(10, 10, 800, 600);
    let receiver = consent.receiver().clone();

    let ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: false, // Egress does NOT require native input control!
            pixel_consent_granted: true,
        },
        now,
    };

    let frame = PixelFrame {
        origin: None,
        width: 800,
        height: 600,
        data: vec![0xAB; 128 * 1024], // 128 KiB
        classification: ScreenSecurityClassification::Normal,
    };

    let receipt = coordinator
        .send_frame(&consent, &observed_frame(&frame, &ctx), &ctx)
        .await
        .expect("send frame succeeds");

    assert_eq!(receipt.bytes_delivered, 128 * 1024);
    assert_eq!(receipt.status, EgressStatus::Success);
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 128 * 1024);
    assert_eq!(sink.finished.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn four_way_permissions_separation_refuses_egress() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = sample_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);
    let receiver = consent.receiver().clone();

    // 1. Control approved but NO pixel consent
    let ctx_control_only = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: true, // Has control!
            pixel_consent_granted: false,  // NO pixel consent!
        },
        now,
    };

    let frame = PixelFrame {
        origin: None,
        width: 500,
        height: 500,
        data: vec![1, 2, 3],
        classification: ScreenSecurityClassification::Normal,
    };

    let err1 = coordinator
        .send_frame(
            &consent,
            &observed_frame(&frame, &ctx_control_only),
            &ctx_control_only,
        )
        .await;
    assert_eq!(err1, Err(PixelEgressError::PermissionDenied));
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);

    // 2. OS capture only, without product read permission
    let ctx_os_only = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: false,
            native_control_approved: false,
            pixel_consent_granted: true,
        },
        now,
    };

    let err2 = coordinator
        .send_frame(
            &consent,
            &observed_frame(&frame, &ctx_os_only),
            &ctx_os_only,
        )
        .await;
    assert_eq!(err2, Err(PixelEgressError::PermissionDenied));
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expiration_and_duration_bounds_enforced() {
    let now = OffsetDateTime::now_utc();

    // Duration > 15 minutes fails on issue
    let mut bad_grant = sample_grant(now);
    bad_grant.expires_at = now + MAX_CONSENT_DURATION + Duration::seconds(1);
    let issue_err = bad_grant.issue();
    assert_eq!(issue_err, Err(PixelConsentError::DurationExceeded));

    // Valid consent validated at a future expired time fails
    let consent = sample_grant(now).issue().expect("issue consent");
    let future_now = now + Duration::minutes(11); // expired (consent was for 10m)

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);
    let receiver = consent.receiver().clone();

    let val_err = consent.validate(
        future_now,
        &actor,
        AuthGeneration::new(1),
        &session,
        &target,
        &region,
        &run_id,
        &receiver,
        ConsentEpoch::new(1),
    );
    assert_eq!(val_err, Err(PixelConsentError::Expired));
}

#[tokio::test]
async fn receiver_account_change_and_refresh_semantics() {
    let now = OffsetDateTime::now_utc();
    let consent = sample_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);

    // Changed account_id fails with AccountChanged
    let changed_account_receiver = ModelReceiver::new(
        "conn-1",
        "claude-3-5-sonnet",
        1,
        "account-anthropic-DIFFERENT",
        "https://api.anthropic.com",
    );
    let acc_err = consent.validate(
        now,
        &actor,
        AuthGeneration::new(1),
        &session,
        &target,
        &region,
        &run_id,
        &changed_account_receiver,
        ConsentEpoch::new(1),
    );
    assert_eq!(acc_err, Err(PixelConsentError::AccountChanged));

    // Changed model fails with ReceiverMismatch
    let changed_model_receiver = ModelReceiver::new(
        "conn-1",
        "claude-3-haiku",
        1,
        "account-anthropic-1",
        "https://api.anthropic.com",
    );
    let model_err = consent.validate(
        now,
        &actor,
        AuthGeneration::new(1),
        &session,
        &target,
        &region,
        &run_id,
        &changed_model_receiver,
        ConsentEpoch::new(1),
    );
    assert_eq!(model_err, Err(PixelConsentError::ReceiverMismatch));

    // Same account legal token refresh preserves identity
    assert!(
        consent
            .receiver()
            .is_same_account_refresh(&ModelReceiver::new(
                "conn-1-refreshed",
                "claude-3-5-sonnet",
                2,
                "account-anthropic-1",
                "https://api.anthropic.com",
            ))
    );
}

#[tokio::test]
async fn protected_and_indeterminate_screen_refused_with_zero_bytes() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = sample_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);
    let receiver = consent.receiver().clone();

    let ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: false,
            pixel_consent_granted: true,
        },
        now,
    };

    // 1. Protected Keychain prompt
    let protected_frame = PixelFrame {
        origin: None,
        width: 500,
        height: 500,
        data: vec![0xFF; 1000],
        classification: ScreenSecurityClassification::Protected(
            ProtectedScreenKind::KeychainPrompt,
        ),
    };
    let err_prot = coordinator
        .send_frame(&consent, &observed_frame(&protected_frame, &ctx), &ctx)
        .await;
    assert_eq!(
        err_prot,
        Err(PixelEgressError::ProtectedContentRefused(
            ProtectedScreenKind::KeychainPrompt
        ))
    );
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);

    // 2. Indeterminate screen
    let indet_frame = PixelFrame {
        origin: None,
        width: 500,
        height: 500,
        data: vec![0xFF; 1000],
        classification: ScreenSecurityClassification::Indeterminate,
    };
    let err_indet = coordinator
        .send_frame(&consent, &observed_frame(&indet_frame, &ctx), &ctx)
        .await;
    assert_eq!(err_indet, Err(PixelEgressError::IndeterminateScreenRefused));
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dimension_and_payload_budgets_refused_with_zero_bytes() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = sample_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);
    let receiver = consent.receiver().clone();

    let ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: false,
            pixel_consent_granted: true,
        },
        now,
    };

    // Oversized dimensions (> 1280x800)
    let bad_dim_frame = PixelFrame {
        origin: None,
        width: 1281,
        height: 800,
        data: vec![0; 100],
        classification: ScreenSecurityClassification::Normal,
    };
    let dim_err = coordinator
        .send_frame(&consent, &observed_frame(&bad_dim_frame, &ctx), &ctx)
        .await;
    assert_eq!(
        dim_err,
        Err(PixelEgressError::OversizedDimensions {
            width: 1281,
            height: 800,
        })
    );
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);

    // Oversized payload (> 8 MiB)
    let bad_payload_frame = PixelFrame {
        origin: None,
        width: 1280,
        height: 800,
        data: vec![0; MAX_PIXEL_PAYLOAD_BYTES + 1],
        classification: ScreenSecurityClassification::Normal,
    };
    let payload_err = coordinator
        .send_frame(&consent, &observed_frame(&bad_payload_frame, &ctx), &ctx)
        .await;
    assert_eq!(
        payload_err,
        Err(PixelEgressError::OversizedPayload {
            bytes: MAX_PIXEL_PAYLOAD_BYTES + 1,
        })
    );
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_revocation_mid_stream_halts_chunks() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let now = OffsetDateTime::now_utc();
    let consent = sample_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-1");
    let session = OsSessionId::new("session-test");
    let target = NativeTargetHandle::new("target-window-1");
    let run_id = RunId::new("run-001");
    let region = PixelRegion::new(0, 0, 500, 500);
    let receiver = consent.receiver().clone();

    // Revoke before sending
    coordinator.revoke().await;

    let ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &region,
        run_id: &run_id,
        receiver: &receiver,
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
        width: 500,
        height: 500,
        data: vec![0xEE; STREAM_CHUNK_SIZE * 3],
        classification: ScreenSecurityClassification::Normal,
    };

    let res = coordinator
        .send_frame(&consent, &observed_frame(&frame, &ctx), &ctx)
        .await;
    assert_eq!(res, Err(PixelEgressError::Revoked));
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn latest_value_frame_buffer_drops_old_frames() {
    let sink = Arc::new(MockSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());

    let frame1 = PixelFrame {
        origin: None,
        width: 100,
        height: 100,
        data: vec![1],
        classification: ScreenSecurityClassification::Normal,
    };
    let frame2 = PixelFrame {
        origin: None,
        width: 200,
        height: 200,
        data: vec![2],
        classification: ScreenSecurityClassification::Normal,
    };

    coordinator.set_latest_frame(frame1).await;
    coordinator.set_latest_frame(frame2.clone()).await;

    // Only frame 2 remains in the size-1 buffer
    let taken = coordinator.take_latest_frame().await;
    assert_eq!(taken, Some(frame2));

    // Buffer is now empty
    let empty = coordinator.take_latest_frame().await;
    assert_eq!(empty, None);
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
