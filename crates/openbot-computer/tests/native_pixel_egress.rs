//! Integration tests for pixel consent and egress boundary (v5 §10.7 / PA-04 / V5-PIXEL-01).
use openbot_computer::native::PixelConsent;
use openbot_computer::native::{ObservationGeneration, PixelDeliveryGate, PixelFrameOrigin};

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use openbot_computer::native::{
    ConsentEpoch, EgressContext, EgressStatus, FourWayPermissions, ModelReceiver,
    NativeTargetHandle, OsSessionId, PixelConsentError, PixelConsentGrant, PixelEgressCoordinator,
    PixelEgressError, PixelFrame, PixelRegion, PixelSinkPort, ProtectedScreenKind,
    STREAM_CHUNK_SIZE, ScreenSecurityClassification, SinkError,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

#[derive(Default)]
struct CapturingSinkPort {
    chunks_delivered: AtomicUsize,
    bytes_delivered: AtomicUsize,
    chunks: Mutex<Vec<Vec<u8>>>,
    finish_calls: AtomicUsize,
    fail_on_chunk: Mutex<Option<usize>>,
}

#[async_trait]
impl PixelSinkPort for CapturingSinkPort {
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
        let current_chunk = self.chunks_delivered.fetch_add(1, Ordering::SeqCst);
        if matches!(*self.fail_on_chunk.lock().await, Some(target) if current_chunk == target) {
            return Err(SinkError("simulated_sink_pipe_broken".to_string()));
        }
        dispatch_gate.dispatch(|| {
            self.bytes_delivered
                .fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        self.chunks.lock().await.push(chunk.to_vec());
        Ok(())
    }

    async fn finish(&self, dispatch_gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        dispatch_gate.dispatch(|| {
            self.finish_calls.fetch_add(1, Ordering::SeqCst);
        })?;
        Ok(())
    }
}

fn create_valid_grant(now: OffsetDateTime) -> PixelConsentGrant {
    PixelConsentGrant {
        consent_id: "grant-test-01".to_string(),
        actor: ActorId::new("actor-integ"),
        auth_generation: AuthGeneration::new(1),
        os_session: OsSessionId::new("session-integ"),
        target_handle: NativeTargetHandle::new("target-app-window"),
        region: PixelRegion::new(100, 100, 800, 600),
        run_id: RunId::new("run-integ-1"),
        receiver: ModelReceiver::new(
            "conn-openai-prod",
            "gpt-4o",
            10,
            "account-org-corp",
            "https://api.openai.com/v1",
        ),
        consent_epoch: ConsentEpoch::new(1),
        granted_at: now,
        expires_at: now + Duration::minutes(15),
    }
}

#[tokio::test]
async fn test_end_to_end_egress_and_region_expansion_rejection() {
    let sink = Arc::new(CapturingSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();

    let consent = create_valid_grant(now).issue().expect("issue consent");
    let actor = ActorId::new("actor-integ");
    let session = OsSessionId::new("session-integ");
    let target = NativeTargetHandle::new("target-app-window");
    let run_id = RunId::new("run-integ-1");
    let receiver = consent.receiver().clone();

    // 1. Permitted region within consented bounds
    let valid_region = PixelRegion::new(100, 100, 400, 300);
    let valid_ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &valid_region,
        run_id: &run_id,
        receiver: &receiver,
        permissions: FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: false, // Does not require native control!
            pixel_consent_granted: true,
        },
        now,
    };

    let frame = PixelFrame {
        origin: None,
        width: 400,
        height: 300,
        data: vec![0x42; 64 * 1024],
        classification: ScreenSecurityClassification::Normal,
    };

    let receipt = coordinator
        .send_frame(&consent, &observed_frame(&frame, &valid_ctx), &valid_ctx)
        .await
        .expect("send frame ok");

    assert_eq!(receipt.bytes_delivered, 64 * 1024);
    assert_eq!(receipt.status, EgressStatus::Success);
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 64 * 1024);

    // 2. Region expansion beyond consented bounds (e.g. attempting fullscreen 1280x800)
    let expanded_region = PixelRegion::new(0, 0, 1280, 800);
    let expanded_ctx = EgressContext {
        actor: &actor,
        auth_generation: AuthGeneration::new(1),
        session: &session,
        target: &target,
        requested_region: &expanded_region,
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

    let exp_err = coordinator
        .send_frame(
            &consent,
            &observed_frame(&frame, &expanded_ctx),
            &expanded_ctx,
        )
        .await;
    assert_eq!(
        exp_err,
        Err(PixelEgressError::ConsentValidation(
            PixelConsentError::RegionExpanded
        ))
    );
    // Bytes delivered to sink remains at 64 KiB (0 new bytes)
    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 64 * 1024);
}

#[tokio::test]
async fn test_four_way_permissions_matrix_zero_bytes() {
    let sink = Arc::new(CapturingSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = create_valid_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-integ");
    let session = OsSessionId::new("session-integ");
    let target = NativeTargetHandle::new("target-app-window");
    let run_id = RunId::new("run-integ-1");
    let region = PixelRegion::new(100, 100, 400, 300);
    let receiver = consent.receiver().clone();

    let frame = PixelFrame {
        origin: None,
        width: 400,
        height: 300,
        data: vec![0x11; 1000],
        classification: ScreenSecurityClassification::Normal,
    };

    // Test permutations where pixel egress must be denied
    let permutations = [
        // No OS capture
        FourWayPermissions {
            os_capture_permitted: false,
            product_read_permitted: true,
            native_control_approved: true,
            pixel_consent_granted: true,
        },
        // No product read
        FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: false,
            native_control_approved: true,
            pixel_consent_granted: true,
        },
        // No pixel consent (even though native control is approved!)
        FourWayPermissions {
            os_capture_permitted: true,
            product_read_permitted: true,
            native_control_approved: true,
            pixel_consent_granted: false,
        },
        // Only native control approved
        FourWayPermissions {
            os_capture_permitted: false,
            product_read_permitted: false,
            native_control_approved: true,
            pixel_consent_granted: false,
        },
    ];

    for perm in permutations {
        let ctx = EgressContext {
            actor: &actor,
            auth_generation: AuthGeneration::new(1),
            session: &session,
            target: &target,
            requested_region: &region,
            run_id: &run_id,
            receiver: &receiver,
            permissions: perm,
            now,
        };
        let res = coordinator
            .send_frame(&consent, &observed_frame(&frame, &ctx), &ctx)
            .await;
        assert_eq!(res, Err(PixelEgressError::PermissionDenied));
    }

    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_protected_screen_kinds_exclusion() {
    let sink = Arc::new(CapturingSinkPort::default());
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = create_valid_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-integ");
    let session = OsSessionId::new("session-integ");
    let target = NativeTargetHandle::new("target-app-window");
    let run_id = RunId::new("run-integ-1");
    let region = PixelRegion::new(100, 100, 400, 300);
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

    let protected_kinds = [
        ProtectedScreenKind::KeychainPrompt,
        ProtectedScreenKind::SystemAuthentication,
        ProtectedScreenKind::SecretEditingField,
        ProtectedScreenKind::HostSecureWindow,
    ];

    for kind in protected_kinds {
        let frame = PixelFrame {
            origin: None,
            width: 400,
            height: 300,
            data: vec![0x99; 2000],
            classification: ScreenSecurityClassification::Protected(kind.clone()),
        };
        let err = coordinator
            .send_frame(&consent, &observed_frame(&frame, &ctx), &ctx)
            .await;
        assert_eq!(err, Err(PixelEgressError::ProtectedContentRefused(kind)));
    }

    // Indeterminate screen
    let indet_frame = PixelFrame {
        origin: None,
        width: 400,
        height: 300,
        data: vec![0x99; 2000],
        classification: ScreenSecurityClassification::Indeterminate,
    };
    let indet_err = coordinator
        .send_frame(&consent, &observed_frame(&indet_frame, &ctx), &ctx)
        .await;
    assert_eq!(indet_err, Err(PixelEgressError::IndeterminateScreenRefused));

    assert_eq!(sink.bytes_delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_sink_error_zero_retry() {
    let sink = Arc::new(CapturingSinkPort::default());
    // Simulate failure on the second chunk
    *sink.fail_on_chunk.lock().await = Some(1);
    let coordinator = PixelEgressCoordinator::new(sink.clone());
    let now = OffsetDateTime::now_utc();
    let consent = create_valid_grant(now).issue().expect("issue consent");

    let actor = ActorId::new("actor-integ");
    let session = OsSessionId::new("session-integ");
    let target = NativeTargetHandle::new("target-app-window");
    let run_id = RunId::new("run-integ-1");
    let region = PixelRegion::new(100, 100, 400, 300);
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

    let frame = PixelFrame {
        origin: None,
        width: 400,
        height: 300,
        data: vec![0x33; STREAM_CHUNK_SIZE * 3],
        classification: ScreenSecurityClassification::Normal,
    };

    let err = coordinator
        .send_frame(&consent, &observed_frame(&frame, &ctx), &ctx)
        .await;
    assert!(matches!(
        err,
        Err(PixelEgressError::DeliveryUnconfirmed {
            confirmed_bytes: STREAM_CHUNK_SIZE,
            unconfirmed_bytes: 0
        })
    ));

    // Verification of zero automatic retry: only 2 delivery attempts were made (chunk 0 ok, chunk 1 failed)
    assert_eq!(sink.chunks_delivered.load(Ordering::SeqCst), 2);
    assert_eq!(
        sink.bytes_delivered.load(Ordering::SeqCst),
        STREAM_CHUNK_SIZE
    );
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
