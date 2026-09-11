//! GK-08 pixel lifecycle faults. Synthetic sinks only; no capture, vendor network or secrets.
//!
//! Existing coverage (native_pixel_egress / primary / rework / controller): four-way deny,
//! protected screens, origin field mismatch, first-chunk expiry, same-sink mutex, abort of the
//! first in-flight chunk, coordinator rebuild keeping Unknown, finish+revoke ConfirmedWhileRevoked.
//!
//! This file adds: capture-byte binding independent of metadata (P1), later-chunk / finish-after
//! effect faults (P2), and an independent sink that must keep sending while another is poisoned (P3).

use async_trait::async_trait;
use openbot_computer::native::{
    ConsentEpoch, EgressContext, EgressReceipt, EgressStatus, FourWayPermissions, ModelReceiver,
    NativeTargetHandle, ObservationGeneration, OsSessionId, PixelConsent, PixelConsentGrant,
    PixelDeliveryGate, PixelEgressCoordinator, PixelEgressError, PixelFrame, PixelFrameOrigin,
    PixelRegion, PixelSinkPort, STREAM_CHUNK_SIZE, ScreenSecurityClassification, SinkError,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

#[derive(Clone)]
struct CaptureRecord {
    bytes: Vec<u8>,
    target: NativeTargetHandle,
    region: PixelRegion,
    observation: ObservationGeneration,
}

struct BindingSink {
    captures: Mutex<HashMap<String, CaptureRecord>>,
    deny_authority: bool,
    fail_after_chunk: Option<usize>,
    fail_after_finish_dispatch: bool,
    block_after_chunk: Option<usize>,
    started: Semaphore,
    gate: Semaphore,
    bytes: AtomicUsize,
    calls: AtomicUsize,
    finishes: AtomicUsize,
    finish_dispatched: AtomicUsize,
}

impl BindingSink {
    fn new() -> Self {
        Self {
            captures: Mutex::new(HashMap::new()),
            deny_authority: false,
            fail_after_chunk: None,
            fail_after_finish_dispatch: false,
            block_after_chunk: None,
            started: Semaphore::new(0),
            gate: Semaphore::new(0),
            bytes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
            finish_dispatched: AtomicUsize::new(0),
        }
    }

    fn register(&self, capture_id: &str, frame: &PixelFrame) {
        let origin = frame.origin.as_ref().expect("origin");
        self.captures.lock().unwrap().insert(
            capture_id.to_owned(),
            CaptureRecord {
                bytes: frame.data.clone(),
                target: origin.target.clone(),
                region: origin.region,
                observation: origin.observation,
            },
        );
    }
}

#[async_trait]
impl PixelSinkPort for BindingSink {
    fn with_current_egress(
        &self,
        _: &PixelConsent,
        frame: &PixelFrame,
        ctx: &EgressContext<'_>,
        effect: &mut dyn FnMut() -> Result<(), SinkError>,
    ) -> Result<(), SinkError> {
        if self.deny_authority || !ctx.permissions.can_egress_pixels() {
            return Err(SinkError("pixel_authority_unavailable".into()));
        }
        let origin = frame
            .origin
            .as_ref()
            .ok_or_else(|| SinkError("capture_missing".into()))?;
        let stored = self
            .captures
            .lock()
            .unwrap()
            .get(&origin.capture_id)
            .cloned();
        let Some(stored) = stored else {
            return Err(SinkError("capture_unknown".into()));
        };
        if stored.bytes != frame.data
            || stored.target != origin.target
            || stored.region != origin.region
            || stored.observation != origin.observation
            || stored.target != *ctx.target
            || stored.region != *ctx.requested_region
        {
            return Err(SinkError("capture_binding_mismatch".into()));
        }
        effect()
    }

    async fn deliver_chunk(
        &self,
        chunk: &[u8],
        gate: &PixelDeliveryGate<'_>,
    ) -> Result<(), SinkError> {
        let n = self.calls.load(Ordering::SeqCst) + 1;
        gate.dispatch(|| {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bytes.fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        if self.block_after_chunk == Some(n) {
            self.started.add_permits(1);
            self.gate.acquire().await.unwrap().forget();
        }
        if self.fail_after_chunk == Some(n) {
            return Err(SinkError("synthetic_later_chunk_unconfirmed".into()));
        }
        Ok(())
    }

    async fn finish(&self, gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        gate.dispatch(|| {
            self.finish_dispatched.fetch_add(1, Ordering::SeqCst);
        })?;
        self.finishes.fetch_add(1, Ordering::SeqCst);
        if self.fail_after_finish_dispatch {
            return Err(SinkError("synthetic_finish_failed".into()));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Fixture {
    grant: PixelConsent,
    actor: ActorId,
    session: OsSessionId,
    region: PixelRegion,
    frame: PixelFrame,
}

impl Fixture {
    fn with_bytes(capture_id: &str, data: Vec<u8>) -> Self {
        let now = OffsetDateTime::now_utc();
        let actor = ActorId::new("gk08-pixel-actor");
        let session = OsSessionId::new(format!("gk08-pixel-{}", capture_id));
        let region = PixelRegion::new(0, 0, 8, 8);
        let target = NativeTargetHandle::new(format!("gk08-target-{capture_id}"));
        let grant = PixelConsentGrant {
            consent_id: format!("gk08-consent-{capture_id}"),
            actor: actor.clone(),
            auth_generation: AuthGeneration::new(1),
            os_session: session.clone(),
            target_handle: target.clone(),
            region,
            run_id: RunId::new("gk08-pixel-run"),
            receiver: ModelReceiver::new(
                "gk08-connection",
                "gk08-model",
                1,
                "gk08-account",
                "https://receiver.invalid",
            ),
            consent_epoch: ConsentEpoch::new(1),
            granted_at: now,
            expires_at: now + Duration::minutes(1),
        }
        .issue()
        .unwrap();
        let frame = PixelFrame {
            width: 8,
            height: 8,
            data,
            classification: ScreenSecurityClassification::Normal,
            origin: Some(PixelFrameOrigin {
                capture_id: capture_id.to_owned(),
                session: session.clone(),
                target,
                region,
                observation: ObservationGeneration::new(1),
                captured_at: now,
            }),
        };
        Self {
            grant,
            actor,
            session,
            region,
            frame,
        }
    }

    fn ctx(&self) -> EgressContext<'_> {
        EgressContext {
            actor: &self.actor,
            auth_generation: AuthGeneration::new(1),
            session: &self.session,
            target: self.grant.target_handle(),
            requested_region: &self.region,
            run_id: self.grant.run_id(),
            receiver: self.grant.receiver(),
            permissions: FourWayPermissions {
                os_capture_permitted: true,
                product_read_permitted: true,
                native_control_approved: false,
                pixel_consent_granted: true,
            },
            now: OffsetDateTime::now_utc(),
        }
    }

    async fn send(&self, c: &PixelEgressCoordinator) -> Result<EgressReceipt, PixelEgressError> {
        c.send_frame(&self.grant, &self.frame, &self.ctx()).await
    }
}

async fn wait_started(sink: &BindingSink) {
    tokio::time::timeout(StdDuration::from_secs(2), sink.started.acquire())
        .await
        .expect("started")
        .expect("permit")
        .forget();
}

#[tokio::test]
async fn p1_matching_capture_bytes_are_delivered() {
    let sink = Arc::new(BindingSink::new());
    let fixture = Fixture::with_bytes("cap-match", vec![0x11, 0x22, 0x33, 0x44]);
    sink.register("cap-match", &fixture.frame);
    let c = PixelEgressCoordinator::new(sink.clone());
    let receipt = fixture.send(&c).await.unwrap();
    assert_eq!(receipt.status, EgressStatus::Success);
    assert_eq!(receipt.bytes_delivered, 4);
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 4);
    assert_eq!(sink.finishes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn p1_replaced_bytes_with_forged_matching_metadata_deliver_zero() {
    let sink = Arc::new(BindingSink::new());
    let original = Fixture::with_bytes("cap-forged", vec![0x10, 0x20, 0x30, 0x40]);
    sink.register("cap-forged", &original.frame);
    let mut forged = original;
    forged.frame.data = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let c = PixelEgressCoordinator::new(sink.clone());
    let result = forged.send(&c).await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.finish_dispatched.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn p1_missing_permission_port_denies_even_with_matching_bytes() {
    let mut sink = BindingSink::new();
    sink.deny_authority = true;
    let sink = Arc::new(sink);
    let fixture = Fixture::with_bytes("cap-deny", vec![0x01, 0x02, 0x03, 0x04]);
    sink.register("cap-deny", &fixture.frame);
    let c = PixelEgressCoordinator::new(sink.clone());
    assert!(fixture.send(&c).await.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn p2_second_chunk_dispatched_then_failed_keeps_confirmed_and_unconfirmed() {
    let mut sink = BindingSink::new();
    sink.fail_after_chunk = Some(2);
    let sink = Arc::new(sink);
    let mut data = vec![0x21; STREAM_CHUNK_SIZE + 8];
    data[0] = 0x42;
    let fixture = Fixture::with_bytes("cap-chunk2", data);
    sink.register("cap-chunk2", &fixture.frame);
    let c = PixelEgressCoordinator::new(sink.clone());
    let result = fixture.send(&c).await;
    assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        sink.bytes.load(Ordering::SeqCst),
        STREAM_CHUNK_SIZE + 8,
        "chunk 2 was dispatched to the sink"
    );
    match result {
        Err(PixelEgressError::DeliveryUnconfirmed {
            confirmed_bytes,
            unconfirmed_bytes,
        }) => {
            assert_eq!(confirmed_bytes, STREAM_CHUNK_SIZE);
            assert_eq!(unconfirmed_bytes, 8);
        }
        other => panic!("expected unconfirmed later chunk, got {other:?}"),
    }
    let receipt = c.last_receipt();
    assert_eq!(receipt.status, EgressStatus::Unknown);
    assert_eq!(receipt.bytes_delivered, STREAM_CHUNK_SIZE);
    assert_eq!(receipt.bytes_unconfirmed, 8);
    assert_eq!(sink.finishes.load(Ordering::SeqCst), 0);
    let retry = fixture.send(&c).await;
    assert!(retry.is_err(), "{retry:?}");
    assert_eq!(sink.calls.load(Ordering::SeqCst), 2, "retry resent chunks");
}

#[tokio::test]
async fn p2_finish_effect_then_error_does_not_claim_success_or_retry() {
    let mut sink = BindingSink::new();
    sink.fail_after_finish_dispatch = true;
    let sink = Arc::new(sink);
    let fixture = Fixture::with_bytes("cap-finish", vec![0x31; 16]);
    sink.register("cap-finish", &fixture.frame);
    let c = PixelEgressCoordinator::new(sink.clone());
    let result = fixture.send(&c).await;
    assert_eq!(sink.finish_dispatched.load(Ordering::SeqCst), 1);
    assert!(result.is_err(), "{result:?}");
    assert_ne!(result.ok().map(|r| r.status), Some(EgressStatus::Success));
    let receipt = c.last_receipt();
    assert_eq!(receipt.status, EgressStatus::Unknown);
    assert_eq!(receipt.bytes_delivered, 16);
    assert_eq!(receipt.bytes_unconfirmed, 0);
    let retry = fixture.send(&c).await;
    assert!(retry.is_err());
    assert_eq!(
        sink.finish_dispatched.load(Ordering::SeqCst),
        1,
        "finish retried after unknown"
    );
}

#[tokio::test]
async fn p2_epoch_change_after_later_chunk_retains_progress() {
    let mut sink = BindingSink::new();
    sink.block_after_chunk = Some(2);
    let sink = Arc::new(sink);
    let fixture = Fixture::with_bytes("cap-epoch", vec![0x41; STREAM_CHUNK_SIZE + 8]);
    sink.register("cap-epoch", &fixture.frame);
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let job = {
        let c = c.clone();
        let fixture = fixture.clone();
        tokio::spawn(async move { fixture.send(&c).await })
    };
    wait_started(&sink).await;
    c.revoke().await;
    sink.gate.add_permits(1);
    let result = tokio::time::timeout(StdDuration::from_secs(7), job)
        .await
        .expect("send terminates")
        .unwrap();
    assert!(result.is_err(), "{result:?}");
    assert_eq!(sink.finishes.load(Ordering::SeqCst), 0);
    let receipt = c.last_receipt();
    assert!(
        receipt.bytes_delivered + receipt.bytes_unconfirmed > 0,
        "later-chunk progress was zeroed after epoch change: {receipt:?}"
    );
    assert_ne!(receipt.status, EgressStatus::Success);
    assert_eq!(
        receipt.bytes_delivered + receipt.bytes_unconfirmed,
        STREAM_CHUNK_SIZE + 8
    );
    assert_eq!(sink.bytes.load(Ordering::SeqCst), STREAM_CHUNK_SIZE + 8);
}

#[tokio::test]
async fn p3_independent_sink_sends_while_other_sink_is_unknown() {
    let mut poisoned = BindingSink::new();
    poisoned.block_after_chunk = Some(1);
    let poisoned = Arc::new(poisoned);
    let healthy = Arc::new(BindingSink::new());
    let stuck = Fixture::with_bytes("cap-stuck", vec![0x51; 8]);
    poisoned.register("cap-stuck", &stuck.frame);
    let live = Fixture::with_bytes("cap-live", vec![0x52; 8]);
    healthy.register("cap-live", &live.frame);
    let a = Arc::new(PixelEgressCoordinator::new(poisoned.clone()));
    let b = PixelEgressCoordinator::new(healthy.clone());
    let job = {
        let a = a.clone();
        tokio::spawn(async move { stuck.send(&a).await })
    };
    wait_started(&poisoned).await;
    let independent = live.send(&b).await;
    assert!(
        independent.is_ok(),
        "independent sink blocked by the other sink: {independent:?}"
    );
    assert_eq!(healthy.bytes.load(Ordering::SeqCst), 8);
    job.abort();
    let _ = job.await;
    assert_eq!(a.last_receipt().status, EgressStatus::Unknown);
    let rebuilt = PixelEgressCoordinator::new(poisoned.clone());
    poisoned.gate.add_permits(1);
    assert!(
        Fixture::with_bytes("cap-stuck", vec![0x51; 8])
            .send(&rebuilt)
            .await
            .is_err()
    );
    assert_eq!(poisoned.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn p3_old_unknown_on_one_sink_does_not_poison_a_new_sink() {
    let mut first = BindingSink::new();
    first.fail_after_chunk = Some(1);
    let first = Arc::new(first);
    let second = Arc::new(BindingSink::new());
    let a_frame = Fixture::with_bytes("cap-a", vec![0x61; STREAM_CHUNK_SIZE + 1]);
    first.register("cap-a", &a_frame.frame);
    let b_frame = Fixture::with_bytes("cap-b", vec![0x62; 4]);
    second.register("cap-b", &b_frame.frame);
    let a = PixelEgressCoordinator::new(first.clone());
    assert!(a_frame.send(&a).await.is_err());
    assert_eq!(a.last_receipt().status, EgressStatus::Unknown);
    drop(a);
    let b = PixelEgressCoordinator::new(second.clone());
    let ok = b_frame.send(&b).await.unwrap();
    assert_eq!(ok.status, EgressStatus::Success);
    assert_eq!(second.bytes.load(Ordering::SeqCst), 4);
    assert_eq!(first.finishes.load(Ordering::SeqCst), 0);
}
