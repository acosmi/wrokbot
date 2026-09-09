//! Controller review of current pixel authority, frame provenance and unknown delivery.
use async_trait::async_trait;
use openbot_computer::native::*;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
struct Sink {
    allowed: Mutex<bool>,
    block_chunk: bool,
    block_finish: bool,
    started: Semaphore,
    gate: Semaphore,
    bytes: AtomicUsize,
    calls: AtomicUsize,
    finishes: AtomicUsize,
}
impl Sink {
    fn new(block_chunk: bool, block_finish: bool) -> Self {
        Self {
            allowed: Mutex::new(true),
            block_chunk,
            block_finish,
            started: Semaphore::new(0),
            gate: Semaphore::new(0),
            bytes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
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
        let allowed = self.allowed.lock().unwrap();
        if !*allowed {
            return Err(SinkError("synthetic_current_model_revoked".into()));
        }
        effect()
    }
    async fn deliver_chunk(
        &self,
        chunk: &[u8],
        gate: &PixelDeliveryGate<'_>,
    ) -> Result<(), SinkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        gate.dispatch(|| {
            self.bytes.fetch_add(chunk.len(), Ordering::SeqCst);
        })?;
        if self.block_chunk && self.calls.load(Ordering::SeqCst) == 1 {
            self.started.add_permits(1);
            self.gate.acquire().await.unwrap().forget();
        }
        Ok(())
    }
    async fn finish(&self, gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        gate.dispatch(|| {
            self.finishes.fetch_add(1, Ordering::SeqCst);
        })?;
        if self.block_finish {
            self.started.add_permits(1);
            self.gate.acquire().await.unwrap().forget();
        }
        Ok(())
    }
}
struct MissingAuthority(Arc<Sink>);
#[async_trait]
impl PixelSinkPort for MissingAuthority {
    async fn deliver_chunk(&self, c: &[u8], g: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        self.0.deliver_chunk(c, g).await
    }
    async fn finish(&self, g: &PixelDeliveryGate<'_>) -> Result<(), SinkError> {
        self.0.finish(g).await
    }
}
struct Fixture {
    grant: PixelConsent,
    actor: ActorId,
    session: OsSessionId,
    region: PixelRegion,
    frame: PixelFrame,
}
impl Fixture {
    fn new(bytes: usize) -> Self {
        let now = OffsetDateTime::now_utc();
        let actor = ActorId::new("pixel-controller-actor");
        let session = OsSessionId::new("pixel-controller-session");
        let region = PixelRegion::new(3, 4, 1, 1);
        let target = NativeTargetHandle::new("pixel-controller-target");
        let grant = PixelConsentGrant {
            consent_id: "pixel-controller-consent".into(),
            actor: actor.clone(),
            auth_generation: AuthGeneration::new(1),
            os_session: session.clone(),
            target_handle: target.clone(),
            region,
            run_id: RunId::new("pixel-controller-run"),
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
        .unwrap();
        let frame = PixelFrame {
            width: 1,
            height: 1,
            data: vec![0x31; bytes],
            classification: ScreenSecurityClassification::Normal,
            origin: Some(PixelFrameOrigin {
                capture_id: "test-capture".into(),
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
async fn started(s: &Sink) {
    tokio::time::timeout(StdDuration::from_secs(2), s.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}
#[tokio::test]
async fn p01_missing_authority_has_zero_actual_bytes() {
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(Arc::new(MissingAuthority(sink.clone())));
    assert!(Fixture::new(4).send(&c).await.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
    assert_eq!(sink.finishes.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn p02_wrong_capture_target_region_and_absent_origin_send_zero() {
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(sink.clone());
    let mut f = Fixture::new(4);
    f.frame.origin.as_mut().unwrap().target = NativeTargetHandle::new("different-target");
    assert!(f.send(&c).await.is_err());
    f.frame.origin.as_mut().unwrap().target = f.grant.target_handle().clone();
    f.frame.origin.as_mut().unwrap().region.x += 1;
    assert!(f.send(&c).await.is_err());
    f.frame.origin = None;
    assert!(f.send(&c).await.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn p03_current_model_revocation_stops_after_confirmed_prefix() {
    let sink = Arc::new(Sink::new(true, false));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let f = Fixture::new(STREAM_CHUNK_SIZE + 1);
    let job = {
        let c = c.clone();
        tokio::spawn(async move { f.send(&c).await })
    };
    started(&sink).await;
    *sink.allowed.lock().unwrap() = false;
    sink.gate.add_permits(1);
    let result = job.await.unwrap();
    assert!(result.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), STREAM_CHUNK_SIZE);
    assert_eq!(sink.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(c.last_receipt().bytes_delivered, STREAM_CHUNK_SIZE);
}
#[tokio::test]
async fn p04_abort_after_send_retains_unconfirmed_chunk_and_denies_retry() {
    let sink = Arc::new(Sink::new(true, false));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let f = Fixture::new(4);
    let job = {
        let c = c.clone();
        tokio::spawn(async move { f.send(&c).await })
    };
    started(&sink).await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    let receipt = c.last_receipt();
    assert_eq!(receipt.status, EgressStatus::Unknown);
    assert_eq!(receipt.bytes_delivered, 0);
    assert_eq!(receipt.bytes_unconfirmed, 4);
    assert!(Fixture::new(4).send(&c).await.is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn p05_two_coordinators_share_one_sink_delivery_slot() {
    let sink = Arc::new(Sink::new(true, false));
    let a = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let b = PixelEgressCoordinator::new(sink.clone());
    let f = Fixture::new(4);
    let job = {
        let a = a.clone();
        tokio::spawn(async move { f.send(&a).await })
    };
    started(&sink).await;
    assert_eq!(Fixture::new(4).send(&b).await, Err(PixelEgressError::Busy));
    sink.gate.add_permits(1);
    assert!(job.await.unwrap().is_ok());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn p06_caller_clock_cannot_bypass_real_frame_rate() {
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(sink.clone());
    let f = Fixture::new(4);
    assert!(f.send(&c).await.is_ok());
    let mut ctx = f.ctx();
    ctx.now += Duration::seconds(10);
    assert_eq!(
        c.send_frame(&f.grant, &f.frame, &ctx).await,
        Err(PixelEgressError::RateLimitExceeded)
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn p07_finish_started_before_revoke_is_recorded_without_claiming_zero_send() {
    let sink = Arc::new(Sink::new(false, true));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let f = Fixture::new(4);
    let job = {
        let c = c.clone();
        tokio::spawn(async move { f.send(&c).await })
    };
    started(&sink).await;
    c.revoke().await;
    sink.gate.add_permits(1);
    let result = job.await.unwrap().unwrap();
    assert_eq!(result.status, EgressStatus::ConfirmedWhileRevoked);
    assert_eq!(result.bytes_delivered, 4);
    assert_eq!(result.bytes_unconfirmed, 0);
}
#[tokio::test]
async fn p08_future_dated_consent_is_not_valid_now() {
    let f = Fixture::new(4);
    let now = OffsetDateTime::now_utc();
    let future = PixelConsentGrant {
        consent_id: "future".into(),
        actor: f.actor.clone(),
        auth_generation: AuthGeneration::new(1),
        os_session: f.session.clone(),
        target_handle: f.grant.target_handle().clone(),
        region: f.region,
        run_id: f.grant.run_id().clone(),
        receiver: f.grant.receiver().clone(),
        consent_epoch: ConsentEpoch::new(1),
        granted_at: now + Duration::seconds(30),
        expires_at: now + Duration::seconds(60),
    }
    .issue()
    .unwrap();
    let sink = Arc::new(Sink::new(false, false));
    let c = PixelEgressCoordinator::new(sink.clone());
    assert!(c.send_frame(&future, &f.frame, &f.ctx()).await.is_err());
    assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn p09_recreating_coordinator_cannot_forget_unknown_sink_prefix() {
    let sink = Arc::new(Sink::new(true, false));
    let c = Arc::new(PixelEgressCoordinator::new(sink.clone()));
    let f = Fixture::new(4);
    let job = {
        let c = c.clone();
        tokio::spawn(async move { f.send(&c).await })
    };
    started(&sink).await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    drop(c);
    let next = PixelEgressCoordinator::new(sink.clone());
    sink.gate.add_permits(1);
    assert!(Fixture::new(4).send(&next).await.is_err());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}
