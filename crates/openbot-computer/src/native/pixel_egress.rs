//! Bounded native pixel delivery. Capture provenance and current egress authority are independent
//! of metadata and consent construction. Production adapters must implement the checked port.
use super::consent::{
    ConsentEpoch, FourWayPermissions, ModelReceiver, PixelConsent, PixelConsentError, PixelRegion,
};
use super::identity::{NativeTargetHandle, ObservationGeneration, OsSessionId};
use async_trait::async_trait;
use core::fmt;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, Weak};
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tokio::time::timeout;
pub const MAX_PIXEL_WIDTH: u32 = 1280;
pub const MAX_PIXEL_HEIGHT: u32 = 800;
pub const MAX_PIXEL_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MIN_FRAME_INTERVAL: Duration = Duration::milliseconds(200);
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;
pub const SINK_CHUNK_TIMEOUT: StdDuration = StdDuration::from_secs(5);
pub const SINK_FINISH_TIMEOUT: StdDuration = StdDuration::from_secs(5);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectedScreenKind {
    KeychainPrompt,
    SystemAuthentication,
    SecretEditingField,
    HostSecureWindow,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScreenSecurityClassification {
    Normal,
    Protected(ProtectedScreenKind),
    Indeterminate,
}
/// Host capture metadata. The trusted port must resolve capture_id against actual capture bytes,
/// target/observation and protected-surface policy; a caller-supplied description is not proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PixelFrameOrigin {
    pub capture_id: String,
    pub session: OsSessionId,
    pub target: NativeTargetHandle,
    pub region: PixelRegion,
    pub observation: ObservationGeneration,
    pub captured_at: OffsetDateTime,
}
#[derive(Clone, PartialEq, Eq)]
pub struct PixelFrame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
    pub classification: ScreenSecurityClassification,
    pub origin: Option<PixelFrameOrigin>,
}
impl fmt::Debug for PixelFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PixelFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("classification", &self.classification)
            .field("bytes", &self.data.len())
            .finish()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("pixel_sink_failed")]
pub struct SinkError(pub String);
#[async_trait]
pub trait PixelSinkPort: Send + Sync {
    /// Every actual submission must occur exactly once inside gate.dispatch, after any async
    /// preparation. No unguarded background submission survives cancellation.
    async fn deliver_chunk(
        &self,
        chunk: &[u8],
        gate: &PixelDeliveryGate<'_>,
    ) -> Result<(), SinkError>;
    async fn finish(&self, gate: &PixelDeliveryGate<'_>) -> Result<(), SinkError>;
    /// Under current authority locks, verify actor/run, OS capture and product read permission,
    /// consent/recovery epochs, capture byte provenance and current connection/model identity.
    /// Missing host authority fails closed; the context booleans cannot grant authority.
    fn with_current_egress(
        &self,
        _consent: &PixelConsent,
        _frame: &PixelFrame,
        _ctx: &EgressContext<'_>,
        _effect: &mut dyn FnMut() -> Result<(), SinkError>,
    ) -> Result<(), SinkError> {
        Err(SinkError("pixel_authority_unavailable".into()))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PixelEgressError {
    #[error("pixel_egress_permission_denied")]
    PermissionDenied,
    #[error("pixel_egress_consent_error: {0}")]
    ConsentValidation(#[from] PixelConsentError),
    #[error("pixel_egress_protected_content_refused: {0:?}")]
    ProtectedContentRefused(ProtectedScreenKind),
    #[error("pixel_egress_indeterminate_screen_refused")]
    IndeterminateScreenRefused,
    #[error("pixel_egress_frame_source_unverified")]
    FrameSourceUnverified,
    #[error("pixel_egress_oversized_dimensions: {width}x{height}")]
    OversizedDimensions { width: u32, height: u32 },
    #[error("pixel_egress_oversized_payload: {bytes}")]
    OversizedPayload { bytes: usize },
    #[error("pixel_egress_rate_limit_exceeded")]
    RateLimitExceeded,
    #[error("pixel_egress_busy")]
    Busy,
    #[error("pixel_egress_revoked")]
    Revoked,
    #[error("pixel_egress_revoked_mid_stream: {bytes_delivered}")]
    RevokedMidStream { bytes_delivered: usize },
    #[error("pixel_egress_sink_failed: {0}")]
    SinkDeliveryFailed(String),
    #[error("pixel_egress_unknown: confirmed={confirmed_bytes} unconfirmed={unconfirmed_bytes}")]
    DeliveryUnconfirmed {
        confirmed_bytes: usize,
        unconfirmed_bytes: usize,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressStatus {
    NotSent,
    InFlight,
    Success,
    ConfirmedWhileRevoked,
    PartialRevocation,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressReceipt {
    pub bytes_delivered: usize,
    pub bytes_unconfirmed: usize,
    pub epoch: ConsentEpoch,
    pub status: EgressStatus,
}
pub struct EgressContext<'a> {
    pub actor: &'a ActorId,
    pub auth_generation: AuthGeneration,
    pub session: &'a OsSessionId,
    pub target: &'a NativeTargetHandle,
    pub requested_region: &'a PixelRegion,
    pub run_id: &'a RunId,
    pub receiver: &'a ModelReceiver,
    pub permissions: FourWayPermissions,
    /// Diagnostic input only. Time limits use the coordinator's own clocks.
    pub now: OffsetDateTime,
}
struct SinkState {
    epoch: ConsentEpoch,
    revoked: bool,
    poisoned: bool,
    last_start: Option<Instant>,
    latest: Option<PixelFrame>,
    receipt: EgressReceipt,
}
struct SharedSink {
    state: StdMutex<SinkState>,
    delivery: Mutex<()>,
}
struct SinkEntry {
    sink: Weak<dyn PixelSinkPort>,
    shared: Arc<SharedSink>,
}
// Retain unknown progress for the entire transport lifetime, including coordinator recreation.
static SINKS: LazyLock<StdMutex<HashMap<usize, SinkEntry>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
pub struct PixelEgressCoordinator {
    sink: Arc<dyn PixelSinkPort>,
    shared: Arc<SharedSink>,
}
impl PixelEgressCoordinator {
    pub fn new(sink: Arc<dyn PixelSinkPort>) -> Self {
        let key = Arc::as_ptr(&sink) as *const () as usize;
        let mut map = SINKS.lock().expect("pixel registry poisoned");
        map.retain(|_, v| v.sink.strong_count() > 0);
        let shared = map
            .get(&key)
            .map(|entry| entry.shared.clone())
            .unwrap_or_else(|| {
                let shared = Arc::new(SharedSink {
                    state: StdMutex::new(SinkState {
                        epoch: ConsentEpoch::new(1),
                        revoked: map.len() >= 64,
                        poisoned: false,
                        last_start: None,
                        latest: None,
                        receipt: EgressReceipt {
                            bytes_delivered: 0,
                            bytes_unconfirmed: 0,
                            epoch: ConsentEpoch::new(1),
                            status: EgressStatus::NotSent,
                        },
                    }),
                    delivery: Mutex::new(()),
                });
                if map.len() < 64 {
                    map.insert(
                        key,
                        SinkEntry {
                            sink: Arc::downgrade(&sink),
                            shared: shared.clone(),
                        },
                    );
                }
                shared
            });
        Self { sink, shared }
    }
    pub async fn revoke(&self) {
        let mut s = self.shared.state.lock().expect("pixel state poisoned");
        s.revoked = true;
        s.epoch = s.epoch.next();
        s.latest = None;
    }
    pub async fn current_epoch(&self) -> ConsentEpoch {
        self.shared
            .state
            .lock()
            .expect("pixel state poisoned")
            .epoch
    }
    pub async fn last_delivery_progress(&self) -> usize {
        self.shared
            .state
            .lock()
            .expect("pixel state poisoned")
            .receipt
            .bytes_delivered
    }
    pub fn last_receipt(&self) -> EgressReceipt {
        self.shared
            .state
            .lock()
            .expect("pixel state poisoned")
            .receipt
            .clone()
    }
    pub async fn set_latest_frame(&self, frame: PixelFrame) {
        let mut s = self.shared.state.lock().expect("pixel state poisoned");
        if !s.revoked
            && frame.width > 0
            && frame.height > 0
            && frame.width <= MAX_PIXEL_WIDTH
            && frame.height <= MAX_PIXEL_HEIGHT
            && frame.data.len() <= MAX_PIXEL_PAYLOAD_BYTES
        {
            s.latest = Some(frame);
        }
    }
    pub async fn take_latest_frame(&self) -> Option<PixelFrame> {
        self.shared
            .state
            .lock()
            .expect("pixel state poisoned")
            .latest
            .take()
    }
    fn validate(
        &self,
        s: &SinkState,
        consent: &PixelConsent,
        frame: &PixelFrame,
        ctx: &EgressContext<'_>,
    ) -> Result<(), PixelEgressError> {
        if s.revoked {
            return Err(PixelEgressError::Revoked);
        }
        if !ctx.permissions.can_egress_pixels() {
            return Err(PixelEgressError::PermissionDenied);
        }
        let now = OffsetDateTime::now_utc();
        consent.validate(
            now,
            ctx.actor,
            ctx.auth_generation,
            ctx.session,
            ctx.target,
            ctx.requested_region,
            ctx.run_id,
            ctx.receiver,
            s.epoch,
        )?;
        match &frame.classification {
            ScreenSecurityClassification::Normal => {}
            ScreenSecurityClassification::Protected(k) => {
                return Err(PixelEgressError::ProtectedContentRefused(k.clone()));
            }
            ScreenSecurityClassification::Indeterminate => {
                return Err(PixelEgressError::IndeterminateScreenRefused);
            }
        }
        if frame.width == 0
            || frame.height == 0
            || frame.width > MAX_PIXEL_WIDTH
            || frame.height > MAX_PIXEL_HEIGHT
        {
            return Err(PixelEgressError::OversizedDimensions {
                width: frame.width,
                height: frame.height,
            });
        }
        if frame.data.is_empty() || frame.data.len() > MAX_PIXEL_PAYLOAD_BYTES {
            return Err(PixelEgressError::OversizedPayload {
                bytes: frame.data.len(),
            });
        }
        if frame.width > ctx.requested_region.width || frame.height > ctx.requested_region.height {
            return Err(PixelEgressError::ConsentValidation(
                PixelConsentError::RegionExpanded,
            ));
        }
        let origin = frame
            .origin
            .as_ref()
            .ok_or(PixelEgressError::FrameSourceUnverified)?;
        if origin.capture_id.is_empty()
            || origin.capture_id.len() > 256
            || &origin.session != ctx.session
            || &origin.target != ctx.target
            || origin.region != *ctx.requested_region
            || origin.observation.get() == 0
            || now < origin.captured_at
        {
            return Err(PixelEgressError::FrameSourceUnverified);
        }
        Ok(())
    }
    pub async fn send_frame(
        &self,
        consent: &PixelConsent,
        frame: &PixelFrame,
        ctx: &EgressContext<'_>,
    ) -> Result<EgressReceipt, PixelEgressError> {
        // Reject concurrent sends; do not retain an unbounded queue of caller-owned frames.
        let _delivery = self
            .shared
            .delivery
            .try_lock()
            .map_err(|_| PixelEgressError::Busy)?;
        {
            let mut s = self.shared.state.lock().expect("pixel state poisoned");
            if s.poisoned {
                return Err(PixelEgressError::DeliveryUnconfirmed {
                    confirmed_bytes: s.receipt.bytes_delivered,
                    unconfirmed_bytes: s.receipt.bytes_unconfirmed,
                });
            }
            s.receipt = EgressReceipt {
                bytes_delivered: 0,
                bytes_unconfirmed: 0,
                epoch: s.epoch,
                status: EgressStatus::NotSent,
            };
            self.validate(&s, consent, frame, ctx)?;
            if s.last_start
                .is_some_and(|t| t.elapsed() < StdDuration::from_millis(200))
            {
                return Err(PixelEgressError::RateLimitExceeded);
            }
            s.last_start = Some(Instant::now());
            s.receipt.status = EgressStatus::InFlight;
        }
        let _progress = FrameProgress(&self.shared);
        let result = timeout(SINK_CHUNK_TIMEOUT, async {
            for chunk in frame.data.chunks(STREAM_CHUNK_SIZE) {
                let gate = PixelDeliveryGate {
                    coordinator: self,
                    consent,
                    frame,
                    ctx,
                    bytes: chunk.len(),
                    dispatched: AtomicBool::new(false),
                };
                {
                    let s = self.shared.state.lock().expect("pixel state poisoned");
                    if self.validate(&s, consent, frame, ctx).is_err() {
                        return Err(PixelEgressError::RevokedMidStream {
                            bytes_delivered: s.receipt.bytes_delivered,
                        });
                    }
                }
                let result = self.sink.deliver_chunk(chunk, &gate).await;
                let mut s = self.shared.state.lock().expect("pixel state poisoned");
                if result.is_err() || !gate.dispatched.load(Ordering::SeqCst) {
                    if s.receipt.bytes_delivered == 0 && s.receipt.bytes_unconfirmed == 0 {
                        s.receipt.status = EgressStatus::NotSent;
                        return Err(PixelEgressError::SinkDeliveryFailed(
                            "pixel_submission_refused".into(),
                        ));
                    }
                    return Err(PixelEgressError::DeliveryUnconfirmed {
                        confirmed_bytes: s.receipt.bytes_delivered,
                        unconfirmed_bytes: s.receipt.bytes_unconfirmed,
                    });
                }
                s.receipt.bytes_delivered += chunk.len();
                s.receipt.bytes_unconfirmed = 0;
                if self.validate(&s, consent, frame, ctx).is_err() {
                    s.receipt.status = EgressStatus::PartialRevocation;
                    return Err(PixelEgressError::RevokedMidStream {
                        bytes_delivered: s.receipt.bytes_delivered,
                    });
                }
            }
            let gate = PixelDeliveryGate {
                coordinator: self,
                consent,
                frame,
                ctx,
                bytes: 0,
                dispatched: AtomicBool::new(false),
            };
            let result = self.sink.finish(&gate).await;
            let mut s = self.shared.state.lock().expect("pixel state poisoned");
            if result.is_err() || !gate.dispatched.load(Ordering::SeqCst) {
                return Err(PixelEgressError::DeliveryUnconfirmed {
                    confirmed_bytes: s.receipt.bytes_delivered,
                    unconfirmed_bytes: s.receipt.bytes_unconfirmed,
                });
            }
            s.receipt.status = if self.validate(&s, consent, frame, ctx).is_ok() {
                EgressStatus::Success
            } else {
                EgressStatus::ConfirmedWhileRevoked
            };
            Ok(s.receipt.clone())
        })
        .await;
        result.unwrap_or_else(|_| {
            let s = self.shared.state.lock().expect("pixel state poisoned");
            Err(PixelEgressError::DeliveryUnconfirmed {
                confirmed_bytes: s.receipt.bytes_delivered,
                unconfirmed_bytes: s.receipt.bytes_unconfirmed,
            })
        })
    }
}
struct FrameProgress<'a>(&'a SharedSink);
impl Drop for FrameProgress<'_> {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.state.lock()
            && s.receipt.status == EgressStatus::InFlight
        {
            if s.receipt.bytes_delivered == 0 && s.receipt.bytes_unconfirmed == 0 {
                s.receipt.status = EgressStatus::NotSent;
            } else {
                s.receipt.status = EgressStatus::Unknown;
                s.poisoned = true;
            }
        }
    }
}
pub struct PixelDeliveryGate<'a> {
    coordinator: &'a PixelEgressCoordinator,
    consent: &'a PixelConsent,
    frame: &'a PixelFrame,
    ctx: &'a EgressContext<'a>,
    bytes: usize,
    dispatched: AtomicBool,
}
impl PixelDeliveryGate<'_> {
    pub fn dispatch(&self, effect: impl FnOnce()) -> Result<(), SinkError> {
        let mut s = self
            .coordinator
            .shared
            .state
            .lock()
            .map_err(|_| SinkError("pixel_state_unavailable".into()))?;
        self.coordinator
            .validate(&s, self.consent, self.frame, self.ctx)
            .map_err(|_| SinkError("pixel_authority_refused".into()))?;
        if self.dispatched.load(Ordering::SeqCst) {
            return Err(SinkError("pixel_dispatch_used".into()));
        }
        let mut effect = Some(effect);
        self.coordinator.sink.with_current_egress(
            self.consent,
            self.frame,
            self.ctx,
            &mut || {
                let effect = effect
                    .take()
                    .ok_or_else(|| SinkError("pixel_dispatch_used".into()))?;
                self.dispatched.store(true, Ordering::SeqCst);
                s.receipt.bytes_unconfirmed = self.bytes;
                effect();
                Ok(())
            },
        )?;
        if !self.dispatched.load(Ordering::SeqCst) {
            return Err(SinkError("pixel_authority_unavailable".into()));
        }
        Ok(())
    }
}
