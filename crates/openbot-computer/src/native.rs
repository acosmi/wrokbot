//! Native computer control and pixel egress coordination (v5 §10.7 / PA-04).

pub mod consent;
pub mod control;
pub mod identity;
pub mod pixel_egress;
pub mod runtime;

#[cfg(test)]
pub mod consent_tests;
#[cfg(test)]
pub mod control_tests;

pub use consent::{
    ConsentEpoch, FourWayPermissions, MAX_CONSENT_DURATION, ModelReceiver, PixelConsent,
    PixelConsentError, PixelConsentGrant, PixelRegion,
};
pub use control::{
    ActionCapability, InjectedInputState, NativeActionStatus, NativeControlError,
    NativeControlHolder, NativeReceipt, NativeSessionEpoch,
};
pub use identity::{
    BootId, CoordinateTransform, LogicalRect, MouseButton, NativeAction, NativeActionCategory,
    NativeDisplayId, NativeKey, NativeModifier, NativeTarget, NativeTargetHandle, NativeWindowId,
    ObservationGeneration, OsSessionId,
};
pub use pixel_egress::{
    EgressContext, EgressReceipt, EgressStatus, MAX_PIXEL_HEIGHT, MAX_PIXEL_PAYLOAD_BYTES,
    MAX_PIXEL_WIDTH, MIN_FRAME_INTERVAL, PixelDeliveryGate, PixelEgressCoordinator,
    PixelEgressError, PixelFrame, PixelFrameOrigin, PixelSinkPort, ProtectedScreenKind,
    STREAM_CHUNK_SIZE, ScreenSecurityClassification, SinkError,
};
pub use runtime::{
    ACTION_TIMEOUT, MAX_OBSERVATION_AGE, MAX_PENDING_ACTIONS, NativeActionGate, NativeCleanupGate,
    NativeEnvironmentChange, NativeInjectionOutcome, NativePlatformError, NativePlatformPort,
    NativeSessionCoordinator, NativeSessionHandle, NativeSessionRegistry, NativeSessionState,
    STOP_CLEANUP_TIMEOUT,
};
