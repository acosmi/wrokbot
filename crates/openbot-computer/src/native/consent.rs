//! Independent pixel consent, four-way permission boundary, and receiver binding (v5 §10.7 / PA-04).
//!
//! OS capture permission, product read permission, native control approval, and model pixel consent
//! are four distinct facts. Consent is explicitly approved by the local user, binds actor,
//! OS session, target, region, run, and model receiver, and expires within the current run (<= 15m).

use core::fmt;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, RunId};
use time::{Duration, OffsetDateTime};

use super::identity::{NativeTargetHandle, OsSessionId};

/// Maximum allowable consent duration (15 minutes).
pub const MAX_CONSENT_DURATION: Duration = Duration::minutes(15);

/// Monotonic consent revocation epoch. Advances upon revocation or permission change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsentEpoch(u64);

impl ConsentEpoch {
    /// Construct consent epoch.
    #[must_use]
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance epoch.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for ConsentEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Bounded rectangular pixel region on a native display or window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PixelRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl PixelRegion {
    /// Construct a pixel region.
    #[must_use]
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Verify whether `self` is fully contained within the consented `bounds`.
    #[must_use]
    pub fn is_within(&self, bounds: &PixelRegion) -> bool {
        if self.is_empty() || bounds.is_empty() {
            return false;
        }
        let Some(self_right) = self.x.checked_add(self.width) else {
            return false;
        };
        let Some(self_bottom) = self.y.checked_add(self.height) else {
            return false;
        };
        let Some(bounds_right) = bounds.x.checked_add(bounds.width) else {
            return false;
        };
        let Some(bounds_bottom) = bounds.y.checked_add(bounds.height) else {
            return false;
        };
        self.x >= bounds.x
            && self.y >= bounds.y
            && self_right <= bounds_right
            && self_bottom <= bounds_bottom
    }

    /// Check if dimensions are zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// External model receiver identity binding connection, model, revision, account, and endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelReceiver {
    pub connection_id: String,
    pub model: String,
    pub source_revision: i64,
    pub account_id: String,
    pub endpoint: String,
}

impl ModelReceiver {
    /// Construct a model receiver identity.
    #[must_use]
    pub fn new(
        connection_id: impl Into<String>,
        model: impl Into<String>,
        source_revision: i64,
        account_id: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            connection_id: connection_id.into(),
            model: model.into(),
            source_revision,
            account_id: account_id.into(),
            endpoint: endpoint.into(),
        }
    }

    /// Verify exact receiver equality.
    #[must_use]
    pub fn matches(&self, other: &ModelReceiver) -> bool {
        self == other
    }

    /// Check if other is a legal same-account token refresh without endpoint or model drift.
    #[must_use]
    pub fn is_same_account_refresh(&self, other: &ModelReceiver) -> bool {
        self.account_id == other.account_id
            && self.endpoint == other.endpoint
            && self.model == other.model
    }
}

/// Four-way permission status maintaining strict separation between facts (§10.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourWayPermissions {
    pub os_capture_permitted: bool,
    pub product_read_permitted: bool,
    pub native_control_approved: bool,
    pub pixel_consent_granted: bool,
}

impl FourWayPermissions {
    /// Check whether pixel egress is authorized.
    ///
    /// Notice: does NOT require `native_control_approved`, and `native_control_approved`
    /// does NOT imply `pixel_consent_granted`.
    #[must_use]
    pub fn can_egress_pixels(&self) -> bool {
        self.os_capture_permitted && self.product_read_permitted && self.pixel_consent_granted
    }
}

/// Error returned when consent validation fails.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PixelConsentError {
    #[error("pixel_consent_missing")]
    MissingConsent,
    #[error("pixel_consent_expired")]
    Expired,
    #[error("pixel_consent_duration_exceeded")]
    DurationExceeded,
    #[error("pixel_consent_actor_mismatch")]
    ActorMismatch,
    #[error("pixel_consent_auth_generation_mismatch")]
    AuthGenerationMismatch,
    #[error("pixel_consent_session_mismatch")]
    SessionMismatch,
    #[error("pixel_consent_target_mismatch")]
    TargetMismatch,
    #[error("pixel_consent_region_expanded")]
    RegionExpanded,
    #[error("pixel_consent_run_mismatch")]
    RunMismatch,
    #[error("pixel_consent_receiver_mismatch")]
    ReceiverMismatch,
    #[error("pixel_consent_epoch_stale")]
    EpochStale,
    #[error("pixel_consent_account_changed")]
    AccountChanged,
    #[error("pixel_consent_revoked")]
    Revoked,
}

/// Builder provided by trusted local user approval seam to issue a valid consent.
pub struct PixelConsentGrant {
    pub consent_id: String,
    pub actor: ActorId,
    pub auth_generation: AuthGeneration,
    pub os_session: OsSessionId,
    pub target_handle: NativeTargetHandle,
    pub region: PixelRegion,
    pub run_id: RunId,
    pub receiver: ModelReceiver,
    pub consent_epoch: ConsentEpoch,
    pub granted_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl PixelConsentGrant {
    /// Validate consent metadata; the current authority port must verify its issuer and validity.
    pub fn issue(self) -> Result<PixelConsent, PixelConsentError> {
        if self.expires_at <= self.granted_at {
            return Err(PixelConsentError::Expired);
        }
        if (self.expires_at - self.granted_at) > MAX_CONSENT_DURATION {
            return Err(PixelConsentError::DurationExceeded);
        }
        if !self.region.is_within(&self.region) {
            return Err(PixelConsentError::RegionExpanded);
        }

        Ok(PixelConsent {
            consent_id: self.consent_id,
            actor: self.actor,
            auth_generation: self.auth_generation,
            os_session: self.os_session,
            target_handle: self.target_handle,
            region: self.region,
            run_id: self.run_id,
            receiver: self.receiver,
            consent_epoch: self.consent_epoch,
            granted_at: self.granted_at,
            expires_at: self.expires_at,
        })
    }
}

/// Validated consent metadata. Private fields do not by themselves prove user authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PixelConsent {
    consent_id: String,
    actor: ActorId,
    auth_generation: AuthGeneration,
    os_session: OsSessionId,
    target_handle: NativeTargetHandle,
    region: PixelRegion,
    run_id: RunId,
    receiver: ModelReceiver,
    consent_epoch: ConsentEpoch,
    granted_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl PixelConsent {
    /// Validate this consent token against current call context before sending pixels.
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        now: OffsetDateTime,
        actor: &ActorId,
        auth_generation: AuthGeneration,
        session: &OsSessionId,
        target: &NativeTargetHandle,
        requested_region: &PixelRegion,
        run_id: &RunId,
        current_receiver: &ModelReceiver,
        current_epoch: ConsentEpoch,
    ) -> Result<(), PixelConsentError> {
        if now < self.granted_at || now >= self.expires_at {
            return Err(PixelConsentError::Expired);
        }
        if self.consent_epoch != current_epoch {
            return Err(PixelConsentError::EpochStale);
        }
        if &self.actor != actor {
            return Err(PixelConsentError::ActorMismatch);
        }
        if self.auth_generation != auth_generation {
            return Err(PixelConsentError::AuthGenerationMismatch);
        }
        if &self.os_session != session {
            return Err(PixelConsentError::SessionMismatch);
        }
        if &self.target_handle != target {
            return Err(PixelConsentError::TargetMismatch);
        }
        if !requested_region.is_within(&self.region) {
            return Err(PixelConsentError::RegionExpanded);
        }
        if &self.run_id != run_id {
            return Err(PixelConsentError::RunMismatch);
        }
        if &self.receiver != current_receiver {
            if self.receiver.account_id != current_receiver.account_id {
                return Err(PixelConsentError::AccountChanged);
            }
            return Err(PixelConsentError::ReceiverMismatch);
        }
        Ok(())
    }

    /// Consent ID accessor.
    #[must_use]
    pub fn consent_id(&self) -> &str {
        &self.consent_id
    }

    /// Target handle accessor.
    #[must_use]
    pub fn target_handle(&self) -> &NativeTargetHandle {
        &self.target_handle
    }

    /// Region accessor.
    #[must_use]
    pub fn region(&self) -> PixelRegion {
        self.region
    }

    /// Model receiver accessor.
    #[must_use]
    pub fn receiver(&self) -> &ModelReceiver {
        &self.receiver
    }

    /// Run ID accessor.
    #[must_use]
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Consent epoch accessor.
    #[must_use]
    pub fn consent_epoch(&self) -> ConsentEpoch {
        self.consent_epoch
    }

    /// Expiration time accessor.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}
