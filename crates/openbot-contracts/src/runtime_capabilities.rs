//! Closed authenticated runtime-capability wire values and deterministic validation.
//! Host facts and current authority are produced by actual Rust hosts, outside this DTO.

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize};

/// Fixed public projection schema.
pub const RUNTIME_CAPABILITY_SCHEMA_VERSION: u8 = 1;
/// Exact number of capability entries.
pub const RUNTIME_CAPABILITY_COUNT: usize = 13;
/// Public opaque revision byte limit.
pub const MAX_RUNTIME_CAPABILITY_REVISION_BYTES: usize = 64;

/// Closed public CapabilityId literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeCapabilityId {
    /// `workspace`.
    #[serde(rename = "workspace")]
    Workspace,
    /// `agent_tools`.
    #[serde(rename = "agent_tools")]
    AgentTools,
    /// `model_custom_v1`.
    #[serde(rename = "model_custom_v1")]
    ModelCustomV1,
    /// `model_selection_v2`.
    #[serde(rename = "model_selection_v2")]
    ModelSelectionV2,
    /// `model_sdk_gateway`.
    #[serde(rename = "model_sdk_gateway")]
    ModelSdkGateway,
    /// `model_account_bridge`.
    #[serde(rename = "model_account_bridge")]
    ModelAccountBridge,
    /// `browser_control`.
    #[serde(rename = "browser_control")]
    BrowserControl,
    /// `native_control`.
    #[serde(rename = "native_control")]
    NativeControl,
    /// `pixel_egress`.
    #[serde(rename = "pixel_egress")]
    PixelEgress,
    /// `local_confirmation`.
    #[serde(rename = "local_confirmation")]
    LocalConfirmation,
    /// `backup_restore`.
    #[serde(rename = "backup_restore")]
    BackupRestore,
    /// `dynamic_sso`.
    #[serde(rename = "dynamic_sso")]
    DynamicSso,
    /// `device_pairing`.
    #[serde(rename = "device_pairing")]
    DevicePairing,
}

impl RuntimeCapabilityId {
    /// Exact stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::AgentTools => "agent_tools",
            Self::ModelCustomV1 => "model_custom_v1",
            Self::ModelSelectionV2 => "model_selection_v2",
            Self::ModelSdkGateway => "model_sdk_gateway",
            Self::ModelAccountBridge => "model_account_bridge",
            Self::BrowserControl => "browser_control",
            Self::NativeControl => "native_control",
            Self::PixelEgress => "pixel_egress",
            Self::LocalConfirmation => "local_confirmation",
            Self::BackupRestore => "backup_restore",
            Self::DynamicSso => "dynamic_sso",
            Self::DevicePairing => "device_pairing",
        }
    }
}

/// Closed public CapabilityState literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeCapabilityState {
    /// `unsupported`.
    #[serde(rename = "unsupported")]
    Unsupported,
    /// `unconfigured`.
    #[serde(rename = "unconfigured")]
    Unconfigured,
    /// `permission_required`.
    #[serde(rename = "permission_required")]
    PermissionRequired,
    /// `ready`.
    #[serde(rename = "ready")]
    Ready,
    /// `unavailable`.
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl RuntimeCapabilityState {
    /// Exact stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Unconfigured => "unconfigured",
            Self::PermissionRequired => "permission_required",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Closed public ReasonCode literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeCapabilityReasonCode {
    /// `current_checks_available`.
    #[serde(rename = "current_checks_available")]
    CurrentChecksAvailable,
    /// `platform_unimplemented`.
    #[serde(rename = "platform_unimplemented")]
    PlatformUnimplemented,
    /// `independent_api_missing`.
    #[serde(rename = "independent_api_missing")]
    IndependentApiMissing,
    /// `support_unproven`.
    #[serde(rename = "support_unproven")]
    SupportUnproven,
    /// `release_dependency_missing`.
    #[serde(rename = "release_dependency_missing")]
    ReleaseDependencyMissing,
    /// `release_dependency_unproven`.
    #[serde(rename = "release_dependency_unproven")]
    ReleaseDependencyUnproven,
    /// `policy_unconfigured`.
    #[serde(rename = "policy_unconfigured")]
    PolicyUnconfigured,
    /// `policy_empty`.
    #[serde(rename = "policy_empty")]
    PolicyEmpty,
    /// `policy_invalid`.
    #[serde(rename = "policy_invalid")]
    PolicyInvalid,
    /// `policy_unproven`.
    #[serde(rename = "policy_unproven")]
    PolicyUnproven,
    /// `model_key_missing`.
    #[serde(rename = "model_key_missing")]
    ModelKeyMissing,
    /// `model_key_unproven`.
    #[serde(rename = "model_key_unproven")]
    ModelKeyUnproven,
    /// `configuration_missing`.
    #[serde(rename = "configuration_missing")]
    ConfigurationMissing,
    /// `configuration_invalid`.
    #[serde(rename = "configuration_invalid")]
    ConfigurationInvalid,
    /// `configuration_unproven`.
    #[serde(rename = "configuration_unproven")]
    ConfigurationUnproven,
    /// `account_bridge_source_blocked`.
    #[serde(rename = "account_bridge_source_blocked")]
    AccountBridgeSourceBlocked,
    /// `account_bridge_source_unproven`.
    #[serde(rename = "account_bridge_source_unproven")]
    AccountBridgeSourceUnproven,
    /// `product_permission_required`.
    #[serde(rename = "product_permission_required")]
    ProductPermissionRequired,
    /// `product_permission_unproven`.
    #[serde(rename = "product_permission_unproven")]
    ProductPermissionUnproven,
    /// `os_permission_capture_required`.
    #[serde(rename = "os_permission_capture_required")]
    OsPermissionCaptureRequired,
    /// `os_permission_accessibility_required`.
    #[serde(rename = "os_permission_accessibility_required")]
    OsPermissionAccessibilityRequired,
    /// `os_permission_input_required`.
    #[serde(rename = "os_permission_input_required")]
    OsPermissionInputRequired,
    /// `os_permission_unproven`.
    #[serde(rename = "os_permission_unproven")]
    OsPermissionUnproven,
    /// `os_permission_expired`.
    #[serde(rename = "os_permission_expired")]
    OsPermissionExpired,
    /// `local_confirmation_required`.
    #[serde(rename = "local_confirmation_required")]
    LocalConfirmationRequired,
    /// `local_confirmation_pending`.
    #[serde(rename = "local_confirmation_pending")]
    LocalConfirmationPending,
    /// `local_confirmation_unavailable`.
    #[serde(rename = "local_confirmation_unavailable")]
    LocalConfirmationUnavailable,
    /// `local_confirmation_unproven`.
    #[serde(rename = "local_confirmation_unproven")]
    LocalConfirmationUnproven,
    /// `local_confirmation_expired`.
    #[serde(rename = "local_confirmation_expired")]
    LocalConfirmationExpired,
    /// `pixel_consent_required`.
    #[serde(rename = "pixel_consent_required")]
    PixelConsentRequired,
    /// `pixel_consent_unproven`.
    #[serde(rename = "pixel_consent_unproven")]
    PixelConsentUnproven,
    /// `pixel_consent_expired`.
    #[serde(rename = "pixel_consent_expired")]
    PixelConsentExpired,
    /// `computer_source_missing`.
    #[serde(rename = "computer_source_missing")]
    ComputerSourceMissing,
    /// `native_source_missing`.
    #[serde(rename = "native_source_missing")]
    NativeSourceMissing,
    /// `screen_source_missing`.
    #[serde(rename = "screen_source_missing")]
    ScreenSourceMissing,
    /// `source_unproven`.
    #[serde(rename = "source_unproven")]
    SourceUnproven,
    /// `source_expired`.
    #[serde(rename = "source_expired")]
    SourceExpired,
    /// `provider_disconnected`.
    #[serde(rename = "provider_disconnected")]
    ProviderDisconnected,
    /// `provider_unproven`.
    #[serde(rename = "provider_unproven")]
    ProviderUnproven,
    /// `provider_expired`.
    #[serde(rename = "provider_expired")]
    ProviderExpired,
}

impl RuntimeCapabilityReasonCode {
    /// Exact stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentChecksAvailable => "current_checks_available",
            Self::PlatformUnimplemented => "platform_unimplemented",
            Self::IndependentApiMissing => "independent_api_missing",
            Self::SupportUnproven => "support_unproven",
            Self::ReleaseDependencyMissing => "release_dependency_missing",
            Self::ReleaseDependencyUnproven => "release_dependency_unproven",
            Self::PolicyUnconfigured => "policy_unconfigured",
            Self::PolicyEmpty => "policy_empty",
            Self::PolicyInvalid => "policy_invalid",
            Self::PolicyUnproven => "policy_unproven",
            Self::ModelKeyMissing => "model_key_missing",
            Self::ModelKeyUnproven => "model_key_unproven",
            Self::ConfigurationMissing => "configuration_missing",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::ConfigurationUnproven => "configuration_unproven",
            Self::AccountBridgeSourceBlocked => "account_bridge_source_blocked",
            Self::AccountBridgeSourceUnproven => "account_bridge_source_unproven",
            Self::ProductPermissionRequired => "product_permission_required",
            Self::ProductPermissionUnproven => "product_permission_unproven",
            Self::OsPermissionCaptureRequired => "os_permission_capture_required",
            Self::OsPermissionAccessibilityRequired => "os_permission_accessibility_required",
            Self::OsPermissionInputRequired => "os_permission_input_required",
            Self::OsPermissionUnproven => "os_permission_unproven",
            Self::OsPermissionExpired => "os_permission_expired",
            Self::LocalConfirmationRequired => "local_confirmation_required",
            Self::LocalConfirmationPending => "local_confirmation_pending",
            Self::LocalConfirmationUnavailable => "local_confirmation_unavailable",
            Self::LocalConfirmationUnproven => "local_confirmation_unproven",
            Self::LocalConfirmationExpired => "local_confirmation_expired",
            Self::PixelConsentRequired => "pixel_consent_required",
            Self::PixelConsentUnproven => "pixel_consent_unproven",
            Self::PixelConsentExpired => "pixel_consent_expired",
            Self::ComputerSourceMissing => "computer_source_missing",
            Self::NativeSourceMissing => "native_source_missing",
            Self::ScreenSourceMissing => "screen_source_missing",
            Self::SourceUnproven => "source_unproven",
            Self::SourceExpired => "source_expired",
            Self::ProviderDisconnected => "provider_disconnected",
            Self::ProviderUnproven => "provider_unproven",
            Self::ProviderExpired => "provider_expired",
        }
    }
}

/// Closed public HostMode literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeCapabilityHostMode {
    /// `desktop_local`.
    #[serde(rename = "desktop_local")]
    DesktopLocal,
    /// `desktop_remote`.
    #[serde(rename = "desktop_remote")]
    DesktopRemote,
    /// `server`.
    #[serde(rename = "server")]
    Server,
    /// `mobile_remote`.
    #[serde(rename = "mobile_remote")]
    MobileRemote,
}

impl RuntimeCapabilityHostMode {
    /// Exact stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesktopLocal => "desktop_local",
            Self::DesktopRemote => "desktop_remote",
            Self::Server => "server",
            Self::MobileRemote => "mobile_remote",
        }
    }
}

/// Exact public entry order.
pub const ORDERED_RUNTIME_CAPABILITY_IDS: [RuntimeCapabilityId; RUNTIME_CAPABILITY_COUNT] = [
    RuntimeCapabilityId::Workspace,
    RuntimeCapabilityId::AgentTools,
    RuntimeCapabilityId::ModelCustomV1,
    RuntimeCapabilityId::ModelSelectionV2,
    RuntimeCapabilityId::ModelSdkGateway,
    RuntimeCapabilityId::ModelAccountBridge,
    RuntimeCapabilityId::BrowserControl,
    RuntimeCapabilityId::NativeControl,
    RuntimeCapabilityId::PixelEgress,
    RuntimeCapabilityId::LocalConfirmation,
    RuntimeCapabilityId::BackupRestore,
    RuntimeCapabilityId::DynamicSso,
    RuntimeCapabilityId::DevicePairing,
];

impl RuntimeCapabilityReasonCode {
    /// The only state compatible with this closed reason.
    #[must_use]
    pub const fn state(self) -> RuntimeCapabilityState {
        match self {
            Self::CurrentChecksAvailable => RuntimeCapabilityState::Ready,
            Self::PlatformUnimplemented => RuntimeCapabilityState::Unsupported,
            Self::IndependentApiMissing => RuntimeCapabilityState::Unsupported,
            Self::SupportUnproven => RuntimeCapabilityState::Unavailable,
            Self::ReleaseDependencyMissing => RuntimeCapabilityState::Unavailable,
            Self::ReleaseDependencyUnproven => RuntimeCapabilityState::Unavailable,
            Self::PolicyUnconfigured => RuntimeCapabilityState::Unconfigured,
            Self::PolicyEmpty => RuntimeCapabilityState::Unconfigured,
            Self::PolicyInvalid => RuntimeCapabilityState::Unconfigured,
            Self::PolicyUnproven => RuntimeCapabilityState::Unavailable,
            Self::ModelKeyMissing => RuntimeCapabilityState::Unconfigured,
            Self::ModelKeyUnproven => RuntimeCapabilityState::Unavailable,
            Self::ConfigurationMissing => RuntimeCapabilityState::Unconfigured,
            Self::ConfigurationInvalid => RuntimeCapabilityState::Unconfigured,
            Self::ConfigurationUnproven => RuntimeCapabilityState::Unavailable,
            Self::AccountBridgeSourceBlocked => RuntimeCapabilityState::Unconfigured,
            Self::AccountBridgeSourceUnproven => RuntimeCapabilityState::Unavailable,
            Self::ProductPermissionRequired => RuntimeCapabilityState::PermissionRequired,
            Self::ProductPermissionUnproven => RuntimeCapabilityState::Unavailable,
            Self::OsPermissionCaptureRequired => RuntimeCapabilityState::PermissionRequired,
            Self::OsPermissionAccessibilityRequired => RuntimeCapabilityState::PermissionRequired,
            Self::OsPermissionInputRequired => RuntimeCapabilityState::PermissionRequired,
            Self::OsPermissionUnproven => RuntimeCapabilityState::Unavailable,
            Self::OsPermissionExpired => RuntimeCapabilityState::Unavailable,
            Self::LocalConfirmationRequired => RuntimeCapabilityState::PermissionRequired,
            Self::LocalConfirmationPending => RuntimeCapabilityState::PermissionRequired,
            Self::LocalConfirmationUnavailable => RuntimeCapabilityState::Unavailable,
            Self::LocalConfirmationUnproven => RuntimeCapabilityState::Unavailable,
            Self::LocalConfirmationExpired => RuntimeCapabilityState::Unavailable,
            Self::PixelConsentRequired => RuntimeCapabilityState::PermissionRequired,
            Self::PixelConsentUnproven => RuntimeCapabilityState::Unavailable,
            Self::PixelConsentExpired => RuntimeCapabilityState::Unavailable,
            Self::ComputerSourceMissing => RuntimeCapabilityState::Unavailable,
            Self::NativeSourceMissing => RuntimeCapabilityState::Unavailable,
            Self::ScreenSourceMissing => RuntimeCapabilityState::Unavailable,
            Self::SourceUnproven => RuntimeCapabilityState::Unavailable,
            Self::SourceExpired => RuntimeCapabilityState::Unavailable,
            Self::ProviderDisconnected => RuntimeCapabilityState::Unavailable,
            Self::ProviderUnproven => RuntimeCapabilityState::Unavailable,
            Self::ProviderExpired => RuntimeCapabilityState::Unavailable,
        }
    }
}

/// Sanitized deterministic public-shape rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCapabilitiesWireError {
    /// Projection schema differs from the fixed public schema.
    SchemaVersion,
    /// Revision is empty, overbound or contains a forbidden byte.
    Revision,
    /// Capability count, order or uniqueness differs from the fixed vector.
    Order,
    /// A closed state and reason do not describe the same blocker class.
    StateReason,
}
impl fmt::Display for RuntimeCapabilitiesWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SchemaVersion => "runtime_capabilities_schema_invalid",
            Self::Revision => "runtime_capabilities_revision_invalid",
            Self::Order => "runtime_capabilities_order_invalid",
            Self::StateReason => "runtime_capabilities_state_reason_invalid",
        })
    }
}
impl std::error::Error for RuntimeCapabilitiesWireError {}

/// One validated, content-free capability projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilityEntry {
    id: RuntimeCapabilityId,
    state: RuntimeCapabilityState,
    reason_code: RuntimeCapabilityReasonCode,
}
impl RuntimeCapabilityEntry {
    /// Validate the closed state/reason relationship.
    pub fn try_new(
        id: RuntimeCapabilityId,
        state: RuntimeCapabilityState,
        reason_code: RuntimeCapabilityReasonCode,
    ) -> Result<Self, RuntimeCapabilitiesWireError> {
        if reason_code.state() != state {
            return Err(RuntimeCapabilitiesWireError::StateReason);
        }
        Ok(Self {
            id,
            state,
            reason_code,
        })
    }
    /// Stable capability identifier.
    #[must_use]
    pub const fn id(self) -> RuntimeCapabilityId {
        self.id
    }
    /// Closed current projection state.
    #[must_use]
    pub const fn state(self) -> RuntimeCapabilityState {
        self.state
    }
    /// Closed reason; no remote prose.
    #[must_use]
    pub const fn reason_code(self) -> RuntimeCapabilityReasonCode {
        self.reason_code
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEntry {
    id: RuntimeCapabilityId,
    state: RuntimeCapabilityState,
    reason_code: RuntimeCapabilityReasonCode,
}
impl<'de> Deserialize<'de> for RuntimeCapabilityEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawEntry::deserialize(deserializer)?;
        Self::try_new(raw.id, raw.state, raw.reason_code).map_err(serde::de::Error::custom)
    }
}

/// Complete validated public projection; it does not grant subsequent action authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilitiesResponse {
    schema_version: u8,
    host_mode: RuntimeCapabilityHostMode,
    revision: String,
    capabilities: [RuntimeCapabilityEntry; RUNTIME_CAPABILITY_COUNT],
}
impl RuntimeCapabilitiesResponse {
    /// Validate public revision bounds and the exact entry vector.
    pub fn try_new(
        host_mode: RuntimeCapabilityHostMode,
        revision: String,
        capabilities: [RuntimeCapabilityEntry; RUNTIME_CAPABILITY_COUNT],
    ) -> Result<Self, RuntimeCapabilitiesWireError> {
        if revision.is_empty()
            || revision.len() > MAX_RUNTIME_CAPABILITY_REVISION_BYTES
            || !revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(RuntimeCapabilitiesWireError::Revision);
        }
        if capabilities
            .iter()
            .zip(ORDERED_RUNTIME_CAPABILITY_IDS)
            .any(|(entry, id)| entry.id() != id)
        {
            return Err(RuntimeCapabilitiesWireError::Order);
        }
        Ok(Self {
            schema_version: RUNTIME_CAPABILITY_SCHEMA_VERSION,
            host_mode,
            revision,
            capabilities,
        })
    }
    /// Exact public schema.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }
    /// Rust-minted projection mode, not a client authority input.
    #[must_use]
    pub const fn host_mode(&self) -> RuntimeCapabilityHostMode {
        self.host_mode
    }
    /// Nonsecret opaque observation revision, not a permission token.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
    /// Exact ordered entries.
    #[must_use]
    pub const fn capabilities(&self) -> &[RuntimeCapabilityEntry; RUNTIME_CAPABILITY_COUNT] {
        &self.capabilities
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawResponse {
    schema_version: u8,
    host_mode: RuntimeCapabilityHostMode,
    revision: String,
    capabilities: [RuntimeCapabilityEntry; RUNTIME_CAPABILITY_COUNT],
}
impl<'de> Deserialize<'de> for RuntimeCapabilitiesResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawResponse::deserialize(deserializer)?;
        if raw.schema_version != RUNTIME_CAPABILITY_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                RuntimeCapabilitiesWireError::SchemaVersion,
            ));
        }
        Self::try_new(raw.host_mode, raw.revision, raw.capabilities)
            .map_err(serde::de::Error::custom)
    }
}
