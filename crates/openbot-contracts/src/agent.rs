//! Remote Agent administration wire types.

use core::fmt;
use std::sync::Arc;

use serde::de::Error as _;
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::ids::BotId;

/// Fixed upstream Agent form limits. Application repeats them for typed in-process callers.
pub const MAX_AGENT_NAME_BYTES: usize = 80;
/// Maximum short title size.
pub const MAX_AGENT_TITLE_BYTES: usize = 120;
/// Maximum standing-role description size.
pub const MAX_AGENT_ROLE_DESCRIPTION_BYTES: usize = 1_000;
/// Maximum remote AG-UI endpoint size.
pub const MAX_AGENT_ENDPOINT_BYTES: usize = 8 * 1_024;
/// Maximum write-only remote Agent authorization value size.
pub const MAX_AGENT_AUTH_BYTES: usize = 16 * 1_024;

/// Browser-visible coworker visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentVisibility {
    /// Visible to every authenticated actor.
    Public,
    /// Visible only to the owner and administrators.
    Private,
}

/// Closed coworker projection; no credential value or raw configuration crosses this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentProfile {
    /// Agent identity.
    pub id: BotId,
    /// Display name.
    pub name: String,
    /// Short title.
    pub title: String,
    /// Standing role description.
    pub role_description: String,
    /// Deterministic avatar seed.
    pub avatar_seed: String,
    /// Public/private visibility.
    pub visibility: AgentVisibility,
    /// Remote AG-UI endpoint, or `None` for built-in.
    pub endpoint: Option<String>,
    /// Whether a write-only outbound auth reference exists; never the key.
    pub has_auth: bool,
    /// Whether a hash-only callback credential exists; never the token.
    pub has_callback_token: bool,
    /// Per-current-user hidden state.
    pub hidden: bool,
    /// Whether the profile came from a deployment package.
    pub system_owned: bool,
    /// Server-decided current-actor management permission.
    pub can_manage: bool,
    /// Whether the current actor owns this profile.
    pub mine: bool,
}

/// Exact `GET /api/agents` response envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfilesResponse {
    /// Visible profiles.
    pub agents: Vec<AgentProfile>,
}

/// Exact `GET /api/agents/{agent_id}` response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfileResponse {
    /// Visible profile.
    pub agent: AgentProfile,
}

/// Write-only customer Agent authorization. Clone shares one zeroizing allocation and Debug never
/// renders either the endpoint credential or a prefix that could be tested offline.
#[derive(Clone)]
pub struct AgentAuthInput {
    header: String,
    value: Arc<Zeroizing<String>>,
}

impl AgentAuthInput {
    /// Validate the closed remote-Agent authentication channel.
    ///
    /// The fixed product form sends `Authorization`; arbitrary header names would require a second
    /// redirect-stripping policy in the unique SafeDialer, so they are rejected rather than stored
    /// and silently ignored.
    pub fn new(header: String, value: String) -> Result<Self, AgentWireError> {
        Self::with_zeroizing_value(header, Zeroizing::new(value))
    }

    /// Validate an already zeroizing input allocation; rejection and trimming keep the secret
    /// under the same owner and successful construction does not duplicate it.
    pub fn with_zeroizing_value(
        header: String,
        mut value: Zeroizing<String>,
    ) -> Result<Self, AgentWireError> {
        let header = header.trim();
        let start = value.len().saturating_sub(value.trim_start().len());
        let trimmed_len = value.trim().len();
        if start > 0 {
            value.drain(..start);
        }
        value.truncate(trimmed_len);
        if !header.eq_ignore_ascii_case("authorization") {
            return Err(AgentWireError::InvalidAuthHeader);
        }
        if value.is_empty()
            || value.len() > MAX_AGENT_AUTH_BYTES
            || value.as_bytes().contains(&0)
            || value
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        {
            return Err(AgentWireError::InvalidAuthValue);
        }
        Ok(Self {
            header: "Authorization".to_owned(),
            value: Arc::new(value),
        })
    }

    /// Canonical header name.
    #[must_use]
    pub fn header(&self) -> &str {
        &self.header
    }

    /// Explicit secret exposure for Vault sealing or one SafeDialer request.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for AgentAuthInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAuthInput")
            .field("header", &self.header)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl PartialEq for AgentAuthInput {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && bool::from(self.value.as_bytes().ct_eq(other.value.as_bytes()))
    }
}

impl Eq for AgentAuthInput {}

impl Serialize for AgentAuthInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AgentAuthInput", 2)?;
        state.serialize_field("header", self.header())?;
        state.serialize_field("value", self.expose_value())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AgentAuthInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            header: String,
            #[serde(deserialize_with = "crate::secret_text::deserialize")]
            value: Zeroizing<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::with_zeroizing_value(wire.header, wire.value).map_err(D::Error::custom)
    }
}

/// Full create/update Agent form. Server-owned id/owner/avatar/package/deletion fields cannot fit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentMutationRequest {
    /// Display name.
    pub name: String,
    /// Short title.
    pub title: String,
    /// Standing role applied to every channel.
    pub role_description: String,
    /// Public/private visibility.
    pub visibility: AgentVisibility,
    /// Remote AG-UI endpoint; absent/blank selects the managed built-in slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional replacement credential. Absence preserves an existing remote credential on update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AgentAuthInput>,
}

impl fmt::Debug for AgentMutationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentMutationRequest")
            .field("name_bytes", &self.name.len())
            .field("title_bytes", &self.title.len())
            .field("role_description_bytes", &self.role_description.len())
            .field("visibility", &self.visibility)
            .field("endpoint_present", &self.endpoint.is_some())
            .field("auth_present", &self.auth.is_some())
            .finish()
    }
}

/// Connection probe input after HTTP framing has canonicalized the Authorization header.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentConnectionTestRequest {
    /// Candidate remote AG-UI endpoint.
    pub endpoint: String,
    /// Unsaved write-only Authorization value, if supplied by the form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AgentAuthInput>,
}

impl fmt::Debug for AgentConnectionTestRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentConnectionTestRequest")
            .field("endpoint_present", &!self.endpoint.is_empty())
            .field("auth_present", &self.auth.is_some())
            .finish()
    }
}

/// Stable, localizable reason a connection probe did not prove an AG-UI endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentConnectionFailure {
    /// URL/scheme/destination failed before a request.
    DestinationRejected,
    /// DNS/connect/TLS failed before the request became commit-unknown.
    Unreachable,
    /// Endpoint rejected the supplied key.
    Authentication,
    /// Endpoint answered but did not provide a valid AG-UI event.
    Protocol,
    /// Request may have arrived but no bounded verdict was available.
    Inconclusive,
}

/// Connection-test result. Natural-language vendor/server payload never crosses this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentConnectionVerdict {
    /// True only after at least one bounded AG-UI event type was decoded.
    pub ok: bool,
    /// Stable event type names, ordered and duplicate-free; empty on refusal.
    pub events: Vec<String>,
    /// Closed failure reason; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AgentConnectionFailure>,
}

impl AgentConnectionVerdict {
    /// Construct a positive bounded verdict.
    #[must_use]
    pub fn working(events: Vec<String>) -> Self {
        Self {
            ok: true,
            events,
            reason: None,
        }
    }

    /// Construct a fail-closed verdict.
    #[must_use]
    pub fn rejected(reason: AgentConnectionFailure) -> Self {
        Self {
            ok: false,
            events: Vec::new(),
            reason: Some(reason),
        }
    }
}

/// Non-profile lifecycle state committed by a hide/unhide/delete command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    /// Hidden only for the current actor.
    Hidden,
    /// Returned to the current actor's default roster.
    Visible,
    /// Soft-deleted and no longer visible/runnable.
    Deleted,
}

/// Authoritative lifecycle acknowledgement used by in-process transports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentLifecycleReceipt {
    /// Server-owned Agent identity.
    pub agent_id: BotId,
    /// Committed lifecycle state.
    pub state: AgentLifecycleState,
}

/// Agent lifecycle wire validation failure without echoing the rejected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentWireError {
    /// Only the closed Authorization channel is accepted.
    #[error("agent_auth_header_invalid")]
    InvalidAuthHeader,
    /// Secret is empty, oversized, NUL/CR/LF-bearing, or otherwise unsafe for a header.
    #[error("agent_auth_value_invalid")]
    InvalidAuthValue,
}

/// One-time callback credential response.
///
/// The value must cross the response boundary once, so it implements serde. It deliberately does
/// not implement `Clone` or `Display`; `Debug` is redacted and the owned allocation is zeroized on
/// drop. PostgreSQL stores only its SHA-256 digest.
pub struct CallbackTokenIssued {
    token: Zeroizing<String>,
}

impl CallbackTokenIssued {
    /// Take ownership of an already validated freshly minted token.
    pub fn new(token: String) -> Result<Self, CallbackTokenWireError> {
        if token.is_empty() || token.len() > 4096 || token.as_bytes().contains(&0) {
            return Err(CallbackTokenWireError::Invalid);
        }
        Ok(Self {
            token: Zeroizing::new(token),
        })
    }

    /// Explicitly expose the token only to hashing or response serialization call sites.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.token.as_str()
    }
}

impl fmt::Debug for CallbackTokenIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackTokenIssued")
            .field("token", &"[redacted]")
            .finish()
    }
}

impl PartialEq for CallbackTokenIssued {
    fn eq(&self, other: &Self) -> bool {
        self.token.as_bytes().ct_eq(other.token.as_bytes()).into()
    }
}

impl Eq for CallbackTokenIssued {}

impl Serialize for CallbackTokenIssued {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CallbackTokenIssued", 1)?;
        state.serialize_field("token", self.expose())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CallbackTokenIssued {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            token: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.token).map_err(D::Error::custom)
    }
}

/// Callback token wire value is empty, oversized, or contains NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallbackTokenWireError {
    /// Invalid token response value.
    #[error("callback_token_wire_invalid")]
    Invalid,
}

/// Successful idempotent callback-token revocation acknowledgement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackTokenRevoked;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_input_transfers_the_zeroizing_allocation_and_rejects_late_fields() {
        let value = Zeroizing::new("Bearer allocation-canary".to_owned());
        let address = value.as_ptr();
        let input =
            AgentAuthInput::with_zeroizing_value("Authorization".to_owned(), value).unwrap();
        assert_eq!(input.expose_value().as_ptr(), address);
        assert_eq!(input.clone().expose_value().as_ptr(), address);
        assert!(!format!("{input:?}").contains("allocation-canary"));
        assert!(
            serde_json::from_str::<AgentAuthInput>(
                r#"{"header":"Authorization","value":"allocation-canary","role":"admin"}"#
            )
            .is_err()
        );
    }

    fn profile() -> AgentProfile {
        AgentProfile {
            id: BotId::new("agent-1"),
            name: "Research".to_owned(),
            title: "Research coworker".to_owned(),
            role_description: "Find cited facts.".to_owned(),
            avatar_seed: "research-seed".to_owned(),
            visibility: AgentVisibility::Private,
            endpoint: Some("https://agent.example.test/ag-ui".to_owned()),
            has_auth: true,
            has_callback_token: true,
            hidden: false,
            system_owned: false,
            can_manage: true,
            mine: true,
        }
    }

    #[test]
    fn agent_projection_envelopes_are_closed_camel_case_and_secret_free() {
        let list = AgentProfilesResponse {
            agents: vec![profile()],
        };
        let value = serde_json::to_value(&list).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "agents": [{
                    "id": "agent-1",
                    "name": "Research",
                    "title": "Research coworker",
                    "roleDescription": "Find cited facts.",
                    "avatarSeed": "research-seed",
                    "visibility": "private",
                    "endpoint": "https://agent.example.test/ag-ui",
                    "hasAuth": true,
                    "hasCallbackToken": true,
                    "hidden": false,
                    "systemOwned": false,
                    "canManage": true,
                    "mine": true
                }]
            })
        );
        assert!(value.to_string().find("credential").is_none());
        assert!(
            serde_json::from_value::<AgentProfileResponse>(serde_json::json!({
                "agent": serde_json::to_value(profile()).unwrap(),
                "ownerUserId": "must-not-cross"
            }))
            .is_err()
        );
        assert_eq!(
            serde_json::from_value::<AgentProfilesResponse>(value).unwrap(),
            list
        );
    }

    #[test]
    fn one_time_token_serializes_but_debug_redacts_and_clone_is_not_available() {
        let token = CallbackTokenIssued::new("obot_agt_secret-value".to_owned()).unwrap();
        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            r#"{"token":"obot_agt_secret-value"}"#
        );
        let debug = format!("{token:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret-value"));
        let round_trip: CallbackTokenIssued =
            serde_json::from_str(r#"{"token":"obot_agt_secret-value"}"#).unwrap();
        assert_eq!(round_trip, token);
    }

    #[test]
    fn lifecycle_wire_is_closed_and_write_only_auth_is_redacted() {
        let auth = AgentAuthInput::new(
            " authorization ".to_owned(),
            "  Bearer customer-secret  ".to_owned(),
        )
        .unwrap();
        assert_eq!(auth.header(), "Authorization");
        assert_eq!(auth.expose_value(), "Bearer customer-secret");
        assert!(!format!("{auth:?}").contains("customer-secret"));
        let request = AgentMutationRequest {
            name: "Remote".to_owned(),
            title: "Research".to_owned(),
            role_description: "Find facts.".to_owned(),
            visibility: AgentVisibility::Private,
            endpoint: Some("https://agent.example/ag-ui".to_owned()),
            auth: Some(auth),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["auth"]["header"], "Authorization");
        assert_eq!(value["auth"]["value"], "Bearer customer-secret");
        assert_eq!(
            serde_json::from_value::<AgentMutationRequest>(value).unwrap(),
            request
        );
        assert!(
            serde_json::from_value::<AgentMutationRequest>(serde_json::json!({
                "name":"Remote","title":"Research","roleDescription":"Find facts.",
                "visibility":"private","ownerUserId":"forged"
            }))
            .is_err()
        );
        assert_eq!(
            AgentAuthInput::new("Authorization".to_owned(), "   ".to_owned()),
            Err(AgentWireError::InvalidAuthValue)
        );
        assert_eq!(
            AgentAuthInput::new("X-Injected".to_owned(), "secret".to_owned()),
            Err(AgentWireError::InvalidAuthHeader)
        );
    }

    #[test]
    fn connection_and_lifecycle_receipts_have_closed_stable_shapes() {
        assert_eq!(
            serde_json::to_value(AgentConnectionVerdict::working(vec![
                "RUN_STARTED".to_owned()
            ]))
            .unwrap(),
            serde_json::json!({"ok":true,"events":["RUN_STARTED"]})
        );
        assert_eq!(
            serde_json::to_value(AgentConnectionVerdict::rejected(
                AgentConnectionFailure::Authentication
            ))
            .unwrap(),
            serde_json::json!({"ok":false,"events":[],"reason":"authentication"})
        );
        assert_eq!(
            serde_json::to_value(AgentLifecycleReceipt {
                agent_id: BotId::new("agent-1"),
                state: AgentLifecycleState::Hidden,
            })
            .unwrap(),
            serde_json::json!({"agentId":"agent-1","state":"hidden"})
        );
    }
}
