//! Personal custom-model connection management. Read DTOs never contain secret material.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, sync::Arc};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// New bounded personal inventory page.
pub const MODEL_CONNECTION_PAGE_SIZE: usize = 100;
/// Maximum user-authored display name in UTF-8 bytes.
pub const MAX_MODEL_CONNECTION_NAME_BYTES: usize = 100;
/// Existing provider model identifier budget.
pub const MAX_MODEL_CONNECTION_MODEL_BYTES: usize = 512;
/// Maximum normalized endpoint URL bytes.
pub const MAX_MODEL_CONNECTION_ENDPOINT_BYTES: usize = 2048;

/// Explicit personal connection selection for one run; contains no authority or credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunModelSelection {
    /// Opaque UUID previously minted by the connection service.
    pub connection_id: String,
    /// Positive owner-visible connection revision, frozen at acceptance.
    pub expected_revision: i64,
}

impl RunModelSelection {
    /// Validate the closed wire shape again for callers constructing the typed input directly.
    pub fn is_valid(&self) -> bool {
        self.expected_revision > 0
            && self.connection_id.len() == 36
            && self.connection_id.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
    }
}

impl<'de> Deserialize<'de> for RunModelSelection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            connection_id: String,
            expected_revision: i64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            connection_id: wire.connection_id,
            expected_revision: wire.expected_revision,
        };
        if !value.is_valid() {
            return Err(serde::de::Error::custom("invalid_model_selection"));
        }
        Ok(value)
    }
}

/// Server-produced connection source; only the implemented custom source exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelConnectionSource {
    /// A user's own compatible provider connection.
    Custom,
}

/// Only implemented provider protocols; no gateway/account/local placeholders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomModelProtocol {
    /// OpenAI-compatible Chat Completions.
    OpenaiChatCompletions,
    /// OpenAI-compatible Responses.
    OpenaiResponses,
    /// Anthropic-compatible Messages.
    AnthropicMessages,
}

impl CustomModelProtocol {
    /// Stable storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiChatCompletions => "openai_chat_completions",
            Self::OpenaiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
        }
    }
}

/// One temporary shared zeroizing token allocation. Serialization is write-side only.
#[derive(Clone)]
pub struct ModelApiKey(Arc<Zeroizing<String>>);

impl ModelApiKey {
    /// Validate a model header token; no user value appears in errors.
    pub fn new(value: Zeroizing<String>) -> Result<Self, &'static str> {
        if value.is_empty()
            || value.len() > crate::credential_admin::MAX_CREDENTIAL_TOKEN_BYTES
            || value.contains(['\r', '\n', '\0'])
            || value.trim() != value.as_str()
        {
            return Err("invalid_model_api_key");
        }
        Ok(Self(Arc::new(value)))
    }

    /// Explicit exposure only for the write boundary or Vault sealing.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ModelApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ModelApiKey([redacted])")
    }
}
impl PartialEq for ModelApiKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.expose().as_bytes().ct_eq(other.expose().as_bytes()))
    }
}
impl Eq for ModelApiKey {}
impl Serialize for ModelApiKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}
impl<'de> Deserialize<'de> for ModelApiKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        Self::new(crate::secret_text::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Create input; actor, scope, revision and connection ID are server-owned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateModelConnection {
    /// User-visible name.
    pub name: String,
    /// Exact supported wire protocol.
    pub protocol: CustomModelProtocol,
    /// Base or final API URL, normalized by the shared application helper.
    pub endpoint: String,
    /// Exact model identifier.
    pub model: String,
    /// Whether future runtime selection may use this connection.
    pub enabled: bool,
    /// Write-only model token.
    pub api_key: ModelApiKey,
}

/// Full metadata replacement under an optimistic revision; omitted key keeps the current one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateModelConnection {
    /// Revision previously read by this owner.
    pub expected_revision: i64,
    /// Replacement display name.
    pub name: String,
    /// Exact supported wire protocol.
    pub protocol: CustomModelProtocol,
    /// Base or final endpoint URL.
    pub endpoint: String,
    /// Exact model identifier; changing only it does not require a new key.
    pub model: String,
    /// Replacement enabled state.
    pub enabled: bool,
    /// Required when endpoint/protocol changes; never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<ModelApiKey>,
}

/// Delete under a current revision; no global or vendor revocation is implied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteModelConnection {
    /// Current owner-visible revision.
    pub expected_revision: i64,
}

/// Cursor is an ordering position, never an authority token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelConnectionPageRequest {
    /// UUID position returned by the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Safe personal connection projection. Presence of a credential does not claim connectivity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelConnection {
    /// Opaque server-minted UUID.
    pub id: String,
    /// Authoritative source, never inferred from a name or endpoint.
    pub source: ModelConnectionSource,
    /// User-visible name.
    pub name: String,
    /// Selected wire protocol.
    pub protocol: CustomModelProtocol,
    /// Credential-free normalized final URL.
    pub endpoint: String,
    /// Exact model identifier.
    pub model: String,
    /// Current enabled state.
    pub enabled: bool,
    /// Monotonic concurrency revision.
    pub revision: i64,
    /// Active stored credential reference, not a key validation result.
    pub has_credential: bool,
    /// Server creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Server last mutation time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Bounded current owner's inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelConnectionPage {
    /// Rows in UUID creation order.
    pub connections: Vec<ModelConnection>,
    /// Next ordering position, if present.
    pub next_cursor: Option<String>,
}

/// Confirmed local soft-delete receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelConnectionDeleted {
    /// Removed connection.
    pub id: String,
    /// Revision after deletion.
    pub revision: i64,
    /// Local deletion time.
    #[serde(with = "time::serde::rfc3339")]
    pub deleted_at: OffsetDateTime,
}

impl fmt::Debug for CreateModelConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateModelConnection")
            .field("input", &"[redacted]")
            .finish()
    }
}
impl fmt::Debug for UpdateModelConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateModelConnection")
            .field("input", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn run_selection_is_closed_bounded_and_optional_on_existing_begin_wire() {
        use crate::command::BeginThreadRunBody;
        let selection =
            json!({"connectionId":"01234567-89ab-cdef-0123-456789abcdef","expectedRevision":7});
        let base =
            json!({"runId":"run","botId":"bot","anchor":{"kind":"direct_bot"},"message":"hello"});
        let old: BeginThreadRunBody = serde_json::from_value(base.clone()).unwrap();
        assert!(old.model_selection.is_none());
        assert_eq!(serde_json::to_value(&old).unwrap(), base);
        let mut input = base.clone();
        input["modelSelection"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<BeginThreadRunBody>(input.clone())
                .unwrap()
                .model_selection
                .is_none()
        );
        input["modelSelection"] = selection.clone();
        let parsed: BeginThreadRunBody = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), input);
        for revision in [
            json!(0),
            json!(-1),
            json!(9223372036854775808_u64),
            json!("7"),
            json!(1.1),
        ] {
            let mut bad = selection.clone();
            bad["expectedRevision"] = revision;
            assert!(serde_json::from_value::<RunModelSelection>(bad).is_err());
        }
        for id in [
            "",
            "bad",
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            let mut bad = selection.clone();
            bad["connectionId"] = json!(id);
            assert!(serde_json::from_value::<RunModelSelection>(bad).is_err());
        }
        for field in [
            "owner",
            "authGeneration",
            "endpoint",
            "protocol",
            "model",
            "apiKey",
        ] {
            let mut bad = selection.clone();
            bad[field] = json!("forged");
            assert!(serde_json::from_value::<RunModelSelection>(bad).is_err());
        }
        assert!(serde_json::from_value::<RunModelSelection>(json!({})).is_err());
    }

    #[test]
    fn secret_input_is_bounded_redacted_and_closed() {
        let value = json!({"name":"Test","protocol":"openai_chat_completions","endpoint":"https://example.test/v1","model":"model","enabled":true,"apiKey":"SECRET_CANARY"});
        let input: CreateModelConnection = serde_json::from_value(value.clone()).unwrap();
        assert!(!format!("{input:?}").contains("SECRET_CANARY"));
        assert_eq!(serde_json::to_value(&input).unwrap(), value);
        for secret in ["", " x", "x\n", "x\0"] {
            assert!(ModelApiKey::new(Zeroizing::new(secret.to_owned())).is_err());
        }
        assert!(ModelApiKey::new(Zeroizing::new("x".repeat(16 * 1024))).is_ok());
        assert!(ModelApiKey::new(Zeroizing::new("x".repeat(16 * 1024 + 1))).is_err());
        for (field, extra) in [("owner", json!("other")), ("protocol", json!("gateway"))] {
            let mut bad = value.clone();
            bad[field] = extra;
            assert!(serde_json::from_value::<CreateModelConnection>(bad).is_err());
        }
    }
}
