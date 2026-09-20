//! Write-only deployment credential administration; manual inputs cannot impersonate consent or
//! Agent lifecycle credentials. Existing secret material has no field in any read-side DTO.

use std::fmt;
use std::sync::Arc;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Maximum reference bytes admitted to both the public metadata and typed audit identifier.
pub const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 256;
/// Existing package model credential references admit up to 1024 bytes.
pub const MAX_CREDENTIAL_KEY_ID_BYTES: usize = 1024;
/// Maximum one write-only UTF-8 secret body.
pub const MAX_CREDENTIAL_SECRET_BYTES: usize = 64 * 1024;
/// Model/MCP header token consumers accept at most 16 KiB.
pub const MAX_CREDENTIAL_TOKEN_BYTES: usize = 16 * 1024;
/// Maximum public, caller-authored metadata document; server lifecycle metadata is separate.
pub const MAX_CREDENTIAL_METADATA_BYTES: usize = 16 * 1024;
/// A bounded page of metadata, never ciphertext.
pub const CREDENTIAL_PAGE_SIZE: usize = 100;

/// Fixed-upstream manual creation allowlist, deliberately excluding managed credential kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualCredentialKind {
    /// Provider model key.
    Model,
    /// First-party connector secret.
    Connector,
    /// Deployment bearer bound to one named MCP server.
    Mcp,
}

impl ManualCredentialKind {
    /// Stable storage and wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Connector => "connector",
            Self::Mcp => "mcp",
        }
    }
}

/// Inventory includes managed rows, without giving the renderer authority to manufacture them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRecordKind {
    /// Provider model key.
    Model,
    /// First-party connector secret.
    Connector,
    /// Agent endpoint credential, owned by the Agent lifecycle.
    Agent,
    /// Deployment MCP bearer.
    Mcp,
    /// Deployment OAuth client, owned by its connector registration flow.
    McpOauthClient,
    /// Actor OAuth token, created only through consent.
    McpUserToken,
}

impl CredentialRecordKind {
    /// Manual replacement is possible only for the original three admitted kinds.
    pub const fn manual(self) -> Option<ManualCredentialKind> {
        match self {
            Self::Model => Some(ManualCredentialKind::Model),
            Self::Connector => Some(ManualCredentialKind::Connector),
            Self::Mcp => Some(ManualCredentialKind::Mcp),
            _ => None,
        }
    }
}

/// External cleanup is independent from the local revoked timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialExternalRevocation {
    /// No local revocation has been requested.
    NotRequested,
    /// An idempotent vendor revocation is pending reconciliation.
    Pending,
    /// Vendor authorization revocation was confirmed.
    Revoked,
    /// Operator action is required; never a claim that the provider revoked the key.
    OperatorRequired,
}

/// Safe status for one immutable credential identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialStatus {
    /// Opaque credential row identifier.
    pub id: String,
    /// Stored kind, including managed inventory entries.
    pub kind: CredentialRecordKind,
    /// Provider or MCP server identifier; never a credential value.
    pub provider: String,
    /// Configuration reference or human-readable key label.
    pub key_id: String,
    /// Public caller metadata, excluding internal revocation snapshots.
    pub metadata: Value,
    /// First local retirement timestamp; independent from vendor cleanup.
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    /// Stable ordering/display timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Current external cleanup classification.
    pub external_revocation: CredentialExternalRevocation,
}

/// Bounded metadata page request. The cursor is only a position, never an authorization claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPageRequest {
    /// Opaque position returned by the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Metadata page shared by Server, Desktop and the GUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPage {
    /// Rows in stable creation/id order.
    pub credentials: Vec<CredentialStatus>,
    /// Present only when another bounded page exists.
    pub next_cursor: Option<String>,
    /// Read-only reference from the deployment's configured default model, when available.
    pub model_reference: Option<CredentialModelReference>,
}

/// Non-secret configuration hint; it never reports an API key or infers provider readiness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialModelReference {
    /// Provider selected by deployment configuration.
    pub provider: String,
    /// Credential reference selected by deployment configuration.
    pub key_id: String,
}

/// Create/rotate receipt. There is no plaintext or ciphertext response channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialWritten {
    /// Authoritative row after a confirmed transaction.
    pub credential: CredentialStatus,
}

/// Local retirement acknowledgement plus honest external cleanup status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRevoked {
    /// Retired row identity.
    pub id: String,
    /// First local retirement time.
    #[serde(with = "time::serde::rfc3339")]
    pub revoked_at: OffsetDateTime,
    /// Provider cleanup must not be inferred from local success.
    pub external_revocation: CredentialExternalRevocation,
}

/// Fixed-upstream HTTP retirement envelope shared by both hosts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRevocationReceipt {
    /// Locally retired credential and external cleanup state.
    pub credential: CredentialRevoked,
}

/// Secret input error carries only a static field name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("credential_input_invalid field={field}")]
pub struct CredentialInputError {
    /// Static schema field; never data supplied by the caller.
    pub field: &'static str,
}

/// Closed manual write; Clone shares one zeroizing secret allocation, Debug omits all content.
#[derive(Clone)]
pub struct CredentialWrite {
    kind: ManualCredentialKind,
    provider: String,
    key_id: String,
    metadata: Value,
    plaintext: Arc<Zeroizing<String>>,
}

impl CredentialWrite {
    /// Validate safe public fields and transfer the secret without a plain intermediate copy.
    pub fn new(
        kind: ManualCredentialKind,
        provider: String,
        key_id: String,
        metadata: Value,
        plaintext: Zeroizing<String>,
    ) -> Result<Self, CredentialInputError> {
        for (field, value, maximum) in [
            (
                "provider",
                provider.as_str(),
                MAX_CREDENTIAL_REFERENCE_BYTES,
            ),
            ("keyId", key_id.as_str(), MAX_CREDENTIAL_KEY_ID_BYTES),
        ] {
            if value.is_empty()
                || value.trim() != value
                || value.len() > maximum
                || value.chars().any(char::is_control)
            {
                return Err(CredentialInputError { field });
            }
        }
        if plaintext.is_empty()
            || plaintext.len() > MAX_CREDENTIAL_SECRET_BYTES
            || plaintext.contains('\0')
            || (kind != ManualCredentialKind::Connector
                && (plaintext.len() > MAX_CREDENTIAL_TOKEN_BYTES
                    || plaintext.contains(['\r', '\n'])))
        {
            return Err(CredentialInputError { field: "plaintext" });
        }
        if !metadata.is_object()
            || serde_json::to_vec(&metadata)
                .map_or(true, |v| v.len() > MAX_CREDENTIAL_METADATA_BYTES)
            || !metadata_bounded(&metadata, 0, &mut 0)
        {
            return Err(CredentialInputError { field: "metadata" });
        }
        Ok(Self {
            kind,
            provider,
            key_id,
            metadata,
            plaintext: Arc::new(plaintext),
        })
    }
    /// Manual kind, never a caller-supplied managed identity.
    pub const fn kind(&self) -> ManualCredentialKind {
        self.kind
    }
    /// Public provider identifier.
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Public configuration/key reference.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    /// Public metadata owned by the caller; not trusted as lifecycle authority.
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
    /// Explicit exposure only for serialization or Vault sealing.
    pub fn expose_plaintext(&self) -> &str {
        &self.plaintext
    }
}

impl fmt::Debug for CredentialWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialWrite")
            .field("kind", &self.kind)
            .field("input", &"[redacted]")
            .finish()
    }
}

impl PartialEq for CredentialWrite {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.kind == other.kind
            && self.provider == other.provider
            && self.key_id == other.key_id
            && self.metadata == other.metadata
            && bool::from(self.plaintext.as_bytes().ct_eq(other.plaintext.as_bytes()))
    }
}
impl Eq for CredentialWrite {}

impl Serialize for CredentialWrite {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            kind: ManualCredentialKind,
            provider: &'a str,
            key_id: &'a str,
            metadata: &'a Value,
            plaintext: &'a str,
        }
        Wire {
            kind: self.kind,
            provider: self.provider(),
            key_id: self.key_id(),
            metadata: &self.metadata,
            plaintext: self.expose_plaintext(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialWrite {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            kind: ManualCredentialKind,
            provider: String,
            key_id: String,
            metadata: Value,
            #[serde(deserialize_with = "crate::secret_text::deserialize")]
            plaintext: Zeroizing<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.kind,
            wire.provider,
            wire.key_id,
            wire.metadata,
            wire.plaintext,
        )
        .map_err(D::Error::custom)
    }
}

fn metadata_bounded(value: &Value, depth: usize, count: &mut usize) -> bool {
    *count += 1;
    if depth > 8 || *count > 1024 {
        return false;
    }
    match value {
        Value::Array(values) => values
            .iter()
            .all(|value| metadata_bounded(value, depth + 1, count)),
        Value::Object(values) => values.iter().all(|(key, value)| {
            key.len() <= 256
                && !key.chars().any(char::is_control)
                && metadata_bounded(value, depth + 1, count)
        }),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn manual_kinds_do_not_manufacture_managed_identity_and_secrets_are_not_debugged() {
        let value = json!({"kind":"model","provider":"openai","keyId":"primary","metadata":{"label":"Production"},"plaintext":"canary"});
        let write: CredentialWrite = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&write).unwrap(), value);
        assert!(!format!("{write:?}").contains("canary"));
        for kind in ["agent", "mcp_oauth_client", "mcp_user_token"] {
            let mut value = value.clone();
            value["kind"] = json!(kind);
            assert!(serde_json::from_value::<CredentialWrite>(value).is_err());
        }
        let mut forged = value;
        forged["actorUserId"] = json!("admin");
        assert!(serde_json::from_value::<CredentialWrite>(forged).is_err());
    }
}
