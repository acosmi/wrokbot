//! Personal custom-model management authority and shared endpoint normalization.

use async_trait::async_trait;
use openbot_contracts::{
    auth::{AuthContext, Role},
    error::AppError,
    model_connections::{
        CreateModelConnection, CustomModelProtocol, DeleteModelConnection,
        MAX_MODEL_CONNECTION_ENDPOINT_BYTES, MAX_MODEL_CONNECTION_MODEL_BYTES,
        MAX_MODEL_CONNECTION_NAME_BYTES, ModelConnection, ModelConnectionDeleted,
        ModelConnectionPage, ModelConnectionPageRequest, UpdateModelConnection,
    },
};

/// Closed operational failures; no URL, key, database prose or user content crosses this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModelConnectionError {
    /// Bad typed input.
    #[error("model_connection_invalid field={field}")]
    InvalidInput {
        /// Static schema field.
        field: &'static str,
    },
    /// Actor or object is not visible.
    #[error("model_connection_not_visible")]
    NotVisible,
    /// A stale revision or incompatible credential change.
    #[error("model_connection_conflict")]
    Conflict,
    /// Database/Vault/audit could not complete.
    #[error("model_connection_unavailable")]
    Unavailable,
    /// Stored schema/AAD is corrupt; no fallback.
    #[error("model_connection_corrupt")]
    Corrupt,
    /// The COMMIT acknowledgement was lost; never auto replay.
    #[error("model_connection_commit_unknown")]
    CommitUnknown,
}

impl ModelConnectionError {
    /// Existing shared error vocabulary.
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::Conflict => AppError::RequestConflict {
                resource: "model_connection",
            },
            Self::Unavailable | Self::Corrupt => AppError::DependencyUnavailable {
                dependency: "model_connections",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Canonical metadata used identically by storage and future probe/runtime consumers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedModelConnection {
    /// Bounded name.
    pub name: String,
    /// Exact protocol.
    pub protocol: CustomModelProtocol,
    /// Final, normalized, credential-free API URL.
    pub endpoint: String,
    /// Bounded model identifier.
    pub model: String,
    /// Current enabled preference.
    pub enabled: bool,
}

fn text(value: &str, max: usize, field: &'static str) -> Result<(), ModelConnectionError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModelConnectionError::InvalidInput { field })
    } else {
        Ok(())
    }
}

/// Normalize base/final URL once. This function neither dials nor grants egress access.
pub fn normalize_model_endpoint(
    protocol: CustomModelProtocol,
    endpoint: &str,
) -> Result<String, ModelConnectionError> {
    let invalid = || ModelConnectionError::InvalidInput { field: "endpoint" };
    text(endpoint, MAX_MODEL_CONNECTION_ENDPOINT_BYTES, "endpoint")?;
    let mut url = url::Url::parse(endpoint).map_err(|_| invalid())?;
    let raw_authority = endpoint
        .split_once("://")
        .map(|(_, value)| value.split(['/', '?', '#']).next().unwrap_or(""))
        .unwrap_or("");
    if raw_authority.contains('@') {
        return Err(invalid());
    }
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let path = url.path().trim_end_matches('/');
    let suffix = match protocol {
        CustomModelProtocol::OpenaiChatCompletions => "/chat/completions",
        CustomModelProtocol::OpenaiResponses => "/responses",
        CustomModelProtocol::AnthropicMessages => "/messages",
    };
    if ["/chat/completions", "/responses", "/messages"]
        .iter()
        .any(|candidate| path.ends_with(candidate) && *candidate != suffix)
    {
        return Err(invalid());
    }
    let path = if path.ends_with(suffix) {
        path.to_owned()
    } else if protocol == CustomModelProtocol::AnthropicMessages && !path.ends_with("/v1") {
        format!("{path}/v1/messages")
    } else {
        format!("{path}{suffix}")
    };
    url.set_path(&path);
    let normalized = url.to_string();
    text(&normalized, MAX_MODEL_CONNECTION_ENDPOINT_BYTES, "endpoint")?;
    Ok(normalized)
}

/// Validate all metadata for both the use case and the direct persistence adapter.
pub fn normalize_model_configuration(
    name: &str,
    protocol: CustomModelProtocol,
    endpoint: &str,
    model: &str,
    enabled: bool,
) -> Result<NormalizedModelConnection, ModelConnectionError> {
    text(name, MAX_MODEL_CONNECTION_NAME_BYTES, "name")?;
    text(model, MAX_MODEL_CONNECTION_MODEL_BYTES, "model")?;
    Ok(NormalizedModelConnection {
        name: name.to_owned(),
        protocol,
        endpoint: normalize_model_endpoint(protocol, endpoint)?,
        model: model.to_owned(),
        enabled,
    })
}

/// One transaction boundary for personal metadata, Vault references and audit.
#[async_trait]
pub trait ModelConnectionAdministration: Send + Sync {
    /// Current owner's bounded inventory.
    async fn list(
        &self,
        auth: &AuthContext,
        request: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, ModelConnectionError>;
    /// One currently visible connection, without ciphertext.
    async fn get(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ModelConnection, ModelConnectionError>;
    /// Create a server-owned identity and sealed key.
    async fn create(
        &self,
        auth: &AuthContext,
        input: &CreateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError>;
    /// CAS metadata and optionally rotate a credential in one transaction.
    async fn update(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &UpdateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError>;
    /// CAS soft-delete and retire the current key.
    async fn delete(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, ModelConnectionError>;
}

/// Missing assembly is unavailable, never an empty success.
pub struct NoModelConnectionAdministration;
#[async_trait]
impl ModelConnectionAdministration for NoModelConnectionAdministration {
    async fn list(
        &self,
        _: &AuthContext,
        _: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, ModelConnectionError> {
        Err(ModelConnectionError::Unavailable)
    }
    async fn get(&self, _: &AuthContext, _: &str) -> Result<ModelConnection, ModelConnectionError> {
        Err(ModelConnectionError::Unavailable)
    }
    async fn create(
        &self,
        _: &AuthContext,
        _: &CreateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        Err(ModelConnectionError::Unavailable)
    }
    async fn update(
        &self,
        _: &AuthContext,
        _: &str,
        _: &UpdateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        Err(ModelConnectionError::Unavailable)
    }
    async fn delete(
        &self,
        _: &AuthContext,
        _: &str,
        _: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, ModelConnectionError> {
        Err(ModelConnectionError::Unavailable)
    }
}

/// Personal scope requires a role, and never grants administrators another user's ownership.
pub fn require_model_connection_actor(auth: &AuthContext) -> Result<(), AppError> {
    if auth.has_role(Role::User) || auth.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(AppError::NotVisible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_endpoints_are_canonical_and_shared() {
        for (p, base, expected) in [
            (
                CustomModelProtocol::OpenaiChatCompletions,
                "https://EXAMPLE.test/v1/",
                "https://example.test/v1/chat/completions",
            ),
            (
                CustomModelProtocol::OpenaiResponses,
                "https://example.test/v1",
                "https://example.test/v1/responses",
            ),
            (
                CustomModelProtocol::AnthropicMessages,
                "https://example.test",
                "https://example.test/v1/messages",
            ),
            (
                CustomModelProtocol::AnthropicMessages,
                "https://example.test/v1/",
                "https://example.test/v1/messages",
            ),
        ] {
            let result = normalize_model_endpoint(p, base).unwrap();
            assert_eq!(result, expected);
            assert_eq!(normalize_model_endpoint(p, &result).unwrap(), result);
        }
        for endpoint in [
            "http://example.test",
            "https://u:p@example.test",
            "https://@example.test",
            "https://example.test?",
            "https://example.test#",
            " https://example.test",
            "https://example.test\n",
            "file:///x",
            "https://example.test/v1/responses",
        ] {
            assert!(
                normalize_model_endpoint(CustomModelProtocol::AnthropicMessages, endpoint).is_err()
            );
        }
    }
    #[test]
    fn metadata_budgets_count_utf8_bytes() {
        let p = CustomModelProtocol::OpenaiResponses;
        assert!(
            normalize_model_configuration(&"名".repeat(33), p, "https://example.test", "m", true)
                .is_ok()
        );
        assert!(
            normalize_model_configuration(&"名".repeat(34), p, "https://example.test", "m", true)
                .is_err()
        );
        assert!(
            normalize_model_configuration("n", p, "https://example.test", &"m".repeat(512), true)
                .is_ok()
        );
        assert!(
            normalize_model_configuration("n", p, "https://example.test", &"m".repeat(513), true)
                .is_err()
        );
    }
}
