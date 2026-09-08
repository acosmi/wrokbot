//! Package model credential selection：active PostgreSQL row first, environment fallback second。

use async_trait::async_trait;
use openbot_domain::vault::{SecretKind, SecretPrincipal};
use uuid::Uuid;

use super::openai::{OpenAiApiKey, OpenAiCredentialError, OpenAiCredentialSource};
use crate::vault::CredentialRecordVault;

/// Fresh per-run OpenAI model credential resolver。
///
/// The query deliberately runs for every sampling request. Rotation/revocation therefore takes
/// effect without rebuilding an Agent object. A matching but corrupt stored row never falls back
/// to the environment, matching the fixed upstream fail-closed order。
pub struct PostgresOpenAiCredentialSource {
    pool: deadpool_postgres::Pool,
    vault: CredentialRecordVault,
    key_id: String,
    environment_fallback: Option<OpenAiApiKey>,
}

impl PostgresOpenAiCredentialSource {
    /// Construct from the verified package `credential_secret_ref` and optional environment key。
    pub fn new(
        pool: deadpool_postgres::Pool,
        vault: CredentialRecordVault,
        key_id: String,
        environment_fallback: Option<OpenAiApiKey>,
    ) -> Result<Self, OpenAiCredentialError> {
        if key_id.is_empty()
            || key_id.len() > 1024
            || key_id.trim() != key_id
            || key_id.as_bytes().contains(&0)
        {
            return Err(OpenAiCredentialError::Corrupt);
        }
        Ok(Self {
            pool,
            vault,
            key_id,
            environment_fallback,
        })
    }
}

impl core::fmt::Debug for PostgresOpenAiCredentialSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresOpenAiCredentialSource")
            .field(
                "has_environment_fallback",
                &self.environment_fallback.is_some(),
            )
            .field("credential", &"PostgreSQL active model/[redacted]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OpenAiCredentialSource for PostgresOpenAiCredentialSource {
    async fn resolve(&self) -> Result<OpenAiApiKey, OpenAiCredentialError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "model credential 获取 PostgreSQL 连接失败");
            OpenAiCredentialError::Unavailable
        })?;
        let row = client
            .query_opt(
                "SELECT id,encrypted_value FROM public.credentials \
                 WHERE kind='model' AND provider='openai' AND key_id=$1 AND revoked_at IS NULL \
                 ORDER BY created_at DESC,id DESC LIMIT 1",
                &[&self.key_id],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "选择 active model credential 失败");
                OpenAiCredentialError::Unavailable
            })?;
        let Some(row) = row else {
            return match &self.environment_fallback {
                Some(fallback) => fallback.resolve().await,
                None => Err(OpenAiCredentialError::Missing),
            };
        };
        let id: Uuid = row
            .try_get("id")
            .map_err(|_| OpenAiCredentialError::Corrupt)?;
        let encrypted: String = row
            .try_get("encrypted_value")
            .map_err(|_| OpenAiCredentialError::Corrupt)?;
        let secret = self
            .vault
            .open(
                &id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &encrypted,
            )
            .map_err(|error| {
                tracing::error!(code = %error, "active model credential 密文被拒");
                OpenAiCredentialError::Corrupt
            })?
            .into_secret();
        OpenAiApiKey::from_secret(secret).map_err(|_| OpenAiCredentialError::Corrupt)
    }
}
