//! Deployment administrator credential use cases. Transports provide fresh authentication;
//! persistence revalidates the current database actor before any mutation.

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::credential_admin::{
    CredentialPage, CredentialPageRequest, CredentialRevoked, CredentialWrite, CredentialWritten,
};
use openbot_contracts::error::AppError;

/// Closed operational failure with no secret, metadata, database message or caller text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CredentialAdministrationError {
    /// Request framing or identity is invalid.
    #[error("credential_admin_invalid field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// Row or actor is not visible in this configured deployment/tenant.
    #[error("credential_admin_not_visible")]
    NotVisible,
    /// Stored binding changed, or a retired credential cannot be rotated again.
    #[error("credential_admin_conflict")]
    Conflict,
    /// Database or Vault is unavailable.
    #[error("credential_admin_unavailable")]
    Unavailable,
    /// Persistence violates a closed binding or metadata schema.
    #[error("credential_admin_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Transaction acknowledgement was lost; never automatically replay the secret write.
    #[error("credential_admin_commit_unknown")]
    CommitUnknown,
}

impl CredentialAdministrationError {
    /// Preserve the shared HTTP/application error vocabulary.
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::Conflict => AppError::RequestConflict {
                resource: "credential",
            },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "credentials",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Credential storage plus reference/audit transaction boundary, shared by Server and Desktop.
#[async_trait]
pub trait CredentialAdministration: Send + Sync {
    /// Safe bounded inventory, including managed credential statuses.
    async fn list(
        &self,
        auth: &AuthContext,
        request: &CredentialPageRequest,
    ) -> Result<CredentialPage, CredentialAdministrationError>;
    /// Seal and create a manual credential with its audit in one transaction.
    async fn create(
        &self,
        auth: &AuthContext,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, CredentialAdministrationError>;
    /// Atomically install a replacement, switch allowed references, retire the old row and audit.
    async fn rotate(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, CredentialAdministrationError>;
    /// Local retirement with dependent invalidation and durable external cleanup state.
    async fn revoke(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<CredentialRevoked, CredentialAdministrationError>;
}

/// Unconfigured administration never fabricates a success or empty inventory.
pub struct NoCredentialAdministration;

#[async_trait]
impl CredentialAdministration for NoCredentialAdministration {
    async fn list(
        &self,
        _: &AuthContext,
        _: &CredentialPageRequest,
    ) -> Result<CredentialPage, CredentialAdministrationError> {
        Err(CredentialAdministrationError::Unavailable)
    }
    async fn create(
        &self,
        _: &AuthContext,
        _: &CredentialWrite,
    ) -> Result<CredentialWritten, CredentialAdministrationError> {
        Err(CredentialAdministrationError::Unavailable)
    }
    async fn rotate(
        &self,
        _: &AuthContext,
        _: &str,
        _: &CredentialWrite,
    ) -> Result<CredentialWritten, CredentialAdministrationError> {
        Err(CredentialAdministrationError::Unavailable)
    }
    async fn revoke(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<CredentialRevoked, CredentialAdministrationError> {
        Err(CredentialAdministrationError::Unavailable)
    }
}

fn admin(auth: &AuthContext) -> Result<(), AppError> {
    if auth.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(AppError::ForbiddenRole {
            required: Role::Admin,
        })
    }
}

/// List only after the role gate; a cursor cannot manufacture authority.
pub async fn list_credentials(
    port: &dyn CredentialAdministration,
    auth: &AuthContext,
    request: &CredentialPageRequest,
) -> Result<CredentialPage, AppError> {
    admin(auth)?;
    port.list(auth, request)
        .await
        .map_err(CredentialAdministrationError::into_app_error)
}
/// Create only after the role gate.
pub async fn create_credential(
    port: &dyn CredentialAdministration,
    auth: &AuthContext,
    input: &CredentialWrite,
) -> Result<CredentialWritten, AppError> {
    admin(auth)?;
    port.create(auth, input)
        .await
        .map_err(CredentialAdministrationError::into_app_error)
}
/// Rotate only after the role gate.
pub async fn rotate_credential(
    port: &dyn CredentialAdministration,
    auth: &AuthContext,
    id: &str,
    input: &CredentialWrite,
) -> Result<CredentialWritten, AppError> {
    admin(auth)?;
    port.rotate(auth, id, input)
        .await
        .map_err(CredentialAdministrationError::into_app_error)
}
/// Revoke only after the role gate.
pub async fn revoke_credential(
    port: &dyn CredentialAdministration,
    auth: &AuthContext,
    id: &str,
) -> Result<CredentialRevoked, AppError> {
    admin(auth)?;
    port.revoke(auth, id)
        .await
        .map_err(CredentialAdministrationError::into_app_error)
}
