//! Current Desktop installation authority for Local OS confirmation; no provisioning or repair.

use async_trait::async_trait;
use openbot_contracts::{auth::AuthContext, error::AppError};

/// Host-owned read capability. A renderer cannot choose the installation or the database pool.
#[async_trait]
pub(crate) trait LocalConfirmationAuthority: Send + Sync {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError>;
}

#[cfg(feature = "desktop-local-runtime")]
pub(crate) struct PostgresLocalConfirmationAuthority {
    installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
    pool: openbot_infra::db::pool::DatabasePool,
}

#[cfg(feature = "desktop-local-runtime")]
impl PostgresLocalConfirmationAuthority {
    pub(crate) fn new(
        installation: openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthority,
        pool: openbot_infra::db::pool::DatabasePool,
    ) -> Self {
        Self { installation, pool }
    }
}

#[cfg(feature = "desktop-local-runtime")]
#[async_trait]
impl LocalConfirmationAuthority for PostgresLocalConfirmationAuthority {
    async fn verify_current(&self, expected: &AuthContext) -> Result<AuthContext, AppError> {
        // This established resolver reads canonical user/generation/deny/sole-admin in one SQL
        // snapshot. It never initializes, repairs or advances authority in response to a request.
        let current = self
            .installation
            .load_runtime_auth_context(&self.pool)
            .await
            .map_err(|error| match error {
                openbot_infra::db::InfraError::RepositoryInvariant {
                    code: "canonical_principal_missing" | "canonical_principal_refused",
                } => AppError::Unauthenticated,
                _ => AppError::DependencyUnavailable {
                    dependency: "desktop_local_confirmation_authority",
                },
            })?;
        if !expected.is_single_user()
            || !current.is_single_user()
            || current.deployment() != expected.deployment()
            || current.tenant() != expected.tenant()
            || current.actor() != expected.actor()
            || current.auth_generation() != expected.auth_generation()
            || current.roles() != expected.roles()
        {
            return Err(AppError::Unauthenticated);
        }
        Ok(current)
    }
}

#[cfg(all(test, feature = "desktop-local-runtime"))]
#[path = "local_confirmation_authority_tests.rs"]
mod tests;
