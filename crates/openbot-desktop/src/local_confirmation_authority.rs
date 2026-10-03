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

    // Request-binding observations have a stricter current-only contract than the established
    // OS-confirmation reader. Do not call its compatibility loader: NULL is not generation zero.
    async fn verify_binding_current(
        &self,
        expected: &AuthContext,
    ) -> Result<(), openbot_contracts::HostRequestBindingError> {
        use openbot_contracts::HostRequestBindingError;
        use openbot_infra::auth::single_user::desktop_local::{
            DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL,
        };

        let installation = self.installation.auth_context();
        if !expected.is_single_user()
            || expected.deployment() != installation.deployment()
            || expected.tenant() != installation.tenant()
            || expected.actor().as_str() != DESKTOP_LOCAL_ACTOR_ID
            || expected.actor() != installation.actor()
            || expected.roles() != installation.roles()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .read_only(true)
            .start()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let observation = async {
            transaction
                .batch_execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'")
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = transaction
                .query_opt(
                    LOCAL_BINDING_CURRENT_SQL,
                    &[&DESKTOP_LOCAL_ACTOR_ID, &DESKTOP_LOCAL_EMAIL],
                )
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            decode_binding_generation(row)
        }
        .await;
        // Both successful and failed observations wait for explicit rollback. Rollback failure
        // cannot certify current authority; an outer timeout likewise supplies no cleanup proof.
        transaction
            .rollback()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let generation = observation?;
        if generation != expected.auth_generation() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-local-runtime")]
const LOCAL_BINDING_CURRENT_SQL: &str = "SELECT u.auth_generation AS generation,u.email=$2 AS canonical_email, \
    EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
    ARRAY(SELECT ur.role::text FROM public.user_roles ur \
    WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
    FROM public.users u WHERE u.id=$1";

#[cfg(feature = "desktop-local-runtime")]
fn decode_binding_generation(
    row: Option<tokio_postgres::Row>,
) -> Result<openbot_contracts::auth::AuthGeneration, openbot_contracts::HostRequestBindingError> {
    use openbot_contracts::HostRequestBindingError;
    let row = row.ok_or(HostRequestBindingError::NotCurrent)?;
    let generation: Option<i64> = row
        .try_get("generation")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let generation = generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(HostRequestBindingError::NotCurrent)?;
    let canonical_email: bool = row
        .try_get("canonical_email")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let denied: bool = row
        .try_get("denied")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    let roles: Vec<String> = row
        .try_get("roles")
        .map_err(|_| HostRequestBindingError::Unavailable)?;
    if !canonical_email || denied || roles != ["admin"] {
        return Err(HostRequestBindingError::NotCurrent);
    }
    Ok(openbot_contracts::auth::AuthGeneration::new(generation))
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

#[cfg(feature = "desktop-local-runtime")]
impl openbot_contracts::HostRequestBindingGuard for PostgresLocalConfirmationAuthority {
    fn verify_current<'a>(
        &'a self,
        expected: &'a AuthContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), openbot_contracts::HostRequestBindingError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.verify_binding_current(expected),
            )
            .await
            .unwrap_or(Err(openbot_contracts::HostRequestBindingError::Unavailable))
        })
    }
}
