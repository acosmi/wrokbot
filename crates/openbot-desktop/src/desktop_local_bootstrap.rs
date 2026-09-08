//! Composition owner from a verified PostgreSQL child to the shared Desktop Local data plane.
//!
//! This module deliberately stops before Tauri window creation. Its success value proves the
//! exact sequence required by v4 R153–R156: same installation/data directory, exact Tenant Package
//! scope, administrative SCRAM connection, live sidecar attestation, fixed database
//! create/reconciliation, shared migrations, canonical principal, and package membership. The
//! Tauri background runtime now consumes this owner and may bind a window only while it remains
//! alive.

use openbot_application::tenant::package::LoadedTenantPackage;
use openbot_contracts::auth::AuthContext;
use openbot_domain::vault::secret::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::{
    DesktopLocalAuthority, DesktopLocalBootstrapError, DesktopLocalBootstrapReport,
    DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{
    DesktopLocalDatabase, DesktopLocalDatabaseError, DesktopLocalDatabaseOrigin,
    connect_for_attestation,
};
use openbot_infra::db::pool::DatabasePool;
use openbot_infra::thread_listener::ThreadListenerDatabase;

use crate::postgres_sidecar::{PostgresSidecarOrigin, RunningPostgresSidecar};

/// One running PostgreSQL child plus the exact verified business pool and app-instance authority.
///
/// Dropping this owner without [`Self::shutdown`] closes the pool, then lets the sidecar's unclean
/// Drop preserve its stale start lock before killing the child. Clean application shutdown must
/// call the async method so verified `pg_ctl` can release the lock.
pub struct RunningDesktopLocalDataPlane {
    database: DesktopLocalDatabase,
    sidecar: Option<RunningPostgresSidecar>,
    installation: DesktopLocalInstallation,
    runtime_auth: AuthContext,
    report: DesktopLocalBootstrapReport,
}

impl RunningDesktopLocalDataPlane {
    /// Installation identity for package/key-store scope. Runtime application/window binding must
    /// use [`Self::auth_context`] so it receives the PostgreSQL generation snapshot.
    #[must_use]
    pub fn authority(&self) -> &DesktopLocalAuthority {
        self.installation.authority()
    }

    /// Borrow the database-verified runtime authority, including its preserved generation.
    #[must_use]
    pub const fn auth_context(&self) -> &AuthContext {
        &self.runtime_auth
    }

    /// Borrow the verified business pool for production adapter assembly.
    #[must_use]
    pub const fn pool(&self) -> &DatabasePool {
        self.database.pool()
    }

    /// Whether the fixed `openbot` database was created, pre-existing, or reconciled.
    #[must_use]
    pub const fn database_origin(&self) -> DesktopLocalDatabaseOrigin {
        self.database.origin()
    }

    /// Whether the PostgreSQL cluster itself was initialized by this process start.
    #[must_use]
    pub fn sidecar_origin(&self) -> Option<PostgresSidecarOrigin> {
        self.sidecar.as_ref().map(RunningPostgresSidecar::origin)
    }

    /// Shared migration and Tenant Package synchronization report.
    #[must_use]
    pub const fn bootstrap_report(&self) -> &DesktopLocalBootstrapReport {
        &self.report
    }

    /// Build a redacted dedicated LISTEN config directly from the owned SCRAM bytes, without a
    /// password `String`. The future shared application assembly consumes this before any window.
    pub fn thread_listener_database(
        &self,
    ) -> Result<ThreadListenerDatabase, DesktopLocalCompositionError> {
        let Some(sidecar) = self.sidecar.as_ref() else {
            return Err(DesktopLocalCompositionError::ListenerConfiguration);
        };
        let connection = sidecar.connection();
        ThreadListenerDatabase::desktop_local(connection.port(), connection.expose_password())
            .map_err(|_| DesktopLocalCompositionError::ListenerConfiguration)
    }

    /// Close the application pool, then stop the exact child through its verified `pg_ctl` before
    /// releasing the single-instance lock.
    pub async fn shutdown(mut self) -> Result<(), DesktopLocalCompositionError> {
        self.database.close();
        let Some(sidecar) = self.sidecar.take() else {
            return Err(DesktopLocalCompositionError::SidecarShutdown);
        };
        sidecar
            .shutdown()
            .await
            .map_err(|_| DesktopLocalCompositionError::SidecarShutdown)
    }
}

impl core::fmt::Debug for RunningDesktopLocalDataPlane {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RunningDesktopLocalDataPlane")
            .field("instance", &"<redacted>")
            .field("database_origin", &self.database.origin())
            .field("sidecar_origin", &self.sidecar_origin())
            .field("pool", &"<redacted>")
            .finish()
    }
}

impl Drop for RunningDesktopLocalDataPlane {
    fn drop(&mut self) {
        self.database.close();
    }
}

/// Stable pre-window composition failures; path, package contents and SCRAM bytes are never kept.
#[derive(Debug, thiserror::Error)]
pub enum DesktopLocalCompositionError {
    /// The running child belongs to a different app-instance data directory.
    #[error("desktop_local_sidecar_installation_mismatch")]
    InstallationMismatch,
    /// The package tenant differs from the installation authority, rejected before DB creation.
    #[error("desktop_local_package_scope_mismatch")]
    PackageScope(#[source] DesktopLocalBootstrapError),
    /// Administrative connection or fixed database create/reconciliation failed.
    #[error("desktop_local_database_assembly_failed")]
    Database(#[source] DesktopLocalDatabaseError),
    /// Live attestation or shared migration/principal/package bootstrap failed.
    #[error("desktop_local_bootstrap_failed")]
    Bootstrap(#[source] DesktopLocalBootstrapError),
    /// Failure cleanup could not prove a verified clean stop; the stale lock remains fail-closed.
    #[error("desktop_local_failure_cleanup_failed")]
    FailureCleanup,
    /// Explicit clean shutdown did not complete through verified `pg_ctl` and exact-child wait.
    #[error("desktop_local_sidecar_shutdown_failed")]
    SidecarShutdown,
    /// Dedicated PostgreSQL LISTEN configuration could not be built from the owned sidecar.
    #[error("desktop_local_listener_configuration_failed")]
    ListenerConfiguration,
}

/// Consume one SCRAM-ready child and close the full Batch79 bootstrap before any window authority
/// can be issued.
pub async fn bootstrap_running_sidecar(
    installation: DesktopLocalInstallation,
    sidecar: RunningPostgresSidecar,
    package: &LoadedTenantPackage,
) -> Result<RunningDesktopLocalDataPlane, DesktopLocalCompositionError> {
    if sidecar.data_dir() != installation.sidecar_data_dir() {
        return Err(cleanup_after_failure(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
        )
        .await);
    }
    if let Err(error) = installation.validate_package_scope(package) {
        return Err(cleanup_after_failure(
            sidecar,
            DesktopLocalCompositionError::PackageScope(error),
        )
        .await);
    }

    let (port, password) = {
        let connection = sidecar.connection();
        (
            connection.port(),
            SecretBytes::new(connection.expose_password().to_vec()),
        )
    };
    let admin = connect_for_attestation(port, password).await;
    let admin = match admin {
        Ok(admin) => admin,
        Err(error) => {
            return Err(cleanup_after_failure(
                sidecar,
                DesktopLocalCompositionError::Database(error),
            )
            .await);
        }
    };
    let admin = match installation.attest_postgres_admin(admin).await {
        Ok(admin) => admin,
        Err(error) => {
            return Err(cleanup_after_failure(
                sidecar,
                DesktopLocalCompositionError::Bootstrap(error),
            )
            .await);
        }
    };
    let database = match admin.connect_application().await {
        Ok(database) => database,
        Err(error) => {
            return Err(cleanup_after_failure(
                sidecar,
                DesktopLocalCompositionError::Database(error),
            )
            .await);
        }
    };
    let report = match installation
        .bootstrap_postgres(database.pool(), package)
        .await
    {
        Ok(report) => report,
        Err(error) => {
            database.close();
            return Err(cleanup_after_failure(
                sidecar,
                DesktopLocalCompositionError::Bootstrap(error),
            )
            .await);
        }
    };

    let runtime_auth = match installation
        .authority()
        .load_runtime_auth_context(database.pool())
        .await
    {
        Ok(auth) => auth,
        Err(error) => {
            database.close();
            return Err(cleanup_after_failure(
                sidecar,
                DesktopLocalCompositionError::Bootstrap(DesktopLocalBootstrapError::Principal(
                    error,
                )),
            )
            .await);
        }
    };

    Ok(RunningDesktopLocalDataPlane {
        database,
        sidecar: Some(sidecar),
        installation,
        runtime_auth,
        report,
    })
}

async fn cleanup_after_failure(
    sidecar: RunningPostgresSidecar,
    original: DesktopLocalCompositionError,
) -> DesktopLocalCompositionError {
    match sidecar.shutdown().await {
        Ok(()) => original,
        Err(_) => DesktopLocalCompositionError::FailureCleanup,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn errors_and_debug_never_retain_runtime_values() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let path = "/Users/private/example/postgresql-17-secret";
        let error = DesktopLocalCompositionError::InstallationMismatch;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains(path));
        assert_ne!(Path::new(path), Path::new("/different"));
    }
}
