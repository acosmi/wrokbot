//! Shared fresh / legacy / Rust-managed database initialization.
//!
//! Server and Desktop Local use one PostgreSQL schema and therefore must use one origin detector
//! and migration path. Keeping this in a transport binary would let the Desktop setup silently
//! diverge from Server at the most security-sensitive bootstrap boundary.

use deadpool_postgres::Pool;

use super::compat::{DataMigrationVerdict, check_migration_boundary_on};
use super::{InfraError, fresh, native};

/// The database origin recognized during this startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOrigin {
    /// The public schema was empty and received the atomic Rust baseline plus native migrations.
    Fresh,
    /// A trusted Rust native migration ledger already existed.
    RustManaged,
    /// A legacy database had a complete Drizzle ledger and then received native migrations.
    LegacyUpgraded,
}

/// Stable database initialization failure without row values or connection secrets.
#[derive(Debug)]
pub enum DatabaseInitializationError {
    /// A redacted connection/schema/migration error from the infra database layer.
    Infra(InfraError),
    /// A nonempty public schema had neither a complete Drizzle ledger nor a trusted native ledger.
    LegacyDataMigrationUnverifiable,
}

impl core::fmt::Display for DatabaseInitializationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Infra(error) => core::fmt::Display::fmt(error, formatter),
            Self::LegacyDataMigrationUnverifiable => {
                formatter.write_str("legacy_data_migration_unverifiable")
            }
        }
    }
}

impl std::error::Error for DatabaseInitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Infra(error) => Some(error),
            Self::LegacyDataMigrationUnverifiable => None,
        }
    }
}

impl From<InfraError> for DatabaseInitializationError {
    fn from(error: InfraError) -> Self {
        Self::Infra(error)
    }
}

/// Initialize or verify one OpenBot PostgreSQL database and apply current native migrations.
///
/// Rust fresh databases use the native ledger as their restart provenance. Unknown nonempty
/// legacy databases remain fail-closed; schema similarity cannot prove that data-only migration
/// `0003` ran.
///
/// # Errors
///
/// Returns [`DatabaseInitializationError`] when origin evidence, baseline, or a native migration
/// cannot be verified and committed.
pub async fn initialize(pool: &Pool) -> Result<DatabaseOrigin, DatabaseInitializationError> {
    let mut client = pool
        .get()
        .await
        .map_err(|source| InfraError::connect("取数据库初始化连接", source))?;
    let public_tables: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM information_schema.tables \
             WHERE table_schema='public' AND table_type='BASE TABLE'",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("检查 public schema 是否为空", source))?
        .try_get(0)
        .map_err(|source| {
            super::RowDecodeError::column("(information_schema.tables)", "count", source)
        })
        .map_err(InfraError::from)?;

    if public_tables == 0 {
        match fresh::apply(&mut client).await? {
            fresh::FreshApplyOutcome::Applied(_) => return Ok(DatabaseOrigin::Fresh),
            fresh::FreshApplyOutcome::AlreadyInitialized => {}
        }
    }

    let rust_managed = native::ledger_exists(&client).await?;
    let report = check_migration_boundary_on(&client).await?;
    if matches!(
        report.data_migrations,
        DataMigrationVerdict::Unverifiable { .. }
    ) && !rust_managed
    {
        return Err(DatabaseInitializationError::LegacyDataMigrationUnverifiable);
    }

    native::apply(&mut client).await?;
    Ok(if rust_managed {
        DatabaseOrigin::RustManaged
    } else {
        DatabaseOrigin::LegacyUpgraded
    })
}
