//! 本项目自有的 native schema 增量施加器。
//!
//! 上游的 13 条 Drizzle migration 与本项目的增量有两条不同的职责边界：
//!
//! - [`crate::db::baseline`] 把空库一次建成上游 0012 终态；
//! - [`crate::db::compat`] 只读 `drizzle.__drizzle_migrations`，确认旧库至少到 0012；
//! - 本模块从 0012 往后施加 Rust-owned migration，schema 只允许 expand，**绝不写上游账本**；
//! - 唯一数据覆写例外是具名、可审计的隐私保留期清除；它只能把已终态 run 的 reasoning
//!   payload 收敛为固定无内容标记，不能改业务身份、序列或 terminal 事实。
//!
//! # 自有账本与并发
//!
//! 自有账本是 [`NATIVE_LEDGER_TABLE`]。每条记录绑定 version、名字与 migration SQL 的
//! SHA-256；同版本字节漂移会 fail-closed，不会因为对象“看起来已存在”就跳过。施加全过程在
//! 一个事务里，并先取固定的 transaction-scoped advisory lock，因此多个 replica 同时启动时
//! 恰好一个施加，随后者读到账本后返回 [`ApplyOutcome::AlreadyApplied`]。
//!
//! 真实 migration SQL 刻意没有 `IF NOT EXISTS`：账本缺失而对象已存在是 drift，必须让 DDL
//! 报错并整体回滚。只有账本自身的 bootstrap 使用 `IF NOT EXISTS`，且随后立刻按列读它；一个
//! 同名异形表不会被当作正常账本。
//!
//! # Fresh install 与 upgrade 是同一条终态
//!
//! Fresh install 只走 [`crate::db::fresh::apply`]，把 baseline 与本模块的事务内核心/账本同批
//! 提交；既有库先过 compat，再调用 [`apply`]。这样 0012 fixture 始终只表达固定上游 oracle，
//! 每个 native 边界另有自己的 post fixture，事实不会互相污染。

use openbot_domain::audit::hash::Sha256Digest;
use tokio_postgres::Client;

use crate::db::{InfraError, RowDecodeError};

/// 自有 migration 账本。它不在 `public`，也不是上游 Drizzle 的账本。
pub const NATIVE_LEDGER_TABLE: &str = "openbot_internal.schema_migrations";

/// 第一条 Rust-owned 增量的版本号。
pub const NATIVE_0013_VERSION: i32 = 13;

/// 第一条 Rust-owned 增量的稳定名字。
pub const NATIVE_0013_NAME: &str = "native_0013_audit_tool_pipeline";

/// 第一条 Rust-owned 增量的 SQL 原文。
pub const NATIVE_0013_SQL: &str = include_str!("../../sql/native_0013.sql");

/// 持久化 user auth generation 的版本号。
pub const NATIVE_0014_VERSION: i32 = 14;

/// 0014 的稳定名字。
pub const NATIVE_0014_NAME: &str = "native_0014_user_auth_generation";

/// 0014 SQL 原文。
pub const NATIVE_0014_SQL: &str = include_str!("../../sql/native_0014.sql");

/// Rust session 签发代际的版本号。
pub const NATIVE_0015_VERSION: i32 = 15;

/// 0015 的稳定名字。
pub const NATIVE_0015_NAME: &str = "native_0015_session_auth_generation";

/// 0015 SQL 原文。
pub const NATIVE_0015_SQL: &str = include_str!("../../sql/native_0015.sql");

/// Native thread/realtime/memory 地基版本号。
pub const NATIVE_0016_VERSION: i32 = 16;

/// 0016 的稳定名字。
pub const NATIVE_0016_NAME: &str = "native_0016_thread_realtime_memory_base";

/// 0016 SQL 原文。
pub const NATIVE_0016_SQL: &str = include_str!("../../sql/native_0016.sql");

/// MCP catalog/stale-grant/callback sequence version.
pub const NATIVE_0017_VERSION: i32 = 17;

/// 0017 stable name.
pub const NATIVE_0017_NAME: &str = "native_0017_mcp_catalog_callback_sequence";

/// 0017 SQL source.
pub const NATIVE_0017_SQL: &str = include_str!("../../sql/native_0017.sql");

/// MCP credential-generation identity version.
pub const NATIVE_0018_VERSION: i32 = 18;

/// 0018 stable name.
pub const NATIVE_0018_NAME: &str = "native_0018_mcp_credential_generation";

/// 0018 SQL source.
pub const NATIVE_0018_SQL: &str = include_str!("../../sql/native_0018.sql");

/// Explicit MCP/Drive vendor transport identity version.
pub const NATIVE_0019_VERSION: i32 = 19;

/// 0019 stable name.
pub const NATIVE_0019_NAME: &str = "native_0019_vendor_transport_identity";

/// 0019 SQL source.
pub const NATIVE_0019_SQL: &str = include_str!("../../sql/native_0019.sql");

/// Durable tool-approval request version.
pub const NATIVE_0020_VERSION: i32 = 20;

/// 0020 stable name.
pub const NATIVE_0020_NAME: &str = "native_0020_tool_approvals";

/// 0020 SQL source.
pub const NATIVE_0020_SQL: &str = include_str!("../../sql/native_0020.sql");

/// Actor-scoped Server UI preference version.
pub const NATIVE_0021_VERSION: i32 = 21;

/// 0021 stable name.
pub const NATIVE_0021_NAME: &str = "native_0021_user_ui_preferences";

/// 0021 SQL source.
pub const NATIVE_0021_SQL: &str = include_str!("../../sql/native_0021.sql");

/// Actor-scoped runtime memory control version.
pub const NATIVE_0022_VERSION: i32 = 22;

/// 0022 stable name.
pub const NATIVE_0022_NAME: &str = "native_0022_user_memory_controls";

/// 0022 SQL source.
pub const NATIVE_0022_SQL: &str = include_str!("../../sql/native_0022.sql");

/// Durable compiled-component human-decision version.
pub const NATIVE_0023_VERSION: i32 = 23;

/// 0023 stable name.
pub const NATIVE_0023_NAME: &str = "native_0023_component_human_decisions";

/// 0023 SQL source.
pub const NATIVE_0023_SQL: &str = include_str!("../../sql/native_0023.sql");

/// Durable run-wide normalized provider token accounting version.
pub const NATIVE_0024_VERSION: i32 = 24;

/// 0024 stable name.
pub const NATIVE_0024_NAME: &str = "native_0024_run_token_usage";

/// 0024 SQL source.
pub const NATIVE_0024_SQL: &str = include_str!("../../sql/native_0024.sql");

/// Durable operator-attested provider cost accounting version.
pub const NATIVE_0025_VERSION: i32 = 25;

/// 0025 stable name.
pub const NATIVE_0025_NAME: &str = "native_0025_run_provider_cost_upper_bound";

/// 0025 SQL source.
pub const NATIVE_0025_SQL: &str = include_str!("../../sql/native_0025.sql");

/// Actor-scoped per-run cost-cap and immutable snapshot version.
pub const NATIVE_0026_VERSION: i32 = 26;

/// 0026 stable name.
pub const NATIVE_0026_NAME: &str = "native_0026_user_run_cost_budgets";

/// 0026 SQL source.
pub const NATIVE_0026_SQL: &str = include_str!("../../sql/native_0026.sql");

/// Terminal-run reasoning retention redaction version.
pub const NATIVE_0027_VERSION: i32 = 27;

/// 0027 stable name.
pub const NATIVE_0027_NAME: &str = "native_0027_terminal_reasoning_retention";

/// 0027 SQL source.
pub const NATIVE_0027_SQL: &str = include_str!("../../sql/native_0027.sql");

/// Durable remote AG-UI interrupt/resume version.
pub const NATIVE_0028_VERSION: i32 = 28;

/// 0028 stable name.
pub const NATIVE_0028_NAME: &str = "native_0028_remote_agent_interrupts";

/// 0028 SQL source.
pub const NATIVE_0028_SQL: &str = include_str!("../../sql/native_0028.sql");

/// Explicit custom-MCP private-egress authority version.
pub const NATIVE_0029_VERSION: i32 = 29;

/// 0029 stable name.
pub const NATIVE_0029_NAME: &str = "native_0029_mcp_private_egress";

/// 0029 SQL source.
pub const NATIVE_0029_SQL: &str = include_str!("../../sql/native_0029.sql");

/// Personal custom-model connection/credential authority version.
pub const NATIVE_0030_VERSION: i32 = 30;
/// 0030 stable name.
pub const NATIVE_0030_NAME: &str = "native_0030_personal_model_connections";
/// 0030 SQL source.
pub const NATIVE_0030_SQL: &str = include_str!("../../sql/native_0030.sql");

/// 当前二进制认识的最新 native schema 版本。
pub const NATIVE_LATEST_VERSION: i32 = NATIVE_0031_VERSION;

/// Immutable explicit custom-model run binding version.
pub const NATIVE_0031_VERSION: i32 = 31;
/// 0031 stable migration name.
pub const NATIVE_0031_NAME: &str = "native_0031_run_model_selections";
/// 0031 expand-only SQL source.
pub const NATIVE_0031_SQL: &str = include_str!("../../sql/native_0031.sql");

/// 当前二进制钉住的 native migration 数量。
pub const NATIVE_MIGRATION_COUNT: usize = MIGRATIONS.len();

/// 全部署共用的 migration advisory lock key（ASCII `OPENBOT1`）。
const MIGRATION_LOCK_KEY: i64 = 0x4f50_454e_424f_5431;

const LEDGER_ROW_LABEL: &str = "(openbot_internal.schema_migrations)";

struct MigrationSpec {
    version: i32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[MigrationSpec] = &[
    MigrationSpec {
        version: NATIVE_0013_VERSION,
        name: NATIVE_0013_NAME,
        sql: NATIVE_0013_SQL,
    },
    MigrationSpec {
        version: NATIVE_0014_VERSION,
        name: NATIVE_0014_NAME,
        sql: NATIVE_0014_SQL,
    },
    MigrationSpec {
        version: NATIVE_0015_VERSION,
        name: NATIVE_0015_NAME,
        sql: NATIVE_0015_SQL,
    },
    MigrationSpec {
        version: NATIVE_0016_VERSION,
        name: NATIVE_0016_NAME,
        sql: NATIVE_0016_SQL,
    },
    MigrationSpec {
        version: NATIVE_0017_VERSION,
        name: NATIVE_0017_NAME,
        sql: NATIVE_0017_SQL,
    },
    MigrationSpec {
        version: NATIVE_0018_VERSION,
        name: NATIVE_0018_NAME,
        sql: NATIVE_0018_SQL,
    },
    MigrationSpec {
        version: NATIVE_0019_VERSION,
        name: NATIVE_0019_NAME,
        sql: NATIVE_0019_SQL,
    },
    MigrationSpec {
        version: NATIVE_0020_VERSION,
        name: NATIVE_0020_NAME,
        sql: NATIVE_0020_SQL,
    },
    MigrationSpec {
        version: NATIVE_0021_VERSION,
        name: NATIVE_0021_NAME,
        sql: NATIVE_0021_SQL,
    },
    MigrationSpec {
        version: NATIVE_0022_VERSION,
        name: NATIVE_0022_NAME,
        sql: NATIVE_0022_SQL,
    },
    MigrationSpec {
        version: NATIVE_0023_VERSION,
        name: NATIVE_0023_NAME,
        sql: NATIVE_0023_SQL,
    },
    MigrationSpec {
        version: NATIVE_0024_VERSION,
        name: NATIVE_0024_NAME,
        sql: NATIVE_0024_SQL,
    },
    MigrationSpec {
        version: NATIVE_0025_VERSION,
        name: NATIVE_0025_NAME,
        sql: NATIVE_0025_SQL,
    },
    MigrationSpec {
        version: NATIVE_0026_VERSION,
        name: NATIVE_0026_NAME,
        sql: NATIVE_0026_SQL,
    },
    MigrationSpec {
        version: NATIVE_0027_VERSION,
        name: NATIVE_0027_NAME,
        sql: NATIVE_0027_SQL,
    },
    MigrationSpec {
        version: NATIVE_0028_VERSION,
        name: NATIVE_0028_NAME,
        sql: NATIVE_0028_SQL,
    },
    MigrationSpec {
        version: NATIVE_0029_VERSION,
        name: NATIVE_0029_NAME,
        sql: NATIVE_0029_SQL,
    },
    MigrationSpec {
        version: NATIVE_0030_VERSION,
        name: NATIVE_0030_NAME,
        sql: NATIVE_0030_SQL,
    },
    MigrationSpec {
        version: NATIVE_0031_VERSION,
        name: NATIVE_0031_NAME,
        sql: NATIVE_0031_SQL,
    },
];

const LEDGER_BOOTSTRAP_SQL: &str = r#"
CREATE SCHEMA IF NOT EXISTS openbot_internal;
CREATE TABLE IF NOT EXISTS openbot_internal.schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT schema_migrations_checksum_lower_hex
        CHECK (checksum ~ '^[0-9a-f]{64}$')
);
"#;

/// 一次施加的可观察结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 本次事务施加并记账。
    Applied,
    /// 同字节的 migration 已经记账，本次零 DDL。
    AlreadyApplied,
}

/// 自有 migration 账本的构造性违例。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeMigrationViolation {
    /// 同版本已经存在，但名字或 SQL 摘要不同。
    #[error(
        "native migration {version} 账本漂移：期望 name={expected_name} checksum={expected_checksum}，实际 name={actual_name} checksum={actual_checksum}"
    )]
    LedgerDrift {
        /// 版本号。
        version: i32,
        /// 当前二进制钉死的名字。
        expected_name: &'static str,
        /// 当前二进制钉死的 SQL 摘要。
        expected_checksum: String,
        /// 数据库账本里的名字。
        actual_name: String,
        /// 数据库账本里的摘要。
        actual_checksum: String,
    },
    /// 账本已经有更晚版本，却缺当前版本；不能倒序补写。
    #[error(
        "native migration 账本有版本 {future_version}，却缺前置版本 {missing_version}；拒绝倒序施加"
    )]
    MissingBeforeFuture {
        /// 缺失的当前版本。
        missing_version: i32,
        /// 已经存在的更晚版本。
        future_version: i32,
    },
}

/// 0013 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0013_checksum() -> String {
    Sha256Digest::of(NATIVE_0013_SQL.as_bytes()).to_hex()
}

/// 当前 0014 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0014_checksum() -> String {
    Sha256Digest::of(NATIVE_0014_SQL.as_bytes()).to_hex()
}

/// 当前 0015 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0015_checksum() -> String {
    Sha256Digest::of(NATIVE_0015_SQL.as_bytes()).to_hex()
}

/// 当前 0016 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0016_checksum() -> String {
    Sha256Digest::of(NATIVE_0016_SQL.as_bytes()).to_hex()
}

/// Current 0017 SQL lowercase SHA-256.
#[must_use]
pub fn native_0017_checksum() -> String {
    Sha256Digest::of(NATIVE_0017_SQL.as_bytes()).to_hex()
}

/// Current 0018 SQL lowercase SHA-256.
#[must_use]
pub fn native_0018_checksum() -> String {
    Sha256Digest::of(NATIVE_0018_SQL.as_bytes()).to_hex()
}

/// Current 0019 SQL lowercase SHA-256.
#[must_use]
pub fn native_0019_checksum() -> String {
    Sha256Digest::of(NATIVE_0019_SQL.as_bytes()).to_hex()
}

/// Current 0020 SQL lowercase SHA-256.
#[must_use]
pub fn native_0020_checksum() -> String {
    Sha256Digest::of(NATIVE_0020_SQL.as_bytes()).to_hex()
}

/// Current 0021 SQL lowercase SHA-256.
#[must_use]
pub fn native_0021_checksum() -> String {
    Sha256Digest::of(NATIVE_0021_SQL.as_bytes()).to_hex()
}

/// Current 0022 SQL lowercase SHA-256.
#[must_use]
pub fn native_0022_checksum() -> String {
    Sha256Digest::of(NATIVE_0022_SQL.as_bytes()).to_hex()
}

/// Current 0023 SQL lowercase SHA-256.
#[must_use]
pub fn native_0023_checksum() -> String {
    Sha256Digest::of(NATIVE_0023_SQL.as_bytes()).to_hex()
}

/// Current 0024 SQL lowercase SHA-256.
#[must_use]
pub fn native_0024_checksum() -> String {
    Sha256Digest::of(NATIVE_0024_SQL.as_bytes()).to_hex()
}

/// Current 0025 SQL lowercase SHA-256.
#[must_use]
pub fn native_0025_checksum() -> String {
    Sha256Digest::of(NATIVE_0025_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0026 SQL bytes.
#[must_use]
pub fn native_0026_checksum() -> String {
    Sha256Digest::of(NATIVE_0026_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0027 SQL bytes.
#[must_use]
pub fn native_0027_checksum() -> String {
    Sha256Digest::of(NATIVE_0027_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0028 SQL bytes.
#[must_use]
pub fn native_0028_checksum() -> String {
    Sha256Digest::of(NATIVE_0028_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0029 SQL bytes.
#[must_use]
pub fn native_0029_checksum() -> String {
    Sha256Digest::of(NATIVE_0029_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0030 SQL bytes.
#[must_use]
pub fn native_0030_checksum() -> String {
    Sha256Digest::of(NATIVE_0030_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0031 SQL bytes.
#[must_use]
pub fn native_0031_checksum() -> String {
    Sha256Digest::of(NATIVE_0031_SQL.as_bytes()).to_hex()
}

/// 在一个已到 0012 的数据库上施加当前二进制认识的全部 Rust-owned migrations。
///
/// # Errors
///
/// - 连接/DDL/账本查询失败返回脱敏的 [`InfraError::Query`]；
/// - 同版本账本漂移或出现版本空洞返回 [`InfraError::NativeMigration`]；
/// - commit 失败同样返回查询错误，事务由 PostgreSQL 回滚。
pub async fn apply(client: &mut Client) -> Result<ApplyOutcome, InfraError> {
    apply_through(client, NATIVE_LATEST_VERSION).await
}

/// 只施加到给定版本（含）；历史 fixture 测试用它固定 0013 边界。
///
/// 生产启动应调用 [`apply`]。本入口仍走同一账本/锁/摘要校验，不是绕过 migration 的测试后门。
pub async fn apply_through(
    client: &mut Client,
    max_version: i32,
) -> Result<ApplyOutcome, InfraError> {
    let transaction = client
        .transaction()
        .await
        .map_err(|source| InfraError::query("开始 native schema migration 事务", source))?;

    let outcome = apply_through_in_transaction(&transaction, max_version).await?;
    transaction
        .commit()
        .await
        .map_err(|source| InfraError::query("提交 native schema migrations", source))?;
    Ok(outcome)
}

/// 自有账本表是否存在；存在只代表“应走 native 校验”，不代表内容已经可信。
///
/// 调用方随后必须调用 [`apply`]，由名字/版本/checksum/空洞四项验证内容。
pub async fn ledger_exists(client: &Client) -> Result<bool, InfraError> {
    client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&NATIVE_LEDGER_TABLE],
        )
        .await
        .map_err(|source| InfraError::query("探测 native schema migration 账本", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column("(to_regclass)", "exists", source).into())
}

pub(crate) async fn apply_through_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    max_version: i32,
) -> Result<ApplyOutcome, InfraError> {
    lock_migrations(transaction).await?;

    transaction
        .batch_execute(LEDGER_BOOTSTRAP_SQL)
        .await
        .map_err(|source| InfraError::query("初始化 native schema migration 账本", source))?;

    let mut applied = 0usize;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= max_version)
    {
        let checksum = Sha256Digest::of(migration.sql.as_bytes()).to_hex();
        let existing = transaction
            .query_opt(
                "SELECT name, checksum FROM openbot_internal.schema_migrations WHERE version = $1",
                &[&migration.version],
            )
            .await
            .map_err(|source| InfraError::query("读取 native schema migration 账本", source))?;

        if let Some(row) = existing {
            let actual_name: String = row
                .try_get("name")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
            let actual_checksum: String = row
                .try_get("checksum")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
            if actual_name != migration.name || actual_checksum != checksum {
                return Err(NativeMigrationViolation::LedgerDrift {
                    version: migration.version,
                    expected_name: migration.name,
                    expected_checksum: checksum,
                    actual_name,
                    actual_checksum,
                }
                .into());
            }
            continue;
        }

        let future = transaction
            .query_opt(
                "SELECT version FROM openbot_internal.schema_migrations \
                 WHERE version > $1 ORDER BY version LIMIT 1",
                &[&migration.version],
            )
            .await
            .map_err(|source| InfraError::query("检查 native schema migration 版本空洞", source))?;
        if let Some(row) = future {
            let future_version: i32 = row
                .try_get("version")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
            return Err(NativeMigrationViolation::MissingBeforeFuture {
                missing_version: migration.version,
                future_version,
            }
            .into());
        }

        transaction
            .batch_execute(migration.sql)
            .await
            .map_err(|source| InfraError::query(format!("应用 {}", migration.name), source))?;
        transaction
            .execute(
                "INSERT INTO openbot_internal.schema_migrations (version, name, checksum) \
                 VALUES ($1, $2, $3)",
                &[&migration.version, &migration.name, &checksum],
            )
            .await
            .map_err(|source| InfraError::query(format!("记录 {} 账本", migration.name), source))?;
        applied += 1;
    }

    Ok(if applied == 0 {
        ApplyOutcome::AlreadyApplied
    } else {
        ApplyOutcome::Applied
    })
}

pub(crate) async fn lock_migrations(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map(|_| ())
        .map_err(|source| InfraError::query("获取 native schema migration 锁", source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_lines(sql: &'static str) -> impl Iterator<Item = &'static str> {
        sql.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("--"))
    }

    #[test]
    fn schema_migration_sql_is_mechanically_expand_only() {
        let forbidden_prefixes = ["DROP ", "TRUNCATE ", "DELETE ", "UPDATE "];
        for line in statement_lines(NATIVE_0013_SQL)
            .chain(statement_lines(NATIVE_0014_SQL))
            .chain(statement_lines(NATIVE_0015_SQL))
            .chain(statement_lines(NATIVE_0016_SQL))
            .chain(statement_lines(NATIVE_0017_SQL))
            .chain(statement_lines(NATIVE_0018_SQL))
            .chain(statement_lines(NATIVE_0019_SQL))
            .chain(statement_lines(NATIVE_0020_SQL))
            .chain(statement_lines(NATIVE_0021_SQL))
            .chain(statement_lines(NATIVE_0022_SQL))
            .chain(statement_lines(NATIVE_0023_SQL))
            .chain(statement_lines(NATIVE_0024_SQL))
            .chain(statement_lines(NATIVE_0025_SQL))
            .chain(statement_lines(NATIVE_0026_SQL))
            .chain(statement_lines(NATIVE_0030_SQL))
            .chain(statement_lines(NATIVE_0031_SQL))
        {
            let uppercase = line.to_ascii_uppercase();
            assert!(
                !forbidden_prefixes
                    .iter()
                    .any(|prefix| uppercase.starts_with(prefix)),
                "0013 出现 destructive 语句：{line}",
            );
            for forbidden in [" RENAME ", "ALTER COLUMN", "SET NOT NULL"] {
                assert!(
                    !uppercase.contains(forbidden),
                    "0013 出现兼容期禁令 `{forbidden}`：{line}",
                );
            }
        }

        assert_eq!(NATIVE_0013_SQL.matches("CREATE TABLE public.").count(), 3);
        assert_eq!(
            NATIVE_0013_SQL
                .matches("ALTER TABLE public.audit_events\n    ADD COLUMN")
                .count(),
            2,
        );
        assert!(NATIVE_0013_SQL.contains("ADD COLUMN prev_hash text"));
        assert!(NATIVE_0013_SQL.contains("ADD COLUMN row_hash text"));
        assert!(NATIVE_0014_SQL.contains("ADD COLUMN auth_generation bigint"));
        assert!(!statement_lines(NATIVE_0014_SQL).any(|line| line.contains("SET NOT NULL")));
        assert!(NATIVE_0015_SQL.contains("ADD COLUMN auth_generation bigint"));
        assert!(!statement_lines(NATIVE_0015_SQL).any(|line| line.contains("SET NOT NULL")));
        assert_eq!(NATIVE_0016_SQL.matches("CREATE TABLE public.").count(), 10);
        assert!(NATIVE_0016_SQL.contains("ADD CONSTRAINT tool_calls_run_id_fkey"));
        assert!(NATIVE_0016_SQL.contains("NOT VALID"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN next_tool_call_seq bigint"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN catalog_generation bigint"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN catalog_transport_fingerprint text"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN transport_fingerprint text"));
        assert!(NATIVE_0017_SQL.contains("suspended_missing"));
        assert!(NATIVE_0018_SQL.contains("ADD COLUMN credential_generation bigint"));
        assert!(NATIVE_0019_SQL.contains("ADD COLUMN transport text"));
        assert!(NATIVE_0019_SQL.contains("google_drive_rest"));
        assert!(NATIVE_0020_SQL.contains("CREATE TABLE public.tool_approvals"));
        assert!(NATIVE_0020_SQL.contains("tool_approvals_decision_shape"));
        assert!(NATIVE_0021_SQL.contains("CREATE TABLE public.user_ui_preferences"));
        assert!(NATIVE_0021_SQL.contains("user_ui_preferences_nonempty"));
        assert!(NATIVE_0022_SQL.contains("CREATE TABLE public.user_memory_controls"));
        assert!(NATIVE_0022_SQL.contains("user_memory_controls_identity_nonempty"));
        assert!(NATIVE_0023_SQL.contains("CREATE TABLE public.component_human_decisions"));
        assert!(NATIVE_0023_SQL.contains("component_human_decisions_answer_shape"));
        assert!(NATIVE_0024_SQL.contains("ADD COLUMN budget_max_output_tokens bigint"));
        assert!(NATIVE_0024_SQL.contains("runs_usage_last_shape"));
        assert!(NATIVE_0025_SQL.contains("ADD COLUMN cost_currency text"));
        assert!(NATIVE_0025_SQL.contains("runs_cost_accounting_shape"));
        assert!(NATIVE_0026_SQL.contains("CREATE TABLE public.user_run_cost_budgets"));
        assert!(NATIVE_0026_SQL.contains("ADD COLUMN budget_cost_currency text"));
        assert!(NATIVE_0026_SQL.contains("runs_cost_budget_shape"));
        assert!(NATIVE_0028_SQL.contains("CREATE TABLE public.remote_agent_interrupts"));
        assert!(NATIVE_0028_SQL.contains("remote_agent_interrupts_state_shape"));
        assert!(NATIVE_0029_SQL.contains("ADD COLUMN egress_allow_cidrs text[]"));
        assert!(NATIVE_0029_SQL.contains("provenance = 'custom'"));
    }

    #[test]
    fn terminal_reasoning_retention_is_the_only_narrow_data_redaction() {
        let statements = statement_lines(NATIVE_0027_SQL).collect::<Vec<_>>();
        let statement_sql = statements.join("\n");
        assert_eq!(statement_sql.matches(';').count(), 1);
        assert_eq!(
            statements
                .iter()
                .filter(|line| line.to_ascii_uppercase().starts_with("UPDATE "))
                .count(),
            1
        );
        assert!(statements[0].starts_with("UPDATE public.run_events AS reasoning_event"));
        assert!(NATIVE_0027_SQL.contains(
            "SET payload = jsonb_build_object(\n    'channel', 'reasoning',\n    'delta', '',\n    'retained', false\n)"
        ));
        assert!(NATIVE_0027_SQL.contains("reasoning_event.event_type = 'semantic_chunk'"));
        assert!(NATIVE_0027_SQL.contains(
            "run.status IN ('completed', 'failed', 'cancelled', 'reconciliation_required')"
        ));
        assert!(NATIVE_0027_SQL.contains("reasoning_event.payload->>'channel' = 'reasoning'"));
        for forbidden in [
            "DROP ",
            "TRUNCATE ",
            "DELETE ",
            "ALTER ",
            "CREATE ",
            "INSERT ",
            " RENAME ",
            "SET NOT NULL",
        ] {
            assert!(
                !statement_sql.to_ascii_uppercase().contains(forbidden),
                "0027 privacy redaction escaped its DML boundary: {forbidden}"
            );
        }
    }

    #[test]
    fn real_migration_uses_the_ledger_not_object_existence_as_idempotency() {
        assert!(
            !statement_lines(NATIVE_0013_SQL)
                .chain(statement_lines(NATIVE_0014_SQL))
                .chain(statement_lines(NATIVE_0015_SQL))
                .chain(statement_lines(NATIVE_0016_SQL))
                .chain(statement_lines(NATIVE_0017_SQL))
                .chain(statement_lines(NATIVE_0018_SQL))
                .chain(statement_lines(NATIVE_0019_SQL))
                .chain(statement_lines(NATIVE_0020_SQL))
                .chain(statement_lines(NATIVE_0021_SQL))
                .chain(statement_lines(NATIVE_0022_SQL))
                .chain(statement_lines(NATIVE_0023_SQL))
                .chain(statement_lines(NATIVE_0024_SQL))
                .chain(statement_lines(NATIVE_0025_SQL))
                .chain(statement_lines(NATIVE_0026_SQL))
                .chain(statement_lines(NATIVE_0027_SQL))
                .chain(statement_lines(NATIVE_0028_SQL))
                .chain(statement_lines(NATIVE_0029_SQL))
                .chain(statement_lines(NATIVE_0030_SQL))
                .chain(statement_lines(NATIVE_0031_SQL))
                .any(|line| line.contains("IF NOT EXISTS"))
        );
        assert!(LEDGER_BOOTSTRAP_SQL.contains("IF NOT EXISTS"));
        assert!(!LEDGER_BOOTSTRAP_SQL.contains("drizzle"));
        assert_eq!(NATIVE_LEDGER_TABLE, "openbot_internal.schema_migrations");
    }

    #[test]
    fn checksum_is_lowercase_sha256_and_changes_with_the_sql() {
        let checksum = native_0013_checksum();
        assert_eq!(checksum.len(), 64);
        assert!(
            checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        );
        assert_ne!(checksum, Sha256Digest::of(b"different migration").to_hex());
        let next = native_0014_checksum();
        assert_eq!(next.len(), 64);
        assert_ne!(checksum, next);
        let latest = native_0015_checksum();
        assert_eq!(latest.len(), 64);
        assert_ne!(next, latest);
        let native_thread = native_0016_checksum();
        assert_eq!(native_thread.len(), 64);
        assert_ne!(latest, native_thread);
        let native_mcp = native_0017_checksum();
        assert_eq!(native_mcp.len(), 64);
        assert_ne!(native_thread, native_mcp);
        let native_credential_generation = native_0018_checksum();
        assert_eq!(native_credential_generation.len(), 64);
        assert_ne!(native_mcp, native_credential_generation);
        let native_transport = native_0019_checksum();
        assert_eq!(native_transport.len(), 64);
        assert_ne!(native_credential_generation, native_transport);
        let native_approval = native_0020_checksum();
        assert_eq!(native_approval.len(), 64);
        assert_ne!(native_transport, native_approval);
        let native_ui_preferences = native_0021_checksum();
        assert_eq!(native_ui_preferences.len(), 64);
        assert_ne!(native_approval, native_ui_preferences);
        let native_memory_controls = native_0022_checksum();
        assert_eq!(native_memory_controls.len(), 64);
        assert_ne!(native_ui_preferences, native_memory_controls);
        let native_component_decisions = native_0023_checksum();
        assert_eq!(native_component_decisions.len(), 64);
        assert_ne!(native_memory_controls, native_component_decisions);
        let native_run_usage = native_0024_checksum();
        assert_eq!(native_run_usage.len(), 64);
        assert_ne!(native_component_decisions, native_run_usage);
        let native_run_cost = native_0025_checksum();
        assert_eq!(native_run_cost.len(), 64);
        assert_ne!(native_run_usage, native_run_cost);
        let native_run_cost_budget = native_0026_checksum();
        assert_eq!(native_run_cost_budget.len(), 64);
        assert_ne!(native_run_cost, native_run_cost_budget);
        let native_reasoning_retention = native_0027_checksum();
        assert_eq!(native_reasoning_retention.len(), 64);
        assert_ne!(native_run_cost_budget, native_reasoning_retention);
        let native_remote_interrupts = native_0028_checksum();
        assert_eq!(native_remote_interrupts.len(), 64);
        assert_ne!(native_reasoning_retention, native_remote_interrupts);
        let native_mcp_private_egress = native_0029_checksum();
        assert_eq!(native_mcp_private_egress.len(), 64);
        assert_ne!(native_remote_interrupts, native_mcp_private_egress);
        let personal_model_connections = native_0030_checksum();
        assert_eq!(personal_model_connections.len(), 64);
        assert_ne!(native_mcp_private_egress, personal_model_connections);
        let run_model_selections = native_0031_checksum();
        assert_eq!(run_model_selections.len(), 64);
        assert_ne!(personal_model_connections, run_model_selections);
        assert_eq!(MIGRATIONS.len(), 19);
        assert_eq!(MIGRATIONS[18].version, NATIVE_LATEST_VERSION);
    }
}
