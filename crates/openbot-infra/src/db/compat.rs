//! 迁移边界检查（v3 §14.1 逐字：「升级前先要求旧 OpenBot 把数据库迁到当前第 13 条 migration
//! （`0012`）；Rust 不接收更早 schema」）。
//!
//! [`check_migration_boundary`] 是**纯函数**：吃一份 [`SchemaFacts`]，吐 `Ok(())` 或一份结构化的
//! 不兼容报告。不做 I/O，所以每一条判据都能在单测里两个方向各造一个用例。
//! [`check_migration_boundary_on`] 是它的薄 I/O 封装，从活连接取事实再喂给它。
//!
//! # 判据（五条，每条都点名到具体的表 / 列 / 类型）
//!
//! 1. 28 张表一张不少 —— 缺表说明库比 0012 老，或者根本不是 OpenBot 的库。
//! 2. 每张表的列名 / 类型 / 可空性与 [`crate::db::tables`] 的台账逐列相等。
//! 3. [`RETIRED_TABLES`] 里 7 张表一张都不能在 —— 其中 `chunks` 在说明**没迁过 `0010`**。
//! 4. 4 个 enum 都在，标签逐个相等且顺序相同。
//! 5. [`RETIRED_ENUMS`] 里 3 个 enum 一个都不能在。
//!
//! # 刻意**不**检查的
//!
//! - **多出来的表 / 列 / 索引 / 触发器**：v3 §14.3 兼容期只允许 expand，新表与 nullable 新列
//!   本来就是允许的动作；G1 之后要落的 12 张 native 表正是以"多出来的表"形态出现，
//!   在这里判红会把自己锁死。
//! - **列默认值**：`DEFAULT now()` 之类由 baseline 负责建对，不是"库够不够新"的判据。
//!   真要逐字比对默认值，那是 baseline 与参照库的等价性测试（`tests/schema_baseline_parity.rs`）
//!   在做的事，判据比这里严格得多。
//!
//! # schema 级与账本级的分工（缺一条就有盲区）
//!
//! 13 条 migration 里 **12 条有 DDL 效果**（`0000` / `0001` / `0002` / `0004`..`0012`），
//! 它们跑没跑，[`check_migration_boundary`] 看 schema 事实就能判。
//!
//! **`0003_backfill_account_issuer.sql` 是唯一一条纯数据 migration** —— 整条只有一句
//! `UPDATE "accounts" SET "issuer" = CASE … END WHERE "issuer" IS NULL`，不动任何结构
//! （复算：`grep -cE '^\s*(CREATE|ALTER|DROP)' server/drizzle/0003_*.sql` = 0，
//! 其余 12 条均 ≥ 1，`0000` = 85，最少的 `0005` = 1）。
//!
//! 于是有一个结构性盲区：**一个跑到 `0002` 但没跑 `0003` 的库，与一个完整迁到 `0012` 的库，
//! schema 事实逐字段完全相同** —— [`check_migration_boundary`] 在构造上不可能区分它们。
//!
//! ## 为什么**不能**用 `accounts.issuer IS NULL` 来判（本轮被推翻的判据）
//!
//! 本模块第一版拿"`accounts` 里还有 `issuer IS NULL` 的行"当作"没跑过 `0003`"的证据。
//! **那是错的，已删除。** 上游 `server/src/db/schema/core.ts::accounts` 的 `issuer` 字段注释
//! 逐字写着：
//!
//! > Nullable in the database, **deliberately**, even though every write fills it. A rolling
//! > deploy runs the migrations and then serves from old and new replicas at once, and an old
//! > replica inserts an account without this column. Under `NOT NULL` that insert fails, so the
//! > release that adds the column would break the first sign-in of everybody who landed on a
//! > replica that had not been replaced yet.
//!
//! 也就是说 `issuer IS NULL` **在一个完整迁移过的库上是合法状态**。按它判红会拒绝启动健康的库
//! —— 这正是"把数据形状当成迁移证据"的典型误判：数据形状是**结果**，可以由多条路径产生，
//! 反推不出唯一的原因。
//!
//! 佐证同一件事：`0006` 里那句 `ALTER TABLE "accounts" ALTER COLUMN "issuer" DROP NOT NULL`
//! 是 **no-op** —— 全仓 migration `SET NOT NULL` 零命中，该列自 `0002`
//! （`ADD COLUMN "issuer" text`，无 `NOT NULL`）起就一直可空。
//!
//! ## 正确的信号是迁移账本
//!
//! 上游用 `drizzle-kit migrate`（`server/package.json` 的 `db:migrate`），而
//! `server/drizzle.config.ts` **没有**自定义 `migrations` 表/schema，所以账本落在 drizzle 的
//! 默认位置 [`MIGRATION_LEDGER_TABLE`]。本地对照物是 `server/drizzle/meta/_journal.json`，
//! 其 `entries` 恰好 [`EXPECTED_MIGRATION_ENTRIES`] 条（实测 13，`tag` 从 `0000_schema`
//! 到 `0012_truncate_is_not_a_way_around_append_only`）。
//!
//! [`check_migration_ledger`] 因此给出**三态**（[`DataMigrationVerdict`]），而不是二值：
//!
//! | 观测 | 判定 | 理由 |
//! | --- | --- | --- |
//! | 账本存在且 ≥ 13 条 | `Applied` | 13 条都跑过，含 `0003` |
//! | 账本存在但 < 13 条 | `Incomplete` | 没迁到 0012，判红并报出实得条数 |
//! | 账本表不存在 | `Unverifiable` | **既不判红也不默认通过** |
//!
//! 第三态不能折叠成"通过"，也不能折叠成"判红"：本项目的 Rust baseline 直接建 0012 终态、
//! **不写** drizzle 账本，所以"没有账本"对全新安装是正常的；而对一个从上游迁过来的库，
//! 没有账本意味着我们**确实不知道** `0003` 跑没跑。把"不知道"写成"通过"是撒谎，
//! 写成"判红"会拒绝全新安装。所以 [`check_migration_boundary_on`] 返回
//! [`MigrationBoundaryReport`]，把这个判定原样交给调用方去决定怎么处置。
//!
//! **将来若再出现纯数据 migration，账本判据自动覆盖它**（条目数会变），不需要再为它单独写
//! 数据形状判据 —— 这正是账本比数据形状好的地方。
//!
//! # 为什么 enum 标签要求**逐个相等**而不是"至少包含"
//!
//! 多出来的标签意味着库里可能存在 Rust 侧 `FromSql` 解不出来的值 —— [`crate::db::types`] 的
//! 四个枚举是封闭的，遇到未知标签会报错。放行"多标签"等于把一个确定性的启动期拒绝，
//! 换成运行期某一行随机解码失败。

use std::fmt;

use crate::db::schema_facts::{self, SchemaFacts};
use crate::db::tables::{ALL_TABLES, ColumnSpec};
use crate::db::types::EXPECTED_ENUMS;
use crate::db::{InfraError, RowDecodeError};

/// `0010` / `0011` 删掉的 7 张表。库里还有任何一张 = 没迁到 0012。
///
/// - `chunks` / `document_acls` / `documents` 由 `0010_drop_the_document_index.sql` 删除；
/// - `connector_cursors` / `webhook_subscriptions` / `sync_runs` / `connector_instances`
///   由 `0011_drop_the_old_connector_tables.sql` 删除。
///
/// 按名升序。
pub const RETIRED_TABLES: &[&str] = &[
    "chunks",
    "connector_cursors",
    "connector_instances",
    "document_acls",
    "documents",
    "sync_runs",
    "webhook_subscriptions",
];

/// `0010` / `0011` 删掉的 3 个 enum 类型。按名升序。
pub const RETIRED_ENUMS: &[&str] = &["acl_effect", "connector_type", "sync_status"];

/// 一条具体的不兼容。
///
/// 每个变体都点名到表 / 列 / 类型 —— 报告里出现"schema 不兼容"这五个字而说不出差在哪，
/// 对运维等于没说。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// 台账里有、库里没有的表。
    MissingTable {
        /// 表名。
        table: String,
    },
    /// 表在、但缺这一列。
    MissingColumn {
        /// 表名。
        table: String,
        /// 列名。
        column: String,
        /// 期望的 SQL 类型文本。
        expected_type: String,
    },
    /// 列在、但类型或可空性对不上。
    ColumnMismatch {
        /// 表名。
        table: String,
        /// 列名。
        column: String,
        /// 期望的 SQL 类型文本。
        expected_type: String,
        /// 库里实际的 SQL 类型文本。
        actual_type: String,
        /// 期望是否 NOT NULL。
        expected_not_null: bool,
        /// 库里实际是否 NOT NULL。
        actual_not_null: bool,
    },
    /// `0010` / `0011` 已删除、却仍在库里的表。
    RetiredTablePresent {
        /// 表名。
        table: String,
    },
    /// 缺失的 enum 类型。
    MissingEnum {
        /// 类型名。
        name: String,
    },
    /// 标签集或标签顺序对不上的 enum 类型。
    EnumMismatch {
        /// 类型名。
        name: String,
        /// 期望的标签，按 `enumsortorder`。
        expected: Vec<String>,
        /// 库里实际的标签，按 `enumsortorder`。
        actual: Vec<String>,
    },
    /// `0010` / `0011` 已删除、却仍在库里的 enum 类型。
    RetiredEnumPresent {
        /// 类型名。
        name: String,
    },
    /// 迁移账本条目不足：库没迁到 0012。
    ///
    /// schema 级检查照不到纯数据 migration，所以证据取自迁移账本而不是数据形状。
    IncompleteMigrationLedger {
        /// 账本表名。
        ledger_table: &'static str,
        /// 账本里实得的条目数。
        entries: i64,
        /// 迁到 0012 应有的条目数。
        expected: i64,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTable { table } => write!(f, "缺表：{table}"),
            Self::MissingColumn {
                table,
                column,
                expected_type,
            } => write!(f, "缺列：{table}.{column}（期望 {expected_type}）"),
            Self::ColumnMismatch {
                table,
                column,
                expected_type,
                actual_type,
                expected_not_null,
                actual_not_null,
            } => write!(
                f,
                "列不符：{table}.{column} 期望 {expected_type}{}，实际 {actual_type}{}",
                null_suffix(*expected_not_null),
                null_suffix(*actual_not_null),
            ),
            Self::RetiredTablePresent { table } => {
                write!(f, "已删除的表仍在：{table}")
            }
            Self::MissingEnum { name } => write!(f, "缺 enum 类型：{name}"),
            Self::EnumMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "enum `{name}` 标签不符：期望 [{}]，实际 [{}]",
                expected.join(", "),
                actual.join(", "),
            ),
            Self::RetiredEnumPresent { name } => {
                write!(f, "已删除的 enum 类型仍在：{name}")
            }
            Self::IncompleteMigrationLedger {
                ledger_table,
                entries,
                expected,
            } => write!(
                f,
                "迁移账本不足：{ledger_table} 只有 {entries} 条记录，期望 {expected} 条。\
                 说明库没迁到 0012（其中 0003 是纯数据 migration，不动结构，schema 级检查照不到它）。\
                 处置：用旧版 OpenBot 跑 `bun drizzle-kit migrate` 把剩余 migration 补完"
            ),
        }
    }
}

fn null_suffix(not_null: bool) -> &'static str {
    if not_null { " NOT NULL" } else { "" }
}

/// 库的 schema 与 0012 终态不兼容的结构化报告。
///
/// 全部不兼容一次收齐再返回，不在第一条不匹配处短路：运维要的是"还差哪些"，
/// 不是"第一个被发现的差异"。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationBoundaryViolation {
    findings: Vec<Finding>,
}

impl MigrationBoundaryViolation {
    /// 全部不兼容项，顺序 = 检查顺序（先表与列，再退休表，再 enum）。
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// 没有任何一条不兼容。
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// 库里是否还留着 `0010` 之前才有的 document 索引。
    ///
    /// 单独给一个判据，是因为它对运维的含义比"多了一张表"具体得多：
    /// `chunks` 在，说明 `0010` 根本没跑过，该库至少落后三条 migration。
    pub fn stuck_before_0010(&self) -> bool {
        self.findings.iter().any(|finding| {
            matches!(finding, Finding::RetiredTablePresent { table } if table == "chunks")
        })
    }

    fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}

impl fmt::Display for MigrationBoundaryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "数据库 schema 不是上游第 13 条 migration（0012）的终态，拒绝启动。\
             请先用旧版 OpenBot 把库迁到 0012 再升级（v3 §14.1：Rust 不接收更早 schema）。\
             共 {} 处不兼容：",
            self.findings.len(),
        )?;
        if self.stuck_before_0010() {
            writeln!(
                f,
                "  - 库里仍有 `chunks` 表：0010_drop_the_document_index.sql 没有跑过，\
                 该库至少落后 3 条 migration。"
            )?;
        }
        for finding in &self.findings {
            writeln!(f, "  - {finding}")?;
        }
        Ok(())
    }
}

impl std::error::Error for MigrationBoundaryViolation {}

/// 纯函数版迁移边界检查：只看事实，不碰 I/O。
///
/// # Errors
///
/// 任一判据不满足即返回 [`MigrationBoundaryViolation`]，里面列全了所有不满足项。
pub fn check_migration_boundary(observed: &SchemaFacts) -> Result<(), MigrationBoundaryViolation> {
    let mut report = MigrationBoundaryViolation::default();

    for expected in ALL_TABLES {
        let Some(actual) = observed.table(expected.name) else {
            report.push(Finding::MissingTable {
                table: expected.name.to_string(),
            });
            continue;
        };
        for column in expected.column_specs {
            check_column(expected.name, column, actual, &mut report);
        }
    }

    for retired in RETIRED_TABLES {
        if observed.table(retired).is_some() {
            report.push(Finding::RetiredTablePresent {
                table: (*retired).to_string(),
            });
        }
    }

    for expected in EXPECTED_ENUMS {
        match observed.enum_type(expected.name) {
            None => report.push(Finding::MissingEnum {
                name: expected.name.to_string(),
            }),
            Some(actual) => {
                let same = actual.values.len() == expected.labels.len()
                    && actual
                        .values
                        .iter()
                        .zip(expected.labels)
                        .all(|(got, want)| got == want);
                if !same {
                    report.push(Finding::EnumMismatch {
                        name: expected.name.to_string(),
                        expected: expected.labels.iter().map(|s| (*s).to_string()).collect(),
                        actual: actual.values.clone(),
                    });
                }
            }
        }
    }

    for retired in RETIRED_ENUMS {
        if observed.enum_type(retired).is_some() {
            report.push(Finding::RetiredEnumPresent {
                name: (*retired).to_string(),
            });
        }
    }

    if report.is_empty() {
        Ok(())
    } else {
        Err(report)
    }
}

fn check_column(
    table: &str,
    expected: &ColumnSpec,
    actual_table: &schema_facts::TableFacts,
    report: &mut MigrationBoundaryViolation,
) {
    let Some(actual) = actual_table.column(expected.name) else {
        report.push(Finding::MissingColumn {
            table: table.to_string(),
            column: expected.name.to_string(),
            expected_type: expected.sql_type.to_string(),
        });
        return;
    };
    if actual.sql_type != expected.sql_type || actual.notnull != expected.not_null {
        report.push(Finding::ColumnMismatch {
            table: table.to_string(),
            column: expected.name.to_string(),
            expected_type: expected.sql_type.to_string(),
            actual_type: actual.sql_type.clone(),
            expected_not_null: expected.not_null,
            actual_not_null: actual.notnull,
        });
    }
}

/// I/O 版：从活连接取 schema 事实，再走 [`check_migration_boundary`]。
///
/// # Errors
///
/// 取事实失败返回 [`InfraError::Query`] / [`InfraError::RowDecode`]；
/// schema 不兼容返回 [`InfraError::IncompatibleDatabase`]。
pub async fn check_migration_boundary_on(
    client: &tokio_postgres::Client,
) -> Result<MigrationBoundaryReport, InfraError> {
    let facts = schema_facts::fetch(client).await?;
    let mut violation = check_migration_boundary(&facts).err().unwrap_or_default();

    let verdict = check_migration_ledger(fetch_migration_ledger(client).await?);
    if let Some(finding) = verdict.finding() {
        violation.push(finding);
    }

    if violation.is_empty() {
        Ok(MigrationBoundaryReport {
            data_migrations: verdict,
        })
    } else {
        Err(violation.into())
    }
}

/// 边界检查通过时的报告。
///
/// 存在的理由只有一个：数据迁移的判定是**三态**的，而 `Result<(), _>` 只有两态。
/// 把 `Unverifiable` 折叠进 `Ok(())` 就是把"不知道"写成"通过"，那是撒谎；
/// 折叠进 `Err` 会拒绝全新安装。所以让它原样穿过来，由调用方决定怎么处置
/// （通常是启动日志里 warn 一句，而不是拦住启动）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct MigrationBoundaryReport {
    /// 数据迁移是否执行过。
    pub data_migrations: DataMigrationVerdict,
}

/// drizzle 迁移账本的表名（schema 限定）。
///
/// 上游 `server/drizzle.config.ts` 没有自定义 `migrations` 表/schema，所以是 drizzle 的默认位置。
pub const MIGRATION_LEDGER_TABLE: &str = "drizzle.__drizzle_migrations";

/// 迁到 0012 时账本里应有的条目数。
///
/// 复算：`jq '.entries|length' server/drizzle/meta/_journal.json` = 13。
pub const EXPECTED_MIGRATION_ENTRIES: i64 = 13;

/// 迁移账本的**观测结果**（不含判定）。
///
/// 观测与判定分开，判定才能留在纯函数里两个方向各造用例。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationLedger {
    /// 账本表存在，里面有 `entries` 条记录。
    Present {
        /// 账本里的条目数。
        entries: i64,
    },
    /// 账本表不存在。
    Absent,
}

/// 数据迁移是否执行过的**三态**判定。
///
/// 刻意不是 `bool`、也不是 `Result<(), _>`：账本不存在时的正确答案是"不知道"，
/// 而"不知道"既不是"通过"也不是"判红"。二值类型会逼着调用点在那一刻撒谎。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMigrationVerdict {
    /// 账本齐全：13 条都跑过，含唯一那条纯数据 migration `0003`。
    Applied {
        /// 账本里的条目数。
        entries: i64,
    },
    /// 账本存在但条目不足：没迁到 0012。
    Incomplete {
        /// 账本里的条目数。
        entries: i64,
        /// 期望条目数。
        expected: i64,
    },
    /// 没有账本表，无法验证。**既不判红也不默认通过。**
    ///
    /// 两种正常来路都会落到这里：① 本项目的 Rust baseline 直接建 0012 终态、不写 drizzle 账本；
    /// ② 运维用别的方式迁的库。区别不出来就如实说区别不出来。
    Unverifiable {
        /// 本该承载证据的表名，便于运维自己去看。
        ledger_table: &'static str,
    },
}

impl DataMigrationVerdict {
    /// 是否确证跑完了 13 条。
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    /// 是否确证**没**迁完。
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    /// 是否无从判断。
    pub fn is_unverifiable(&self) -> bool {
        matches!(self, Self::Unverifiable { .. })
    }

    /// 判红时对应的那条不兼容项；其余两态为 `None`。
    pub fn finding(&self) -> Option<Finding> {
        match self {
            Self::Incomplete { entries, expected } => Some(Finding::IncompleteMigrationLedger {
                ledger_table: MIGRATION_LEDGER_TABLE,
                entries: *entries,
                expected: *expected,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for DataMigrationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied { entries } => {
                write!(
                    f,
                    "迁移账本齐全：{MIGRATION_LEDGER_TABLE} 有 {entries} 条记录"
                )
            }
            Self::Incomplete { entries, expected } => write!(
                f,
                "迁移账本不足：{MIGRATION_LEDGER_TABLE} 只有 {entries} 条，期望 {expected} 条"
            ),
            Self::Unverifiable { ledger_table } => write!(
                f,
                "无法验证数据迁移是否执行：账本表 {ledger_table} 不存在。\
                 这既不代表已迁完、也不代表没迁完 —— 本项目的 Rust baseline 直接建 0012 终态、\
                 不写 drizzle 账本，全新安装本来就没有它；而从上游迁来的库若没有它，\
                 则确实无从判断 0003 跑没跑"
            ),
        }
    }
}

/// 纯函数版账本判定：只看观测结果，不碰 I/O。
pub fn check_migration_ledger(ledger: MigrationLedger) -> DataMigrationVerdict {
    match ledger {
        MigrationLedger::Absent => DataMigrationVerdict::Unverifiable {
            ledger_table: MIGRATION_LEDGER_TABLE,
        },
        MigrationLedger::Present { entries } if entries >= EXPECTED_MIGRATION_ENTRIES => {
            DataMigrationVerdict::Applied { entries }
        }
        MigrationLedger::Present { entries } => DataMigrationVerdict::Incomplete {
            entries,
            expected: EXPECTED_MIGRATION_ENTRIES,
        },
    }
}

/// 从活连接观测迁移账本。
///
/// 分两步走：先用 `to_regclass` 探表是否存在，存在才数条目。**不能**合成一条
/// `CASE WHEN to_regclass(...) IS NULL THEN NULL ELSE (SELECT count(*) FROM ...) END` ——
/// PostgreSQL 在**解析期**就要解析子查询里的关系名，表不存在时整条语句直接报错，
/// 于是"表不存在"这个正常情况会被伪装成查询失败。
///
/// # Errors
///
/// 查询失败返回 [`InfraError::Query`]；解码失败返回 [`InfraError::RowDecode`]。
pub async fn fetch_migration_ledger(
    client: &tokio_postgres::Client,
) -> Result<MigrationLedger, InfraError> {
    let present: bool = client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&MIGRATION_LEDGER_TABLE],
        )
        .await
        .map_err(|source| InfraError::query("探测 drizzle 迁移账本是否存在", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column("(to_regclass)", "exists", source))?;

    if !present {
        return Ok(MigrationLedger::Absent);
    }

    // 只数条目，不读任何列 —— 我们不依赖账本的列语义，只依赖"跑过几条"。
    let entries: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM drizzle.__drizzle_migrations",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("统计 drizzle 迁移账本条目数", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column(MIGRATION_LEDGER_TABLE, "count", source))?;

    Ok(MigrationLedger::Present { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema_facts::{ColumnFacts, EnumFacts, TableFacts};
    use crate::db::testdata::reference_facts;

    fn table_facts(name: &str) -> TableFacts {
        TableFacts {
            columns: Vec::new(),
            constraints: Vec::new(),
            indexes: Vec::new(),
            name: name.to_string(),
            triggers: Vec::new(),
        }
    }

    /// 正向对照：一份完整正确的事实必须通过。
    ///
    /// 没有这一条，下面每一条"应当被拒绝"的断言在"函数恒返回 Err"的世界里同样成立。
    #[test]
    fn the_reference_schema_passes_the_migration_boundary() {
        let facts = reference_facts();
        if let Err(report) = check_migration_boundary(&facts) {
            panic!("参照库事实必须通过迁移边界检查，实际报了 {report}");
        }
    }

    #[test]
    fn a_missing_table_is_rejected_and_named() {
        let mut facts = reference_facts();
        facts.tables.retain(|t| t.name != "users");
        let report = check_migration_boundary(&facts).expect_err("缺表必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::MissingTable {
                table: "users".to_string(),
            }],
        );
        assert!(report.to_string().contains("缺表：users"));
    }

    #[test]
    fn a_missing_column_is_rejected_and_named() {
        let mut facts = reference_facts();
        let users = facts
            .tables
            .iter_mut()
            .find(|t| t.name == "users")
            .expect("参照事实里应当有 users");
        users.columns.retain(|c| c.name != "email");
        let report = check_migration_boundary(&facts).expect_err("缺列必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::MissingColumn {
                table: "users".to_string(),
                column: "email".to_string(),
                expected_type: "text".to_string(),
            }],
        );
    }

    #[test]
    fn a_column_type_change_is_rejected_and_named() {
        let mut facts = reference_facts();
        let column = facts
            .tables
            .iter_mut()
            .find(|t| t.name == "audit_events")
            .expect("参照事实里应当有 audit_events")
            .columns
            .iter_mut()
            .find(|c| c.name == "id")
            .expect("audit_events 应当有 id 列");
        column.sql_type = "text".to_string();
        let report = check_migration_boundary(&facts).expect_err("列类型变更必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::ColumnMismatch {
                table: "audit_events".to_string(),
                column: "id".to_string(),
                expected_type: "uuid".to_string(),
                actual_type: "text".to_string(),
                expected_not_null: true,
                actual_not_null: true,
            }],
        );
    }

    #[test]
    fn a_nullability_change_is_rejected_even_when_the_type_matches() {
        let mut facts = reference_facts();
        let column = facts
            .tables
            .iter_mut()
            .find(|t| t.name == "sessions")
            .expect("参照事实里应当有 sessions")
            .columns
            .iter_mut()
            .find(|c| c.name == "token")
            .expect("sessions 应当有 token 列");
        assert!(column.notnull, "前提自检：token 在参照库里是 NOT NULL");
        column.notnull = false;
        let report = check_migration_boundary(&facts).expect_err("可空性变更必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::ColumnMismatch {
                table: "sessions".to_string(),
                column: "token".to_string(),
                expected_type: "text".to_string(),
                actual_type: "text".to_string(),
                expected_not_null: true,
                actual_not_null: false,
            }],
        );
    }

    #[test]
    fn a_surviving_chunks_table_is_rejected_as_stuck_before_0010() {
        let mut facts = reference_facts();
        facts.tables.push(table_facts("chunks"));
        facts.tables.sort_by(|a, b| a.name.cmp(&b.name));
        let report = check_migration_boundary(&facts).expect_err("chunks 还在必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::RetiredTablePresent {
                table: "chunks".to_string(),
            }],
        );
        assert!(report.stuck_before_0010());
        let rendered = report.to_string();
        assert!(rendered.contains("0010_drop_the_document_index.sql"));
    }

    #[test]
    fn surviving_connector_tables_are_rejected() {
        let mut facts = reference_facts();
        facts.tables.push(table_facts("connector_instances"));
        facts.tables.push(table_facts("sync_runs"));
        facts.tables.sort_by(|a, b| a.name.cmp(&b.name));
        let report = check_migration_boundary(&facts).expect_err("connector 表还在必须被拒绝");
        assert_eq!(
            report.findings(),
            [
                Finding::RetiredTablePresent {
                    table: "connector_instances".to_string(),
                },
                Finding::RetiredTablePresent {
                    table: "sync_runs".to_string(),
                },
            ],
        );
        // 这些是 0011 删的，不是 0010，所以 chunks 判据必须为假 —— 否则报告在指错方向。
        assert!(!report.stuck_before_0010());
    }

    /// 多出来一张 0012 之后才有的新表必须**放行**（v3 §14.3 兼容期只允许 expand）。
    ///
    /// 这条是"退休表被拒绝"的负向对照：证明拒绝的是那 7 张具名表，而不是"凡多出来的表都拒"。
    #[test]
    fn an_unknown_extra_table_is_allowed_because_expand_is_legal() {
        let mut facts = reference_facts();
        facts.tables.push(table_facts("threads"));
        facts.tables.sort_by(|a, b| a.name.cmp(&b.name));
        assert!(check_migration_boundary(&facts).is_ok());
    }

    /// 同理：多出来一列也放行。
    #[test]
    fn an_unknown_extra_column_is_allowed_because_expand_is_legal() {
        let mut facts = reference_facts();
        facts
            .tables
            .iter_mut()
            .find(|t| t.name == "sessions")
            .expect("参照事实里应当有 sessions")
            .columns
            .push(ColumnFacts {
                default: None,
                name: "device_id".to_string(),
                notnull: false,
                ordinal: 99,
                sql_type: "text".to_string(),
            });
        assert!(check_migration_boundary(&facts).is_ok());
    }

    #[test]
    fn a_missing_enum_is_rejected_and_named() {
        let mut facts = reference_facts();
        facts.enums.retain(|e| e.name != "role");
        let report = check_migration_boundary(&facts).expect_err("缺 enum 必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::MissingEnum {
                name: "role".to_string(),
            }],
        );
    }

    #[test]
    fn an_extra_enum_label_is_rejected_because_the_rust_enum_is_closed() {
        let mut facts = reference_facts();
        facts
            .enums
            .iter_mut()
            .find(|e| e.name == "role")
            .expect("参照事实里应当有 role")
            .values
            .push("superadmin".to_string());
        let report = check_migration_boundary(&facts).expect_err("多标签必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::EnumMismatch {
                name: "role".to_string(),
                expected: vec!["admin".to_string(), "user".to_string()],
                actual: vec![
                    "admin".to_string(),
                    "user".to_string(),
                    "superadmin".to_string(),
                ],
            }],
        );
    }

    #[test]
    fn a_reordered_enum_is_rejected() {
        let mut facts = reference_facts();
        facts
            .enums
            .iter_mut()
            .find(|e| e.name == "role")
            .expect("参照事实里应当有 role")
            .values
            .reverse();
        let report = check_migration_boundary(&facts).expect_err("标签顺序变更必须被拒绝");
        assert_eq!(report.findings().len(), 1);
        assert!(matches!(
            &report.findings()[0],
            Finding::EnumMismatch { name, .. } if name == "role",
        ));
    }

    #[test]
    fn a_surviving_retired_enum_is_rejected() {
        let mut facts = reference_facts();
        facts.enums.push(EnumFacts {
            name: "acl_effect".to_string(),
            values: vec!["allow".to_string(), "deny".to_string()],
        });
        facts.enums.sort_by(|a, b| a.name.cmp(&b.name));
        let report = check_migration_boundary(&facts).expect_err("已删除的 enum 还在必须被拒绝");
        assert_eq!(
            report.findings(),
            [Finding::RetiredEnumPresent {
                name: "acl_effect".to_string(),
            }],
        );
    }

    /// 所有不兼容一次收齐，不在第一条处短路。
    #[test]
    fn the_report_collects_every_problem_instead_of_stopping_at_the_first() {
        let mut facts = reference_facts();
        facts
            .tables
            .retain(|t| t.name != "users" && t.name != "skills");
        facts.tables.push(table_facts("documents"));
        facts.enums.retain(|e| e.name != "role");
        let report = check_migration_boundary(&facts).expect_err("多处不兼容必须被拒绝");
        assert_eq!(
            report.findings(),
            [
                Finding::MissingTable {
                    table: "skills".to_string(),
                },
                Finding::MissingTable {
                    table: "users".to_string(),
                },
                Finding::RetiredTablePresent {
                    table: "documents".to_string(),
                },
                Finding::MissingEnum {
                    name: "role".to_string(),
                },
            ],
        );
        let rendered = report.to_string();
        assert!(rendered.contains("共 4 处不兼容"));
    }

    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    // 迁移账本三态判定
    // -----------------------------------------------------------------

    /// 账本齐全 ⇒ `Applied`。
    #[test]
    fn a_complete_ledger_is_verified_as_applied() {
        let verdict = check_migration_ledger(MigrationLedger::Present { entries: 13 });
        assert_eq!(verdict, DataMigrationVerdict::Applied { entries: 13 });
        assert!(verdict.is_applied());
        assert!(!verdict.is_incomplete());
        assert!(!verdict.is_unverifiable());
        assert!(verdict.finding().is_none(), "齐全不该产出不兼容项");
        // 条目多于 13（上游后来又加了 migration）同样算跑完了 0012 —— 判据是 `>=` 不是 `==`。
        assert!(check_migration_ledger(MigrationLedger::Present { entries: 14 }).is_applied());
    }

    /// 账本不足 ⇒ `Incomplete`，且报文给出实得条数。
    #[test]
    fn a_short_ledger_is_incomplete_and_reports_the_actual_count() {
        let verdict = check_migration_ledger(MigrationLedger::Present { entries: 3 });
        assert_eq!(
            verdict,
            DataMigrationVerdict::Incomplete {
                entries: 3,
                expected: EXPECTED_MIGRATION_ENTRIES,
            },
        );
        assert!(verdict.is_incomplete());
        assert!(!verdict.is_applied());
        assert!(!verdict.is_unverifiable());

        let finding = verdict.finding().expect("不足必须产出不兼容项");
        assert_eq!(
            finding,
            Finding::IncompleteMigrationLedger {
                ledger_table: MIGRATION_LEDGER_TABLE,
                entries: 3,
                expected: 13,
            },
        );
        let rendered = finding.to_string();
        assert!(rendered.contains('3'), "报文没给出实得条数：{rendered}");
        assert!(rendered.contains("13"), "报文没给出期望条数：{rendered}");
        assert!(
            rendered.contains(MIGRATION_LEDGER_TABLE),
            "报文没点名账本表：{rendered}",
        );
        assert!(
            rendered.contains("处置："),
            "报文没给出处置建议：{rendered}"
        );
    }

    /// **最重要的一条**：账本表不存在 ⇒ `Unverifiable`，它既不是通过也不是判红。
    ///
    /// 三态一旦被谁悄悄折叠成二值，这条就会红：无论折进哪一边，
    /// `is_applied()` 与 `is_incomplete()` 里必有一个变成 true。
    #[test]
    fn a_missing_ledger_is_unverifiable_neither_pass_nor_fail() {
        let verdict = check_migration_ledger(MigrationLedger::Absent);
        assert_eq!(
            verdict,
            DataMigrationVerdict::Unverifiable {
                ledger_table: MIGRATION_LEDGER_TABLE,
            },
        );
        assert!(verdict.is_unverifiable());
        // 不是通过。
        assert!(!verdict.is_applied(), "不可验证被折叠成了通过");
        // 也不是判红 —— 不产出任何不兼容项，所以不会拦住启动。
        assert!(!verdict.is_incomplete(), "不可验证被折叠成了判红");
        assert!(
            verdict.finding().is_none(),
            "不可验证不得产出不兼容项，否则全新安装会被自己拒绝",
        );
        // 而且必须说人话，不能只是一个静默的 None。
        let rendered = verdict.to_string();
        assert!(rendered.contains("无法验证"), "没如实说明：{rendered}");
        assert!(rendered.contains(MIGRATION_LEDGER_TABLE));
    }

    /// 三态互斥且穷尽：任一观测下三个判据恰好有一个为真。
    ///
    /// 防的是"有人加了第四态却忘了更新判据"，以及"两个判据同时为真"。
    #[test]
    fn the_three_verdicts_are_mutually_exclusive_and_exhaustive() {
        for ledger in [
            MigrationLedger::Absent,
            MigrationLedger::Present { entries: 0 },
            MigrationLedger::Present { entries: 12 },
            MigrationLedger::Present { entries: 13 },
            MigrationLedger::Present { entries: 99 },
        ] {
            let verdict = check_migration_ledger(ledger);
            let hits = u8::from(verdict.is_applied())
                + u8::from(verdict.is_incomplete())
                + u8::from(verdict.is_unverifiable());
            assert_eq!(hits, 1, "{ledger:?} 的三态判据命中 {hits} 个：{verdict:?}");
        }
    }

    /// 账本发现与 schema 级发现共用同一份报告，一次全给出来。
    #[test]
    fn schema_and_ledger_findings_share_one_report() {
        let mut report = MigrationBoundaryViolation::default();
        report.push(Finding::MissingTable {
            table: "users".to_string(),
        });
        report.push(
            check_migration_ledger(MigrationLedger::Present { entries: 2 })
                .finding()
                .expect("不足必须产出不兼容项"),
        );
        assert_eq!(report.findings().len(), 2);
        let rendered = report.to_string();
        assert!(rendered.contains("共 2 处不兼容"));
        assert!(rendered.contains("users"));
        assert!(rendered.contains(MIGRATION_LEDGER_TABLE));
    }

    /// 期望条目数必须与上游 `_journal.json` 的条目数一致。
    ///
    /// 复算：`jq '.entries|length' server/drizzle/meta/_journal.json` = 13。
    #[test]
    fn the_expected_entry_count_matches_the_upstream_journal() {
        assert_eq!(EXPECTED_MIGRATION_ENTRIES, 13);
        assert_eq!(MIGRATION_LEDGER_TABLE, "drizzle.__drizzle_migrations");
    }

    #[test]
    fn retired_lists_do_not_overlap_the_live_ledger() {
        for retired in RETIRED_TABLES {
            assert!(
                !ALL_TABLES.iter().any(|t| t.name == *retired),
                "{retired} 同时出现在 ALL_TABLES 与 RETIRED_TABLES",
            );
        }
        for retired in RETIRED_ENUMS {
            assert!(
                !EXPECTED_ENUMS.iter().any(|e| e.name == *retired),
                "{retired} 同时出现在 EXPECTED_ENUMS 与 RETIRED_ENUMS",
            );
        }
        assert_eq!(RETIRED_TABLES.len(), 7);
        assert_eq!(RETIRED_ENUMS.len(), 3);
    }
}
