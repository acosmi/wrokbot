//! 数据库层的错误分层。
//!
//! 五档刻意分开，因为调用方对它们的处置不同：连接失败可重试、查询失败要看 SQLSTATE、
//! 行解码失败说明 Rust 侧的类型映射与真库漂了（属于本仓的 bug，不是运行期状况）、
//! schema 不兼容则必须 fail-closed 停机并要求先把库迁到 0012，native migration 账本漂移
//! 则拒绝继续施加并要求人工调查。
//!
//! # 错误里**只留标识符，不留自由文本**（repository contract §5 不变量 8）
//!
//! 本模块不保存 `tokio_postgres::Error` 本身，只保存 [`PostgresErrorSummary`]。理由是实测过的
//! 泄漏路径，不是理论风险：
//!
//! - `tokio_postgres::Error` 的 `source()` 是 `DbError`，而 `DbError` 的 `Display` 会打印
//!   `DETAIL:` 与 `HINT:` —— PostgreSQL 恰恰把**列取值**放在 DETAIL 里
//!   （唯一约束冲突的 `Key (token)=(…) already exists.`）。
//! - `DbError` 还 `#[derive(Debug)]`，所以 `{:?}` 会把 `detail` / `hint` / `where` 全打出来；
//!   而 `Result::unwrap()` 的 panic 消息用的就是 `{:?}`。
//!
//! 于是任何一句 `tracing::error!("{:?}", err)`、任何一次 `unwrap()`，都会把明文令牌写进普通日志。
//! [`PostgresErrorSummary`] 的做法是 **default-deny**：只保留服务端错误里由 PostgreSQL 文档
//! 定义为标识符的字段（SQLSTATE、约束名、表名、列名、类型名、routine），自由文本字段
//! （`message` / `detail` / `hint` / `where`）一律丢弃 —— `message` 同样不安全，
//! `invalid input syntax for type uuid: "…"` 就把取值写在里面。
//!
//! 解码失败的成因链只放行两个**具名**的安全类型（`postgres_types::WasNull` /
//! `postgres_types::WrongType`，它们的文案只含类型名），其余一律折叠成占位说明。
//! 这是白名单而不是启发式：新类型默认被挡住，不是默认放行。

use std::error::Error as StdError;
use std::fmt;

use thiserror::Error;

use crate::db::compat::MigrationBoundaryViolation;
use crate::db::native::NativeMigrationViolation;

/// `openbot-infra` 数据库层对外暴露的错误。
#[derive(Debug, Error)]
pub enum InfraError {
    /// 建连接池 / 取连接失败。
    ///
    /// 这一档的 `source` 保留原始错误：建连阶段库里**还没有行**，服务端错误只可能提到库名、
    /// 用户名与 SQLSTATE，不可能携带行取值。口令永远不会被 PostgreSQL 回显，
    /// 本地那份也早已被 [`crate::db::pool::DatabaseConfig`] 手写的 `Debug` 遮住。
    #[error("连接 PostgreSQL 失败（{context}）")]
    Connect {
        /// 失败时正在做的事，人类可读。
        context: String,
        /// 底层错误。可能来自 `tokio_postgres`、`deadpool` 的 build 或 pool 取用。
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },

    /// 语句执行失败。
    #[error("PostgreSQL 查询失败（{context}）")]
    Query {
        /// 失败的语句在做什么，人类可读。
        context: String,
        /// 服务端错误的**脱敏**摘要。
        #[source]
        source: PostgresErrorSummary,
    },

    /// 查到了行但解不出 Rust 类型 —— Rust 侧映射与真库漂了。
    #[error(transparent)]
    RowDecode(#[from] RowDecodeError),

    /// 库的 schema 不是 0012 终态（v3 §14.1：Rust 不接收更早 schema）。
    #[error(transparent)]
    IncompatibleDatabase(#[from] MigrationBoundaryViolation),

    /// Rust-owned native migration 的账本漂移或版本空洞。
    #[error(transparent)]
    NativeMigration(#[from] NativeMigrationViolation),

    /// repository 入参或持久化状态违反封闭不变量；只带稳定 code，不带运行期值。
    #[error("repository 不变量失败（{code}）")]
    RepositoryInvariant {
        /// 稳定、无载荷的错误码。
        code: &'static str,
    },
}

impl InfraError {
    /// 构造 [`InfraError::Connect`]。
    pub fn connect(
        context: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Self::Connect {
            context: context.into(),
            source: source.into(),
        }
    }

    /// 构造 [`InfraError::Query`]，顺手把服务端错误脱敏成摘要。
    pub fn query(context: impl Into<String>, source: tokio_postgres::Error) -> Self {
        Self::Query {
            context: context.into(),
            source: PostgresErrorSummary::from_error(&source),
        }
    }

    /// 构造一个无载荷 repository 不变量错误。
    #[must_use]
    pub const fn repository_invariant(code: &'static str) -> Self {
        Self::RepositoryInvariant { code }
    }

    /// 服务端错误的 SQLSTATE（形如 `23505`），非服务端错误为 `None`。
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Query { source, .. } => source.sqlstate(),
            Self::RowDecode(error) => error.sqlstate(),
            _ => None,
        }
    }
}

/// `tokio_postgres::Error` 的脱敏摘要：只留固定文案与标识符。
///
/// 刻意**不**实现 `From<tokio_postgres::Error>`：这次转换是有损的（丢掉 `message` / `detail` /
/// `hint`），让它看起来像一次普通的 `?` 自动转换会掩盖这件事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresErrorSummary {
    /// `tokio_postgres::Error` 自己的 `Display`。各分支都是固定文案或列序号
    /// （`db error` / `error deserializing column 2` / `connection closed` …），不含取值。
    kind: String,
    /// 服务端错误的安全元数据；非服务端错误为 `None`。
    ///
    /// 装箱是为了把 `Result<_, InfraError>` 的 `Err` 变体压回 clippy `result_large_err` 的
    /// 阈值以内：六个 `Option<String>` 摊在栈上会让每一次成功返回都拖着 200+ 字节。
    db: Option<Box<DbErrorSummary>>,
    /// 成因链里被白名单放行的那部分。
    cause: Option<String>,
    /// 成因链里被挡下的层数（挡下的可能含取值，只报层数不报内容）。
    withheld_causes: usize,
}

impl PostgresErrorSummary {
    /// 从驱动错误提取摘要。
    pub fn from_error(error: &tokio_postgres::Error) -> Self {
        let db = error
            .as_db_error()
            .map(|db| Box::new(DbErrorSummary::from_db_error(db)));
        let (cause, withheld_causes) = summarize_cause_chain(error);
        Self {
            kind: error.to_string(),
            db,
            cause,
            withheld_causes,
        }
    }

    /// SQLSTATE（形如 `23505`），非服务端错误为 `None`。
    pub fn sqlstate(&self) -> Option<&str> {
        self.db.as_ref().map(|db| db.code.as_str())
    }

    /// 违反的约束名，服务端没给则为 `None`。
    pub fn constraint(&self) -> Option<&str> {
        self.db.as_ref().and_then(|db| db.constraint.as_deref())
    }
}

impl fmt::Display for PostgresErrorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.kind)?;
        if let Some(db) = &self.db {
            write!(f, " [{}]", db.code)?;
            for (label, value) in [
                ("constraint", &db.constraint),
                ("table", &db.table),
                ("column", &db.column),
                ("datatype", &db.datatype),
                ("routine", &db.routine),
            ] {
                if let Some(value) = value {
                    write!(f, " {label}={value}")?;
                }
            }
        }
        if let Some(cause) = &self.cause {
            write!(f, "：{cause}")?;
        }
        if self.withheld_causes > 0 {
            write!(
                f,
                "（另有 {} 层成因未展开：其文案可能含列取值）",
                self.withheld_causes,
            )?;
        }
        Ok(())
    }
}

impl StdError for PostgresErrorSummary {}

/// 服务端错误里**只**由标识符构成的字段。
///
/// 刻意不收 `message` / `detail` / `hint` / `where`：这四个是自由文本，PostgreSQL 会把列取值
/// 插进去（`Key (token)=(…) already exists.` / `invalid input syntax for type uuid: "…"`）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct DbErrorSummary {
    code: String,
    constraint: Option<String>,
    table: Option<String>,
    column: Option<String>,
    datatype: Option<String>,
    routine: Option<String>,
}

impl DbErrorSummary {
    fn from_db_error(error: &tokio_postgres::error::DbError) -> Self {
        Self {
            code: error.code().code().to_string(),
            constraint: error.constraint().map(str::to_string),
            table: error.table().map(str::to_string),
            column: error.column().map(str::to_string),
            datatype: error.datatype().map(str::to_string),
            routine: error.routine().map(str::to_string),
        }
    }
}

/// 成因链白名单：只放行文案里绝不含取值的具名类型。
///
/// - `postgres_types::WasNull` —— "a Postgres value was `NULL`"，固定文案。
/// - `postgres_types::WrongType` —— "cannot convert between the Rust type `X` and the Postgres
///   type `Y`"，只含类型名。
///
/// 其余（尤其 `serde_json::Error`，它的 `invalid type: string "…"` 会把内容原样回显）一律挡下，
/// 只报层数。default-deny：新出现的成因类型默认被挡，不是默认放行。
fn summarize_cause_chain(error: &tokio_postgres::Error) -> (Option<String>, usize) {
    let mut allowed: Vec<String> = Vec::new();
    let mut withheld = 0usize;
    let mut current = StdError::source(error);
    while let Some(source) = current {
        if source.is::<postgres_types::WasNull>() || source.is::<postgres_types::WrongType>() {
            allowed.push(source.to_string());
        } else {
            withheld += 1;
        }
        current = source.source();
    }
    let joined = if allowed.is_empty() {
        None
    } else {
        Some(allowed.join(" <- "))
    };
    (joined, withheld)
}

/// 单列 / 单个载荷的解码失败，带上是哪张表的哪一列。
///
/// 不带行内容：行里可能有明文令牌与密文（repository contract §5 不变量 8），错误串会进日志。
#[derive(Debug, Error)]
#[error("表 `{table}` 的列 `{column}` 解码失败")]
pub struct RowDecodeError {
    table: &'static str,
    column: &'static str,
    #[source]
    source: RowDecodeCause,
}

impl RowDecodeError {
    /// 列取值失败（类型不匹配、列不存在、值为 NULL 而 Rust 侧是非 Option）。
    ///
    /// 由 `crate::db::tables::define_table!` 展开出来的 `TryFrom` 调用。
    pub fn column(
        table: &'static str,
        column: &'static str,
        source: tokio_postgres::Error,
    ) -> Self {
        Self {
            table,
            column,
            source: RowDecodeCause::Column(PostgresErrorSummary::from_error(&source)),
        }
    }

    /// 取到了值但 JSON 载荷解析失败。
    pub fn json(table: &'static str, column: &'static str, source: serde_json::Error) -> Self {
        Self {
            table,
            column,
            source: RowDecodeCause::Json(JsonErrorSummary::from_error(&source)),
        }
    }

    /// 出错的表名。
    pub fn table(&self) -> &'static str {
        self.table
    }

    /// 出错的列名。
    pub fn column_name(&self) -> &'static str {
        self.column
    }

    /// 服务端错误的 SQLSTATE，非服务端错误为 `None`。
    pub fn sqlstate(&self) -> Option<&str> {
        match &self.source {
            RowDecodeCause::Column(summary) => summary.sqlstate(),
            RowDecodeCause::Json(_) => None,
        }
    }
}

/// [`RowDecodeError`] 的直接成因。
#[derive(Debug, Error)]
pub enum RowDecodeCause {
    /// `tokio_postgres::Row::try_get` 失败。
    #[error("列取值失败：{0}")]
    Column(#[source] PostgresErrorSummary),
    /// JSON 载荷解析失败。
    #[error("JSON 载荷解析失败：{0}")]
    Json(#[source] JsonErrorSummary),
}

/// `serde_json::Error` 的脱敏摘要。
///
/// 只留**类别**与**位置**。`serde_json` 的 `Display` 会把不合期望的内容原样回显
/// （`invalid type: string "…", expected …`），所以原文一个字都不留。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonErrorSummary {
    category: &'static str,
    line: usize,
    column: usize,
}

impl JsonErrorSummary {
    /// 从 `serde_json::Error` 提取摘要。
    pub fn from_error(error: &serde_json::Error) -> Self {
        let category = match error.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        };
        Self {
            category,
            line: error.line(),
            column: error.column(),
        }
    }
}

impl fmt::Display for JsonErrorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} 错误，位置 行 {} 列 {}（原文已略去：可能含列取值）",
            self.category, self.line, self.column,
        )
    }
}

impl StdError for JsonErrorSummary {}

/// 把错误链摊平。测试里用它模拟 `tracing` / `anyhow` 这类会走 `source()` 的消费者。
pub fn error_chain(error: &(dyn StdError + 'static)) -> String {
    let mut parts = vec![error.to_string()];
    let mut current = error.source();
    while let Some(source) = current {
        parts.push(source.to_string());
        current = source.source();
    }
    parts.join(" <- ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-DO-NOT-LOG";

    /// 前提自检：`serde_json` 的原始错误**确实**会回显内容。
    ///
    /// 没有这一条，下面的脱敏断言在"serde_json 本来就不回显"的世界里同样通过。
    #[test]
    fn the_raw_serde_json_error_really_does_echo_the_offending_value() {
        let error = serde_json::from_str::<u32>(&format!("\"{SENTINEL}\"")).unwrap_err();
        assert!(
            error.to_string().contains(SENTINEL),
            "前提自检失败：原始错误没有回显内容，脱敏断言将失去意义",
        );
    }

    #[test]
    fn the_json_summary_keeps_the_position_but_drops_the_content() {
        let error = serde_json::from_str::<u32>(&format!("\"{SENTINEL}\"")).unwrap_err();
        let summary = JsonErrorSummary::from_error(&error);
        let rendered = format!("{summary} | {summary:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "JSON 摘要泄漏了内容：{rendered}"
        );
        // 正向对照：摘要不是空串，类别与位置都还在。
        assert!(rendered.contains("data"));
        assert!(rendered.contains("行 1"));
    }

    #[test]
    fn row_decode_error_display_and_debug_and_source_chain_carry_no_values() {
        let error = serde_json::from_str::<u32>(&format!("\"{SENTINEL}\"")).unwrap_err();
        let decode = RowDecodeError::json("sessions", "token", error);
        let rendered = format!("{decode} | {decode:?} | {}", error_chain(&decode));
        assert!(
            !rendered.contains(SENTINEL),
            "RowDecodeError 泄漏了取值：{rendered}",
        );
        // 正向对照：表名与列名必须还在，否则这条断言在"输出恒为空"的世界里同样通过。
        assert!(rendered.contains("sessions"));
        assert!(rendered.contains("token"));
        assert!(rendered.contains("原文已略去"));
        assert_eq!(decode.table(), "sessions");
        assert_eq!(decode.column_name(), "token");
        assert_eq!(decode.sqlstate(), None);
    }

    #[test]
    fn infra_error_from_a_row_decode_failure_also_carries_no_values() {
        let error = serde_json::from_str::<u32>(&format!("\"{SENTINEL}\"")).unwrap_err();
        let infra: InfraError = RowDecodeError::json("credentials", "metadata", error).into();
        let rendered = format!("{infra} | {infra:?} | {}", error_chain(&infra));
        assert!(
            !rendered.contains(SENTINEL),
            "InfraError 泄漏了取值：{rendered}"
        );
        assert!(rendered.contains("credentials"));
        assert!(rendered.contains("metadata"));
    }
}
