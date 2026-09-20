//! Fresh install 的 baseline DDL（v3 §14.1）。
//!
//! v3 §14.1 逐字：「Fresh install 使用当前最终 schema 的 Rust baseline，不创建已删除的
//! document/vector 表」。所以本模块嵌的是**一份**把空库直接建成 0012 终态的 SQL，
//! 而不是把上游 13 条 migration 重放一遍 —— 重放会先建出 `documents` / `chunks` /
//! `connector_instances` 等 7 张表和 3 个 enum，再删掉，中间态里还得有 pgvector。
//!
//! 已迁移的库走的是另一条路：[`crate::db::compat::check_migration_boundary`] 要求它**已经**
//! 在 0012，本模块对它零操作。两条路合起来就是 v3 §14.1 的全部：要么全新建，要么已经到位。
//!
//! [`BASELINE_0012_SQL`] 与参照库的等价性由集成测试 `tests/schema_baseline_parity.rs`
//! 在真库上逐字段验证 —— 本模块的单测只能证明这份 SQL 的**形状**没被改坏。

/// fresh install 的 baseline DDL。
///
/// 一条 `batch_execute`（简单查询协议）即可执行完；PostgreSQL 会把它整体当作一个隐式事务，
/// 所以中途失败不会留下半个库。
pub const BASELINE_0012_SQL: &str = include_str!("../../sql/baseline_0012.sql");

/// 在给定连接上建出 0012 终态。
///
/// 只能对**空库**调用：里面全是不带 `IF NOT EXISTS` 的 `CREATE`，对已有对象会直接报错 ——
/// 这是要的行为，把 baseline 泼在一个已有数据的库上必须失败而不是"尽量建"。
///
/// # Errors
///
/// 任一语句失败返回 [`crate::db::InfraError::Query`]。
pub async fn apply(client: &tokio_postgres::Client) -> Result<(), crate::db::InfraError> {
    client
        .batch_execute(BASELINE_0012_SQL)
        .await
        .map_err(|source| crate::db::InfraError::query("应用 baseline_0012.sql", source))
}

/// 在调用方已有事务里施加 baseline；只供 fresh bootstrap 把 baseline 与 native 账本同批提交。
pub(crate) async fn apply_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(), crate::db::InfraError> {
    transaction
        .batch_execute(BASELINE_0012_SQL)
        .await
        .map_err(|source| crate::db::InfraError::query("事务内应用 baseline_0012.sql", source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::compat::{RETIRED_ENUMS, RETIRED_TABLES};
    use crate::db::tables::ALL_TABLES;

    /// 去掉整行注释后的语句行。
    ///
    /// baseline 里既有文件头的中文注释，也有 `prevent_audit_event_mutation()` 函数体里
    /// 上游原样保留的英文注释 —— 后者含 "TRUNCATE"、"table" 这类词，裸 `grep` 会把它们数进去。
    fn statement_lines() -> Vec<&'static str> {
        BASELINE_0012_SQL
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect()
    }

    fn count_lines_starting_with(prefix: &str) -> usize {
        statement_lines()
            .iter()
            .filter(|line| line.starts_with(prefix))
            .count()
    }

    #[test]
    fn baseline_creates_exactly_the_28_tables_of_the_ledger() {
        assert_eq!(count_lines_starting_with("CREATE TABLE "), 28);
        assert_eq!(ALL_TABLES.len(), 28);
        for table in ALL_TABLES {
            let needle = format!("CREATE TABLE public.{} (", table.name);
            assert!(
                statement_lines().contains(&needle.as_str()),
                "baseline 里没有建表语句：{}",
                table.name,
            );
        }
    }

    #[test]
    fn baseline_creates_the_four_surviving_enums_one_function_and_two_triggers() {
        assert_eq!(count_lines_starting_with("CREATE TYPE "), 4);
        assert_eq!(count_lines_starting_with("CREATE FUNCTION "), 1);
        assert_eq!(count_lines_starting_with("CREATE TRIGGER "), 2);
    }

    /// 44 个索引里只有 12 个需要显式 `CREATE INDEX`，其余 32 个是 28 个主键 + 4 个唯一约束
    /// 隐含建出来的。59 条 `ALTER TABLE ONLY` = 28 主键 + 4 唯一 + 27 外键。
    #[test]
    fn baseline_declares_the_explicit_indexes_and_the_table_level_constraints() {
        let explicit_indexes = count_lines_starting_with("CREATE INDEX ")
            + count_lines_starting_with("CREATE UNIQUE INDEX ");
        assert_eq!(explicit_indexes, 12);
        assert_eq!(count_lines_starting_with("ALTER TABLE ONLY "), 59);
    }

    #[test]
    fn baseline_never_touches_extensions() {
        assert!(
            !statement_lines()
                .iter()
                .any(|line| line.contains("CREATE EXTENSION") || line.contains("DROP EXTENSION")),
            "v3 §14.1：Rust 兼容 migration 对 extension 零操作",
        );
        // 正向对照：同一份语句行里确实找得到别的 CREATE，说明上面不是在一个空集合上判空。
        assert!(
            statement_lines()
                .iter()
                .any(|line| line.starts_with("CREATE TYPE ")),
            "语句行集合不应为空",
        );
    }

    #[test]
    fn baseline_never_recreates_the_tables_and_enums_that_0010_and_0011_removed() {
        for retired in RETIRED_TABLES {
            let needle = format!("CREATE TABLE public.{retired} (");
            assert!(
                !statement_lines().contains(&needle.as_str()),
                "baseline 不得重建已删除的表：{retired}",
            );
        }
        for retired in RETIRED_ENUMS {
            let needle = format!("CREATE TYPE public.{retired} AS ENUM (");
            assert!(
                !statement_lines().contains(&needle.as_str()),
                "baseline 不得重建已删除的 enum：{retired}",
            );
        }
        // 正向对照：同一条判据在一张确实该建的表上必须命中。
        assert!(
            statement_lines().contains(&"CREATE TABLE public.users ("),
            "同一判据在 users 上应当命中",
        );
    }

    /// baseline 是给空库用的，不允许出现 `IF NOT EXISTS` 这类"尽量建"的写法：
    /// 把它泼在已有数据的库上必须失败，而不是悄悄跳过已存在的对象、留下半新半旧的 schema。
    #[test]
    fn baseline_has_no_if_not_exists_escape_hatch() {
        assert!(
            !statement_lines()
                .iter()
                .any(|line| line.contains("IF NOT EXISTS")),
        );
    }

    /// psql 元命令（`\restrict` / `\unrestrict`）与会话级 `SET` 必须已被清掉：
    /// 前者 `tokio_postgres` 根本不认，后者会让答案取决于导出那台机器的 pg_dump 版本。
    #[test]
    fn baseline_contains_no_psql_meta_commands_or_session_settings() {
        for line in statement_lines() {
            assert!(!line.starts_with('\\'), "残留 psql 元命令：{line}");
            assert!(!line.starts_with("SET "), "残留会话级 SET：{line}");
            assert!(
                !line.starts_with("SELECT pg_catalog.set_config("),
                "残留 set_config：{line}",
            );
            assert!(!line.contains("OWNER TO"), "残留属主声明：{line}");
        }
    }
}
