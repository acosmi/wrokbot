//! `public.sessions` 的类型化行 —— 上游 server/src/db/schema/core.ts::sessions。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//! 唯一：UNIQUE (token)。
//!
//! 外键：
//!
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//!
//! ⚠️ 本表承载敏感数据：`token` 是**明文**会话令牌，拿到即可冒充该用户。repository contract §5
//! 不变量 8 要求 secret 不进模型、GUI state、browser event、普通日志与 trace，所以 `token` 一列
//! 已登记进 `crate::db::tables::SECRET_COLUMNS`，`Row` 的 `Debug` 会把它渲染成 `<redacted>`。
//! **取值本身仍在字段里** —— 脱敏只挡住日志与 panic 消息这条默认打开的泄漏路径，把值往别处传
//! 仍是调用方的责任。

crate::db::tables::define_table! {
    table = "sessions";
    id: String = ("id", "text", true),
    user_id: String = ("user_id", "text", true),
    token: String = ("token", "text", true),
    expires_at: time::OffsetDateTime = ("expires_at", "timestamp with time zone", true),
    ip_address: Option<String> = ("ip_address", "text", false),
    user_agent: Option<String> = ("user_agent", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

/// 0015 追加后的完整列清单；签发代际只可位于 0012 八列之后。
pub const CURRENT_COLUMNS: &[&str] = &[
    "id",
    "user_id",
    "token",
    "expires_at",
    "ip_address",
    "user_agent",
    "created_at",
    "updated_at",
    "auth_generation",
];

/// 当前 session 行；旧 Better Auth 行的 generation 为 `None`，生产 resolver 必须拒绝。
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// 上游 0012 八列。
    pub session: Row,
    /// Rust session 签发时的 auth generation。
    pub auth_generation: Option<i64>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            session: Row::try_from(row)?,
            auth_generation: row.try_get("auth_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "auth_generation", source)
            })?,
        })
    }
}

#[cfg(test)]
mod native_0015_tests {
    use super::*;

    #[test]
    fn auth_generation_is_one_nullable_append_only_suffix() {
        assert_eq!(&CURRENT_COLUMNS[..COLUMNS.len()], COLUMNS);
        assert_eq!(&CURRENT_COLUMNS[COLUMNS.len()..], &["auth_generation"]);
    }
}
