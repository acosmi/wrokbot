//! `public.users` 的类型化行 —— 上游 server/src/db/schema/core.ts::users。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//! 唯一：UNIQUE (email)。

crate::db::tables::define_table! {
    table = "users";
    id: String = ("id", "text", true),
    email: String = ("email", "text", true),
    name: Option<String> = ("name", "text", false),
    image: Option<String> = ("image", "text", false),
    email_verified: bool = ("email_verified", "boolean", true),
    groups: Vec<Option<String>> = ("groups", "text[]", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

/// 0014 追加后的完整列清单；`auth_generation` 只可追加在 0012 八列之后。
pub const CURRENT_COLUMNS: &[&str] = &[
    "id",
    "email",
    "name",
    "image",
    "email_verified",
    "groups",
    "created_at",
    "updated_at",
    "auth_generation",
];

/// 0014 当前 user 行；旧行的 NULL generation 在 identity 适配器读作 0。
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// 上游 0012 八列。
    pub user: Row,
    /// 当前 auth generation；兼容窗口旧行为 `None`。
    pub auth_generation: Option<i64>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            user: Row::try_from(row)?,
            auth_generation: row.try_get("auth_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "auth_generation", source)
            })?,
        })
    }
}

#[cfg(test)]
mod native_0014_tests {
    use super::*;

    #[test]
    fn auth_generation_is_one_nullable_append_only_suffix() {
        assert_eq!(&CURRENT_COLUMNS[..COLUMNS.len()], COLUMNS);
        assert_eq!(&CURRENT_COLUMNS[COLUMNS.len()..], &["auth_generation"]);
    }
}
