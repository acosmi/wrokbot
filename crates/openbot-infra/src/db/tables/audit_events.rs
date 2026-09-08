//! `public.audit_events` 的类型化行 —— 上游 server/src/db/schema/core.ts::auditEvents。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。

crate::db::tables::define_table! {
    table = "audit_events";
    id: uuid::Uuid = ("id", "uuid", true),
    actor_user_id: Option<String> = ("actor_user_id", "text", false),
    event_type: String = ("event_type", "text", true),
    target_type: String = ("target_type", "text", true),
    target_id: Option<String> = ("target_id", "text", false),
    payload: serde_json::Value = ("payload", "jsonb", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}

/// 0013 追加后的完整列清单。前 7 列必须逐字等于 [`COLUMNS`]，hash 两列只追加在末尾。
pub const CURRENT_COLUMNS: &[&str] = &[
    "id",
    "actor_user_id",
    "event_type",
    "target_type",
    "target_id",
    "payload",
    "created_at",
    "prev_hash",
    "row_hash",
];

/// 0013 追加后的完整列形态。
pub const CURRENT_COLUMN_SPECS: &[crate::db::tables::ColumnSpec] = &[
    crate::db::tables::ColumnSpec::new("id", "uuid", true),
    crate::db::tables::ColumnSpec::new("actor_user_id", "text", false),
    crate::db::tables::ColumnSpec::new("event_type", "text", true),
    crate::db::tables::ColumnSpec::new("target_type", "text", true),
    crate::db::tables::ColumnSpec::new("target_id", "text", false),
    crate::db::tables::ColumnSpec::new("payload", "jsonb", true),
    crate::db::tables::ColumnSpec::new("created_at", "timestamp with time zone", true),
    crate::db::tables::ColumnSpec::new("prev_hash", "text", false),
    crate::db::tables::ColumnSpec::new("row_hash", "text", false),
];

/// 0013 当前行：保留原 0012 行结构，并显式带上 hash chain 两列。
#[derive(Clone, Debug, PartialEq)]
pub struct ChainedRow {
    /// 上游 0012 的七列。
    pub event: Row,
    /// 链上一行的摘要；genesis 与旧行均为 NULL，二者由 `row_hash` 区分。
    pub prev_hash: Option<String>,
    /// 当前行摘要；旧行未入链时为 NULL。
    pub row_hash: Option<String>,
}

impl TryFrom<&tokio_postgres::Row> for ChainedRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            event: Row::try_from(row)?,
            prev_hash: row.try_get("prev_hash").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "prev_hash", source)
            })?,
            row_hash: row.try_get("row_hash").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "row_hash", source)
            })?,
        })
    }
}

#[cfg(test)]
mod native_0013_tests {
    use super::*;

    #[test]
    fn chain_columns_are_append_only_suffixes_of_the_upstream_shape() {
        assert_eq!(&CURRENT_COLUMNS[..COLUMNS.len()], COLUMNS);
        assert_eq!(
            &CURRENT_COLUMN_SPECS[..COLUMN_SPECS.len()],
            COLUMN_SPECS,
        );
        assert_eq!(&CURRENT_COLUMNS[COLUMNS.len()..], &["prev_hash", "row_hash"]);
        assert!(
            CURRENT_COLUMN_SPECS[COLUMN_SPECS.len()..]
                .iter()
                .all(|column| !column.not_null),
            "§8.6 / §14.3：hash chain 两列必须只追加且 nullable",
        );
    }
}
