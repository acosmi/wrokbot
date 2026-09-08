//! `public.action_policy` 的类型化行 —— 上游 server/src/db/schema/computer.ts::actionPolicy。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。

crate::db::tables::define_table! {
    table = "action_policy";
    id: String = ("id", "text", true),
    mode: String = ("mode", "text", true),
    deny: Vec<Option<String>> = ("deny", "text[]", true),
    allow: Vec<Option<String>> = ("allow", "text[]", true),
    updated_by: Option<String> = ("updated_by", "text", false),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
