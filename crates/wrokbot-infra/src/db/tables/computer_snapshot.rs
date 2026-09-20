//! `public.computer_snapshot` 的类型化行 —— 上游
//! server/src/db/schema/computer.ts::computerSnapshot。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (computer_id)。

crate::db::tables::define_table! {
    table = "computer_snapshot";
    computer_id: String = ("computer_id", "text", true),
    snapshot_id: i32 = ("snapshot_id", "integer", true),
    url: String = ("url", "text", true),
    elements: serde_json::Value = ("elements", "jsonb", true),
    taken_at: time::OffsetDateTime = ("taken_at", "timestamp with time zone", true),
}
