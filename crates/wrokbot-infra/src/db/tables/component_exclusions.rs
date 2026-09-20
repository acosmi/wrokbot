//! `public.component_exclusions` 的类型化行 —— 上游
//! server/src/db/schema/components.ts::componentExclusions。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (component_name, agent_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
//! - FOREIGN KEY (component_name) REFERENCES components(name) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "component_exclusions";
    component_name: String = ("component_name", "text", true),
    agent_id: String = ("agent_id", "text", true),
    withheld_by: Option<String> = ("withheld_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
