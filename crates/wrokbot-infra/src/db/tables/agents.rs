//! `public.agents` 的类型化行 —— 上游 server/src/db/schema/core.ts::agents。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (package_id) REFERENCES deployment_packages(id) ON DELETE SET NULL

crate::db::tables::define_table! {
    table = "agents";
    id: String = ("id", "text", true),
    name: String = ("name", "text", true),
    r#type: crate::db::types::AgentType = ("type", "agent_type", true),
    configuration: serde_json::Value = ("configuration", "jsonb", true),
    package_id: Option<uuid::Uuid> = ("package_id", "uuid", false),
    r#override: Option<serde_json::Value> = ("override", "jsonb", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
