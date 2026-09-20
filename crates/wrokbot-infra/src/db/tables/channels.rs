//! `public.channels` 的类型化行 —— 上游 server/src/db/schema/core.ts::channels。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (last_message_agent_id) REFERENCES agents(id) ON DELETE SET NULL
//! - FOREIGN KEY (package_id) REFERENCES deployment_packages(id) ON DELETE SET NULL

crate::db::tables::define_table! {
    table = "channels";
    id: String = ("id", "text", true),
    name: String = ("name", "text", true),
    description: String = ("description", "text", true),
    suggested_prompts: Vec<Option<String>> = ("suggested_prompts", "text[]", true),
    allowed_groups: Vec<Option<String>> = ("allowed_groups", "text[]", true),
    package_id: Option<uuid::Uuid> = ("package_id", "uuid", false),
    r#override: Option<serde_json::Value> = ("override", "jsonb", false),
    last_message: Option<String> = ("last_message", "text", false),
    last_message_at: Option<time::OffsetDateTime> = ("last_message_at", "timestamp with time zone", false),
    last_message_agent_id: Option<String> = ("last_message_agent_id", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
