//! `public.intelligence_channel_mappings` 的类型化行 —— 上游
//! server/src/db/schema/core.ts::intelligenceChannelMappings。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (user_id, channel_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "intelligence_channel_mappings";
    user_id: String = ("user_id", "text", true),
    channel_id: String = ("channel_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
