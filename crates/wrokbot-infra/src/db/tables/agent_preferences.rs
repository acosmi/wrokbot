//! `public.agent_preferences` 的类型化行 —— 上游
//! server/src/db/schema/coworker.ts::agentPreferences。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (user_id, agent_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
//! - FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "agent_preferences";
    user_id: String = ("user_id", "text", true),
    agent_id: String = ("agent_id", "text", true),
    hidden_at: Option<time::OffsetDateTime> = ("hidden_at", "timestamp with time zone", false),
}
