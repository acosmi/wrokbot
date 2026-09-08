//! `public.skills` 的类型化行 —— 上游 server/src/db/schema/plugins.ts::skills。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "skills";
    id: String = ("id", "text", true),
    owner_user_id: Option<String> = ("owner_user_id", "text", false),
    slug: String = ("slug", "text", true),
    title: String = ("title", "text", true),
    summary: String = ("summary", "text", true),
    instructions: String = ("instructions", "text", true),
    origin: String = ("origin", "text", true),
    installed_by: Option<String> = ("installed_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
