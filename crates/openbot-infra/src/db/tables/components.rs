//! `public.components` 的类型化行 —— 上游 server/src/db/schema/components.ts::components。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (name)。

crate::db::tables::define_table! {
    table = "components";
    name: String = ("name", "text", true),
    title: String = ("title", "text", true),
    kind: String = ("kind", "text", true),
    draft_description: String = ("draft_description", "text", true),
    published_description: Option<String> = ("published_description", "text", false),
    published: bool = ("published", "boolean", true),
    published_at: Option<time::OffsetDateTime> = ("published_at", "timestamp with time zone", false),
    updated_by: Option<String> = ("updated_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
