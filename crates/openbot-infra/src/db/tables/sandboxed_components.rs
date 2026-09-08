//! `public.sandboxed_components` 的类型化行 —— 上游
//! server/src/db/schema/plugins.ts::sandboxedComponents。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (name)。

crate::db::tables::define_table! {
    table = "sandboxed_components";
    name: String = ("name", "text", true),
    title: String = ("title", "text", true),
    draft_description: String = ("draft_description", "text", true),
    draft_html: String = ("draft_html", "text", true),
    draft_css: String = ("draft_css", "text", true),
    draft_js_functions: String = ("draft_js_functions", "text", true),
    draft_argument_schema: serde_json::Value = ("draft_argument_schema", "jsonb", true),
    published_description: Option<String> = ("published_description", "text", false),
    published_html: Option<String> = ("published_html", "text", false),
    published_css: Option<String> = ("published_css", "text", false),
    published_js_functions: Option<String> = ("published_js_functions", "text", false),
    published_argument_schema: Option<serde_json::Value> = ("published_argument_schema", "jsonb", false),
    sample_arguments: serde_json::Value = ("sample_arguments", "jsonb", true),
    revision: i32 = ("revision", "integer", true),
    published: bool = ("published", "boolean", true),
    published_at: Option<time::OffsetDateTime> = ("published_at", "timestamp with time zone", false),
    authored_by: Option<String> = ("authored_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}
