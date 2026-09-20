//! `public.deployment_packages` 的类型化行 —— 上游
//! server/src/db/schema/core.ts::deploymentPackages。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//! 唯一：UNIQUE (tenant_id)。

crate::db::tables::define_table! {
    table = "deployment_packages";
    id: uuid::Uuid = ("id", "uuid", true),
    tenant_id: String = ("tenant_id", "text", true),
    source_path: String = ("source_path", "text", true),
    checksum: String = ("checksum", "text", true),
    loaded_at: time::OffsetDateTime = ("loaded_at", "timestamp with time zone", true),
}
