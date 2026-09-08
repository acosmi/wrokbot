//! `public.revoked_access` 的类型化行 —— 上游 server/src/db/schema/core.ts::revokedAccess。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (email)。

crate::db::tables::define_table! {
    table = "revoked_access";
    email: String = ("email", "text", true),
    revoked_at: time::OffsetDateTime = ("revoked_at", "timestamp with time zone", true),
    revoked_by: String = ("revoked_by", "text", true),
}
