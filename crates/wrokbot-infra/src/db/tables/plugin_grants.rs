//! `public.plugin_grants` 的类型化行 —— 上游 server/src/db/schema/plugins.ts::pluginGrants。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (kind, ref, agent_id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "plugin_grants";
    kind: String = ("kind", "text", true),
    r#ref: String = ("ref", "text", true),
    agent_id: String = ("agent_id", "text", true),
    granted_by: Option<String> = ("granted_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

/// Native-current projection columns.
pub const CURRENT_COLUMNS: &[&str] = &[
    "kind", "ref", "agent_id", "granted_by", "created_at", "updated_at", "state",
    "catalog_generation", "schema_hash", "effect", "transport_fingerprint",
    "credential_generation",
];

/// Current grant with stale-catalog binding.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// Baseline 0012 grant row.
    pub grant: Row,
    /// `active` or `suspended_missing`; legacy rows are NULL until refresh.
    pub state: Option<String>,
    /// Exact catalog generation reviewed/observed.
    pub catalog_generation: Option<i64>,
    /// Exact schema hash bound to the grant.
    pub schema_hash: Option<String>,
    /// Exact first-party effect classification bound to the grant.
    pub effect: Option<String>,
    /// Exact endpoint/vendor/provenance identity bound to the grant.
    pub transport_fingerprint: Option<String>,
    /// Deployment credential generation reviewed with this grant.
    pub credential_generation: Option<i64>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            grant: Row::try_from(row)?,
            state: row.try_get("state").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "state", source)
            })?,
            catalog_generation: row.try_get("catalog_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "catalog_generation", source)
            })?,
            schema_hash: row.try_get("schema_hash").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "schema_hash", source)
            })?,
            effect: row.try_get("effect").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "effect", source)
            })?,
            transport_fingerprint: row.try_get("transport_fingerprint").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "transport_fingerprint", source)
            })?,
            credential_generation: row.try_get("credential_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "credential_generation", source)
            })?,
        })
    }
}
