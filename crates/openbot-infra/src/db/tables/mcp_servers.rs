//! `public.mcp_servers` 的类型化行 —— 上游 server/src/db/schema/plugins.ts::mcpServers。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (id)。
//!
//! 外键：
//!
//! - FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE RESTRICT

crate::db::tables::define_table! {
    table = "mcp_servers";
    id: String = ("id", "text", true),
    title: String = ("title", "text", true),
    vendor: String = ("vendor", "text", true),
    url: String = ("url", "text", true),
    provenance: String = ("provenance", "text", true),
    credential_id: Option<uuid::Uuid> = ("credential_id", "uuid", false),
    tools_refreshed_at: Option<time::OffsetDateTime> = ("tools_refreshed_at", "timestamp with time zone", false),
    last_error: Option<String> = ("last_error", "text", false),
    added_by: Option<String> = ("added_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

/// Native-current projection columns.
pub const CURRENT_COLUMNS: &[&str] = &[
    "id", "title", "vendor", "url", "provenance", "credential_id", "tools_refreshed_at",
    "last_error", "added_by", "created_at", "updated_at", "catalog_generation", "catalog_hash",
    "catalog_transport_fingerprint", "credential_generation", "transport", "egress_allow_cidrs",
];

/// Current MCP server row with catalog identity.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// Baseline 0012 row.
    pub server: Row,
    /// Monotonic generation; legacy/unrefreshed is NULL.
    pub catalog_generation: Option<i64>,
    /// Canonical catalog hash paired with generation.
    pub catalog_hash: Option<String>,
    /// Canonical endpoint/vendor/provenance identity paired with generation.
    pub catalog_transport_fingerprint: Option<String>,
    /// Deployment credential generation; legacy NULL reads as zero at runtime.
    pub credential_generation: Option<i64>,
    /// `mcp` or `google_drive_rest`; legacy NULL reads as MCP.
    pub transport: Option<String>,
    /// Exact numeric CIDRs that may override default-deny special/private destinations.
    pub egress_allow_cidrs: Option<Vec<String>>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            server: Row::try_from(row)?,
            catalog_generation: row.try_get("catalog_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "catalog_generation", source)
            })?,
            catalog_hash: row.try_get("catalog_hash").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "catalog_hash", source)
            })?,
            catalog_transport_fingerprint: row
                .try_get("catalog_transport_fingerprint")
                .map_err(|source| {
                    crate::db::RowDecodeError::column(
                        TABLE_NAME,
                        "catalog_transport_fingerprint",
                        source,
                    )
                })?,
            credential_generation: row.try_get("credential_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "credential_generation", source)
            })?,
            transport: row.try_get("transport").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "transport", source)
            })?,
            egress_allow_cidrs: row.try_get("egress_allow_cidrs").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "egress_allow_cidrs", source)
            })?,
        })
    }
}
