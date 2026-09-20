//! `public.mcp_tools` 的类型化行 —— 上游 server/src/db/schema/plugins.ts::mcpTools。
//!
//! 列名、列序（`pg_attribute.attnum`）、可空性与类型逐列对应上游 0012 终态，真源是
//! `fixtures/db/schema-0012.json`；`COLUMN_SPECS` 与真库的一致性由
//! `crate::db::compat::check_migration_boundary` 在活库上机械核对。
//!
//! 主键：PRIMARY KEY (server_id, name)。
//!
//! 外键：
//!
//! - FOREIGN KEY (server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE

crate::db::tables::define_table! {
    table = "mcp_tools";
    server_id: String = ("server_id", "text", true),
    name: String = ("name", "text", true),
    description: String = ("description", "text", true),
    input_schema: serde_json::Value = ("input_schema", "jsonb", true),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
}

/// 0017 current projection columns.
pub const CURRENT_COLUMNS: &[&str] = &[
    "server_id", "name", "description", "input_schema", "created_at", "schema_hash", "effect",
    "catalog_generation", "first_seen_at", "last_seen_at", "available",
];

/// Current cached MCP tool row.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentRow {
    /// Baseline 0012 row.
    pub tool: Row,
    /// Canonical input schema hash.
    pub schema_hash: Option<String>,
    /// First-party classified effect.
    pub effect: Option<String>,
    /// Catalog generation last seen.
    pub catalog_generation: Option<i64>,
    /// First verified appearance.
    pub first_seen_at: Option<time::OffsetDateTime>,
    /// Most recent verified appearance.
    pub last_seen_at: Option<time::OffsetDateTime>,
    /// Current listing contains this tool.
    pub available: Option<bool>,
}

impl TryFrom<&tokio_postgres::Row> for CurrentRow {
    type Error = crate::db::RowDecodeError;

    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            tool: Row::try_from(row)?,
            schema_hash: row.try_get("schema_hash").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "schema_hash", source)
            })?,
            effect: row.try_get("effect").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "effect", source)
            })?,
            catalog_generation: row.try_get("catalog_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "catalog_generation", source)
            })?,
            first_seen_at: row.try_get("first_seen_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "first_seen_at", source)
            })?,
            last_seen_at: row.try_get("last_seen_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "last_seen_at", source)
            })?,
            available: row.try_get("available").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "available", source)
            })?,
        })
    }
}
