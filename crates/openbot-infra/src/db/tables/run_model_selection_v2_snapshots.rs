//! Immutable accepted custom-V2 snapshots in the internal schema.
//! This row contains references and values, never a credential or authorization grant.

/// Fully qualified internal relation name.
pub const TABLE_NAME: &str = "openbot_internal.run_model_selection_v2_snapshots";
/// Exact physical column order.
pub const COLUMNS: &[&str] = &[
    "run_id",
    "deployment_id",
    "tenant_id",
    "owner_user_id",
    "auth_generation",
    "connection_id",
    "connection_revision",
    "secret_id",
    "protocol",
    "endpoint",
    "model",
    "created_at",
    "snapshot_schema",
    "source",
    "model_id",
    "catalog_revision",
    "dataset_id",
    "dataset_binding_schema",
    "dataset_initial_origin",
    "dataset_binding_created_at",
    "credential_policy",
];
/// Exact physical types and nullability, kept outside the public-table registry.
pub const COLUMN_SPECS: &[crate::db::tables::ColumnSpec] = &[
    crate::db::tables::ColumnSpec::new("run_id", "text", true),
    crate::db::tables::ColumnSpec::new("deployment_id", "text", true),
    crate::db::tables::ColumnSpec::new("tenant_id", "text", true),
    crate::db::tables::ColumnSpec::new("owner_user_id", "text", true),
    crate::db::tables::ColumnSpec::new("auth_generation", "bigint", true),
    crate::db::tables::ColumnSpec::new("connection_id", "uuid", true),
    crate::db::tables::ColumnSpec::new("connection_revision", "bigint", true),
    crate::db::tables::ColumnSpec::new("secret_id", "uuid", true),
    crate::db::tables::ColumnSpec::new("protocol", "text", true),
    crate::db::tables::ColumnSpec::new("endpoint", "text", true),
    crate::db::tables::ColumnSpec::new("model", "text", true),
    crate::db::tables::ColumnSpec::new("created_at", "timestamp with time zone", true),
    crate::db::tables::ColumnSpec::new("snapshot_schema", "smallint", true),
    crate::db::tables::ColumnSpec::new("source", "text", true),
    crate::db::tables::ColumnSpec::new("model_id", "text", true),
    crate::db::tables::ColumnSpec::new("catalog_revision", "bigint", true),
    crate::db::tables::ColumnSpec::new("dataset_id", "text", true),
    crate::db::tables::ColumnSpec::new("dataset_binding_schema", "smallint", true),
    crate::db::tables::ColumnSpec::new("dataset_initial_origin", "text", true),
    crate::db::tables::ColumnSpec::new(
        "dataset_binding_created_at",
        "timestamp with time zone",
        true,
    ),
    crate::db::tables::ColumnSpec::new("credential_policy", "text", true),
];

/// One immutable historical snapshot. Debug does not expose model or dataset values.
#[derive(Clone, PartialEq)]
pub struct Row {
    /// `run_id text NOT NULL`.
    pub run_id: String,
    /// `deployment_id text NOT NULL`.
    pub deployment_id: String,
    /// `tenant_id text NOT NULL`.
    pub tenant_id: String,
    /// `owner_user_id text NOT NULL`.
    pub owner_user_id: String,
    /// `auth_generation bigint NOT NULL`.
    pub auth_generation: i64,
    /// `connection_id uuid NOT NULL`.
    pub connection_id: uuid::Uuid,
    /// `connection_revision bigint NOT NULL`.
    pub connection_revision: i64,
    /// `secret_id uuid NOT NULL`.
    pub secret_id: uuid::Uuid,
    /// `protocol text NOT NULL`.
    pub protocol: String,
    /// `endpoint text NOT NULL`.
    pub endpoint: String,
    /// `model text NOT NULL`.
    pub model: String,
    /// `created_at timestamp with time zone NOT NULL`.
    pub created_at: time::OffsetDateTime,
    /// `snapshot_schema smallint NOT NULL`.
    pub snapshot_schema: i16,
    /// `source text NOT NULL`.
    pub source: String,
    /// `model_id text NOT NULL`.
    pub model_id: String,
    /// `catalog_revision bigint NOT NULL`.
    pub catalog_revision: i64,
    /// `dataset_id text NOT NULL`.
    pub dataset_id: String,
    /// `dataset_binding_schema smallint NOT NULL`.
    pub dataset_binding_schema: i16,
    /// `dataset_initial_origin text NOT NULL`.
    pub dataset_initial_origin: String,
    /// `dataset_binding_created_at timestamp with time zone NOT NULL`.
    pub dataset_binding_created_at: time::OffsetDateTime,
    /// `credential_policy text NOT NULL`.
    pub credential_policy: String,
}

impl core::fmt::Debug for Row {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelSelectionV2SnapshotRow(<redacted>)")
    }
}

impl TryFrom<&tokio_postgres::Row> for Row {
    type Error = crate::db::RowDecodeError;
    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            run_id: row.try_get("run_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "run_id", source)
            })?,
            deployment_id: row.try_get("deployment_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "deployment_id", source)
            })?,
            tenant_id: row.try_get("tenant_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "tenant_id", source)
            })?,
            owner_user_id: row.try_get("owner_user_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "owner_user_id", source)
            })?,
            auth_generation: row.try_get("auth_generation").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "auth_generation", source)
            })?,
            connection_id: row.try_get("connection_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "connection_id", source)
            })?,
            connection_revision: row.try_get("connection_revision").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "connection_revision", source)
            })?,
            secret_id: row.try_get("secret_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "secret_id", source)
            })?,
            protocol: row.try_get("protocol").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "protocol", source)
            })?,
            endpoint: row.try_get("endpoint").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "endpoint", source)
            })?,
            model: row
                .try_get("model")
                .map_err(|source| crate::db::RowDecodeError::column(TABLE_NAME, "model", source))?,
            created_at: row.try_get("created_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "created_at", source)
            })?,
            snapshot_schema: row.try_get("snapshot_schema").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "snapshot_schema", source)
            })?,
            source: row.try_get("source").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "source", source)
            })?,
            model_id: row.try_get("model_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "model_id", source)
            })?,
            catalog_revision: row.try_get("catalog_revision").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "catalog_revision", source)
            })?,
            dataset_id: row.try_get("dataset_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "dataset_id", source)
            })?,
            dataset_binding_schema: row.try_get("dataset_binding_schema").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "dataset_binding_schema", source)
            })?,
            dataset_initial_origin: row.try_get("dataset_initial_origin").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "dataset_initial_origin", source)
            })?,
            dataset_binding_created_at: row.try_get("dataset_binding_created_at").map_err(
                |source| {
                    crate::db::RowDecodeError::column(
                        TABLE_NAME,
                        "dataset_binding_created_at",
                        source,
                    )
                },
            )?,
            credential_policy: row.try_get("credential_policy").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "credential_policy", source)
            })?,
        })
    }
}

impl crate::db::tables::TableRow for Row {
    const TABLE_NAME: &'static str = TABLE_NAME;
    const COLUMNS: &'static [&'static str] = COLUMNS;
    fn as_sql_params(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
        vec![
            &self.run_id,
            &self.deployment_id,
            &self.tenant_id,
            &self.owner_user_id,
            &self.auth_generation,
            &self.connection_id,
            &self.connection_revision,
            &self.secret_id,
            &self.protocol,
            &self.endpoint,
            &self.model,
            &self.created_at,
            &self.snapshot_schema,
            &self.source,
            &self.model_id,
            &self.catalog_revision,
            &self.dataset_id,
            &self.dataset_binding_schema,
            &self.dataset_initial_origin,
            &self.dataset_binding_created_at,
            &self.credential_policy,
        ]
    }
    fn try_from_pg(row: &tokio_postgres::Row) -> Result<Self, crate::db::RowDecodeError> {
        Self::try_from(row)
    }
}
