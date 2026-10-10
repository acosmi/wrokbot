//! Typed storage data for the SDK authorization-attempt journal.
//! A decoded row is never a Host, permission, recoverable grant or send acknowledgement.

/// Fully qualified internal relation name.
pub const TABLE_NAME: &str = "openbot_internal.gateway_authorization_attempts";
/// Exact physical column order.
pub const COLUMNS: &[&str] = &[
    "attempt_id",
    "journal_schema",
    "deployment_id",
    "tenant_id",
    "owner_user_id",
    "auth_generation",
    "installation_id",
    "runtime_epoch",
    "issuer",
    "redirect_uri",
    "phase",
    "client_id",
    "enrollment_id",
    "registration_admitted_at",
    "code_admitted_at",
    "created_at",
    "expires_at",
    "updated_at",
    "finished_at",
    "outcome_code",
];
/// Exact physical types and nullability, outside the public registry.
pub const COLUMN_SPECS: &[crate::db::tables::ColumnSpec] = &[
    crate::db::tables::ColumnSpec::new("attempt_id", "uuid", true),
    crate::db::tables::ColumnSpec::new("journal_schema", "smallint", true),
    crate::db::tables::ColumnSpec::new("deployment_id", "text", true),
    crate::db::tables::ColumnSpec::new("tenant_id", "text", true),
    crate::db::tables::ColumnSpec::new("owner_user_id", "text", true),
    crate::db::tables::ColumnSpec::new("auth_generation", "bigint", true),
    crate::db::tables::ColumnSpec::new("installation_id", "text", true),
    crate::db::tables::ColumnSpec::new("runtime_epoch", "text", true),
    crate::db::tables::ColumnSpec::new("issuer", "text", true),
    crate::db::tables::ColumnSpec::new("redirect_uri", "text", true),
    crate::db::tables::ColumnSpec::new("phase", "text", true),
    crate::db::tables::ColumnSpec::new("client_id", "text", false),
    crate::db::tables::ColumnSpec::new("enrollment_id", "uuid", false),
    crate::db::tables::ColumnSpec::new(
        "registration_admitted_at",
        "timestamp with time zone",
        false,
    ),
    crate::db::tables::ColumnSpec::new("code_admitted_at", "timestamp with time zone", false),
    crate::db::tables::ColumnSpec::new("created_at", "timestamp with time zone", true),
    crate::db::tables::ColumnSpec::new("expires_at", "timestamp with time zone", true),
    crate::db::tables::ColumnSpec::new("updated_at", "timestamp with time zone", true),
    crate::db::tables::ColumnSpec::new("finished_at", "timestamp with time zone", false),
    crate::db::tables::ColumnSpec::new("outcome_code", "text", false),
];

/// Journal storage data; Debug redacts every field.
#[derive(Clone, PartialEq)]
pub struct Row {
    /// `attempt_id uuid NOT NULL`.
    pub attempt_id: uuid::Uuid,
    /// `journal_schema smallint NOT NULL`.
    pub journal_schema: i16,
    /// `deployment_id text NOT NULL`.
    pub deployment_id: String,
    /// `tenant_id text NOT NULL`.
    pub tenant_id: String,
    /// `owner_user_id text NOT NULL`.
    pub owner_user_id: String,
    /// `auth_generation bigint NOT NULL`.
    pub auth_generation: i64,
    /// `installation_id text NOT NULL`.
    pub installation_id: String,
    /// `runtime_epoch text NOT NULL`.
    pub runtime_epoch: String,
    /// `issuer text NOT NULL`.
    pub issuer: String,
    /// `redirect_uri text NOT NULL`.
    pub redirect_uri: String,
    /// `phase text NOT NULL`.
    pub phase: String,
    /// `client_id text nullable`.
    pub client_id: Option<String>,
    /// `enrollment_id uuid nullable`.
    pub enrollment_id: Option<uuid::Uuid>,
    /// `registration_admitted_at timestamp with time zone nullable`.
    pub registration_admitted_at: Option<time::OffsetDateTime>,
    /// `code_admitted_at timestamp with time zone nullable`.
    pub code_admitted_at: Option<time::OffsetDateTime>,
    /// `created_at timestamp with time zone NOT NULL`.
    pub created_at: time::OffsetDateTime,
    /// `expires_at timestamp with time zone NOT NULL`.
    pub expires_at: time::OffsetDateTime,
    /// `updated_at timestamp with time zone NOT NULL`.
    pub updated_at: time::OffsetDateTime,
    /// `finished_at timestamp with time zone nullable`.
    pub finished_at: Option<time::OffsetDateTime>,
    /// `outcome_code text nullable`.
    pub outcome_code: Option<String>,
}

impl core::fmt::Debug for Row {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GatewayAuthorizationAttemptRow(<redacted>)")
    }
}

impl TryFrom<&tokio_postgres::Row> for Row {
    type Error = crate::db::RowDecodeError;
    fn try_from(row: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Self {
            attempt_id: row.try_get("attempt_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "attempt_id", source)
            })?,
            journal_schema: row.try_get("journal_schema").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "journal_schema", source)
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
            installation_id: row.try_get("installation_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "installation_id", source)
            })?,
            runtime_epoch: row.try_get("runtime_epoch").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "runtime_epoch", source)
            })?,
            issuer: row.try_get("issuer").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "issuer", source)
            })?,
            redirect_uri: row.try_get("redirect_uri").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "redirect_uri", source)
            })?,
            phase: row
                .try_get("phase")
                .map_err(|source| crate::db::RowDecodeError::column(TABLE_NAME, "phase", source))?,
            client_id: row.try_get("client_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "client_id", source)
            })?,
            enrollment_id: row.try_get("enrollment_id").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "enrollment_id", source)
            })?,
            registration_admitted_at: row.try_get("registration_admitted_at").map_err(
                |source| {
                    crate::db::RowDecodeError::column(
                        TABLE_NAME,
                        "registration_admitted_at",
                        source,
                    )
                },
            )?,
            code_admitted_at: row.try_get("code_admitted_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "code_admitted_at", source)
            })?,
            created_at: row.try_get("created_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "created_at", source)
            })?,
            expires_at: row.try_get("expires_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "expires_at", source)
            })?,
            updated_at: row.try_get("updated_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "updated_at", source)
            })?,
            finished_at: row.try_get("finished_at").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "finished_at", source)
            })?,
            outcome_code: row.try_get("outcome_code").map_err(|source| {
                crate::db::RowDecodeError::column(TABLE_NAME, "outcome_code", source)
            })?,
        })
    }
}

impl crate::db::tables::TableRow for Row {
    const TABLE_NAME: &'static str = TABLE_NAME;
    const COLUMNS: &'static [&'static str] = COLUMNS;
    fn as_sql_params(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
        vec![
            &self.attempt_id,
            &self.journal_schema,
            &self.deployment_id,
            &self.tenant_id,
            &self.owner_user_id,
            &self.auth_generation,
            &self.installation_id,
            &self.runtime_epoch,
            &self.issuer,
            &self.redirect_uri,
            &self.phase,
            &self.client_id,
            &self.enrollment_id,
            &self.registration_admitted_at,
            &self.code_admitted_at,
            &self.created_at,
            &self.expires_at,
            &self.updated_at,
            &self.finished_at,
            &self.outcome_code,
        ]
    }
    fn try_from_pg(row: &tokio_postgres::Row) -> Result<Self, crate::db::RowDecodeError> {
        Self::try_from(row)
    }
}
