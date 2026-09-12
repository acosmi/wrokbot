//! Read-only preflight and one-shot persistence for the Desktop dataset Vault canary.

use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, DesktopVaultCanaryEnvelope, KeyVersion, SecretBytes,
    open_desktop_vault_canary,
};

use super::desktop_local::DesktopLocalDatabase;
use super::schema_facts::SchemaFacts;
use super::{InfraError, RowDecodeError, native, schema_facts};

const TABLE: &str = "openbot_internal.desktop_vault_canaries";
const TIMEOUT: Duration = Duration::from_secs(10);
const PUBLIC_0031: &str = include_str!("../../../../fixtures/db/schema-0031.json");

#[derive(Debug, thiserror::Error)]
pub enum DesktopVaultCanaryError {
    #[error("desktop_vault_canary_database_unavailable")]
    Infra(#[source] InfraError),
    #[error("desktop_vault_canary_reconciliation_required")]
    ReconciliationRequired,
    #[error("desktop_vault_canary_material_invalid")]
    MaterialInvalid,
}

impl From<InfraError> for DesktopVaultCanaryError {
    fn from(error: InfraError) -> Self {
        Self::Infra(error)
    }
}

/// Exact immutable row stored for one dataset/master version.
pub struct DesktopVaultCanaryRow {
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    canary_schema: i16,
    encrypted_canary: String,
}

/// Cryptographic proof required by Desktop principal/package bootstrap.
pub struct VerifiedDesktopVaultCanary {
    database_owner: Arc<()>,
    system_identifier: String,
    database_oid: u32,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
}

impl VerifiedDesktopVaultCanary {
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn key_version(&self) -> i32 {
        self.key_version
    }

    pub(crate) async fn matches_database(
        &self,
        database: &DesktopLocalDatabase,
    ) -> Result<bool, DesktopVaultCanaryError> {
        if !database.owns_token(&self.database_owner) {
            return Ok(false);
        }
        let (system_identifier, database_oid) = database_identity(database.pool()).await?;
        Ok(self.system_identifier == system_identifier && self.database_oid == database_oid)
    }
}

impl core::fmt::Debug for VerifiedDesktopVaultCanary {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedDesktopVaultCanary(<verified>)")
    }
}

impl DesktopVaultCanaryRow {
    pub fn new(
        dataset_id: impl Into<String>,
        deployment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
        encrypted_canary: impl Into<String>,
    ) -> Result<Self, DesktopVaultCanaryError> {
        let row = Self {
            dataset_id: dataset_id.into(),
            deployment_id: deployment_id.into(),
            tenant_id: tenant_id.into(),
            key_id: key_id.into(),
            key_version: 1,
            canary_schema: 1,
            encrypted_canary: encrypted_canary.into(),
        };
        if !hex_id(&row.dataset_id)
            || !identity(&row.deployment_id)
            || !identity(&row.tenant_id)
            || !hex_id(&row.key_id)
            || row.encrypted_canary.is_empty()
            || row.encrypted_canary.len() > 4096
        {
            return Err(DesktopVaultCanaryError::ReconciliationRequired);
        }
        Ok(row)
    }

    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn key_version(&self) -> i32 {
        self.key_version
    }
    pub const fn canary_schema(&self) -> i16 {
        self.canary_schema
    }
    pub fn encrypted_canary(&self) -> &str {
        &self.encrypted_canary
    }
}

impl core::fmt::Debug for DesktopVaultCanaryRow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DesktopVaultCanaryRow(<redacted>)")
    }
}

fn verify(
    database_owner: Arc<()>,
    system_identifier: String,
    database_oid: u32,
    master: &SecretBytes,
    row: &DesktopVaultCanaryRow,
) -> Result<VerifiedDesktopVaultCanary, DesktopVaultCanaryError> {
    let binding = DesktopVaultCanaryBinding::new(
        row.dataset_id.clone(),
        row.deployment_id.clone(),
        row.tenant_id.clone(),
        row.key_id.clone(),
        KeyVersion::new(1),
    )
    .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    let envelope = DesktopVaultCanaryEnvelope::parse(&row.encrypted_canary)
        .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    open_desktop_vault_canary(master, &binding, &envelope)
        .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    Ok(VerifiedDesktopVaultCanary {
        database_owner,
        system_identifier,
        database_oid,
        dataset_id: row.dataset_id.clone(),
        deployment_id: row.deployment_id.clone(),
        tenant_id: row.tenant_id.clone(),
        key_id: row.key_id.clone(),
        key_version: row.key_version,
    })
}

pub async fn verify_persisted(
    database: &DesktopLocalDatabase,
    master: &SecretBytes,
    dataset_id: &str,
    deployment_id: &str,
    tenant_id: &str,
    key_id: &str,
) -> Result<VerifiedDesktopVaultCanary, DesktopVaultCanaryError> {
    let pool = database.pool();
    let row = read(pool, deployment_id, tenant_id)
        .await?
        .ok_or(DesktopVaultCanaryError::ReconciliationRequired)?;
    if row.dataset_id != dataset_id
        || row.deployment_id != deployment_id
        || row.tenant_id != tenant_id
        || row.key_id != key_id
        || row.key_version != 1
        || row.canary_schema != 1
    {
        return Err(DesktopVaultCanaryError::ReconciliationRequired);
    }
    let (system_identifier, database_oid) = database_identity(pool).await?;
    verify(
        database.owner_token(),
        system_identifier,
        database_oid,
        master,
        &row,
    )
}

async fn database_identity(pool: &Pool) -> Result<(String, u32), DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        let row = client
            .query_one(
                "SELECT pcs.system_identifier::text,d.oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("核验 Desktop Vault canary 数据库身份", source))?;
        let system_identifier = row
            .try_get(0)
            .map_err(|source| RowDecodeError::column("(pg_control_system)", "system_identifier", source))?;
        let database_oid = row
            .try_get(1)
            .map_err(|source| RowDecodeError::column("(pg_database)", "oid", source))?;
        Ok((system_identifier, database_oid))
    })
    .await
}

pub async fn table_exists(pool: &Pool) -> Result<bool, DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&TABLE])
            .await
            .map_err(|source| InfraError::query("只读探测 Desktop Vault canary 表", source))?
            .try_get(0)
            .map_err(|source| RowDecodeError::column("(to_regclass)", "exists", source).into())
    })
    .await
}

pub async fn verify_current_layout(pool: &Pool) -> Result<(), DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        native::validate_current(&client).await?;
        verify_internal_shape(&client).await?;
        let expected: SchemaFacts = serde_json::from_str(PUBLIC_0031)
            .map_err(|_| InfraError::repository_invariant("schema_0031_fixture_invalid"))?;
        if schema_facts::fetch(&client).await? != expected {
            return Err(InfraError::repository_invariant(
                "desktop_vault_public_schema_invalid",
            ));
        }
        let unknown_views: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('v','m','p','f'))",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("只读核验 public 未知关系", source))?
            .try_get(0)
            .map_err(|source| RowDecodeError::column("(pg_class)", "exists", source))?;
        if unknown_views {
            return Err(InfraError::repository_invariant(
                "desktop_vault_public_relation_unknown",
            ));
        }
        Ok(())
    })
    .await
}

async fn verify_internal_shape(client: &tokio_postgres::Client) -> Result<(), InfraError> {
    let relation = client
        .query_opt(
            "SELECT c.relkind::text,c.relpersistence::text,c.relispartition,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='openbot_internal' AND c.relname='desktop_vault_canaries'",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary relation", source))?
        .ok_or_else(|| InfraError::repository_invariant("desktop_vault_canary_table_missing"))?;
    let relation_shape: (String, String, bool, bool, bool) = (
        relation
            .try_get(0)
            .map_err(|source| RowDecodeError::column(TABLE, "relkind", source))?,
        relation
            .try_get(1)
            .map_err(|source| RowDecodeError::column(TABLE, "relpersistence", source))?,
        relation
            .try_get(2)
            .map_err(|source| RowDecodeError::column(TABLE, "relispartition", source))?,
        relation
            .try_get(3)
            .map_err(|source| RowDecodeError::column(TABLE, "relrowsecurity", source))?,
        relation
            .try_get(4)
            .map_err(|source| RowDecodeError::column(TABLE, "relforcerowsecurity", source))?,
    );
    if relation_shape != ("r".to_owned(), "p".to_owned(), false, false, false) {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_table_shape_invalid",
        ));
    }
    let executable_hooks: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='openbot_internal.desktop_vault_canaries'::regclass AND NOT tgisinternal) OR EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class='openbot_internal.desktop_vault_canaries'::regclass)",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary hooks", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column(TABLE, "hooks", source))?;
    if executable_hooks {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_hooks_invalid",
        ));
    }

    let columns = client
        .query(
            "SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attnum FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='openbot_internal.desktop_vault_canaries'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary columns", source))?;
    let expected_columns = [
        ("dataset_id", "text", true, None, 1_i16),
        ("deployment_id", "text", true, None, 2_i16),
        ("tenant_id", "text", true, None, 3_i16),
        ("key_id", "text", true, None, 4_i16),
        ("key_version", "integer", true, None, 5_i16),
        ("canary_schema", "smallint", true, None, 6_i16),
        ("encrypted_canary", "text", true, None, 7_i16),
        (
            "created_at",
            "timestamp with time zone",
            true,
            Some("now()"),
            8_i16,
        ),
    ];
    if columns.len() != expected_columns.len() {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_columns_invalid",
        ));
    }
    for (row, expected) in columns.iter().zip(expected_columns) {
        let actual: (String, String, bool, Option<String>, i16) = (
            row.try_get(0)
                .map_err(|source| RowDecodeError::column(TABLE, "attname", source))?,
            row.try_get(1)
                .map_err(|source| RowDecodeError::column(TABLE, "format_type", source))?,
            row.try_get(2)
                .map_err(|source| RowDecodeError::column(TABLE, "attnotnull", source))?,
            row.try_get(3)
                .map_err(|source| RowDecodeError::column(TABLE, "default", source))?,
            row.try_get(4)
                .map_err(|source| RowDecodeError::column(TABLE, "attnum", source))?,
        );
        let expected = (
            expected.0.to_owned(),
            expected.1.to_owned(),
            expected.2,
            expected.3.map(str::to_owned),
            expected.4,
        );
        if actual != expected {
            return Err(InfraError::repository_invariant(
                "desktop_vault_canary_columns_invalid",
            ));
        }
    }

    let mut constraints: Vec<(String, String)> = client
        .query(
            "SELECT con.contype::text,pg_get_constraintdef(con.oid) FROM pg_constraint con WHERE con.conrelid='openbot_internal.desktop_vault_canaries'::regclass",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary constraints", source))?
        .into_iter()
        .map(|row| Ok((
            row.try_get(0).map_err(|source| RowDecodeError::column(TABLE,"contype",source))?,
            row.try_get(1).map_err(|source| RowDecodeError::column(TABLE,"constraintdef",source))?,
        )))
        .collect::<Result<_, InfraError>>()?;
    constraints.sort();
    let mut expected_constraints: Vec<_> = [
        ("c", "CHECK ((dataset_id ~ '^[0-9a-f]{32}$'::text))"),
        ("c", "CHECK (((octet_length(deployment_id) >= 1) AND (octet_length(deployment_id) <= 256)))"),
        ("c", "CHECK (((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 256)))"),
        ("c", "CHECK ((key_id ~ '^[0-9a-f]{32}$'::text))"),
        ("c", "CHECK ((key_version > 0))"),
        ("c", "CHECK ((canary_schema = 1))"),
        ("c", "CHECK (((octet_length(encrypted_canary) >= 1) AND (octet_length(encrypted_canary) <= 4096)))"),
        ("p", "PRIMARY KEY (dataset_id, key_version)"),
        ("u", "UNIQUE (deployment_id, tenant_id, key_version)"),
        ("u", "UNIQUE (dataset_id, key_id)"),
    ]
    .into_iter()
    .map(|(kind, definition)| (kind.to_owned(), definition.to_owned()))
    .collect();
    expected_constraints.sort();
    if constraints != expected_constraints {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_constraints_invalid",
        ));
    }

    let mut indexes: Vec<(bool, bool, String)> = client
        .query(
            "SELECT i.indisprimary,i.indisunique,i.indkey::text FROM pg_index i WHERE i.indrelid='openbot_internal.desktop_vault_canaries'::regclass",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary indexes", source))?
        .into_iter()
        .map(|row| Ok((
            row.try_get(0).map_err(|source| RowDecodeError::column(TABLE,"indisprimary",source))?,
            row.try_get(1).map_err(|source| RowDecodeError::column(TABLE,"indisunique",source))?,
            row.try_get(2).map_err(|source| RowDecodeError::column(TABLE,"indkey",source))?,
        )))
        .collect::<Result<_, InfraError>>()?;
    indexes.sort();
    let mut expected_indexes: Vec<_> = [
        (true, true, "1 5".to_owned()),
        (false, true, "1 4".to_owned()),
        (false, true, "2 3 5".to_owned()),
    ]
    .into_iter()
    .collect();
    expected_indexes.sort();
    if indexes != expected_indexes {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_indexes_invalid",
        ));
    }
    Ok(())
}

pub async fn verify_empty_initializing(pool: &Pool) -> Result<(), DesktopVaultCanaryError> {
    verify_current_layout(pool).await?;
    bounded(async {
        let client = client(pool).await?;
        let expected: SchemaFacts = serde_json::from_str(PUBLIC_0031)
            .map_err(|_| InfraError::repository_invariant("schema_0031_fixture_invalid"))?;
        for table in expected.tables {
            if !table
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(InfraError::repository_invariant(
                    "schema_0031_table_name_invalid",
                ));
            }
            let statement = format!(
                "SELECT EXISTS(SELECT 1 FROM public.\"{}\" LIMIT 1)",
                table.name
            );
            let has_rows: bool = client
                .query_one(&statement, &[])
                .await
                .map_err(|source| InfraError::query("只读核验初始化业务表为空", source))?
                .try_get(0)
                .map_err(|source| RowDecodeError::column("(public table)", "exists", source))?;
            if has_rows {
                return Err(InfraError::repository_invariant(
                    "desktop_vault_business_rows_present",
                ));
            }
        }
        let canaries: i64 = client
            .query_one(&format!("SELECT count(*)::bigint FROM {TABLE}"), &[])
            .await
            .map_err(|source| InfraError::query("只读核验 canary 尚未写入", source))?
            .try_get(0)
            .map_err(|source| RowDecodeError::column(TABLE, "count", source))?;
        if canaries != 0 {
            return Err(InfraError::repository_invariant(
                "desktop_vault_canary_already_present",
            ));
        }
        Ok(())
    })
    .await
}

pub async fn read(
    pool: &Pool,
    deployment_id: &str,
    tenant_id: &str,
) -> Result<Option<DesktopVaultCanaryRow>, DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        let row = client
            .query_opt(
                "SELECT dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",
                &[&deployment_id, &tenant_id],
            )
            .await
            .map_err(|source| InfraError::query("只读读取 Desktop Vault canary", source))?;
        row.map(decode_row).transpose()
    })
    .await
}

pub async fn insert_once(
    pool: &Pool,
    row: &DesktopVaultCanaryRow,
) -> Result<(), DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        client
            .execute(
                "INSERT INTO openbot_internal.desktop_vault_canaries(dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary) VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[&row.dataset_id,&row.deployment_id,&row.tenant_id,&row.key_id,&row.key_version,&row.canary_schema,&row.encrypted_canary],
            )
            .await
            .map_err(|source| InfraError::query("写入 Desktop Vault canary", source))
            .map(|_| ())
    })
    .await
}

fn decode_row(row: tokio_postgres::Row) -> Result<DesktopVaultCanaryRow, InfraError> {
    let key_version: i32 = row
        .try_get(4)
        .map_err(|source| RowDecodeError::column(TABLE, "key_version", source))?;
    let canary_schema: i16 = row
        .try_get(5)
        .map_err(|source| RowDecodeError::column(TABLE, "canary_schema", source))?;
    if key_version != 1 || canary_schema != 1 {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_row_invalid",
        ));
    }
    DesktopVaultCanaryRow::new(
        row.try_get::<_, String>(0)
            .map_err(|source| RowDecodeError::column(TABLE, "dataset_id", source))?,
        row.try_get::<_, String>(1)
            .map_err(|source| RowDecodeError::column(TABLE, "deployment_id", source))?,
        row.try_get::<_, String>(2)
            .map_err(|source| RowDecodeError::column(TABLE, "tenant_id", source))?,
        row.try_get::<_, String>(3)
            .map_err(|source| RowDecodeError::column(TABLE, "key_id", source))?,
        row.try_get::<_, String>(6)
            .map_err(|source| RowDecodeError::column(TABLE, "encrypted_canary", source))?,
    )
    .map_err(|error| match error {
        DesktopVaultCanaryError::Infra(error) => error,
        DesktopVaultCanaryError::ReconciliationRequired => {
            InfraError::repository_invariant("desktop_vault_canary_row_invalid")
        }
        DesktopVaultCanaryError::MaterialInvalid => {
            InfraError::repository_invariant("desktop_vault_canary_material_invalid")
        }
    })
}

async fn client(pool: &Pool) -> Result<deadpool_postgres::Client, InfraError> {
    pool.get()
        .await
        .map_err(|source| InfraError::connect("取 Desktop Vault canary 连接", source))
}

async fn bounded<T>(
    future: impl std::future::Future<Output = Result<T, InfraError>>,
) -> Result<T, DesktopVaultCanaryError> {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .map_err(|_| DesktopVaultCanaryError::ReconciliationRequired)?
        .map_err(DesktopVaultCanaryError::Infra)
}

fn hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identity(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|ch| ch == '\0' || ch.is_control())
}
