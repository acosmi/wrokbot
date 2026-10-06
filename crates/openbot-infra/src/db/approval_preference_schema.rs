//! Read-only observations of the internal remember preference schema.
//!
//! This verifies storage shape only. It does not bind a repository, observe permission,
//! compare a caller's expected revision, or establish a transaction's deadline or outcome.

use serde_json::Value;
use tokio_postgres::Client;

use super::native;

/// Closed failures without database values, connection details or arbitrary messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalPreferenceSchemaError {
    /// The requested PostgreSQL observation was unavailable.
    #[error("approval_preference_schema_unavailable")]
    Unavailable,
    /// The actual server encoding, version or physical page size is unsupported.
    #[error("approval_preference_storage_incompatible")]
    IncompatibleStorage,
    /// An ordered ledger or catalog fact differs from the independently frozen schema.
    #[error("approval_preference_schema_corrupt")]
    Corrupt {
        /// Static code identifying the failed observation, never a stored value.
        field: &'static str,
    },
}

// Frozen from an owned actual PostgreSQL fixture. Capture never consumes this oracle.
const REGISTERED_SCHEMA: &str =
    include_str!("../../../../fixtures/db/approval-preferences-0043.json");

/// Exact ordered catalog observation of this table, its keys and enabled guard hooks.
pub const APPROVAL_PREFERENCE_SCHEMA_SQL: &str = r"
SELECT pg_catalog.jsonb_build_object(
 'relation',(
   SELECT pg_catalog.jsonb_build_object(
     'kind',c.relkind::text,'persistence',c.relpersistence::text,
     'partition',c.relispartition,'rowSecurity',c.relrowsecurity,
     'forceRowSecurity',c.relforcerowsecurity,'accessMethod',am.amname)
   FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
   WHERE n.nspname='openbot_internal' AND c.relname='approval_preferences'
 ),
 'columns',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),
     'notNull',a.attnotnull,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
     'ordinal',a.attnum,'identity',a.attidentity::text,'generated',a.attgenerated::text,
     'collationSchema',cn.nspname,'collation',co.collname) ORDER BY a.attnum),'[]'::jsonb)
   FROM pg_catalog.pg_attribute a
   LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
   LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
   WHERE a.attrelid=pg_catalog.to_regclass('openbot_internal.approval_preferences')
     AND a.attnum>0 AND NOT a.attisdropped
 ),
 'constraints',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',c.conname,'kind',c.contype::text,'validated',c.convalidated,
     'deferrable',c.condeferrable,'deferred',c.condeferred,
     'definition',pg_catalog.pg_get_constraintdef(c.oid)) ORDER BY c.conname),'[]'::jsonb)
   FROM pg_catalog.pg_constraint c
   WHERE c.conrelid=pg_catalog.to_regclass('openbot_internal.approval_preferences')
     AND c.contype<>'n'
 ),
 'indexes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',c.relname,'primary',i.indisprimary,'unique',i.indisunique,
     'valid',i.indisvalid,'ready',i.indisready,'keys',i.indkey::text,
     'predicate',pg_catalog.pg_get_expr(i.indpred,i.indrelid),
     'expressions',pg_catalog.pg_get_expr(i.indexprs,i.indrelid),
     'definition',pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY c.relname),'[]'::jsonb)
   FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   WHERE i.indrelid=pg_catalog.to_regclass('openbot_internal.approval_preferences')
 ),
 'triggers',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',t.tgname,'enabled',t.tgenabled::text,'type',t.tgtype::integer,
     'definition',pg_catalog.pg_get_triggerdef(t.oid),
     'functionSchema',n.nspname,'functionName',p.proname,
     'functionArguments',pg_catalog.pg_get_function_identity_arguments(p.oid))
       ORDER BY t.tgname),'[]'::jsonb)
   FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE t.tgrelid=pg_catalog.to_regclass('openbot_internal.approval_preferences')
     AND NOT t.tgisinternal
 ),
 'rules',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.pg_get_ruledef(r.oid)
     ORDER BY r.rulename),'[]'::jsonb)
   FROM pg_catalog.pg_rewrite r
   WHERE r.ev_class=pg_catalog.to_regclass('openbot_internal.approval_preferences')
 ),
 'guard',(
   SELECT pg_catalog.jsonb_build_object(
     'schema',n.nspname,'name',p.proname,
     'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),
     'language',l.lanname,'securityDefiner',p.prosecdef,'configuration',p.proconfig,
     'returnType',pg_catalog.format_type(p.prorettype,NULL),
     'definition',pg_catalog.pg_get_functiondef(p.oid))
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   WHERE n.nspname='openbot_internal' AND p.proname='prevent_approval_preference_mutation'
     AND p.pronargs=0
 )
)::text
";

/// Verify the actual server rather than the caller's client encoding or a config label.
pub async fn verify_storage_prerequisites(
    client: &Client,
) -> Result<(), ApprovalPreferenceSchemaError> {
    let row = client
        .query_one(
            "SELECT current_setting('server_encoding'), \
             current_setting('block_size')::integer, \
             current_setting('server_version_num')::integer",
            &[],
        )
        .await
        .map_err(|_| ApprovalPreferenceSchemaError::Unavailable)?;
    let encoding: String = row.try_get(0).map_err(|_| corrupt("server_encoding"))?;
    let page_size: i32 = row.try_get(1).map_err(|_| corrupt("block_size"))?;
    let server_version: i32 = row.try_get(2).map_err(|_| corrupt("server_version"))?;
    if encoding != "UTF8" || page_size != 8192 || !(170_000..180_000).contains(&server_version) {
        return Err(ApprovalPreferenceSchemaError::IncompatibleStorage);
    }
    Ok(())
}

/// Capture live ordered facts; this function never reads its acceptance oracle or writes rows.
pub async fn capture(client: &Client) -> Result<Value, ApprovalPreferenceSchemaError> {
    let raw: String = client
        .query_one(APPROVAL_PREFERENCE_SCHEMA_SQL, &[])
        .await
        .map_err(|_| ApprovalPreferenceSchemaError::Unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("catalog_facts"))?;
    serde_json::from_str(&raw).map_err(|_| corrupt("catalog_facts"))
}

/// Verify a known native prefix and the exact internal schema. No authority is returned.
pub async fn verify(client: &Client) -> Result<(), ApprovalPreferenceSchemaError> {
    verify_storage_prerequisites(client).await?;
    native::validate_known_prefix(client, native::NATIVE_0043_VERSION)
        .await
        .map_err(|_| corrupt("native_prefix"))?;
    let expected: Value =
        serde_json::from_str(REGISTERED_SCHEMA).map_err(|_| corrupt("schema_oracle"))?;
    if capture(client).await? != expected {
        return Err(corrupt("internal_schema"));
    }
    Ok(())
}

const fn corrupt(field: &'static str) -> ApprovalPreferenceSchemaError {
    ApprovalPreferenceSchemaError::Corrupt { field }
}
