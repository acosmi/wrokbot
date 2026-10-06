//! 已物化成果清理 fence 的只读存储观察。
//!
//! 本模块仅比较原迁移前缀和实际 catalog；不发放当前权限，不创建清理事务，
//! 也不证明字节缺失、目录同步、reader 排空、退款或完整删除完成。

use serde_json::Value;
use tokio_postgres::Client;

use super::native;

/// 封闭错误只携带静态字段，不回显数据库值、连接信息或任意消息。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactCleanupSchemaError {
    /// 实际 PostgreSQL 观察不可取得。
    #[error("artifact_cleanup_schema_unavailable")]
    Unavailable,
    /// 服务端版本、字符编码或物理页大小不满足存储前提。
    #[error("artifact_cleanup_storage_incompatible")]
    IncompatibleStorage,
    /// 有序原迁移前缀或 catalog 与独立冻结的观察不符。
    #[error("artifact_cleanup_schema_corrupt")]
    Corrupt {
        /// 失败观察的静态标识，不包含原行值。
        field: &'static str,
    },
}

// 由 Root 在受控真实 PostgreSQL fresh/upgrade 独立比较后冻结；capture 不读取它。
const REGISTERED_SCHEMA: &str =
    include_str!("../../../../fixtures/db/artifact-cleanup-fences-0044.json");

/// 独立读取实际 catalog 与0044及以前原迁移台账，不从预期 fixture 推导事实。
///
/// FK 同时观察列序、引用关系、真实被引用键、动作及延迟属性；所有额外索引、
/// 用户 trigger/rule、FK 内部执行钩子、已丢弃属性和 guard 的安全属性均进入比较。原终态 CHECK
/// 是 completed 结构判断的依赖，因此其实际定义也被观察。将来的合法原迁移
/// 由 native 前缀校验处理，不改变这个0044观察窗口。
pub const ARTIFACT_CLEANUP_SCHEMA_SQL: &str = r"
SELECT pg_catalog.jsonb_build_object(
 'nativeLedger',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'version',m.version,'name',m.name,'checksum',m.checksum)
       ORDER BY m.version,m.name,m.checksum),'[]'::jsonb)
   FROM openbot_internal.schema_migrations m WHERE m.version<=44
 ),
 'relation',(
   SELECT pg_catalog.jsonb_build_object(
     'schema',n.nspname,'name',c.relname,
     'kind',c.relkind::text,'persistence',c.relpersistence::text,
     'partition',c.relispartition,'rowSecurity',c.relrowsecurity,
     'forceRowSecurity',c.relforcerowsecurity,'accessMethod',am.amname,
     'replicaIdentity',c.relreplident::text,'options',c.reloptions)
   FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
   WHERE n.nspname='openbot_internal' AND c.relname='artifact_cleanup_fences'
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
   WHERE a.attrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
     AND a.attnum>0 AND NOT a.attisdropped
 ),
 'droppedAttributes',(
   SELECT coalesce(pg_catalog.jsonb_agg(a.attnum ORDER BY a.attnum),'[]'::jsonb)
   FROM pg_catalog.pg_attribute a
   WHERE a.attrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
     AND a.attnum>0 AND a.attisdropped
 ),
 'constraints',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',c.conname,'kind',c.contype::text,'validated',c.convalidated,
     'deferrable',c.condeferrable,'deferred',c.condeferred,'noInherit',c.connoinherit,
     'definition',pg_catalog.pg_get_constraintdef(c.oid),
     'columns',(
       SELECT coalesce(pg_catalog.jsonb_agg(a.attname ORDER BY k.ordinal),'[]'::jsonb)
       FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinal)
       JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
     ),
     'reference',(
       SELECT pg_catalog.jsonb_build_object(
         'schema',n.nspname,'relation',r.relname,
         'columns',(
           SELECT coalesce(pg_catalog.jsonb_agg(a.attname ORDER BY k.ordinal),'[]'::jsonb)
           FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinal)
           JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
         ),
         'updateAction',c.confupdtype::text,'deleteAction',c.confdeltype::text,
         'match',c.confmatchtype::text,
         'key',(
           SELECT pg_catalog.jsonb_build_object(
             'name',p.conname,'kind',p.contype::text,'validated',p.convalidated,
             'deferrable',p.condeferrable,'deferred',p.condeferred,
             'definition',pg_catalog.pg_get_constraintdef(p.oid),
             'indexName',ic.relname,'indexPrimary',i.indisprimary,
             'indexUnique',i.indisunique,'indexValid',i.indisvalid,
             'indexReady',i.indisready,'indexImmediate',i.indimmediate,
             'indexDefinition',pg_catalog.pg_get_indexdef(i.indexrelid))
           FROM pg_catalog.pg_constraint p
           JOIN pg_catalog.pg_index i ON i.indexrelid=p.conindid
           JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid
           WHERE p.conrelid=c.confrelid AND p.conindid=c.conindid
             AND p.contype IN ('p','u')
         ))
       FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
       WHERE r.oid=c.confrelid AND c.contype='f'
     )) ORDER BY c.conname),'[]'::jsonb)
   FROM pg_catalog.pg_constraint c
   WHERE c.conrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
     AND c.contype<>'n'
 ),
 'indexes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'schema',n.nspname,'name',c.relname,'accessMethod',am.amname,
     'primary',i.indisprimary,'unique',i.indisunique,'immediate',i.indimmediate,
     'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,
     'keys',i.indkey::text,'keyCount',i.indnkeyatts,'attributeCount',i.indnatts,
     'predicate',pg_catalog.pg_get_expr(i.indpred,i.indrelid),
     'expressions',pg_catalog.pg_get_expr(i.indexprs,i.indrelid),
     'definition',pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY c.relname),'[]'::jsonb)
   FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
   WHERE i.indrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
 ),
 'triggers',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',t.tgname,'enabled',t.tgenabled::text,'type',t.tgtype::integer,
     'deferrable',t.tgdeferrable,'deferred',t.tginitdeferred,
     'definition',pg_catalog.pg_get_triggerdef(t.oid),
     'functionSchema',n.nspname,'functionName',p.proname,
     'functionArguments',pg_catalog.pg_get_function_identity_arguments(p.oid),
     'functionDefinition',pg_catalog.pg_get_functiondef(p.oid))
       ORDER BY t.tgname),'[]'::jsonb)
   FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE t.tgrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
     AND NOT t.tgisinternal
 ),
 'foreignKeyTriggers',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'relationSchema',rn.nspname,'relation',r.relname,
     'constraint',c.conname,'enabled',t.tgenabled::text,'type',t.tgtype::integer,
     'deferrable',t.tgdeferrable,'deferred',t.tginitdeferred,
     'columns',t.tgattr::text,'arguments',pg_catalog.encode(t.tgargs,'hex'),
     'condition',pg_catalog.pg_get_expr(t.tgqual,t.tgrelid),
     'oldTransition',t.tgoldtable,'newTransition',t.tgnewtable,
     'functionSchema',pn.nspname,'functionName',p.proname,
     'functionArguments',pg_catalog.pg_get_function_identity_arguments(p.oid))
       ORDER BY rn.nspname,r.relname,pn.nspname,p.proname,t.tgtype),'[]'::jsonb)
   FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   JOIN pg_catalog.pg_class r ON r.oid=t.tgrelid
   JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace
   JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
   JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
   WHERE c.conrelid=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
     AND c.contype='f' AND t.tgisinternal
 ),
 'rules',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.pg_get_ruledef(r.oid)
     ORDER BY r.rulename),'[]'::jsonb)
   FROM pg_catalog.pg_rewrite r
   WHERE r.ev_class=pg_catalog.to_regclass('openbot_internal.artifact_cleanup_fences')
 ),
 'guard',(
   SELECT pg_catalog.jsonb_build_object(
     'schema',n.nspname,'name',p.proname,
     'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),
     'language',l.lanname,'securityDefiner',p.prosecdef,'configuration',p.proconfig,
     'volatility',p.provolatile::text,'parallel',p.proparallel::text,
     'strict',p.proisstrict,'leakproof',p.proleakproof,
     'returnType',pg_catalog.format_type(p.prorettype,NULL),
     'definition',pg_catalog.pg_get_functiondef(p.oid))
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   WHERE n.nspname='openbot_internal' AND p.proname='prevent_artifact_cleanup_fence_mutation'
     AND p.pronargs=0
 ),
 'terminalConstraints',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'schema',n.nspname,'relation',r.relname,'name',c.conname,'kind',c.contype::text,
     'validated',c.convalidated,'noInherit',c.connoinherit,
     'definition',pg_catalog.pg_get_constraintdef(c.oid))
       ORDER BY r.relname,c.conname),'[]'::jsonb)
   FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
   WHERE n.nspname='openbot_internal'
     AND ((r.relname='artifact_records' AND c.conname='artifact_records_payload')
       OR (r.relname='artifact_save_operations' AND c.conname='artifact_save_operations_payload'))
 )
)::text
";

async fn verify_storage_prerequisites(client: &Client) -> Result<(), ArtifactCleanupSchemaError> {
    let row = client
        .query_one(
            "SELECT pg_catalog.current_setting('server_encoding'), \
             pg_catalog.current_setting('block_size')::integer, \
             pg_catalog.current_setting('server_version_num')::integer",
            &[],
        )
        .await
        .map_err(|_| ArtifactCleanupSchemaError::Unavailable)?;
    let encoding: String = row.try_get(0).map_err(|_| corrupt("server_encoding"))?;
    let page_size: i32 = row.try_get(1).map_err(|_| corrupt("block_size"))?;
    let server_version: i32 = row.try_get(2).map_err(|_| corrupt("server_version"))?;
    if encoding != "UTF8" || page_size != 8192 || !(170_000..180_000).contains(&server_version) {
        return Err(ArtifactCleanupSchemaError::IncompatibleStorage);
    }
    Ok(())
}

/// 捕获原连接上的实际有序事实；不读取验收 oracle，也不写入任何行。
pub async fn capture(client: &Client) -> Result<Value, ArtifactCleanupSchemaError> {
    let raw: String = client
        .query_one(ARTIFACT_CLEANUP_SCHEMA_SQL, &[])
        .await
        .map_err(|_| ArtifactCleanupSchemaError::Unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("catalog_facts"))?;
    serde_json::from_str(&raw).map_err(|_| corrupt("catalog_facts"))
}

/// 核对合法原 native 前缀及独立冻结的内部结构；不返回清理权限或成功凭证。
pub async fn verify(client: &Client) -> Result<(), ArtifactCleanupSchemaError> {
    verify_storage_prerequisites(client).await?;
    native::validate_known_prefix(client, native::NATIVE_0044_VERSION)
        .await
        .map_err(|_| corrupt("native_prefix"))?;
    let expected: Value =
        serde_json::from_str(REGISTERED_SCHEMA).map_err(|_| corrupt("schema_oracle"))?;
    if capture(client).await? != expected {
        return Err(corrupt("internal_schema"));
    }
    Ok(())
}

const fn corrupt(field: &'static str) -> ArtifactCleanupSchemaError {
    ArtifactCleanupSchemaError::Corrupt { field }
}
