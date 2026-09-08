//! Explicit memory 与 memory event repositories（v3 §4.3 条 8–11）。

use time::OffsetDateTime;

use crate::db::InfraError;
use crate::db::tables::memories;
use crate::repo::common::{RepoCore, columns_sql, define_table_repo};

/// `memories` repository；用户删除擦除 content，不暴露 hard-delete 方法。
#[derive(Clone, Debug)]
pub struct MemoryRepo {
    core: RepoCore<memories::Row>,
}

/// 一次 scope/owner-bounded full-text recall 查询。
#[derive(Clone, Debug)]
pub struct MemoryRecallQuery<'a> {
    tenant_id: &'a str,
    owner_user_id: &'a str,
    scope_kind: &'a str,
    scope_id: Option<&'a str>,
    query: &'a str,
    now: OffsetDateTime,
    limit: i64,
}

impl<'a> MemoryRecallQuery<'a> {
    /// 构造有界查询；空文本或 limit 超出 1..=100 当场拒绝。
    pub fn new(
        tenant_id: &'a str,
        owner_user_id: &'a str,
        scope_kind: &'a str,
        scope_id: Option<&'a str>,
        query: &'a str,
        now: OffsetDateTime,
        limit: i64,
    ) -> Result<Self, InfraError> {
        if query.is_empty() || !(1..=100).contains(&limit) {
            return Err(InfraError::repository_invariant("memory_recall_bounds"));
        }
        Ok(Self {
            tenant_id,
            owner_user_id,
            scope_kind,
            scope_id,
            query,
            now,
            limit,
        })
    }
}

impl MemoryRepo {
    /// 用共享池构造。
    #[must_use]
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            core: RepoCore::new(pool),
        }
    }

    /// 插入完整 typed row。
    pub async fn insert(&self, row: &memories::Row) -> Result<memories::Row, InfraError> {
        self.core.insert(row).await
    }

    /// 按 ID 读取。
    pub async fn find_by_id(&self, memory_id: &str) -> Result<Option<memories::Row>, InfraError> {
        self.core.find("\"memory_id\"=$1", &[&memory_id]).await
    }

    /// 管理/迁移面稳定列出全部行；运行时召回必须走 [`MemoryRepo::recall`]。
    pub async fn list_all(&self) -> Result<Vec<memories::Row>, InfraError> {
        self.core
            .list("\"owner_user_id\",\"created_at\",\"memory_id\"")
            .await
    }

    /// 由权威 owner 删除：同一 UPDATE 擦除 content 并写 deleted 状态。
    pub async fn delete_content(
        &self,
        memory_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<memories::Row>, InfraError> {
        let sql = format!(
            "UPDATE public.memories SET status='deleted',content=NULL,updated_at=$3 \
             WHERE memory_id=$1 AND owner_user_id=$2 RETURNING {}",
            columns_sql::<memories::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 MemoryRepo 删除内容获取连接", source))?;
        let row = client
            .query_opt(&sql, &[&memory_id, &owner_user_id, &now])
            .await
            .map_err(|source| InfraError::query("删除 explicit memory 内容", source))?;
        row.as_ref()
            .map(memories::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }
}

impl MemoryRepo {
    /// 只召回同 tenant/owner、active、未过期且 scope 精确匹配的 memory。
    pub async fn recall(
        &self,
        request: &MemoryRecallQuery<'_>,
    ) -> Result<Vec<memories::Row>, InfraError> {
        let sql = format!(
            "SELECT {} FROM public.memories \
             WHERE tenant_id=$1 AND owner_user_id=$2 AND scope_kind=$3 \
               AND scope_id IS NOT DISTINCT FROM $4::text \
               AND status='active' AND content IS NOT NULL \
               AND (expires_at IS NULL OR expires_at>$6) \
               AND to_tsvector('simple',content) @@ plainto_tsquery('simple',$5) \
             ORDER BY created_at DESC,memory_id LIMIT $7",
            columns_sql::<memories::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 MemoryRepo recall 获取连接", source))?;
        let rows = client
            .query(
                &sql,
                &[
                    &request.tenant_id,
                    &request.owner_user_id,
                    &request.scope_kind,
                    &request.scope_id,
                    &request.query,
                    &request.now,
                    &request.limit,
                ],
            )
            .await
            .map_err(|source| InfraError::query("召回 explicit memory", source))?;
        rows.iter()
            .map(memories::Row::try_from)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

define_table_repo!(
    /// `memory_events` repository。
    MemoryEventRepo,
    table = memory_events,
    order_by = "\"memory_id\", \"seq\"",
    find = find_by_key(memory_id: &str, seq: i64) where "\"memory_id\" = $1 AND \"seq\" = $2"
);
