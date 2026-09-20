//! At-least-once、仅 replay-safe destination 的 outbox repository（v3 §4.3 条 3/5）。

use time::OffsetDateTime;

use crate::db::InfraError;
use crate::db::tables::outbox;
use crate::repo::common::{columns_sql, define_table_repo, qualified_columns_sql};

define_table_repo!(
    /// `outbox` repository。
    OutboxRepo,
    table = outbox,
    order_by = "\"aggregate_id\", \"seq\", \"destination\"",
    find = find_by_id(outbox_id: &str) where "\"outbox_id\" = $1"
);

impl OutboxRepo {
    /// 原子 claim 一条 ready/租约过期记录；`SKIP LOCKED` 允许多 relay 并行。
    pub async fn claim_ready(
        &self,
        worker: &str,
        now: OffsetDateTime,
        claim_expires_at: OffsetDateTime,
    ) -> Result<Option<outbox::Row>, InfraError> {
        if worker.is_empty() || claim_expires_at <= now {
            return Err(InfraError::repository_invariant(
                "outbox_claim_input_invalid",
            ));
        }
        let sql = format!(
            "WITH candidate AS ( \
               SELECT outbox_id FROM public.outbox \
               WHERE (status='pending' AND available_at<=$2) \
                  OR (status='delivering' AND claim_expires_at<=$2) \
               ORDER BY available_at,outbox_id \
               FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) \
             UPDATE public.outbox o SET \
               status='delivering',claimed_by=$1,claim_expires_at=$3, \
               attempt_count=o.attempt_count+1,updated_at=$2 \
             FROM candidate c WHERE o.outbox_id=c.outbox_id \
             RETURNING {}",
            qualified_columns_sql::<outbox::Row>("o")
        );
        let mut client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 OutboxRepo claim 获取连接", source))?;
        let transaction = client
            .transaction()
            .await
            .map_err(|source| InfraError::query("开始 outbox claim 事务", source))?;
        let row = transaction
            .query_opt(&sql, &[&worker, &now, &claim_expires_at])
            .await
            .map_err(|source| InfraError::query("claim outbox", source))?;
        transaction
            .commit()
            .await
            .map_err(|source| InfraError::query("提交 outbox claim", source))?;
        row.as_ref()
            .map(outbox::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }

    /// 只有持有当前 claim 的 worker 能确认投递。
    pub async fn mark_delivered(
        &self,
        outbox_id: &str,
        worker: &str,
        now: OffsetDateTime,
    ) -> Result<Option<outbox::Row>, InfraError> {
        let sql = format!(
            "UPDATE public.outbox SET status='delivered',delivered_at=$3,updated_at=$3, \
             claimed_by=NULL,claim_expires_at=NULL \
             WHERE outbox_id=$1 AND status='delivering' AND claimed_by=$2 \
             RETURNING {}",
            columns_sql::<outbox::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 OutboxRepo 确认投递获取连接", source))?;
        let row = client
            .query_opt(&sql, &[&outbox_id, &worker, &now])
            .await
            .map_err(|source| InfraError::query("确认 outbox 投递", source))?;
        row.as_ref()
            .map(outbox::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }
}
