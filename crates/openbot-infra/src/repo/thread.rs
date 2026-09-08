//! Native thread/message/membership/lease repositories（v3 §4.3）。

use time::OffsetDateTime;

use crate::db::InfraError;
use crate::db::tables::{messages, thread_leases, threads};
use crate::repo::common::{RepoCore, columns_sql, define_table_repo};

/// `threads` repository；用户删除只走 [`ThreadRepo::soft_delete`]。
#[derive(Clone, Debug)]
pub struct ThreadRepo {
    core: RepoCore<threads::Row>,
}

impl ThreadRepo {
    /// 用共享池构造。
    #[must_use]
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            core: RepoCore::new(pool),
        }
    }

    /// 插入完整 typed row。
    pub async fn insert(&self, row: &threads::Row) -> Result<threads::Row, InfraError> {
        self.core.insert(row).await
    }

    /// 按 ID 读取。
    pub async fn find_by_id(&self, thread_id: &str) -> Result<Option<threads::Row>, InfraError> {
        self.core.find("\"thread_id\"=$1", &[&thread_id]).await
    }

    /// 稳定列出全部行；管理/迁移面使用，运行时必须另加 membership predicate。
    pub async fn list_all(&self) -> Result<Vec<threads::Row>, InfraError> {
        self.core.list("\"thread_id\"").await
    }

    /// 软删除；deleted_at 首次写入后保持不变，重复调用幂等返回现行行。
    pub async fn soft_delete(
        &self,
        thread_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<threads::Row>, InfraError> {
        let sql = format!(
            "UPDATE public.threads SET status='deleted', \
             deleted_at=coalesce(deleted_at,$2),updated_at=CASE \
               WHEN status='deleted' THEN updated_at ELSE $2 END \
             WHERE thread_id=$1 RETURNING {}",
            columns_sql::<threads::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 ThreadRepo 软删除获取连接", source))?;
        let row = client
            .query_opt(&sql, &[&thread_id, &now])
            .await
            .map_err(|source| InfraError::query("软删除 thread", source))?;
        row.as_ref()
            .map(threads::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }
}

define_table_repo!(
    /// `thread_memberships` repository；缺行即无访问权。
    ThreadMembershipRepo,
    table = thread_memberships,
    order_by = "\"thread_id\", \"user_id\"",
    find = find_by_key(thread_id: &str, user_id: &str) where "\"thread_id\" = $1 AND \"user_id\" = $2"
);

define_table_repo!(
    /// `messages` repository。
    MessageRepo,
    table = messages,
    order_by = "\"thread_id\", \"seq\"",
    find = find_by_id(message_id: &str) where "\"message_id\" = $1"
);

impl MessageRepo {
    /// 按 thread sequence 补取 message；游标本身不扩大 thread 可见性。
    pub async fn list_after(
        &self,
        thread_id: &str,
        sequence: i64,
        limit: i64,
    ) -> Result<Vec<messages::Row>, InfraError> {
        if sequence < -1 || !(1..=1_000).contains(&limit) {
            return Err(InfraError::repository_invariant("message_replay_bounds"));
        }
        let sql = format!(
            "SELECT {} FROM public.messages \
             WHERE thread_id=$1 AND seq>$2 ORDER BY seq LIMIT $3",
            columns_sql::<messages::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 MessageRepo replay 获取连接", source))?;
        let rows = client
            .query(&sql, &[&thread_id, &sequence, &limit])
            .await
            .map_err(|source| InfraError::query("补取 thread messages", source))?;
        rows.iter()
            .map(messages::Row::try_from)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

define_table_repo!(
    /// `thread_leases` repository；生产写入使用 [`ThreadLeaseRepo::acquire_or_renew`]。
    ThreadLeaseRepo,
    table = thread_leases,
    order_by = "\"thread_id\"",
    find = find_by_thread(thread_id: &str) where "\"thread_id\" = $1"
);

impl ThreadLeaseRepo {
    /// 原子获取、同 owner 续租或接管过期租约。
    ///
    /// 活租约属于别人时返回 `None`。过期接管一定推进 fencing token；到 `i64::MAX` 后拒绝
    /// 接管而不回绕。相同 owner 在未过期时只续 expiry，不推进 token。
    pub async fn acquire_or_renew(
        &self,
        thread_id: &str,
        owner_id: &str,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Option<thread_leases::Row>, InfraError> {
        if owner_id.is_empty() || expires_at <= now {
            return Err(InfraError::repository_invariant(
                "thread_lease_input_invalid",
            ));
        }
        let sql = format!(
            "INSERT INTO public.thread_leases(\
               thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at) \
             VALUES($1,$2,1,$3,$4,$3) \
             ON CONFLICT(thread_id) DO UPDATE SET \
               owner_id=excluded.owner_id, \
               fencing_token=CASE \
                 WHEN thread_leases.expires_at <= $3 THEN thread_leases.fencing_token + 1 \
                 ELSE thread_leases.fencing_token END, \
               acquired_at=CASE \
                 WHEN thread_leases.expires_at <= $3 THEN $3 ELSE thread_leases.acquired_at END, \
               expires_at=$4,updated_at=$3 \
             WHERE (thread_leases.owner_id=$2 AND thread_leases.expires_at>$3) \
                OR (thread_leases.expires_at<=$3 AND thread_leases.fencing_token<9223372036854775807) \
             RETURNING {}",
            columns_sql::<thread_leases::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 ThreadLeaseRepo 获取连接", source))?;
        let row = client
            .query_opt(&sql, &[&thread_id, &owner_id, &now, &expires_at])
            .await
            .map_err(|source| InfraError::query("获取或续租 thread lease", source))?;
        row.as_ref()
            .map(thread_leases::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }
}
