//! Native run 与 replay event repositories（v3 §4.3）。

use crate::db::tables::{run_events, runs};
use crate::db::{InfraError, RowDecodeError, occupancy};
use crate::repo::common::{columns_sql, define_table_repo, qualified_columns_sql};

define_table_repo!(
    /// `runs` repository。
    RunRepo,
    table = runs,
    order_by = "\"thread_id\", \"created_at\", \"run_id\"",
    find = find_by_id(run_id: &str) where "\"run_id\" = $1"
);

impl RunRepo {
    /// Read the exact projected foreground owner and reject any inconsistent thread projection.
    pub async fn active_foreground_for_thread(
        &self,
        thread_id: &str,
    ) -> Result<Option<runs::Row>, InfraError> {
        let sql = format!(
            "WITH occupancy_scope AS (SELECT $1::text AS thread_id) {}
             SELECT i.bad_occupancy,{} FROM occupancy_integrity i
             LEFT JOIN LATERAL (
               SELECT original.* FROM public.thread_run_occupancy slot
               JOIN public.runs original ON original.run_id=slot.run_id AND original.thread_id=slot.thread_id
               WHERE slot.thread_id=i.thread_id LIMIT 1
             ) r ON true",
            occupancy::INTEGRITY_CTE, qualified_columns_sql::<runs::Row>("r")
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|error| InfraError::connect("为 RunRepo occupancy 获取连接", error))?;
        let row = client
            .query_one(&sql, &[&thread_id])
            .await
            .map_err(|error| InfraError::query("读取 foreground occupancy", error))?;
        let bad: bool = row.try_get("bad_occupancy").map_err(|error| {
            RowDecodeError::column("thread_run_occupancy", "bad_occupancy", error)
        })?;
        if bad {
            return Err(InfraError::repository_invariant(occupancy::INCONSISTENT));
        }
        let id: Option<String> = row
            .try_get("run_id")
            .map_err(|error| RowDecodeError::column("runs", "run_id", error))?;
        if id.is_none() {
            return Ok(None);
        }
        runs::Row::try_from(&row).map(Some).map_err(Into::into)
    }
}

define_table_repo!(
    /// `run_events` repository；本表是 replay 真源，NOTIFY 只作唤醒。
    RunEventRepo,
    table = run_events,
    order_by = "\"thread_id\", \"event_seq\"",
    find = find_by_key(run_id: &str, seq: i64) where "\"run_id\" = $1 AND \"seq\" = $2"
);

impl RunEventRepo {
    /// 从持久化 cursor 之后补取事件，再由 transport 切入 live。
    pub async fn replay_after(
        &self,
        thread_id: &str,
        event_sequence: i64,
        limit: i64,
    ) -> Result<Vec<run_events::Row>, InfraError> {
        if event_sequence < -1 || !(1..=1_000).contains(&limit) {
            return Err(InfraError::repository_invariant("run_event_replay_bounds"));
        }
        let sql = format!(
            "SELECT {} FROM public.run_events \
             WHERE thread_id=$1 AND event_seq>$2 \
             ORDER BY event_seq LIMIT $3",
            columns_sql::<run_events::Row>()
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 RunEventRepo replay 获取连接", source))?;
        let rows = client
            .query(&sql, &[&thread_id, &event_sequence, &limit])
            .await
            .map_err(|source| InfraError::query("补取 thread run events", source))?;
        rows.iter()
            .map(run_events::Row::try_from)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}
