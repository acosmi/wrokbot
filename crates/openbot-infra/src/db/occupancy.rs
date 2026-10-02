//! R409: one static read-only integrity predicate for all occupancy consumers.
//! Callers supply `occupancy_scope(thread_id)` alongside visibility in the same statement.

use tokio_postgres::Transaction;

use super::{InfraError, RowDecodeError};

pub(crate) const INTEGRITY_CTE: &str = r"
, occupancy_integrity AS (
  SELECT scope.thread_id,
    (EXISTS (
       SELECT 1 FROM public.runs expected
       WHERE expected.thread_id=scope.thread_id AND expected.foreground
         AND expected.status IN ('queued','running','reconciliation_required')
         AND NOT EXISTS (SELECT 1 FROM public.thread_run_occupancy actual
                         WHERE actual.thread_id=expected.thread_id AND actual.run_id=expected.run_id)
     ) OR EXISTS (
       SELECT 1 FROM public.thread_run_occupancy actual
       LEFT JOIN public.runs original ON original.run_id=actual.run_id
       WHERE (actual.thread_id=scope.thread_id OR original.thread_id=scope.thread_id)
         AND (original.run_id IS NULL OR original.thread_id IS DISTINCT FROM actual.thread_id
              OR (original.foreground AND original.status IN ('queued','running','reconciliation_required'))
                  IS DISTINCT FROM true)
     ) OR (SELECT count(*) FROM public.thread_run_occupancy actual
           WHERE actual.thread_id=scope.thread_id)>1) AS bad_occupancy
  FROM occupancy_scope scope
)
";

pub(crate) const INCONSISTENT: &str = "thread_run_occupancy_inconsistent";

#[cfg(feature = "server-runtime")]
pub(crate) async fn thread_is_occupied(
    transaction: &Transaction<'_>,
    thread_id: &str,
) -> Result<bool, InfraError> {
    let sql = format!(
        "WITH occupancy_scope AS (SELECT $1::text AS thread_id) {INTEGRITY_CTE}
         SELECT bad_occupancy,EXISTS(SELECT 1 FROM public.thread_run_occupancy WHERE thread_id=$1) AS occupied
         FROM occupancy_integrity"
    );
    let row = transaction
        .query_one(&sql, &[&thread_id])
        .await
        .map_err(|error| InfraError::query("核验 thread occupancy", error))?;
    let bad: bool = row
        .try_get("bad_occupancy")
        .map_err(|error| RowDecodeError::column("thread_run_occupancy", "bad_occupancy", error))?;
    if bad {
        return Err(InfraError::repository_invariant(INCONSISTENT));
    }
    row.try_get("occupied")
        .map_err(|error| RowDecodeError::column("thread_run_occupancy", "occupied", error).into())
}

pub(crate) async fn validate_all(transaction: &Transaction<'_>) -> Result<(), InfraError> {
    let sql = format!(
        "WITH occupancy_scope AS (
           SELECT thread_id FROM public.runs UNION SELECT thread_id FROM public.thread_run_occupancy
         ) {INTEGRITY_CTE}
         SELECT EXISTS(SELECT 1 FROM occupancy_integrity WHERE bad_occupancy)"
    );
    let bad: bool = transaction
        .query_one(&sql, &[])
        .await
        .map_err(|error| InfraError::query("核验已迁移 occupancy projection", error))?
        .try_get(0)
        .map_err(|error| RowDecodeError::column("thread_run_occupancy", "bad_occupancy", error))?;
    if bad {
        return Err(InfraError::repository_invariant(INCONSISTENT));
    }
    Ok(())
}
