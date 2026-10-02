//! Positive history from the original remember transaction. No current business-content join,
//! separate authorization round trip, or write is permitted in this read path.

use openbot_application::{RunEffectReceiptsRequest, ThreadDirectoryError};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::reconciliation::{
    MAX_RUN_RECONCILIATION_PAGE, MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunEffectReceipt,
    RunEffectReceiptFact, RunEffectReceiptsSnapshot, RunReconciliationCursor,
    RunReconciliationStatus, valid_reconciliation_id,
};
use tokio_postgres::Row;

// The integrity scan covers every receipt of the original run before pagination. Historical
// auth_generation is deliberately not compared to the reader's current generation in $6.
const PAGE_QUERY: &str = r"
SELECT v.run_id,v.thread_id,
       CASE WHEN v.status IN ('queued','running','completed','failed','cancelled',
                             'reconciliation_required') THEN v.status END AS run_status,
       i.bad_occupancy,
       EXISTS(SELECT 1 FROM public.thread_run_occupancy slot
              WHERE slot.thread_id=v.thread_id AND slot.run_id=v.run_id) AS foreground_blocked,
       v.terminal_event_seq,statement_timestamp() AS observed_at,
       EXISTS(SELECT 1 FROM public.tool_calls c WHERE c.run_id=v.run_id
              AND (c.actor_id<>v.actor_id OR c.bot_id<>v.bot_id)) AS bad_call_binding,
       EXISTS(SELECT 1 FROM public.run_events e WHERE e.run_id=v.run_id
              AND e.thread_id=v.thread_id AND e.seq=v.terminal_event_seq
              AND e.terminal AND e.event_type='reconciliation_required') AS terminal_valid,
       EXISTS(
         SELECT 1 FROM public.remember_effect_receipts e
         LEFT JOIN public.tool_calls c ON c.tool_call_id=e.tool_call_id
         LEFT JOIN public.tool_attempts a ON a.attempt_id=e.attempt_id
         WHERE e.run_id=v.run_id AND (
           c.tool_call_id IS NULL OR a.attempt_id IS NULL
           OR e.deployment_id IS DISTINCT FROM $4 OR e.tenant_id IS DISTINCT FROM $5
           OR e.thread_id IS DISTINCT FROM v.thread_id
           OR e.actor_id IS DISTINCT FROM v.actor_id OR e.bot_id IS DISTINCT FROM v.bot_id
           OR c.run_id IS DISTINCT FROM e.run_id OR c.actor_id IS DISTINCT FROM e.actor_id
           OR c.bot_id IS DISTINCT FROM e.bot_id OR c.tool_name IS DISTINCT FROM 'remember'
           OR c.call_seq IS DISTINCT FROM e.call_seq
           OR c.decision_id IS DISTINCT FROM e.decision_id
           OR c.args_hash IS DISTINCT FROM e.args_hash
           OR c.schema_hash IS DISTINCT FROM e.schema_hash
           OR c.catalog_generation IS DISTINCT FROM e.catalog_generation
           OR c.target_kind IS DISTINCT FROM e.target_kind
           OR c.target_id IS DISTINCT FROM e.target_id
           OR a.tool_call_id IS DISTINCT FROM e.tool_call_id
           OR a.attempt_seq IS DISTINCT FROM e.attempt_seq
           OR a.capability_id IS DISTINCT FROM e.capability_id
           OR a.commit_state='not_committed'
           OR a.status NOT IN ('decision_recorded','executing','completed',
                               'reconciliation_required','aborted')
           OR coalesce(a.commit_state NOT IN ('committed','unknown','not_committed'),false)
           OR e.auth_generation<0 OR e.call_seq<0 OR e.attempt_seq<0
           OR e.catalog_generation<0 OR e.memory_event_seq<>0
           OR e.target_kind NOT IN ('memory_user','memory_bot','memory_thread')
           OR (e.target_kind='memory_user' AND e.target_id IS DISTINCT FROM e.actor_id)
           OR (e.target_kind='memory_bot' AND e.target_id IS DISTINCT FROM e.bot_id)
           OR (e.target_kind='memory_thread' AND e.target_id IS DISTINCT FROM e.thread_id)
         )
       ) AS bad_receipt_binding,
       x.receipt_id,x.tool_call_id,x.call_sequence,x.attempt_id,x.attempt_sequence,x.recorded_at
FROM visible_run v
JOIN occupancy_integrity i ON i.thread_id=v.thread_id
LEFT JOIN LATERAL (
  SELECT CASE WHEN octet_length(e.receipt_id) BETWEEN 1 AND 512
                    AND e.receipt_id !~ U&'[\0001-\001F\007F-\009F]'
              THEN e.receipt_id END AS receipt_id,
         CASE WHEN octet_length(e.tool_call_id) BETWEEN 1 AND 512
                    AND e.tool_call_id !~ U&'[\0001-\001F\007F-\009F]'
              THEN e.tool_call_id END AS tool_call_id,
         CASE WHEN octet_length(e.attempt_id) BETWEEN 1 AND 512
                    AND e.attempt_id !~ U&'[\0001-\001F\007F-\009F]'
              THEN e.attempt_id END AS attempt_id,
         e.call_seq AS call_sequence,e.attempt_seq AS attempt_sequence,e.recorded_at
  FROM public.remember_effect_receipts e
  WHERE e.run_id=v.run_id AND ($7::bigint IS NULL OR (e.call_seq,e.attempt_seq)>($7,$8))
  ORDER BY e.call_seq,e.attempt_seq LIMIT $9
) x ON true
ORDER BY x.call_sequence,x.attempt_sequence
";

pub(super) async fn read(
    pool: &deadpool_postgres::Pool,
    request: RunEffectReceiptsRequest,
) -> Result<RunEffectReceiptsSnapshot, ThreadDirectoryError> {
    if !ThreadIdentity::is_plausible(&request.thread) {
        return Err(ThreadDirectoryError::InvalidInput { field: "thread_id" });
    }
    if !valid_reconciliation_id(request.run.as_str()) {
        return Err(ThreadDirectoryError::InvalidInput { field: "run_id" });
    }
    if !(1..=MAX_RUN_RECONCILIATION_PAGE).contains(&request.limit) {
        return Err(ThreadDirectoryError::InvalidInput { field: "limit" });
    }
    if request.after.is_some_and(|cursor| !cursor.is_valid()) {
        return Err(ThreadDirectoryError::InvalidInput { field: "after" });
    }
    let generation = i64::try_from(request.auth_generation.get())
        .map_err(|_| ThreadDirectoryError::NotVisible)?;
    let after_call = request.after.map(|cursor| cursor.call_sequence);
    let after_attempt = request.after.map(|cursor| cursor.attempt_sequence);
    let fetch_limit = i64::from(request.limit) + 1;
    let query = format!(
        "{}, occupancy_scope AS (SELECT thread_id FROM visible_run) {} {}",
        super::reconciliation_visibility::VISIBLE_RUN,
        crate::db::occupancy::INTEGRITY_CTE,
        PAGE_QUERY
    );
    let client = pool
        .get()
        .await
        .map_err(|_| ThreadDirectoryError::Unavailable)?;
    let rows = client
        .query(
            &query,
            &[
                &request.thread.as_str(),
                &request.run.as_str(),
                &request.actor.as_str(),
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &generation,
                &after_call,
                &after_attempt,
                &fetch_limit,
            ],
        )
        .await
        .map_err(|_| ThreadDirectoryError::Unavailable)?;
    let first = rows.first().ok_or(ThreadDirectoryError::NotVisible)?;
    if value::<bool>(first, "bad_occupancy")? {
        return Err(corrupt());
    }
    match value::<&str>(first, "run_status")? {
        "reconciliation_required" => {}
        "queued" | "running" | "completed" | "failed" | "cancelled" => {
            return Err(ThreadDirectoryError::RequestConflict);
        }
        _ => return Err(corrupt()),
    }
    if value::<bool>(first, "bad_call_binding")?
        || value::<bool>(first, "bad_receipt_binding")?
        || !value::<bool>(first, "terminal_valid")?
    {
        return Err(corrupt());
    }
    if !valid_reconciliation_id(value(first, "thread_id")?)
        || !valid_reconciliation_id(value(first, "run_id")?)
    {
        return Err(corrupt());
    }
    let terminal_event_sequence =
        u64::try_from(value::<i64>(first, "terminal_event_seq")?).map_err(|_| corrupt())?;
    let mut receipts = Vec::with_capacity(rows.len());
    for row in &rows {
        if value::<Option<i64>>(row, "call_sequence")?.is_none() {
            continue;
        }
        receipts.push(decode_receipt(row)?);
    }
    let limit = usize::try_from(request.limit).map_err(|_| corrupt())?;
    let next = if receipts.len() > limit {
        receipts.truncate(limit);
        receipts.last().map(|receipt| RunReconciliationCursor {
            call_sequence: receipt.call_sequence,
            attempt_sequence: receipt.attempt_sequence,
        })
    } else {
        None
    };
    let snapshot = RunEffectReceiptsSnapshot {
        thread_id: request.thread,
        run_id: request.run,
        status: RunReconciliationStatus::ReconciliationRequired,
        terminal_event_sequence,
        observed_at: value(first, "observed_at")?,
        foreground_blocked: value(first, "foreground_blocked")?,
        receipts,
        next,
        available_actions: [],
    };
    if serde_json::to_vec(&snapshot).map_err(|_| corrupt())?.len()
        > MAX_RUN_RECONCILIATION_RESPONSE_BYTES
    {
        return Err(corrupt());
    }
    Ok(snapshot)
}

fn decode_receipt(row: &Row) -> Result<RunEffectReceipt, ThreadDirectoryError> {
    let receipt = RunEffectReceipt {
        receipt_id: value(row, "receipt_id")?,
        tool_call_id: value(row, "tool_call_id")?,
        call_sequence: value(row, "call_sequence")?,
        attempt_id: value(row, "attempt_id")?,
        attempt_sequence: value(row, "attempt_sequence")?,
        fact: RunEffectReceiptFact::MemoryCreated,
        recorded_at: value(row, "recorded_at")?,
    };
    if !valid_reconciliation_id(&receipt.receipt_id)
        || !valid_reconciliation_id(&receipt.tool_call_id)
        || !valid_reconciliation_id(&receipt.attempt_id)
        || receipt.call_sequence < 0
        || receipt.attempt_sequence < 0
    {
        return Err(corrupt());
    }
    Ok(receipt)
}

fn value<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a Row,
    column: &str,
) -> Result<T, ThreadDirectoryError> {
    row.try_get(column).map_err(|_| corrupt())
}

fn corrupt() -> ThreadDirectoryError {
    ThreadDirectoryError::Corrupt {
        field: "run_effect_receipts",
    }
}
