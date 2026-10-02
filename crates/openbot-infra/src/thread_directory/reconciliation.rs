//! Bounded, current-authority reconciliation readback. One statement is the visibility and data
//! snapshot; this module never changes the original run, attempt, foreground occupancy or audit.

use openbot_application::{RunReconciliationRequest, ThreadDirectoryError};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::reconciliation::{
    MAX_RUN_RECONCILIATION_PAGE, MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunReconciliationAttempt,
    RunReconciliationAttemptStatus, RunReconciliationCommitState, RunReconciliationCursor,
    RunReconciliationSnapshot, RunReconciliationStatus, valid_reconciliation_id,
};
use tokio_postgres::Row;

// Do not borrow the execution-authority predicate: a terminal run has no live worker lease.
// Project no business payload or arbitrary error text, including into the database client.
const PAGE_QUERY: &str = r"
SELECT v.run_id,v.thread_id,
       CASE WHEN v.status IN ('queued','running','completed','failed','cancelled',
                             'reconciliation_required') THEN v.status END AS run_status,
       v.foreground,v.terminal_event_seq,
       statement_timestamp() AS observed_at,
       EXISTS(SELECT 1 FROM public.tool_calls c WHERE c.run_id=v.run_id
              AND (c.actor_id<>v.actor_id OR c.bot_id<>v.bot_id)) AS bad_binding,
       EXISTS(SELECT 1 FROM public.run_events e WHERE e.run_id=v.run_id
              AND e.thread_id=v.thread_id AND e.seq=v.terminal_event_seq
              AND e.terminal AND e.event_type='reconciliation_required') AS terminal_valid,
       a.call_sequence,a.attempt_sequence,a.tool_call_id,a.attempt_id,a.attempt_status,
       a.commit_state,a.created_at,a.started_at,a.finished_at,a.bad_shape
FROM visible_run v
LEFT JOIN LATERAL (
  SELECT c.call_seq AS call_sequence,t.attempt_seq AS attempt_sequence,
         CASE WHEN octet_length(c.tool_call_id) BETWEEN 1 AND 512
                   AND c.tool_call_id !~ U&'[\0001-\001F\007F-\009F]'
              THEN c.tool_call_id END AS tool_call_id,
         CASE WHEN octet_length(t.attempt_id) BETWEEN 1 AND 512
                   AND t.attempt_id !~ U&'[\0001-\001F\007F-\009F]'
              THEN t.attempt_id END AS attempt_id,
         CASE WHEN t.status IN ('decision_recorded','executing','completed',
                                'reconciliation_required','aborted')
              THEN t.status END AS attempt_status,
         CASE WHEN t.commit_state IN ('committed','not_committed','unknown')
              THEN t.commit_state END AS commit_state,
         t.created_at,t.started_at,t.finished_at,
         (octet_length(c.tool_call_id) NOT BETWEEN 1 AND 512
          OR octet_length(t.attempt_id) NOT BETWEEN 1 AND 512
          OR c.tool_call_id ~ U&'[\0001-\001F\007F-\009F]'
          OR t.attempt_id ~ U&'[\0001-\001F\007F-\009F]'
          OR t.status NOT IN ('decision_recorded','executing','completed',
                             'reconciliation_required','aborted')
          OR coalesce(t.commit_state NOT IN ('committed','not_committed','unknown'),false)) AS bad_shape
  FROM public.tool_calls c
  JOIN public.tool_attempts t ON t.tool_call_id=c.tool_call_id
  WHERE c.run_id=v.run_id
    AND ($7::bigint IS NULL OR (c.call_seq,t.attempt_seq)>($7,$8))
  ORDER BY c.call_seq,t.attempt_seq LIMIT $9
) a ON true
ORDER BY a.call_sequence,a.attempt_sequence
";

pub(super) async fn read(
    pool: &deadpool_postgres::Pool,
    request: RunReconciliationRequest,
) -> Result<RunReconciliationSnapshot, ThreadDirectoryError> {
    if !ThreadIdentity::is_plausible(&request.thread) {
        return Err(ThreadDirectoryError::InvalidInput { field: "thread_id" });
    }
    if !valid_reconciliation_id(request.run.as_str()) {
        return Err(ThreadDirectoryError::InvalidInput { field: "run_id" });
    }
    if !(1..=MAX_RUN_RECONCILIATION_PAGE).contains(&request.limit) {
        return Err(ThreadDirectoryError::InvalidInput { field: "limit" });
    }
    if request
        .after
        .as_ref()
        .is_some_and(|cursor| cursor.call_sequence < 0 || cursor.attempt_sequence < 0)
    {
        return Err(ThreadDirectoryError::InvalidInput { field: "after" });
    }
    let generation = i64::try_from(request.auth_generation.get())
        .map_err(|_| ThreadDirectoryError::NotVisible)?;
    let after_call = request.after.as_ref().map(|cursor| cursor.call_sequence);
    let after_attempt = request.after.as_ref().map(|cursor| cursor.attempt_sequence);
    let fetch_limit = i64::from(request.limit) + 1;
    let client = pool
        .get()
        .await
        .map_err(|_| ThreadDirectoryError::Unavailable)?;
    let query = format!(
        "{}{}",
        super::reconciliation_visibility::VISIBLE_RUN,
        PAGE_QUERY
    );
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
    let status: &str = value(first, "run_status")?;
    match status {
        "reconciliation_required" => {}
        "queued" | "running" | "completed" | "failed" | "cancelled" => {
            return Err(ThreadDirectoryError::RequestConflict);
        }
        _ => return Err(corrupt()),
    }
    if value::<bool>(first, "bad_binding")? || !value::<bool>(first, "terminal_valid")? {
        return Err(corrupt());
    }
    let thread_id: &str = value(first, "thread_id")?;
    let run_id: &str = value(first, "run_id")?;
    if !valid_reconciliation_id(thread_id) || !valid_reconciliation_id(run_id) {
        return Err(corrupt());
    }
    let terminal_event_sequence =
        u64::try_from(value::<i64>(first, "terminal_event_seq")?).map_err(|_| corrupt())?;
    let mut attempts = Vec::with_capacity(rows.len());
    for row in &rows {
        if value::<Option<i64>>(row, "call_sequence")?.is_none() {
            continue;
        }
        attempts.push(decode_attempt(row)?);
    }
    let limit = usize::try_from(request.limit).map_err(|_| corrupt())?;
    let next = if attempts.len() > limit {
        attempts.truncate(limit);
        attempts.last().map(|attempt| RunReconciliationCursor {
            call_sequence: attempt.call_sequence,
            attempt_sequence: attempt.attempt_sequence,
        })
    } else {
        None
    };
    let snapshot = RunReconciliationSnapshot {
        thread_id: request.thread,
        run_id: request.run,
        status: RunReconciliationStatus::ReconciliationRequired,
        terminal_event_sequence,
        observed_at: value(first, "observed_at")?,
        foreground_blocked: value(first, "foreground")?,
        attempts,
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

fn decode_attempt(row: &Row) -> Result<RunReconciliationAttempt, ThreadDirectoryError> {
    if value::<bool>(row, "bad_shape")? {
        return Err(corrupt());
    }
    let tool_call_id: String = value(row, "tool_call_id")?;
    let attempt_id: String = value(row, "attempt_id")?;
    let call_sequence = value::<i64>(row, "call_sequence")?;
    let attempt_sequence = value::<i64>(row, "attempt_sequence")?;
    if !valid_reconciliation_id(&tool_call_id)
        || !valid_reconciliation_id(&attempt_id)
        || call_sequence < 0
        || attempt_sequence < 0
    {
        return Err(corrupt());
    }
    let status = match value::<&str>(row, "attempt_status")? {
        "decision_recorded" => RunReconciliationAttemptStatus::DecisionRecorded,
        "executing" => RunReconciliationAttemptStatus::Executing,
        "completed" => RunReconciliationAttemptStatus::Completed,
        "reconciliation_required" => RunReconciliationAttemptStatus::ReconciliationRequired,
        "aborted" => RunReconciliationAttemptStatus::Aborted,
        _ => return Err(corrupt()),
    };
    let recorded_commit_state = match value::<Option<&str>>(row, "commit_state")? {
        None => None,
        Some("committed") => Some(RunReconciliationCommitState::Committed),
        Some("not_committed") => Some(RunReconciliationCommitState::NotCommitted),
        Some("unknown") => Some(RunReconciliationCommitState::Unknown),
        Some(_) => return Err(corrupt()),
    };
    Ok(RunReconciliationAttempt {
        tool_call_id,
        call_sequence,
        attempt_id,
        attempt_sequence,
        status,
        recorded_commit_state,
        created_at: value(row, "created_at")?,
        started_at: value(row, "started_at")?,
        finished_at: value(row, "finished_at")?,
    })
}

fn value<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a Row,
    column: &str,
) -> Result<T, ThreadDirectoryError> {
    row.try_get(column).map_err(|_| corrupt())
}

fn corrupt() -> ThreadDirectoryError {
    ThreadDirectoryError::Corrupt {
        field: "run_reconciliation",
    }
}
