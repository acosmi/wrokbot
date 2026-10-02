//! V6-PR-076 J17–J23: real application/journal/runtime journeys on an owned PostgreSQL database.
//! Terminal rows are committed exclusively through PostgresRunRuntime. No index, constraint,
//! trigger or production isolation setting is weakened to manufacture a terminal race.

#[path = "tool_journal_journey/agent.rs"]
mod agent;
mod harness;
#[path = "tool_journal_journey/support.rs"]
mod support;

use core::time::Duration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    ProviderUsage, RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel, RunTerminal,
    RunToolExchange, RunWriteReceipt, ThreadDirectory, ThreadDirectoryError, ToolPortError,
    invoke_tool,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ToolCallId;
use serde_json::json;
use support::{Fixture, Stage, snapshot, wait_for};

fn terminals() -> [RunTerminal; 4] {
    [
        RunTerminal::Completed,
        RunTerminal::Failed(RunFailureCode::ProviderGenerationFailed),
        RunTerminal::Cancelled,
        RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
    ]
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn terminal_before_application_decision_never_executes() {
    application_at_stage(Stage::Decision).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn terminal_after_decision_before_capability_never_executes() {
    application_at_stage(Stage::Attach).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn terminal_after_effect_before_outcome_returns_unaccepted_reconciliation_once() {
    application_at_stage(Stage::Outcome).await;
}

async fn application_at_stage(stage: Stage) {
    let admin = admin_config("application_journal_terminal_journey");
    for terminal in terminals() {
        with_temp_database(&admin, "journaljourney", |config| async move {
            let fixture = Fixture::new(&config).await?;
            let control = fixture.control();
            let journal = fixture.journal(stage)?;
            let gate = journal.gate.clone();
            let auth = fixture.auth();
            let invocation = fixture.invocation();
            let executing_control = control.clone();
            let mut task = tokio::spawn(async move {
                invoke_tool(&executing_control, &journal, &auth, invocation).await
            });

            let result = async {
                wait_for(&gate.entered).await?;
                let expected_executions = usize::from(stage == Stage::Outcome);
                if control.executions() != expected_executions {
                    return Err(format!("{stage:?}: wrong executor count at pause"));
                }
                assert_paused_stage(&fixture, stage).await?;
                let original = fixture
                    .terminal_writer()?
                    .finish_run(&fixture.lease, 1, terminal)
                    .await
                    .map_err(|error| format!("real terminal commit: {error}"))?;
                if original.replayed {
                    return Err("terminal fixture must be a real first commit".to_owned());
                }

                // Completed/Cancelled admit a new legitimate foreground writer. The suspended
                // old journal resumes only AFTER that new lease is established and renewed.
                let successor =
                    if matches!(terminal, RunTerminal::Completed | RunTerminal::Cancelled) {
                        Some(fixture.begin_successor().await?)
                    } else {
                        None
                    };
                let before_resume = snapshot(&fixture.pool).await?;
                gate.resume.add_permits(1);
                let observed = tokio::time::timeout(Duration::from_secs(5), &mut task)
                    .await
                    .map_err(|_| {
                        "application did not finish after releasing the journal barrier".to_owned()
                    })?
                    .map_err(|error| format!("application task: {error}"))?;
                let expected = match stage {
                    Stage::Decision | Stage::Attach => AppError::DependencyUnavailable {
                        dependency: "tool_runtime",
                    },
                    Stage::Outcome => AppError::ReconciliationRequired { accepted: false },
                };
                if observed.as_ref().err() != Some(&expected) {
                    return Err(format!(
                        "{stage:?}/{terminal:?}: wrong application result {observed:?}"
                    ));
                }
                if *gate
                    .last_result
                    .lock()
                    .map_err(|_| "journal observation poisoned")?
                    != Some(Err(ToolPortError::Conflict))
                {
                    return Err(format!(
                        "{stage:?}/{terminal:?}: real journal did not reject with Conflict"
                    ));
                }
                if control.executions() != expected_executions {
                    return Err(format!(
                        "{stage:?}: executor repeated or started after terminal"
                    ));
                }
                if snapshot(&fixture.pool).await? != before_resume {
                    return Err(format!(
                        "{stage:?}/{terminal:?}: rejected journal mutated durable state"
                    ));
                }
                assert_paused_stage(&fixture, stage).await?;

                // These are the old worker's real runtime methods, not SQL stand-ins. In the
                // successor cases they must not expire, delete or rewrite its new active lease.
                let late_exchange = exchange("late-result")?;
                expect_runtime_error(
                    fixture
                        .runtime
                        .append_semantic_chunk(&fixture.lease, 2, RunSemanticChannel::Text, "late")
                        .await,
                    RunRuntimeError::Conflict,
                )?;
                expect_runtime_error(
                    fixture
                        .runtime
                        .append_tool_exchange(&fixture.lease, 2, &late_exchange)
                        .await,
                    RunRuntimeError::Conflict,
                )?;
                expect_runtime_error(
                    fixture.runtime.renew_lease(&fixture.lease).await,
                    RunRuntimeError::StaleLease,
                )?;
                expect_runtime_error(
                    fixture
                        .runtime
                        .record_provider_usage(&fixture.lease, 0, usage(), None, None, None)
                        .await,
                    RunRuntimeError::StaleLease,
                )?;
                expect_runtime_error(
                    fixture
                        .runtime
                        .finish_run(&fixture.lease, 1, different_terminal(terminal))
                        .await,
                    RunRuntimeError::Conflict,
                )?;
                let replay = fixture
                    .runtime
                    .finish_run(&fixture.lease, 1, terminal)
                    .await
                    .map_err(|error| error.to_string())?;
                expect_replay(replay, original)?;
                if snapshot(&fixture.pool).await? != before_resume {
                    return Err(
                        "old runtime refusal/replay mutated old terminal or new lease".to_owned(),
                    );
                }
                if let Some(lease) = successor {
                    // A successful write by the legitimate successor also proves the lease was
                    // not secretly expired by a late old-worker cleanup.
                    fixture
                        .fresh_runtime()?
                        .append_semantic_chunk(
                            &lease,
                            1,
                            RunSemanticChannel::Text,
                            "new writer still owns lease",
                        )
                        .await
                        .map_err(|error| {
                            format!("successor lost authority to old worker: {error}")
                        })?;
                }
                Ok(())
            }
            .await;
            if !task.is_finished() {
                task.abort();
                let _ = task.await;
            }
            result
        })
        .await;
    }
}

async fn assert_paused_stage(fixture: &Fixture, stage: Stage) -> Result<(), String> {
    let client = fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?;
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM public.tool_calls) AS calls,
                (SELECT count(*) FROM public.tool_attempts) AS attempts,
                (SELECT count(*) FROM public.audit_events) AS audits",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    let expected = i64::from(stage != Stage::Decision);
    if row.get::<_, i64>("calls") != expected
        || row.get::<_, i64>("attempts") != expected
        || row.get::<_, i64>("audits") != 0
    {
        return Err(format!("{stage:?}: unexpected call/attempt/audit counts"));
    }
    if stage != Stage::Decision {
        let attempt = client
            .query_one(
                "SELECT status,capability_id,commit_state,finished_at FROM public.tool_attempts",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        let expected_status = if stage == Stage::Attach {
            "decision_recorded"
        } else {
            "executing"
        };
        if attempt.get::<_, &str>("status") != expected_status
            || attempt.get::<_, Option<String>>("capability_id").is_some()
                != (stage == Stage::Outcome)
            || attempt.get::<_, Option<String>>("commit_state").is_some()
            || attempt
                .get::<_, Option<time::OffsetDateTime>>("finished_at")
                .is_some()
        {
            return Err(format!("{stage:?}: rejected journal advanced the attempt"));
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn builtin_worker_late_outcome_stops_before_second_tool_and_sampling() {
    let admin = admin_config("builtin_worker_late_outcome_stops_before_second_tool_and_sampling");
    with_temp_database(&admin, "journalagent", |config| async move {
        agent::journey(&config).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn terminal_runtime_rejects_new_writes_but_replays_exact_history_without_mutation() {
    let admin = admin_config(
        "terminal_runtime_rejects_new_writes_but_replays_exact_history_without_mutation",
    );
    for terminal in terminals() {
        with_temp_database(&admin, "journalreplay", |config| async move {
            let fixture = Fixture::new(&config).await?;
            let original_exchange = exchange("original-redacted-result")?;
            let chunk = fixture
                .runtime
                .append_semantic_chunk(&fixture.lease, 1, RunSemanticChannel::Text, "original text")
                .await
                .map_err(|error| error.to_string())?;
            let pair = fixture
                .runtime
                .append_tool_exchange(&fixture.lease, 2, &original_exchange)
                .await
                .map_err(|error| error.to_string())?;
            fixture
                .runtime
                .record_provider_usage(&fixture.lease, 0, usage(), None, None, None)
                .await
                .map_err(|error| error.to_string())?;
            let finished = fixture
                .terminal_writer()?
                .finish_run(&fixture.lease, 3, terminal)
                .await
                .map_err(|error| error.to_string())?;
            if chunk.replayed || pair.replayed || finished.replayed {
                return Err("runtime fixture must create real new events".to_owned());
            }
            let history = History {
                chunk,
                pair,
                finished,
                exchange: original_exchange,
                terminal,
            };
            probe_terminal_runtime(&fixture, &history).await?;
            if matches!(terminal, RunTerminal::Completed | RunTerminal::Cancelled) {
                let successor = fixture.begin_successor().await?;
                probe_terminal_runtime(&fixture, &history).await?;
                fixture
                    .fresh_runtime()?
                    .append_semantic_chunk(
                        &successor,
                        1,
                        RunSemanticChannel::Text,
                        "successor write",
                    )
                    .await
                    .map_err(|error| {
                        format!("old history replay invalidated successor lease: {error}")
                    })?;
            }
            Ok(())
        })
        .await;
    }
}

struct History {
    chunk: RunWriteReceipt,
    pair: RunWriteReceipt,
    finished: RunWriteReceipt,
    exchange: RunToolExchange,
    terminal: RunTerminal,
}

async fn probe_terminal_runtime(fixture: &Fixture, history: &History) -> Result<(), String> {
    let before = snapshot(&fixture.pool).await?;
    expect_replay(
        fixture
            .runtime
            .append_semantic_chunk(&fixture.lease, 1, RunSemanticChannel::Text, "original text")
            .await
            .map_err(|error| error.to_string())?,
        history.chunk,
    )?;
    expect_replay(
        fixture
            .runtime
            .append_tool_exchange(&fixture.lease, 2, &history.exchange)
            .await
            .map_err(|error| error.to_string())?,
        history.pair,
    )?;
    expect_replay(
        fixture
            .runtime
            .finish_run(&fixture.lease, 3, history.terminal)
            .await
            .map_err(|error| error.to_string())?,
        history.finished,
    )?;
    if snapshot(&fixture.pool).await? != before {
        return Err(
            "exact historical chunk/exchange/terminal replay performed a mutation".to_owned(),
        );
    }

    let mismatch = exchange("different-result")?;
    for sequence in [1, 4] {
        expect_runtime_error(
            fixture
                .runtime
                .append_semantic_chunk(
                    &fixture.lease,
                    sequence,
                    RunSemanticChannel::Text,
                    "different text",
                )
                .await,
            RunRuntimeError::Conflict,
        )?;
    }
    for sequence in [2, 4] {
        expect_runtime_error(
            fixture
                .runtime
                .append_tool_exchange(&fixture.lease, sequence, &mismatch)
                .await,
            RunRuntimeError::Conflict,
        )?;
    }
    // Even identical previously committed usage is not promoted to a post-terminal replay.
    for sampling in [0, 1] {
        expect_runtime_error(
            fixture
                .runtime
                .record_provider_usage(&fixture.lease, sampling, usage(), None, None, None)
                .await,
            RunRuntimeError::StaleLease,
        )?;
    }
    expect_runtime_error(
        fixture.runtime.renew_lease(&fixture.lease).await,
        RunRuntimeError::StaleLease,
    )?;
    for sequence in [3, 4] {
        expect_runtime_error(
            fixture
                .runtime
                .finish_run(
                    &fixture.lease,
                    sequence,
                    different_terminal(history.terminal),
                )
                .await,
            RunRuntimeError::Conflict,
        )?;
    }
    if snapshot(&fixture.pool).await? != before {
        return Err(
            "post-terminal runtime refusal mutated history/usage/lease/outbox/audit".to_owned(),
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL; set OPENBOT_TEST_DATABASE_URL and use --include-ignored"]
async fn fresh_runtime_cannot_admit_a_successor_while_reconciliation_remains_foreground() {
    let admin = admin_config(
        "fresh_runtime_cannot_admit_a_successor_while_reconciliation_remains_foreground",
    );
    with_temp_database(&admin, "journalrr", |config| async move {
        let fixture = Fixture::new(&config).await?;
        let terminal = RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown);
        let original = fixture
            .terminal_writer()?
            .finish_run(&fixture.lease, 1, terminal)
            .await
            .map_err(|error| error.to_string())?;
        let before = snapshot(&fixture.pool).await?;
        let restarted = fixture.fresh_runtime()?;
        if restarted
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("terminal run was dispatched to a fresh runtime".to_owned());
        }
        expect_replay(
            restarted
                .finish_run(&fixture.lease, 1, terminal)
                .await
                .map_err(|error| error.to_string())?,
            original,
        )?;
        let result = fixture
            .fresh_directory()?
            .begin_thread_run(fixture.successor_request())
            .await;
        if result != Err(ThreadDirectoryError::LeaseConflict) {
            return Err(format!(
                "fresh runtime/directory admitted a successor over RR: {result:?}"
            ));
        }
        if snapshot(&fixture.pool).await? != before {
            return Err(
                "rejected RR successor mutated original foreground or its released lease"
                    .to_owned(),
            );
        }
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT status,foreground,terminal_event_seq FROM public.runs WHERE run_id=$1",
                &[&fixture.lease.run_id().as_str()],
            )
            .await
            .map_err(|error| error.to_string())?;
        if row.get::<_, &str>("status") != "reconciliation_required"
            || !row.get::<_, bool>("foreground")
            || row.get::<_, Option<i64>>("terminal_event_seq") != Some(1)
        {
            return Err("RR lost its durable foreground terminal facts".to_owned());
        }
        Ok(())
    })
    .await;
}

fn usage() -> ProviderUsage {
    ProviderUsage {
        input_tokens: 1,
        output_tokens: 1,
        total_tokens: 2,
    }
}

fn exchange(result: &str) -> Result<RunToolExchange, String> {
    RunToolExchange::new(
        ToolCallId::new("historical-call"),
        "historical-provider-call".to_owned(),
        "computer.write".to_owned(),
        json!({"message":"hello"}),
        result.to_owned(),
        None,
    )
    .map_err(|error| error.to_string())
}

fn different_terminal(terminal: RunTerminal) -> RunTerminal {
    if terminal == RunTerminal::Completed {
        RunTerminal::Cancelled
    } else {
        RunTerminal::Completed
    }
}

fn expect_replay(actual: RunWriteReceipt, original: RunWriteReceipt) -> Result<(), String> {
    if actual
        == (RunWriteReceipt {
            replayed: true,
            ..original
        })
    {
        Ok(())
    } else {
        Err(format!(
            "wrong historical receipt: {actual:?}; original={original:?}"
        ))
    }
}

fn expect_runtime_error<T: core::fmt::Debug>(
    actual: Result<T, RunRuntimeError>,
    expected: RunRuntimeError,
) -> Result<(), String> {
    match actual {
        Err(error) if error == expected => Ok(()),
        other => Err(format!("expected runtime {expected:?}, received {other:?}")),
    }
}
