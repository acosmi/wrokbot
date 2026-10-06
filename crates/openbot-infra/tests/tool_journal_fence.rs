//! R405/R406: actual repository/journal transactions against an owned PostgreSQL database.

#[path = "tool_journal_fence/binding.rs"]
mod binding;
mod harness;
#[path = "tool_journal_fence/races.rs"]
mod races;
#[path = "tool_journal_fence/support.rs"]
mod support;

use std::future::Future;
use std::time::Duration;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, RunExecutionLease, RunFailureCode, RunRuntime, RunTerminal,
    ThreadDirectory, ToolDecisionDraft, ToolJournal, ToolOutcomeDraft, ToolPortError,
    ToolRefusalDraft,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{
    ActorId, AttemptId, BotId, CapabilityId, CatalogGeneration, DeploymentId, PolicyDecisionId,
    RunId, TenantId, ToolCallId,
};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
use openbot_domain::tool::commit::{CommitState, IdempotencyKey};
use openbot_domain::tool::metadata::{
    ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    ToolMetadata, ToolName,
};
use openbot_domain::tool::pipeline::{DurableDecisionReceipt, ToolOutcome};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::tables::{tool_attempts, tool_calls};
use openbot_infra::db::{InfraError, baseline, native, pool};
use openbot_infra::repo::tools::{
    FirstDurableDecision, PersistedToolOutcome, PostgresToolJournal, ToolAttemptRepo, ToolCallRepo,
};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use support::*;

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn four_repositories_refuse_queued_and_every_terminal_without_mutation() {
    fixture("journal_states", |f| async move {
        for state in [None, Some(RunTerminal::Completed), Some(RunTerminal::Failed(RunFailureCode::ProviderUnavailable)),
            Some(RunTerminal::Cancelled), Some(RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown))] {
            for kind in WRITES {
                let case = f.run().await?;
                let operation = Operation::prepare(&f.pool, &case.draft, kind).await?;
                if let Some(terminal) = state {
                    runtime(&f.pool)?.finish_run(&case.lease, case.lease.next_event_sequence(), terminal)
                        .await.map_err(|e| e.to_string())?;
                } else {
                    // A negative-only legacy queued shape; no effect or terminal is claimed here.
                    f.pool.get().await.map_err(|e| e.to_string())?
                        .execute("UPDATE public.runs SET status='queued',started_at=NULL WHERE run_id=$1",
                            &[&case.lease.run_id().as_str()]).await.map_err(|e| e.to_string())?;
                }
                let before = snapshot(&f.pool).await?;
                assert_write_conflict(operation.invoke(&f.pool).await);
                assert_eq!(snapshot(&f.pool).await?, before, "{state:?} {kind:?}");
            }
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn decision_identity_pristine_and_retry_capability_cas_are_preserved() {
    fixture("journal_pristine", |f| async move {
        let case = f.run().await?;
        let j = journal(&f.pool);
        let before = snapshot(&f.pool).await?;
        for actor in [true, false] {
            let mut d = case.draft.clone();
            if actor {
                d.actor = ActorId::new("wrong-actor");
            } else {
                d.bot = BotId::new("wrong-bot");
            }
            assert_eq!(j.record_decision(&d).await, Err(ToolPortError::Conflict));
            assert_eq!(snapshot(&f.pool).await?, before);
        }
        let calls = ToolCallRepo::new(f.pool.clone());
        let attempts = ToolAttemptRepo::new(f.pool.clone());
        let original = first(&case.draft);
        for mutation in [0, 1, 2] {
            let mut invalid = original.clone();
            match mutation {
                0 => invalid.attempt.attempt_seq = 1,
                1 => invalid.attempt.capability_id = Some("preminted".to_owned()),
                _ => invalid.attempt.tool_call_id = "wrong-call".to_owned(),
            }
            assert!(matches!(
                calls.record_first_decision(&invalid).await,
                Err(InfraError::RepositoryInvariant { .. })
            ));
            assert_eq!(snapshot(&f.pool).await?, before);
        }
        calls
            .record_first_decision(&original)
            .await
            .map_err(|e| e.to_string())?;
        let call = original.call.tool_call_id.as_str();
        let mut retry = pristine(call, 7);
        retry.capability_id = Some("preminted".to_owned());
        assert!(attempts.insert_retry(&retry).await.is_err());
        retry.capability_id = None;
        attempts
            .insert_retry(&retry)
            .await
            .map_err(|e| e.to_string())?;
        let duplicate = attempts.insert_retry(&retry).await.unwrap_err();
        assert_eq!(duplicate.sqlstate(), Some("23505"));
        j.attach_capability(&case.draft.call_id, &CapabilityId::new("cap-zero"))
            .await
            .map_err(|e| e.to_string())?;
        assert!(
            attempts
                .find_by_key(call, 7)
                .await
                .map_err(|e| e.to_string())?
                .unwrap()
                .capability_id
                .is_none()
        );
        assert!(
            attempts
                .attach_capability(call, 7, "cap-seven", OffsetDateTime::now_utc())
                .await
                .map_err(|e| e.to_string())?
                .is_some()
        );
        assert!(
            attempts
                .attach_capability(call, 7, "second-cap", OffsetDateTime::now_utc())
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        );
        assert!(
            attempts
                .attach_capability(call, 8, "missing-cap", OffsetDateTime::now_utc())
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        );
        assert!(
            attempts
                .record_outcome(call, 7, "wrong-cap", &persisted())
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        );
        attempts
            .record_outcome(call, 7, "cap-seven", &persisted())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("missing outcome")?;
        let settled = snapshot(&f.pool).await?;
        assert!(
            attempts
                .record_outcome(call, 7, "cap-seven", &persisted())
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        );
        assert_eq!(snapshot(&f.pool).await?, settled);
        assert!(
            settled["audit"].as_array().unwrap().is_empty(),
            "low-level API has no audit key"
        );
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn generic_receipt_selects_nonzero_attempt_and_duplicate_journal_writes_stay_conflicts() {
    fixture("journal_sequence", |f| async move {
        let case = f.run().await?;
        let mut d = executing(&f.pool, case.draft).await?;
        let j = journal(&f.pool);
        assert_eq!(
            j.record_decision(&d.decision).await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(
            j.attach_capability(&d.decision.call_id, &d.capability_id)
                .await,
            Err(ToolPortError::Conflict)
        );
        let a = ToolAttemptRepo::new(f.pool.clone());
        let seventh = pristine(d.decision.call_id.as_str(), 7);
        a.insert_retry(&seventh).await.map_err(|e| e.to_string())?;
        let cap = CapabilityId::new(Uuid::now_v7().to_string());
        a.attach_capability(
            d.decision.call_id.as_str(),
            7,
            cap.as_str(),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|e| e.to_string())?
        .ok_or("missing seventh capability")?;
        let zero_before = a
            .find_by_key(d.decision.call_id.as_str(), 0)
            .await
            .map_err(|e| e.to_string())?;
        d.receipt = DurableDecisionReceipt::issued_by_repository(
            d.receipt.decision().clone(),
            AttemptId::new(&seventh.attempt_id),
        );
        d.capability_id = cap;
        j.record_outcome(&d).await.map_err(|e| e.to_string())?;
        assert_eq!(
            a.find_by_key(d.decision.call_id.as_str(), 0)
                .await
                .map_err(|e| e.to_string())?,
            zero_before
        );
        assert_eq!(
            a.find_by_key(d.decision.call_id.as_str(), 7)
                .await
                .map_err(|e| e.to_string())?
                .unwrap()
                .commit_state
                .as_deref(),
            Some("committed")
        );
        let before = snapshot(&f.pool).await?;
        assert_eq!(before["audit"].as_array().unwrap().len(), 1);
        assert_eq!(j.record_outcome(&d).await, Err(ToolPortError::Conflict));
        assert_eq!(snapshot(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn terminal_refusal_keeps_its_original_append_only_audit_behavior() {
    fixture("journal_refusal", |f| async move {
        let case = f.run().await?;
        runtime(&f.pool)?
            .finish_run(
                &case.lease,
                case.lease.next_event_sequence(),
                RunTerminal::Completed,
            )
            .await
            .map_err(|e| e.to_string())?;
        let before = snapshot(&f.pool).await?;
        let refusal = ToolRefusalDraft {
            decision: case.draft,
            rule: openbot_domain::tool::pipeline::PolicyRuleId::new("owned-refusal"),
            error_code: "policy_refused",
        };
        journal(&f.pool)
            .record_refusal(&refusal)
            .await
            .map_err(|e| e.to_string())?;
        let mut after = snapshot(&f.pool).await?;
        assert_eq!(after["audit"].as_array().unwrap().len(), 1);
        assert_eq!(after["checkpoints"].as_array().unwrap().len(), 1);
        after["audit"] = before["audit"].clone();
        after["checkpoints"] = before["checkpoints"].clone();
        assert_eq!(after, before);
        Ok(())
    })
    .await;
}
