use super::get_run_reconciliation;
use std::sync::Mutex;

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::reconciliation::*;
use time::OffsetDateTime;

use crate::ports::{RunReconciliationRequest, ThreadDirectory, ThreadDirectoryError};

struct Directory {
    result: Result<RunReconciliationSnapshot, ThreadDirectoryError>,
    calls: Mutex<Vec<RunReconciliationRequest>>,
}

#[async_trait]
impl ThreadDirectory for Directory {
    async fn mint_thread_id(&self, _: &DeploymentId) -> Result<ThreadId, ThreadDirectoryError> {
        panic!("unrelated port must not be called")
    }
    async fn thread_known(
        &self,
        _: &DeploymentId,
        _: &TenantId,
        _: &ActorId,
        _: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        panic!("separate visibility snapshot must not be used")
    }
    async fn run_reconciliation(
        &self,
        request: RunReconciliationRequest,
    ) -> Result<RunReconciliationSnapshot, ThreadDirectoryError> {
        self.calls.lock().unwrap().push(request);
        self.result.clone()
    }
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [Role::User],
        AuthGeneration::new(7),
        false,
    )
}

fn thread() -> ThreadId {
    ThreadId::new("550e8400-e29b-41d4-a716-446655440000")
}

fn snapshot() -> RunReconciliationSnapshot {
    RunReconciliationSnapshot {
        thread_id: thread(),
        run_id: RunId::new("legacy/run%one"),
        status: RunReconciliationStatus::ReconciliationRequired,
        terminal_event_sequence: 2,
        observed_at: OffsetDateTime::UNIX_EPOCH,
        foreground_blocked: true,
        attempts: vec![],
        next: None,
        available_actions: [],
    }
}

fn directory(result: Result<RunReconciliationSnapshot, ThreadDirectoryError>) -> Directory {
    Directory {
        result,
        calls: Mutex::new(vec![]),
    }
}

#[tokio::test]
async fn injects_current_authority_and_keeps_empty_unknown_unresolved() {
    let directory = directory(Ok(snapshot()));
    let result =
        get_run_reconciliation(&directory, &auth(), thread(), snapshot().run_id, None, None)
            .await
            .unwrap();
    assert_eq!(result, snapshot());
    assert_eq!(
        directory.calls.lock().unwrap().as_slice(),
        &[RunReconciliationRequest {
            deployment: auth().deployment().clone(),
            tenant: auth().tenant().clone(),
            actor: auth().actor().clone(),
            auth_generation: AuthGeneration::new(7),
            thread: thread(),
            run: snapshot().run_id,
            after: None,
            limit: 50,
        }]
    );
}

#[tokio::test]
async fn typed_inputs_cannot_bypass_page_or_identity_validation() {
    let directory = directory(Ok(snapshot()));
    for (thread, run, after, limit) in [
        (ThreadId::new("bad"), RunId::new("run"), None, None),
        (thread(), RunId::new(""), None, None),
        (thread(), RunId::new("a".repeat(513)), None, None),
        (thread(), RunId::new("run\n"), None, None),
        (
            thread(),
            RunId::new("run"),
            Some(RunReconciliationCursor {
                call_sequence: 0,
                attempt_sequence: -1,
            }),
            None,
        ),
        (thread(), RunId::new("run"), None, Some(0)),
        (thread(), RunId::new("run"), None, Some(101)),
    ] {
        assert!(matches!(
            get_run_reconciliation(&directory, &auth(), thread, run, after, limit).await,
            Err(AppError::MalformedPayload { .. })
        ));
    }
    assert!(directory.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn port_failures_use_stable_errors_without_database_material() {
    for (error, expected) in [
        (ThreadDirectoryError::NotVisible, AppError::NotVisible),
        (
            ThreadDirectoryError::RequestConflict,
            AppError::RequestConflict { resource: "run" },
        ),
        (
            ThreadDirectoryError::Corrupt { field: "test" },
            AppError::DependencyUnavailable {
                dependency: "thread_directory",
            },
        ),
    ] {
        assert_eq!(
            get_run_reconciliation(
                &directory(Err(error)),
                &auth(),
                thread(),
                snapshot().run_id,
                None,
                None
            )
            .await
            .unwrap_err(),
            expected
        );
    }
}

fn attempt() -> RunReconciliationAttempt {
    RunReconciliationAttempt {
        tool_call_id: "call".into(),
        call_sequence: 1,
        attempt_id: "attempt".into(),
        attempt_sequence: 0,
        status: RunReconciliationAttemptStatus::Executing,
        recorded_commit_state: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        started_at: None,
        finished_at: None,
    }
}

#[tokio::test]
async fn rejects_wrong_identity_oversized_ids_and_inconsistent_pagination() {
    let mut variants = vec![];
    let mut value = snapshot();
    value.run_id = RunId::new("other");
    variants.push(value);
    let mut value = snapshot();
    value.terminal_event_sequence = u64::MAX;
    variants.push(value);
    let mut value = snapshot();
    value.attempts = vec![attempt(), attempt()];
    variants.push(value);
    let mut value = snapshot();
    value.attempts = vec![attempt()];
    value.attempts[0].attempt_id = "a".repeat(513);
    variants.push(value);
    let mut value = snapshot();
    value.next = Some(RunReconciliationCursor {
        call_sequence: 1,
        attempt_sequence: 0,
    });
    variants.push(value);
    for value in variants {
        assert!(matches!(
            get_run_reconciliation(
                &directory(Ok(value)),
                &auth(),
                thread(),
                snapshot().run_id,
                None,
                Some(1)
            )
            .await,
            Err(AppError::DependencyUnavailable { .. })
        ));
    }
    let mut value = snapshot();
    value.attempts = vec![attempt()];
    let cursor = RunReconciliationCursor {
        call_sequence: 1,
        attempt_sequence: 0,
    };
    assert!(
        get_run_reconciliation(
            &directory(Ok(value)),
            &auth(),
            thread(),
            snapshot().run_id,
            Some(cursor),
            Some(1)
        )
        .await
        .is_err()
    );
}
