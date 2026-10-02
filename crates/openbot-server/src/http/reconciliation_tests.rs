//! R398/R399 framing checks against the shared ApplicationService boundary.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use http::header::{CACHE_CONTROL, CONTENT_LENGTH};
use http::{Method, Request, StatusCode};
use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, HealthReport, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::reconciliation::{
    RunReconciliationAttempt, RunReconciliationAttemptStatus, RunReconciliationCursor,
    RunReconciliationSnapshot, RunReconciliationStatus,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

use super::ServerBuilder;
use crate::auth::FixedAuthResolver;
use crate::config::transport::TrustedTransportPolicy;

const THREAD: &str = "550e8400-e29b-81d4-a716-446655440001";

#[derive(Default)]
struct ReconciliationService {
    calls: Mutex<Vec<(AuthContext, AppCommand)>>,
    error: Option<AppError>,
    wrong_reply: bool,
    oversized: bool,
}

#[async_trait]
impl ApplicationService for ReconciliationService {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        self.calls.lock().unwrap().push((auth, command.clone()));
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if self.wrong_reply {
            return Ok(AppReply::Health(HealthReport { ok: true }));
        }
        let AppCommand::GetRunReconciliation {
            thread_id, run_id, ..
        } = command
        else {
            panic!("reconciliation must use its closed Application command");
        };
        let attempt = RunReconciliationAttempt {
            tool_call_id: "internal-call".into(),
            call_sequence: 7,
            attempt_id: "internal-attempt".into(),
            attempt_sequence: 2,
            status: RunReconciliationAttemptStatus::Executing,
            recorded_commit_state: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            started_at: None,
            finished_at: None,
        };
        Ok(AppReply::RunReconciliation(RunReconciliationSnapshot {
            thread_id,
            run_id,
            status: RunReconciliationStatus::ReconciliationRequired,
            terminal_event_sequence: 12,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            foreground_blocked: true,
            attempts: vec![attempt; if self.oversized { 2000 } else { 1 }],
            next: None,
            available_actions: [],
        }))
    }

    async fn subscribe(
        &self,
        _: AuthContext,
        _: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        panic!("reconciliation is unary");
    }
}

fn authority() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("owner"),
        [Role::User],
        AuthGeneration::new(9),
        false,
    )
}

fn router(service: Arc<ReconciliationService>) -> Router {
    ServerBuilder::new(service, Arc::new(FixedAuthResolver::granting(authority()))).into_router()
}

async fn read(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

fn request(run: &str, query: &str) -> Request<Body> {
    Request::builder()
        .uri(format!(
            "/api/threads/{THREAD}/runs/{run}/reconciliation{query}"
        ))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn reconciliation_maps_shared_command_and_decodes_opaque_run_exactly_once() {
    let service = Arc::new(ReconciliationService::default());
    for (encoded, decoded) in [
        ("legacy%2Frun", "legacy/run"),
        ("legacy%252Frun", "legacy%2Frun"),
        ("%E8%BF%90%E8%A1%8C%25", "运行%"),
    ] {
        let (status, body) = read(
            router(Arc::clone(&service)),
            request(
                encoded,
                "?afterCallSequence=7&afterAttemptSequence=2&limit=100",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["threadId"], THREAD);
        assert_eq!(body["runId"], decoded);
        assert_eq!(body["status"], "reconciliation_required");
        assert_eq!(body["availableActions"], json!([]));
        assert_eq!(body["attempts"][0]["recordedCommitState"], Value::Null);
        assert_eq!(body["attempts"][0]["startedAt"], Value::Null);
        assert_eq!(body["attempts"][0]["finishedAt"], Value::Null);
        assert_eq!(body.as_object().unwrap().len(), 9);
        assert_eq!(body["attempts"][0].as_object().unwrap().len(), 9);
        let calls = service.calls.lock().unwrap();
        let (auth, command) = calls.last().unwrap();
        assert_eq!(auth, &authority());
        assert_eq!(
            command,
            &AppCommand::GetRunReconciliation {
                thread_id: ThreadId::new(THREAD),
                run_id: RunId::new(decoded),
                after: Some(RunReconciliationCursor {
                    call_sequence: 7,
                    attempt_sequence: 2
                }),
                limit: Some(100),
            }
        );
    }
    let (status, _) = read(router(Arc::clone(&service)), request("opaque", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        service.calls.lock().unwrap().last().unwrap().1,
        AppCommand::GetRunReconciliation {
            after: None,
            limit: None,
            ..
        }
    ));
}

#[tokio::test]
async fn reconciliation_rejects_malformed_query_path_and_any_get_body_before_dispatch() {
    let service = Arc::new(ReconciliationService::default());
    for query in [
        "?actor=secret-sentinel",
        "?limit=1&limit=2",
        "?limit=1&%6cimit=2",
        "?afterCallSequence=0",
        "?afterAttemptSequence=0",
        "?limit=0",
        "?limit=101",
        "?limit=4294967296",
        "?afterCallSequence=9223372036854775808&afterAttemptSequence=0",
        "?afterCallSequence=-1&afterAttemptSequence=0",
        "?limit=1.0",
        "?limit=",
        "?limit=1%",
        "?limit=%2",
        "?limit=%GG",
        "?limit=%FF",
        "?%FF=1",
    ] {
        let (status, body) = read(router(Arc::clone(&service)), request("opaque", query)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body, json!({"code":"malformed_payload"}));
    }
    for run in ["%FF", "%", "%2", "%GG"] {
        let (status, body) = read(router(Arc::clone(&service)), request(run, "")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"code":"malformed_payload"}));
    }
    for length in [1, 1024 * 1024 + 1] {
        let mut req = request("opaque", "");
        req.headers_mut()
            .insert(CONTENT_LENGTH, length.to_string().parse().unwrap());
        *req.body_mut() = Body::from(vec![b'x'; length]);
        let (status, body) = read(router(Arc::clone(&service)), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"code":"malformed_payload"}));
    }
    assert!(service.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reconciliation_errors_and_early_denials_are_redacted_and_never_cached() {
    for error in [
        AppError::NotVisible,
        AppError::RequestConflict { resource: "run" },
        AppError::DependencyUnavailable {
            dependency: "secret-sentinel",
        },
    ] {
        let expected_status = StatusCode::from_u16(error.http_status()).unwrap();
        let expected_code = error.code().as_str();
        let service = Arc::new(ReconciliationService {
            error: Some(error.clone()),
            ..Default::default()
        });
        let (status, body) = read(router(service), request("opaque", "")).await;
        assert_eq!(status, expected_status);
        assert_eq!(body, json!({"code":expected_code}));
    }
    for service in [
        ReconciliationService {
            wrong_reply: true,
            ..Default::default()
        },
        ReconciliationService {
            oversized: true,
            ..Default::default()
        },
    ] {
        let (status, body) = read(router(Arc::new(service)), request("opaque", "")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, json!({"code":"dependency_unavailable"}));
    }
    let service = Arc::new(ReconciliationService::default());
    let unauthenticated = ServerBuilder::new(
        service.clone(),
        Arc::new(FixedAuthResolver::rejecting(AppError::Unauthenticated)),
    )
    .into_router();
    let (status, _) = read(unauthenticated, request("opaque", "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let untrusted = ServerBuilder::new(
        service.clone(),
        Arc::new(FixedAuthResolver::granting(authority())),
    )
    .with_transport_policy(TrustedTransportPolicy::deny())
    .into_router();
    let (status, body) = read(untrusted, request("opaque", "")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"code":"transport_untrusted"}));
    for method in [Method::POST, Method::HEAD] {
        let mut wrong_method = request("opaque", "");
        *wrong_method.method_mut() = method;
        let (status, _) = read(router(service.clone()), wrong_method).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }
    assert!(service.calls.lock().unwrap().is_empty());
}
