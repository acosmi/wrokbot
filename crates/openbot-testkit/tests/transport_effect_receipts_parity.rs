//! R401/R402: both host framings reach the exact same real Application allocation.
//! The deterministic read port proves authority/framing/projection parity, not PG commit facts.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    RunEffectReceiptsRequest, ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
use openbot_contracts::reconciliation::{
    RunEffectReceipt, RunEffectReceiptFact, RunEffectReceiptsSnapshot, RunReconciliationCursor,
    RunReconciliationStatus,
};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_server::auth::FixedAuthResolver;
use openbot_server::http::{ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const THREAD: &str = "550e8400-e29b-81d4-a716-446655440001";

#[derive(Default)]
struct PortState {
    calls: Vec<RunEffectReceiptsRequest>,
    error: Option<ThreadDirectoryError>,
}

#[derive(Clone, Default)]
struct ReceiptDirectory(Arc<Mutex<PortState>>);

impl ReceiptDirectory {
    fn drain(&self) -> Vec<RunEffectReceiptsRequest> {
        std::mem::take(&mut self.0.lock().unwrap().calls)
    }
}

#[async_trait]
impl ChannelReader for ReceiptDirectory {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("receipt reads must not enter the channel port");
    }
}

#[async_trait]
impl ThreadDirectory for ReceiptDirectory {
    async fn mint_thread_id(&self, _: &DeploymentId) -> Result<ThreadId, ThreadDirectoryError> {
        panic!("read-only request must not mint a thread");
    }

    async fn thread_known(
        &self,
        _: &DeploymentId,
        _: &TenantId,
        _: &ActorId,
        _: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        panic!("receipt authority must arrive in the one read-port request");
    }

    async fn run_effect_receipts(
        &self,
        request: RunEffectReceiptsRequest,
    ) -> Result<RunEffectReceiptsSnapshot, ThreadDirectoryError> {
        {
            let mut state = self.0.lock().unwrap();
            state.calls.push(request.clone());
            if let Some(error) = state.error {
                return Err(error);
            }
        }
        let mut rows = [(0, 0), (7, 2), (7, 3)]
            .into_iter()
            .enumerate()
            .map(
                |(index, (call_sequence, attempt_sequence))| RunEffectReceipt {
                    receipt_id: format!("550e8400-e29b-41d4-a716-{:012}", index + 1),
                    tool_call_id: format!("call-{call_sequence}"),
                    call_sequence,
                    attempt_id: format!("attempt-{index}"),
                    attempt_sequence,
                    fact: RunEffectReceiptFact::MemoryCreated,
                    recorded_at: OffsetDateTime::UNIX_EPOCH,
                },
            )
            .filter(|row| {
                request.after.is_none_or(|after| {
                    (row.call_sequence, row.attempt_sequence)
                        > (after.call_sequence, after.attempt_sequence)
                })
            })
            .collect::<Vec<_>>();
        let more = rows.len() > request.limit as usize;
        rows.truncate(request.limit as usize);
        let next = more.then(|| {
            let last = rows.last().unwrap();
            RunReconciliationCursor {
                call_sequence: last.call_sequence,
                attempt_sequence: last.attempt_sequence,
            }
        });
        Ok(RunEffectReceiptsSnapshot {
            thread_id: request.thread,
            run_id: request.run,
            status: RunReconciliationStatus::ReconciliationRequired,
            terminal_event_sequence: 12,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            foreground_blocked: true,
            receipts: rows,
            next,
            available_actions: [],
        })
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

struct Fixture {
    service: Arc<dyn ApplicationService>,
    port: ReceiptDirectory,
    transport: Arc<InProcessTransport>,
    protocol: DesktopTauriProtocol,
    assets: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let port = ReceiptDirectory::default();
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(port.clone()).with_threads(port.clone()));
        let transport = Arc::new(InProcessTransport::new(service.clone()));
        let assets = std::env::temp_dir().join(format!(
            "openbot-receipt-host-parity-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&assets).unwrap();
        std::fs::write(
            assets.join("index.html"),
            "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
        )
        .unwrap();
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        let protocol = DesktopTauriProtocol::open(&assets, transport.clone()).unwrap();
        protocol.bind_window("main", authority(), None).unwrap();
        Self {
            service,
            port,
            transport,
            protocol,
            assets,
        }
    }

    async fn pair(
        &self,
        thread: &str,
        run: &str,
        query: &str,
        method: Method,
        body: Vec<u8>,
        authenticated: bool,
    ) -> (StatusCode, Value, Vec<RunEffectReceiptsRequest>) {
        let resolver = if authenticated {
            FixedAuthResolver::granting(authority())
        } else {
            FixedAuthResolver::rejecting(AppError::Unauthenticated)
        };
        let server = ServerBuilder::new(self.service.clone(), Arc::new(resolver)).build();
        assert!(core::ptr::addr_eq(
            Arc::as_ptr(&self.service),
            server.application()
        ));
        assert!(Arc::ptr_eq(&self.service, self.transport.service()));
        let uri = format!("/api/threads/{thread}/runs/{run}/reconciliation/receipts{query}");
        assert!(self.port.drain().is_empty());
        let http = router(server)
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(&uri)
                    .header(CONTENT_LENGTH, body.len())
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let http_calls = self.port.drain();
        assert_eq!(http.headers()[CACHE_CONTROL], "no-store");
        let status = http.status();
        let http_content_type = http.headers().get(CONTENT_TYPE).cloned();
        let http_bytes = to_bytes(http.into_body(), 256 * 1024).await.unwrap();
        let desktop = self
            .protocol
            .handle(
                if authenticated {
                    "main"
                } else {
                    "missing-window"
                },
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .body(body)
                    .unwrap(),
            )
            .await;
        let desktop_calls = self.port.drain();
        assert_eq!(desktop.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(status, desktop.status(), "{uri}");
        let parse = |bytes: &[u8]| {
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(bytes).unwrap()
            }
        };
        let value = parse(&http_bytes);
        assert_eq!(value, parse(desktop.body()), "{uri}");
        assert_eq!(
            http_calls, desktop_calls,
            "authority and pagination must reach the same port unchanged"
        );
        if !http_bytes.is_empty() {
            assert_eq!(http_content_type.unwrap(), "application/json");
            assert_eq!(desktop.headers()[CONTENT_TYPE], "application/json");
        }
        (status, value, http_calls)
    }

    async fn get(
        &self,
        run: &str,
        query: &str,
    ) -> (StatusCode, Value, Vec<RunEffectReceiptsRequest>) {
        self.pair(THREAD, run, query, Method::GET, Vec::new(), true)
            .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.protocol.unbind_window("main").unwrap();
        std::fs::remove_dir_all(&self.assets).unwrap();
    }
}

#[tokio::test]
async fn same_application_receipt_page_is_exact_and_pagination_is_preserved() {
    let fx = Fixture::new();
    let (status, page, calls) = fx.get("opaque", "?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page,
        json!({
            "threadId": THREAD, "runId":"opaque", "status":"reconciliation_required",
            "terminalEventSequence":12, "observedAt":"1970-01-01T00:00:00Z",
            "foregroundBlocked":true,
            "receipts":[{
                "receiptId":"550e8400-e29b-41d4-a716-000000000001",
                "toolCallId":"call-0", "callSequence":0,
                "attemptId":"attempt-0", "attemptSequence":0,
                "fact":"memory_created", "recordedAt":"1970-01-01T00:00:00Z"
            }],
            "next":{"callSequence":0,"attemptSequence":0}, "availableActions":[]
        })
    );
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.deployment, *authority().deployment());
    assert_eq!(call.tenant, *authority().tenant());
    assert_eq!(call.actor, *authority().actor());
    assert_eq!(call.auth_generation, authority().auth_generation());
    assert_eq!(call.limit, 1);
    assert_eq!(call.after, None);
    for (query, position, next) in [
        (
            "?afterCallSequence=0&afterAttemptSequence=0&limit=1",
            (7, 2),
            json!({"callSequence":7,"attemptSequence":2}),
        ),
        (
            "?afterCallSequence=7&afterAttemptSequence=2&limit=1",
            (7, 3),
            Value::Null,
        ),
    ] {
        let (status, page, calls) = fx.get("opaque", query).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(page["receipts"][0]["callSequence"], position.0);
        assert_eq!(page["receipts"][0]["attemptSequence"], position.1);
        assert_eq!(page["next"], next);
        assert_eq!(calls.len(), 1);
    }
    let (status, empty, _) = fx
        .get(
            "opaque",
            "?afterCallSequence=7&afterAttemptSequence=3&limit=1",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(empty["receipts"], json!([]));
    assert_eq!(empty["next"], Value::Null);
    assert_eq!(empty["availableActions"], json!([]));
    let (status, default_page, calls) = fx.get("opaque", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(default_page["receipts"].as_array().unwrap().len(), 3);
    assert_eq!(calls[0].limit, 50);
    assert_eq!(calls[0].after, None);
}

#[tokio::test]
async fn same_application_decodes_once_and_rejects_invalid_frames_without_port_access() {
    let fx = Fixture::new();
    for (encoded, decoded) in [
        ("legacy%2Frun", "legacy/run"),
        ("legacy%252Frun", "legacy%2Frun"),
        ("%E8%BF%90%E8%A1%8C%25", "运行%"),
    ] {
        let (status, page, calls) = fx.get(encoded, "?%6cimit=100").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["runId"], decoded);
        assert_eq!(calls[0].run.as_str(), decoded);
        assert_eq!(calls[0].limit, 100);
    }
    let (status, _, calls) = fx.get(&"x".repeat(512), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls[0].run.as_str().len(), 512);
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
        let (status, body, calls) = fx.get("opaque", query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body, json!({"code":"malformed_payload"}));
        assert!(calls.is_empty());
    }
    for run in ["%FF", "%", "%2", "%GG", "%00", "%0A", &"x".repeat(513)] {
        let (status, body, calls) = fx.get(run, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{run}");
        assert_eq!(body, json!({"code":"malformed_payload"}));
        assert!(calls.is_empty());
    }
    let (status, body, calls) = fx
        .pair("not-a-thread", "opaque", "", Method::GET, Vec::new(), true)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"code":"malformed_payload"}));
    assert!(calls.is_empty());
    for size in [1, 1024 * 1024 + 1] {
        let (status, body, calls) = fx
            .pair(THREAD, "opaque", "", Method::GET, vec![b'x'; size], true)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"code":"malformed_payload"}));
        assert!(calls.is_empty());
    }
    for method in [Method::HEAD, Method::POST] {
        let (status, _, calls) = fx
            .pair(THREAD, "opaque", "", method, Vec::new(), true)
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(calls.is_empty());
    }
    let (status, body, calls) = fx
        .pair(THREAD, "opaque", "", Method::GET, Vec::new(), false)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"code":"unauthenticated"}));
    assert!(calls.is_empty());
}

#[tokio::test]
async fn same_application_maps_read_failures_without_leaking_details_or_caching() {
    let fx = Fixture::new();
    for error in [
        ThreadDirectoryError::NotVisible,
        ThreadDirectoryError::RequestConflict,
        ThreadDirectoryError::Unavailable,
        ThreadDirectoryError::Corrupt {
            field: "secret-sentinel",
        },
    ] {
        fx.port.0.lock().unwrap().error = Some(error);
        let expected = error.into_app_error();
        let (status, body, calls) = fx.get("opaque", "").await;
        assert_eq!(status.as_u16(), expected.http_status());
        assert_eq!(body, json!({"code":expected.code().as_str()}));
        assert_eq!(calls.len(), 1);
    }
    fx.port.0.lock().unwrap().error = None;
    let (status, page, _) = fx.get("opaque", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["receipts"].as_array().unwrap().len(), 3);
}
