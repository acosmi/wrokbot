use super::*;
use crate::InProcessTransport;
use async_trait::async_trait;
use openbot_application::cursor::ChannelCursor;
use openbot_application::{
    AppEventStream, ApplicationService, ChannelReader, CorrectMemoryRequest, MemoryAdministration,
    MemoryAdministrationError, MemoryControlRequest, MemoryPageRequest, MutateMemoryRequest,
    OpenBotApplication, PortError, RecallMemoriesRequest, RememberMemoryRequest,
    UpdateMemoryControlRequest,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{ChannelSummary, SubscriptionRequest};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::memory::{
    MemoryControl, MemoryKind, MemoryOrigin, MemoryPage, MemoryRecall, MemoryRecord, MemoryScope,
    MemorySensitivity, MemoryStatus,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

struct EmptyChannels;

#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _actor: &ActorId,
        _limit: u32,
        _cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("memory routes must not reach the channel port")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Control(MemoryControlRequest),
    Update(UpdateMemoryControlRequest),
    Remember(RememberMemoryRequest),
    List(MemoryPageRequest),
    Correct(CorrectMemoryRequest),
    Mutate(MutateMemoryRequest),
    Recall(RecallMemoriesRequest),
}

#[derive(Default)]
struct MemoryState {
    calls: Mutex<Vec<Call>>,
    error: Mutex<Option<MemoryAdministrationError>>,
    pause: bool,
    entered: Notify,
    release: Notify,
}

#[derive(Clone, Default)]
struct MemoryPort(Arc<MemoryState>);

impl MemoryPort {
    async fn record(&self, call: Call) -> Result<(), MemoryAdministrationError> {
        self.0.calls.lock().unwrap().push(call);
        if self.0.pause {
            self.0.entered.notify_one();
            self.0.release.notified().await;
        }
        match *self.0.error.lock().unwrap() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn record(actor: &ActorId) -> MemoryRecord {
    MemoryRecord {
        memory_id: "memory-original".into(),
        owner_user_id: actor.as_str().into(),
        scope: MemoryScope::User,
        memory_kind: MemoryKind::Preference,
        content: Some("中文原文 café".into()),
        tags: vec!["tag".into()],
        sensitivity: MemorySensitivity::Normal,
        source: None,
        origin: MemoryOrigin::UserAction,
        created_by: actor.as_str().into(),
        supersedes_id: None,
        status: MemoryStatus::Active,
        expires_at: None,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

#[async_trait]
impl MemoryAdministration for MemoryPort {
    async fn memory_control(
        &self,
        request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        self.record(Call::Control(request)).await?;
        Ok(MemoryControl {
            writes_enabled: true,
        })
    }

    async fn update_memory_control(
        &self,
        request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        let writes_enabled = request.update.writes_enabled;
        self.record(Call::Update(request)).await?;
        Ok(MemoryControl { writes_enabled })
    }

    async fn remember(
        &self,
        request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut result = record(&request.actor);
        result.content = Some(request.input.content.clone());
        result.scope = request.input.scope.clone();
        result.source = request.input.source.clone();
        self.record(Call::Remember(request)).await?;
        Ok(result)
    }

    async fn list_memories(
        &self,
        request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError> {
        let result = record(&request.actor);
        self.record(Call::List(request)).await?;
        Ok(MemoryPage {
            memories: vec![result],
            next_cursor: Some("next cursor".into()),
        })
    }

    async fn correct(
        &self,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut result = record(&request.actor);
        result.content = Some(request.correction.content.clone());
        result.supersedes_id = Some(request.memory_id.clone());
        self.record(Call::Correct(request)).await?;
        Ok(result)
    }

    async fn mutate(
        &self,
        request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        let mut result = record(&request.actor);
        result.memory_id = request.memory_id.clone();
        result.content = None;
        result.status = match request.mutation {
            MemoryMutation::Forbid => MemoryStatus::Forbidden,
            MemoryMutation::Delete => MemoryStatus::Deleted,
        };
        self.record(Call::Mutate(request)).await?;
        Ok(result)
    }

    async fn recall(
        &self,
        request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError> {
        let result = record(&request.actor);
        self.record(Call::Recall(request)).await?;
        Ok(MemoryRecall {
            memories: vec![result],
        })
    }
}

struct Fixture {
    protocol: Arc<DesktopTauriProtocol>,
    application: Arc<dyn ApplicationService>,
    memory: MemoryPort,
    root: PathBuf,
}

impl Fixture {
    fn new(memory: MemoryPort) -> Self {
        let application: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_memory(memory.clone()));
        Self::with_application(memory, application)
    }

    fn with_application(memory: MemoryPort, application: Arc<dyn ApplicationService>) -> Self {
        let root =
            std::env::temp_dir().join(format!("wrok-memory-framing-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("index.html"),
            "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
        ).unwrap();
        std::fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        let transport = Arc::new(InProcessTransport::new(application.clone()));
        let protocol = Arc::new(DesktopTauriProtocol::open(&root, transport).unwrap());
        // Ordinary authenticated writes work without the sensitive-write freshness deadline.
        protocol
            .bind_window("main", auth("host-owner"), None)
            .unwrap();
        Self {
            protocol,
            application,
            memory,
            root,
        }
    }

    async fn send(&self, method: Method, path: &str, body: Vec<u8>) -> Response<Vec<u8>> {
        self.protocol
            .handle("main", request(method, path, body))
            .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

fn auth(actor: &str) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("host-deployment"),
        TenantId::new("host-tenant"),
        ActorId::new(actor),
        [Role::User],
        AuthGeneration::new(7),
        true,
    )
}

fn request(method: Method, path: &str, body: Vec<u8>) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

fn remember() -> RememberMemory {
    RememberMemory {
        memory_kind: MemoryKind::Preference,
        scope: MemoryScope::User,
        content: "保留 UTF-8 原文 café".into(),
        tags: vec!["tag".into()],
        sensitivity: MemorySensitivity::Normal,
        source: None,
        expires_at: None,
    }
}

fn correction() -> CorrectMemory {
    CorrectMemory {
        content: "修正原文".into(),
        tags: vec![],
        sensitivity: MemorySensitivity::Sensitive,
        expires_at: None,
    }
}

fn recall() -> RecallMemories {
    RecallMemories {
        query: "中文原文".into(),
        tags: vec!["z".into(), "a".into(), "z".into()],
        bot_id: None,
        thread_id: None,
        limit: Some(1000),
    }
}

fn json_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn value(response: &Response<Vec<u8>>) -> Value {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["content-type"], "application/json");
    serde_json::from_slice(response.body()).unwrap()
}

fn assert_error(response: &Response<Vec<u8>>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(value(response), json!({"code": code}));
}

// The expected mapping is the current Server memories.rs contract. Both lanes below actually
// execute one shared ApplicationService; this is a typed/host parity test, not an Axum HTTP run.
async fn assert_typed_parity(
    fixture: &Fixture,
    method: Method,
    path: &str,
    body: Vec<u8>,
    command: AppCommand,
    status: StatusCode,
) {
    let expected = fixture
        .application
        .execute(auth("host-owner"), command)
        .await
        .unwrap();
    let expected = match expected {
        AppReply::Memory(value) => serde_json::to_value(value).unwrap(),
        AppReply::Memories(value) => serde_json::to_value(value).unwrap(),
        AppReply::MemoryControl(value) => serde_json::to_value(value).unwrap(),
        AppReply::MemoryRecall(value) => serde_json::to_value(value).unwrap(),
        _ => panic!("memory reply expected"),
    };
    let response = fixture.send(method, path, body).await;
    assert_eq!(response.status(), status, "{path}");
    assert_eq!(value(&response), expected, "{path}");
    let calls = fixture.memory.0.calls.lock().unwrap();
    assert!(calls.len() >= 2);
    assert_eq!(calls[calls.len() - 2], calls[calls.len() - 1], "{path}");
}

#[tokio::test]
async fn all_eight_routes_match_shared_application_and_server_reply_mapping() {
    let fixture = Fixture::new(MemoryPort::default());
    assert_typed_parity(
        &fixture,
        Method::GET,
        "/api/memories?cursor=old%2Bid+value&limit=1000",
        vec![],
        AppCommand::ListMemories {
            cursor: Some("old+id value".into()),
            limit: Some(1000),
        },
        StatusCode::OK,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::POST,
        "/api/memories",
        json_body(&remember()),
        AppCommand::RememberMemory(remember()),
        StatusCode::CREATED,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::GET,
        "/api/memories/control",
        vec![],
        AppCommand::GetMemoryControl,
        StatusCode::OK,
    )
    .await;
    let update = UpdateMemoryControl {
        writes_enabled: false,
    };
    assert_typed_parity(
        &fixture,
        Method::PUT,
        "/api/memories/control",
        json_body(&update),
        AppCommand::UpdateMemoryControl(update),
        StatusCode::OK,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::POST,
        "/api/memories/recall",
        json_body(&recall()),
        AppCommand::RecallMemories(recall()),
        StatusCode::OK,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::PUT,
        "/api/memories/old%2Bid",
        json_body(&correction()),
        AppCommand::CorrectMemory {
            memory_id: "old+id".into(),
            correction: correction(),
        },
        StatusCode::OK,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::DELETE,
        "/api/memories/old%2Bid",
        vec![],
        AppCommand::MutateMemory {
            memory_id: "old+id".into(),
            mutation: MemoryMutation::Delete,
        },
        StatusCode::OK,
    )
    .await;
    assert_typed_parity(
        &fixture,
        Method::POST,
        "/api/memories/old%2Bid/forbid",
        vec![],
        AppCommand::MutateMemory {
            memory_id: "old+id".into(),
            mutation: MemoryMutation::Forbid,
        },
        StatusCode::OK,
    )
    .await;
    let calls = fixture.memory.0.calls.lock().unwrap();
    let Call::List(list) = &calls[1] else {
        panic!("list")
    };
    assert_eq!(list.limit, 100);
    let Call::Recall(recall) = &calls[9] else {
        panic!("recall")
    };
    assert_eq!(recall.actor, ActorId::new("host-owner"));
    assert_eq!(recall.tenant, TenantId::new("host-tenant"));
    assert_eq!(recall.deployment, DeploymentId::new("host-deployment"));
    assert_eq!(recall.auth_generation, AuthGeneration::new(7));
    assert_eq!(recall.input.tags, ["a", "z"]);
    assert_eq!(recall.input.limit, Some(100));
}

#[tokio::test]
async fn closed_json_rejects_renderer_authority_and_bad_shapes_before_memory_port() {
    let fixture = Fixture::new(MemoryPort::default());
    let inputs = [
        (
            Method::POST,
            "/api/memories",
            serde_json::to_value(remember()).unwrap(),
        ),
        (
            Method::PUT,
            "/api/memories/control",
            json!({"writesEnabled":false}),
        ),
        (
            Method::POST,
            "/api/memories/recall",
            serde_json::to_value(recall()).unwrap(),
        ),
        (
            Method::PUT,
            "/api/memories/id",
            serde_json::to_value(correction()).unwrap(),
        ),
    ];
    for (method, path, input) in inputs {
        for field in [
            "ownerUserId",
            "actor",
            "tenant",
            "authGeneration",
            "deployment",
            "origin",
            "unknown",
        ] {
            let mut input = input.clone();
            input[field] = json!("renderer-choice");
            assert_error(
                &fixture.send(method.clone(), path, json_body(&input)).await,
                StatusCode::BAD_REQUEST,
                "malformed_payload",
            );
        }
        for body in [
            vec![],
            b"null".to_vec(),
            b"[]".to_vec(),
            b"{broken".to_vec(),
        ] {
            assert_error(
                &fixture.send(method.clone(), path, body).await,
                StatusCode::BAD_REQUEST,
                "malformed_payload",
            );
        }
    }
    assert!(fixture.memory.0.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn query_path_method_and_body_boundaries_fail_before_memory_port() {
    let fixture = Fixture::new(MemoryPort::default());
    for query in [
        "unknown=1",
        "cursor=a&cursor=b",
        "limit=1&limit=2",
        "limit=-1",
        "limit=4294967296",
        "cursor=%Q0",
        "cursor=%FF",
        "limit=abc",
        "cursor",
        "cursor=",
        "cursor=%00",
    ] {
        assert_error(
            &fixture
                .send(Method::GET, &format!("/api/memories?{query}"), vec![])
                .await,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        );
    }
    let long_query = format!(
        "/api/memories?cursor={}",
        "a".repeat(super::super::API_BODY_MAX_BYTES)
    );
    assert_error(
        &fixture.send(Method::GET, &long_query, vec![]).await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    for (method, path, body) in [
        (Method::GET, "/api/memories/control?limit=1", vec![]),
        (
            Method::POST,
            "/api/memories?ownerUserId=other",
            json_body(&remember()),
        ),
        (
            Method::POST,
            "/api/memories/recall?limit=1",
            json_body(&recall()),
        ),
        (Method::GET, "/api/memories", b"{}".to_vec()),
        (Method::GET, "/api/memories/control", b"{}".to_vec()),
        (Method::DELETE, "/api/memories/id", b"{}".to_vec()),
        (Method::POST, "/api/memories/id/forbid", b"{}".to_vec()),
        (Method::DELETE, "/api/memories/%Q0", vec![]),
        (Method::DELETE, "/api/memories/%FF", vec![]),
        (Method::DELETE, "/api/memories/%00", vec![]),
    ] {
        assert_error(
            &fixture.send(method, path, body).await,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        );
    }
    for (method, path, status) in [
        (Method::PUT, "/api/memories", StatusCode::METHOD_NOT_ALLOWED),
        (
            Method::POST,
            "/api/memories/control",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            "/api/memories/recall",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            "/api/memories/id",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::DELETE,
            "/api/memories/id/forbid",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (Method::POST, "/api/memories/", StatusCode::NOT_FOUND),
        (
            Method::POST,
            "/api/memories/a/b/forbid",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/api/memories/id/forbid/extra",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = fixture.send(method, path, vec![]).await;
        assert_eq!(response.status(), status, "{path}");
        assert!(response.body().is_empty());
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert!(fixture.memory.0.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn body_budget_and_application_content_limits_keep_their_distinct_statuses() {
    let fixture = Fixture::new(MemoryPort::default());
    // Exactly 1 MiB of valid JSON (whitespace padding) reaches Application; one more byte does not.
    let mut body = json_body(&remember());
    body.resize(CHANNEL_THREAD_BODY_MAX_BYTES, b' ');
    let response = fixture
        .send(Method::POST, "/api/memories", body.clone())
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    body.push(b' ');
    assert_error(
        &fixture.send(Method::POST, "/api/memories", body).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "malformed_payload",
    );
    let mut input = remember();
    input.content = "x".repeat(64 * 1024);
    assert_eq!(
        fixture
            .send(Method::POST, "/api/memories", json_body(&input))
            .await
            .status(),
        StatusCode::CREATED
    );
    input.content.push('x');
    assert_error(
        &fixture
            .send(Method::POST, "/api/memories", json_body(&input))
            .await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    input = remember();
    input.memory_kind = MemoryKind::Fact;
    assert_error(
        &fixture
            .send(Method::POST, "/api/memories", json_body(&input))
            .await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    assert_eq!(fixture.memory.0.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn port_errors_preserve_shared_status_and_do_not_disclose_scope() {
    let fixture = Fixture::new(MemoryPort::default());
    for error in [
        MemoryAdministrationError::NotVisible,
        MemoryAdministrationError::WritesDisabled,
        MemoryAdministrationError::Conflict,
        MemoryAdministrationError::Unavailable,
        MemoryAdministrationError::CommitUnknown,
    ] {
        *fixture.memory.0.error.lock().unwrap() = Some(error);
        let expected = error.into_app_error();
        assert_error(
            &fixture
                .send(Method::POST, "/api/memories", json_body(&remember()))
                .await,
            StatusCode::from_u16(expected.http_status()).unwrap(),
            expected.code().as_str(),
        );
    }
}

#[tokio::test]
async fn unbound_or_replaced_admission_cannot_reuse_old_authority() {
    let fixture = Fixture::new(MemoryPort::default());
    let old = fixture.protocol.authority("main").unwrap().unwrap();
    fixture.protocol.unbind_window("main").unwrap();
    assert_error(
        &fixture.send(Method::GET, "/api/memories", vec![]).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    fixture
        .protocol
        .bind_window("main", auth("replacement-owner"), None)
        .unwrap();
    let response = fixture
        .protocol
        .memories("main", request(Method::GET, "/api/memories", vec![]), old)
        .await;
    assert_error(&response, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(fixture.memory.0.calls.lock().unwrap().is_empty());
    let response = fixture.send(Method::GET, "/api/memories", vec![]).await;
    assert_eq!(
        value(&response)["memories"][0]["ownerUserId"],
        "replacement-owner"
    );
}

#[tokio::test]
async fn rebind_during_read_withholds_old_result_and_write_returns_reconciliation_without_retry() {
    for write in [false, true] {
        let memory = MemoryPort(Arc::new(MemoryState {
            pause: true,
            ..MemoryState::default()
        }));
        let fixture = Fixture::new(memory.clone());
        let protocol = fixture.protocol.clone();
        let request = if write {
            request(Method::POST, "/api/memories", json_body(&remember()))
        } else {
            request(Method::POST, "/api/memories/recall", json_body(&recall()))
        };
        let pending = tokio::spawn(async move { protocol.handle("main", request).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            memory.0.entered.notified(),
        )
        .await
        .unwrap();
        fixture.protocol.unbind_window("main").unwrap();
        fixture
            .protocol
            .bind_window("main", auth("replacement-owner"), None)
            .unwrap();
        memory.0.release.notify_one();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        if write {
            assert_error(&response, StatusCode::ACCEPTED, "reconciliation_required");
        } else {
            assert_error(&response, StatusCode::UNAUTHORIZED, "unauthenticated");
        }
        assert_eq!(memory.0.calls.lock().unwrap().len(), 1);
    }
}

struct WrongReply;

#[async_trait]
impl ApplicationService for WrongReply {
    async fn execute(
        &self,
        _auth: AuthContext,
        _command: AppCommand,
    ) -> Result<AppReply, AppError> {
        Ok(AppReply::Memory(record(&ActorId::new("must-not-leak"))))
    }

    async fn subscribe(
        &self,
        _auth: AuthContext,
        _request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        panic!("memory routes are unary")
    }
}

#[tokio::test]
async fn mismatched_application_reply_fails_closed() {
    let fixture = Fixture::with_application(MemoryPort::default(), Arc::new(WrongReply));
    for (method, path, body) in [
        (Method::GET, "/api/memories", vec![]),
        (Method::GET, "/api/memories/control", vec![]),
        (Method::POST, "/api/memories/recall", json_body(&recall())),
    ] {
        assert_error(
            &fixture.send(method, path, body).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        );
    }
}
