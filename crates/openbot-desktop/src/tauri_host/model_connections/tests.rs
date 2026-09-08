use super::*;
use async_trait::async_trait;
use openbot_application::{
    AppEventStream, ApplicationService, ChannelReader, OpenBotApplication, PortError,
    cursor::ChannelCursor,
    model_connections::{
        ModelConnectionAdministration, ModelConnectionError, normalize_model_endpoint,
    },
};
use openbot_contracts::{
    auth::{AuthContext, AuthGeneration, Role},
    command::{ChannelSummary, SubscriptionRequest},
    ids::{ActorId, DeploymentId, TenantId},
    model_connections::{
        CustomModelProtocol, ModelConnection, ModelConnectionDeleted, ModelConnectionPage,
        ModelConnectionSource,
    },
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;

const ID: &str = "00000000-0000-7000-8000-000000000001";
const SECRET: &str = "DESKTOP_MODEL_KEY_CANARY";

struct EmptyChannels;
#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("model routes must not reach the channel port")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Operation {
    List(ModelConnectionPageRequest),
    Get(String),
    Create(CreateModelConnection),
    Update(String, UpdateModelConnection),
    Delete(String, DeleteModelConnection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    actor: String,
    tenant: String,
    deployment: String,
    generation: AuthGeneration,
    operation: Operation,
}

#[derive(Default)]
struct State {
    calls: Mutex<Vec<Call>>,
    error: Mutex<Option<ModelConnectionError>>,
    pause: bool,
    entered: Notify,
    release: Notify,
}

#[derive(Clone, Default)]
struct Connections(Arc<State>);
impl Connections {
    async fn record(
        &self,
        auth: &AuthContext,
        operation: Operation,
    ) -> Result<(), ModelConnectionError> {
        self.0.calls.lock().unwrap().push(Call {
            actor: auth.actor().as_str().into(),
            tenant: auth.tenant().as_str().into(),
            deployment: auth.deployment().as_str().into(),
            generation: auth.auth_generation(),
            operation,
        });
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

fn row() -> ModelConnection {
    ModelConnection {
        id: ID.into(),
        source: ModelConnectionSource::Custom,
        name: "个人模型".into(),
        protocol: CustomModelProtocol::OpenaiChatCompletions,
        endpoint: "https://example.test/v1/chat/completions".into(),
        model: "model".into(),
        enabled: true,
        revision: 1,
        has_credential: true,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

#[async_trait]
impl ModelConnectionAdministration for Connections {
    async fn list(
        &self,
        auth: &AuthContext,
        request: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, ModelConnectionError> {
        self.record(auth, Operation::List(request.clone())).await?;
        Ok(ModelConnectionPage {
            connections: vec![row()],
            next_cursor: Some(ID.into()),
        })
    }
    async fn get(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.record(auth, Operation::Get(id.into())).await?;
        Ok(ModelConnection {
            id: id.into(),
            ..row()
        })
    }
    async fn create(
        &self,
        auth: &AuthContext,
        input: &CreateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.record(auth, Operation::Create(input.clone())).await?;
        Ok(ModelConnection {
            name: input.name.clone(),
            protocol: input.protocol,
            endpoint: normalize_model_endpoint(input.protocol, &input.endpoint)?,
            model: input.model.clone(),
            enabled: input.enabled,
            ..row()
        })
    }
    async fn update(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &UpdateModelConnection,
    ) -> Result<ModelConnection, ModelConnectionError> {
        self.record(auth, Operation::Update(id.into(), input.clone()))
            .await?;
        Ok(ModelConnection {
            id: id.into(),
            name: input.name.clone(),
            protocol: input.protocol,
            endpoint: normalize_model_endpoint(input.protocol, &input.endpoint)?,
            model: input.model.clone(),
            enabled: input.enabled,
            revision: input.expected_revision + 1,
            ..row()
        })
    }
    async fn delete(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, ModelConnectionError> {
        self.record(auth, Operation::Delete(id.into(), input.clone()))
            .await?;
        Ok(ModelConnectionDeleted {
            id: id.into(),
            revision: input.expected_revision + 1,
            deleted_at: time::OffsetDateTime::UNIX_EPOCH,
        })
    }
}

struct Fixture {
    protocol: Arc<DesktopTauriProtocol>,
    application: Arc<dyn ApplicationService>,
    connections: Connections,
    root: PathBuf,
}
impl Fixture {
    fn new(connections: Connections) -> Self {
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_model_connections(Arc::new(connections.clone())),
        );
        Self::with_application(connections, application)
    }
    fn with_application(
        connections: Connections,
        application: Arc<dyn ApplicationService>,
    ) -> Self {
        let root =
            std::env::temp_dir().join(format!("wrok-model-framing-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").unwrap();
        std::fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        let protocol = Arc::new(
            DesktopTauriProtocol::open(
                &root,
                Arc::new(crate::InProcessTransport::new(application.clone())),
            )
            .unwrap(),
        );
        protocol
            .bind_window(
                "main",
                auth("owner", 7, [Role::User]),
                Some(Duration::from_secs(60)),
            )
            .unwrap();
        Self {
            protocol,
            application,
            connections,
            root,
        }
    }
    async fn send(&self, method: Method, path: &str, body: Vec<u8>) -> Response<Vec<u8>> {
        self.protocol
            .handle("main", request(method, path, body))
            .await
    }
    fn rebind(
        &self,
        actor: &str,
        generation: u64,
        roles: impl IntoIterator<Item = Role>,
        fresh: Option<Duration>,
    ) {
        self.protocol.unbind_window("main").unwrap();
        self.protocol
            .bind_window("main", auth(actor, generation, roles), fresh)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn auth(actor: &str, generation: u64, roles: impl IntoIterator<Item = Role>) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("desktop-deployment"),
        TenantId::new("desktop-tenant"),
        ActorId::new(actor),
        roles,
        AuthGeneration::new(generation),
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
fn create_value(protocol: &str) -> Value {
    json!({"name":"个人模型", "protocol":protocol, "endpoint":"https://EXAMPLE.test/v1/", "model":"model", "enabled":true, "apiKey":SECRET})
}
fn create() -> CreateModelConnection {
    serde_json::from_value(create_value("openai_chat_completions")).unwrap()
}
fn update() -> UpdateModelConnection {
    let mut value = create_value("openai_responses");
    value["expectedRevision"] = json!(3);
    serde_json::from_value(value).unwrap()
}
fn body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn value(response: &Response<Vec<u8>>) -> Value {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["content-type"], "application/json");
    assert!(!String::from_utf8_lossy(response.body()).contains(SECRET));
    serde_json::from_slice(response.body()).unwrap()
}
fn assert_error(response: &Response<Vec<u8>>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(value(response), json!({"code":code}));
}

async fn parity(
    f: &Fixture,
    method: Method,
    path: &str,
    bytes: Vec<u8>,
    command: AppCommand,
    status: StatusCode,
) {
    let expected = match f
        .application
        .execute(auth("owner", 7, [Role::User]), command)
        .await
        .unwrap()
    {
        AppReply::ModelConnections(value) => serde_json::to_value(value).unwrap(),
        AppReply::ModelConnection(value) => serde_json::to_value(value).unwrap(),
        AppReply::ModelConnectionDeleted(value) => serde_json::to_value(value).unwrap(),
        _ => panic!("model reply expected"),
    };
    let response = f.send(method, path, bytes).await;
    assert_eq!(response.status(), status);
    assert_eq!(value(&response), expected);
    let calls = f.connections.0.calls.lock().unwrap();
    assert_eq!(calls[calls.len() - 2], calls[calls.len() - 1]);
}

#[tokio::test]
async fn five_routes_use_the_same_typed_application_with_native_owner_and_no_secrets() {
    let f = Fixture::new(Connections::default());
    parity(
        &f,
        Method::GET,
        &format!("{COLLECTION}?cursor={ID}"),
        vec![],
        AppCommand::ListModelConnections(ModelConnectionPageRequest {
            cursor: Some(ID.into()),
        }),
        StatusCode::OK,
    )
    .await;
    parity(
        &f,
        Method::GET,
        &format!("{COLLECTION}/{ID}"),
        vec![],
        AppCommand::GetModelConnection {
            connection_id: ID.into(),
        },
        StatusCode::OK,
    )
    .await;
    parity(
        &f,
        Method::POST,
        COLLECTION,
        body(&create()),
        AppCommand::CreateModelConnection(create()),
        StatusCode::CREATED,
    )
    .await;
    parity(
        &f,
        Method::PUT,
        &format!("{COLLECTION}/{ID}"),
        body(&update()),
        AppCommand::UpdateModelConnection {
            connection_id: ID.into(),
            input: update(),
        },
        StatusCode::OK,
    )
    .await;
    let delete = DeleteModelConnection {
        expected_revision: 4,
    };
    parity(
        &f,
        Method::DELETE,
        &format!("{COLLECTION}/{ID}"),
        body(&delete),
        AppCommand::DeleteModelConnection {
            connection_id: ID.into(),
            input: delete,
        },
        StatusCode::OK,
    )
    .await;
    let calls = f.connections.0.calls.lock().unwrap();
    assert_eq!(calls.len(), 10);
    for call in calls.iter() {
        assert_eq!(call.actor, "owner");
        assert_eq!(call.tenant, "desktop-tenant");
        assert_eq!(call.deployment, "desktop-deployment");
        assert_eq!(call.generation, AuthGeneration::new(7));
    }
}

#[tokio::test]
async fn three_protocols_and_rotation_omission_reach_shared_commands() {
    let f = Fixture::new(Connections::default());
    for (protocol, endpoint) in [
        (
            "openai_chat_completions",
            "https://example.test/v1/chat/completions",
        ),
        ("openai_responses", "https://example.test/v1/responses"),
        ("anthropic_messages", "https://example.test/v1/messages"),
    ] {
        let response = f
            .send(Method::POST, COLLECTION, body(&create_value(protocol)))
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(value(&response)["protocol"], protocol);
        assert_eq!(value(&response)["endpoint"], endpoint);
    }
    let mut input = update();
    input.api_key = None;
    let response = f
        .send(Method::PUT, &format!("{COLLECTION}/{ID}"), body(&input))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let calls = f.connections.0.calls.lock().unwrap();
    let Operation::Update(_, input) = &calls.last().unwrap().operation else {
        panic!("update")
    };
    assert!(input.api_key.is_none());
}

#[tokio::test]
async fn unknown_authority_source_protocol_and_bad_payloads_never_reach_port() {
    let f = Fixture::new(Connections::default());
    for (method, path, input) in [
        (
            Method::POST,
            COLLECTION.to_owned(),
            create_value("openai_chat_completions"),
        ),
        (
            Method::PUT,
            format!("{COLLECTION}/{ID}"),
            serde_json::to_value(update()).unwrap(),
        ),
        (
            Method::DELETE,
            format!("{COLLECTION}/{ID}"),
            json!({"expectedRevision":1}),
        ),
    ] {
        for field in [
            "owner",
            "ownerUserId",
            "actor",
            "tenant",
            "deployment",
            "authGeneration",
            "source",
            "connectionId",
            "secretId",
        ] {
            let mut bad = input.clone();
            bad[field] = json!("renderer-choice");
            assert_error(
                &f.send(method.clone(), &path, body(&bad)).await,
                StatusCode::BAD_REQUEST,
                "malformed_payload",
            );
        }
        for bad in [
            vec![],
            b"null".to_vec(),
            b"[]".to_vec(),
            b"{broken".to_vec(),
        ] {
            assert_error(
                &f.send(method.clone(), &path, bad).await,
                StatusCode::BAD_REQUEST,
                "malformed_payload",
            );
        }
    }
    for protocol in ["gateway", "account_bridge", "local", "openai"] {
        assert_error(
            &f.send(Method::POST, COLLECTION, body(&create_value(protocol)))
                .await,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        );
    }
    assert!(f.connections.0.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_role_freshness_and_binding_are_checked_before_secret_parsing() {
    let f = Fixture::new(Connections::default());
    assert_error(
        &f.send(Method::GET, "/api/admin/credentials", vec![]).await,
        StatusCode::FORBIDDEN,
        "forbidden_role",
    );
    let malformed = b"{KEY_ENDPOINT_PARSE_CANARY".to_vec();
    f.rebind("no-role", 7, [], Some(Duration::from_secs(60)));
    assert_error(
        &f.send(Method::POST, COLLECTION, malformed.clone()).await,
        StatusCode::NOT_FOUND,
        "not_visible",
    );
    f.rebind("owner", 7, [Role::User], None);
    for (method, path) in [
        (Method::POST, COLLECTION.to_owned()),
        (Method::PUT, format!("{COLLECTION}/{ID}")),
        (Method::DELETE, format!("{COLLECTION}/{ID}")),
    ] {
        assert_error(
            &f.send(method, &path, malformed.clone()).await,
            StatusCode::UNAUTHORIZED,
            "identity_sensitive_write_session_not_fresh",
        );
    }
    f.protocol.unbind_window("main").unwrap();
    assert_error(
        &f.send(Method::POST, COLLECTION, malformed).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    assert!(f.connections.0.calls.lock().unwrap().is_empty());
    f.protocol
        .bind_window("main", auth("owner-admin", 8, [Role::Admin]), None)
        .unwrap();
    assert_eq!(
        f.send(Method::GET, COLLECTION, vec![]).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        f.connections.0.calls.lock().unwrap()[0].actor,
        "owner-admin"
    );
}

#[tokio::test]
async fn closed_cursor_bodyless_get_and_exact_routes_reject_unused_inputs() {
    let f = Fixture::new(Connections::default());
    for query in [
        "owner=other",
        "source=custom",
        "limit=100",
        "cursor=a&cursor=b",
        "cursor=a&unknown=b",
        "cursor=%ZZ",
        "cursor=%FF",
    ] {
        assert_error(
            &f.send(Method::GET, &format!("{COLLECTION}?{query}"), vec![])
                .await,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        );
    }
    assert_error(
        &f.send(
            Method::GET,
            &format!(
                "{COLLECTION}?cursor={}",
                "x".repeat(super::super::API_BODY_MAX_BYTES)
            ),
            vec![],
        )
        .await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    for (method, path, bytes) in [
        (Method::GET, format!("{COLLECTION}/{ID}"), vec![]),
        (Method::POST, COLLECTION.into(), body(&create())),
        (Method::PUT, format!("{COLLECTION}/{ID}"), body(&update())),
        (
            Method::DELETE,
            format!("{COLLECTION}/{ID}"),
            body(&json!({"expectedRevision":1})),
        ),
    ] {
        for query in ["?", "?owner=other"] {
            assert_error(
                &f.send(method.clone(), &(path.clone() + query), bytes.clone())
                    .await,
                StatusCode::BAD_REQUEST,
                "malformed_payload",
            );
        }
    }
    for path in [COLLECTION.to_owned(), format!("{COLLECTION}/{ID}")] {
        assert_error(
            &f.send(Method::GET, &path, b"{}".to_vec()).await,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        );
    }
    for (method, suffix, status) in [
        (Method::PUT, "", StatusCode::METHOD_NOT_ALLOWED),
        (Method::DELETE, "", StatusCode::METHOD_NOT_ALLOWED),
        (Method::POST, "/id", StatusCode::METHOD_NOT_ALLOWED),
        (Method::GET, "/", StatusCode::NOT_FOUND),
        (Method::POST, "/id/probe", StatusCode::NOT_FOUND),
        (Method::GET, "/id/run", StatusCode::NOT_FOUND),
    ] {
        let response = f
            .send(method, &format!("{COLLECTION}{suffix}"), vec![])
            .await;
        assert_eq!(response.status(), status);
        assert!(response.body().is_empty());
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert_error(
        &f.send(Method::GET, &format!("{COLLECTION}/%GG"), vec![])
            .await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    assert!(f.connections.0.calls.lock().unwrap().is_empty());
    assert_eq!(
        f.send(
            Method::GET,
            &format!("{COLLECTION}?%63ursor=old%2Bid+value"),
            vec![]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let calls = f.connections.0.calls.lock().unwrap();
    assert_eq!(
        calls[0].operation,
        Operation::List(ModelConnectionPageRequest {
            cursor: Some("old+id value".into())
        })
    );
}

#[tokio::test]
async fn credential_framing_budget_preserves_sixteen_kib_key_limit_and_zeroizes_body() {
    let f = Fixture::new(Connections::default());
    let mut input = create_value("openai_chat_completions");
    input["apiKey"] =
        json!("x".repeat(openbot_contracts::credential_admin::MAX_CREDENTIAL_TOKEN_BYTES));
    let mut bytes = body(&input);
    bytes.resize(MODEL_CONNECTION_BODY_MAX_BYTES, b' ');
    assert_eq!(
        f.send(Method::POST, COLLECTION, bytes.clone())
            .await
            .status(),
        StatusCode::CREATED
    );
    bytes.push(b' ');
    assert_error(
        &f.send(Method::POST, COLLECTION, bytes).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "malformed_payload",
    );
    input["apiKey"] =
        json!("x".repeat(openbot_contracts::credential_admin::MAX_CREDENTIAL_TOKEN_BYTES + 1));
    assert_error(
        &f.send(Method::POST, COLLECTION, body(&input)).await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    for bytes in [
        body(&create()),
        b"{malformed".to_vec(),
        vec![b'x'; MODEL_CONNECTION_BODY_MAX_BYTES + 1],
    ] {
        let mut request = request(Method::POST, COLLECTION, bytes);
        let _ = parse_sensitive_body::<CreateModelConnection>(
            &mut request,
            MODEL_CONNECTION_BODY_MAX_BYTES,
        );
        assert!(!request.body().is_empty());
        assert!(request.body().iter().all(|byte| *byte == 0));
    }
    assert_eq!(f.connections.0.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stable_errors_and_commit_unknown_never_disclose_key_or_endpoint_or_retry() {
    let f = Fixture::new(Connections::default());
    for error in [
        ModelConnectionError::NotVisible,
        ModelConnectionError::Conflict,
        ModelConnectionError::Unavailable,
        ModelConnectionError::Corrupt,
        ModelConnectionError::CommitUnknown,
    ] {
        *f.connections.0.error.lock().unwrap() = Some(error);
        let expected = error.into_app_error();
        assert_error(
            &f.send(Method::POST, COLLECTION, body(&create())).await,
            StatusCode::from_u16(expected.http_status()).unwrap(),
            expected.code().as_str(),
        );
    }
    assert_eq!(f.connections.0.calls.lock().unwrap().len(), 5);
    let mut input = create_value("openai_chat_completions");
    input["endpoint"] = json!("https://secret-user:secret-password@example.test/?secret=query");
    assert_error(
        &f.send(Method::POST, COLLECTION, body(&input)).await,
        StatusCode::BAD_REQUEST,
        "malformed_payload",
    );
    assert_eq!(f.connections.0.calls.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn stale_admission_and_same_actor_new_generation_cannot_reuse_old_binding() {
    let f = Fixture::new(Connections::default());
    let old = f.protocol.authority("main").unwrap().unwrap();
    f.rebind("owner", 8, [Role::User], Some(Duration::from_secs(60)));
    assert_error(
        &f.protocol
            .model_connections(
                "main",
                request(Method::POST, COLLECTION, body(&create())),
                old,
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    assert!(f.connections.0.calls.lock().unwrap().is_empty());
    assert_eq!(
        f.send(Method::GET, COLLECTION, vec![]).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        f.connections.0.calls.lock().unwrap()[0].generation,
        AuthGeneration::new(8)
    );
}

#[tokio::test]
async fn outer_authentication_failures_keep_stable_status_and_never_parse_or_dispatch() {
    let f = Fixture::new(Connections::default());
    f.protocol.unbind_window("main").unwrap();
    // Already materialized secret-bearing bytes are discarded on both outer failures. This
    // runtime check proves ordering/status, not allocator-level observation after Vec ownership
    // has moved into handle; the explicit buffer fill is independently visible at each branch.
    let rejected_body = vec![b'x'; MODEL_CONNECTION_BODY_MAX_BYTES + 1];
    assert_error(
        &f.send(Method::POST, COLLECTION, rejected_body.clone())
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let protocol = f.protocol.clone();
    let poisoned = std::thread::spawn(move || {
        let _guard = protocol.windows.write().unwrap();
        panic!("test poisons native authority lock");
    })
    .join();
    assert!(poisoned.is_err());
    assert_error(
        &f.send(Method::POST, COLLECTION, rejected_body).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "dependency_unavailable",
    );
    assert!(f.connections.0.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rebind_during_read_withholds_result_and_admitted_write_requires_reconciliation_once() {
    for (write, error) in [
        (false, None),
        (true, None),
        (true, Some(ModelConnectionError::CommitUnknown)),
        (true, Some(ModelConnectionError::Conflict)),
    ] {
        let connections = Connections(Arc::new(State {
            pause: true,
            error: Mutex::new(error),
            ..State::default()
        }));
        let f = Fixture::new(connections.clone());
        let protocol = f.protocol.clone();
        let request = if write {
            request(Method::POST, COLLECTION, body(&create()))
        } else {
            request(Method::GET, COLLECTION, vec![])
        };
        let pending = tokio::spawn(async move { protocol.handle("main", request).await });
        tokio::time::timeout(Duration::from_secs(2), connections.0.entered.notified())
            .await
            .unwrap();
        f.rebind(
            "replacement-owner",
            8,
            [Role::User],
            Some(Duration::from_secs(60)),
        );
        connections.0.release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        if write && error != Some(ModelConnectionError::Conflict) {
            assert_error(&response, StatusCode::ACCEPTED, "reconciliation_required");
        } else {
            assert_error(&response, StatusCode::UNAUTHORIZED, "unauthenticated");
        }
        let calls = connections.0.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].actor, "owner");
        assert_eq!(calls[0].generation, AuthGeneration::new(7));
    }
}

struct WrongReply;
#[async_trait]
impl ApplicationService for WrongReply {
    async fn execute(&self, _: AuthContext, _: AppCommand) -> Result<AppReply, AppError> {
        Ok(AppReply::ModelConnection(row()))
    }
    async fn subscribe(
        &self,
        _: AuthContext,
        _: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        panic!("model management is unary")
    }
}
#[tokio::test]
async fn unexpected_reply_cannot_escape_the_closed_route_projection() {
    let f = Fixture::with_application(Connections::default(), Arc::new(WrongReply));
    for (method, path, bytes) in [
        (Method::GET, COLLECTION.to_owned(), vec![]),
        (
            Method::DELETE,
            format!("{COLLECTION}/{ID}"),
            body(&json!({"expectedRevision":1})),
        ),
    ] {
        assert_error(
            &f.send(method, &path, bytes).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        );
    }
}
