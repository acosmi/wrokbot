//! Owner-scoped explicit memory HTTP framing；业务与原子性只在 ApplicationService/port。

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use http::header::{CACHE_CONTROL, HeaderValue};
use http::{HeaderMap, StatusCode};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::memory::{
    CorrectMemory, MemoryControl, MemoryMutation, MemoryPage, MemoryRecall, MemoryRecord,
    RecallMemories, RememberMemory, UpdateMemoryControl,
};
use serde::Deserialize;

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// Memory keyset query。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListMemoryQuery {
    /// Opaque memory-id cursor。
    pub cursor: Option<String>,
    /// 页长；application 夹到 1..=100。
    pub limit: Option<u32>,
}

/// `GET /api/memories/control`; absent durable row projects the compatibility default enabled.
pub async fn control_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<MemoryControl>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::GetMemoryControl)
        .await?
    {
        AppReply::MemoryControl(control) => Ok((no_store_headers(), Json(control))),
        _ => Err(application_contract_error()),
    }
}

/// `PUT /api/memories/control`; trusted Origin is resolved before body extraction.
pub async fn control_put(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<UpdateMemoryControl>, JsonRejection>,
) -> Result<(HeaderMap, Json<MemoryControl>), HttpError> {
    let Json(update) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "memory control body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::UpdateMemoryControl(update))
        .await?
    {
        AppReply::MemoryControl(control) => Ok((no_store_headers(), Json(control))),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/memories`。
pub async fn list(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    query: Result<Query<ListMemoryQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<MemoryPage>), HttpError> {
    let Query(query) = query.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "memory query 解析失败");
        AppError::MalformedPayload { field: "query" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::ListMemories {
                cursor: query.cursor,
                limit: query.limit,
            },
        )
        .await?
    {
        AppReply::Memories(page) => Ok((no_store_headers(), Json(page))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/memories/recall`；只读，因此不要求 Origin，但 scope 仍只取 AuthContext。
pub async fn recall(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    body: Result<Json<RecallMemories>, JsonRejection>,
) -> Result<(HeaderMap, Json<MemoryRecall>), HttpError> {
    let Json(input) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "memory recall body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::RecallMemories(input))
        .await?
    {
        AppReply::MemoryRecall(recall) => Ok((no_store_headers(), Json(recall))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/memories`；guard 在 body parse 前。
pub async fn remember(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<RememberMemory>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<MemoryRecord>), HttpError> {
    let Json(input) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "remember memory body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::RememberMemory(input))
        .await?
    {
        AppReply::Memory(memory) => Ok((StatusCode::CREATED, no_store_headers(), Json(memory))),
        _ => Err(application_contract_error()),
    }
}

/// `PUT /api/memories/{memory_id}`；correct + supersede。
pub async fn correct(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(memory_id): Path<String>,
    body: Result<Json<CorrectMemory>, JsonRejection>,
) -> Result<(HeaderMap, Json<MemoryRecord>), HttpError> {
    let Json(correction) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "correct memory body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    memory_reply(
        state
            .application()
            .execute(
                auth,
                AppCommand::CorrectMemory {
                    memory_id,
                    correction,
                },
            )
            .await?,
    )
}

/// `POST /api/memories/{memory_id}/forbid`。
pub async fn forbid(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(memory_id): Path<String>,
) -> Result<(HeaderMap, Json<MemoryRecord>), HttpError> {
    memory_reply(
        state
            .application()
            .execute(
                auth,
                AppCommand::MutateMemory {
                    memory_id,
                    mutation: MemoryMutation::Forbid,
                },
            )
            .await?,
    )
}

/// `DELETE /api/memories/{memory_id}`。
pub async fn delete(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(memory_id): Path<String>,
) -> Result<(HeaderMap, Json<MemoryRecord>), HttpError> {
    memory_reply(
        state
            .application()
            .execute(
                auth,
                AppCommand::MutateMemory {
                    memory_id,
                    mutation: MemoryMutation::Delete,
                },
            )
            .await?,
    )
}

fn memory_reply(reply: AppReply) -> Result<(HeaderMap, Json<MemoryRecord>), HttpError> {
    match reply {
        AppReply::Memory(memory) => Ok((no_store_headers(), Json(memory))),
        _ => Err(application_contract_error()),
    }
}

fn application_contract_error() -> HttpError {
    tracing::error!("memory command 收到不匹配 reply");
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request};
    use openbot_application::{
        ChannelCursor, ChannelReader, CorrectMemoryRequest, MemoryAdministration,
        MemoryAdministrationError, MemoryControlRequest, MemoryPageRequest, MutateMemoryRequest,
        OpenBotApplication, PortError, RecallMemoriesRequest, RememberMemoryRequest,
        UpdateMemoryControlRequest,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::memory::{
        MemoryKind, MemoryOrigin, MemoryScope, MemorySensitivity, MemoryStatus,
    };
    use openbot_domain::identity::session::TrustedOrigins;
    use openbot_infra::auth::config::default_session_lifetime;
    use time::OffsetDateTime;
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{FixedAuthResolver, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

    #[derive(Clone, Copy)]
    struct EmptyChannels;

    #[async_trait]
    impl ChannelReader for EmptyChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        GetControl(MemoryControlRequest),
        UpdateControl(UpdateMemoryControlRequest),
        Remember(RememberMemoryRequest),
        List(MemoryPageRequest),
        Correct(CorrectMemoryRequest),
        Mutate(MutateMemoryRequest),
        Recall(RecallMemoriesRequest),
    }

    #[derive(Clone, Default)]
    struct FakeMemory {
        calls: Arc<Mutex<Vec<Call>>>,
    }

    impl FakeMemory {
        fn calls(&self) -> Vec<Call> {
            self.calls.lock().expect("fake lock").clone()
        }
    }

    fn record() -> MemoryRecord {
        MemoryRecord {
            memory_id: "memory-1".to_owned(),
            owner_user_id: "actor-memory".to_owned(),
            scope: MemoryScope::User,
            memory_kind: MemoryKind::Preference,
            content: Some("tea".to_owned()),
            tags: Vec::new(),
            sensitivity: MemorySensitivity::Normal,
            source: None,
            origin: MemoryOrigin::UserAction,
            created_by: "actor-memory".to_owned(),
            supersedes_id: None,
            status: MemoryStatus::Active,
            expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[async_trait]
    impl MemoryAdministration for FakeMemory {
        async fn memory_control(
            &self,
            request: MemoryControlRequest,
        ) -> Result<MemoryControl, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::GetControl(request));
            Ok(MemoryControl::default())
        }

        async fn update_memory_control(
            &self,
            request: UpdateMemoryControlRequest,
        ) -> Result<MemoryControl, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::UpdateControl(request.clone()));
            Ok(MemoryControl {
                writes_enabled: request.update.writes_enabled,
            })
        }

        async fn remember(
            &self,
            request: RememberMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Remember(request));
            Ok(record())
        }

        async fn list_memories(
            &self,
            request: MemoryPageRequest,
        ) -> Result<MemoryPage, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::List(request));
            Ok(MemoryPage {
                memories: vec![record()],
                next_cursor: None,
            })
        }

        async fn correct(
            &self,
            request: CorrectMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Correct(request));
            Ok(record())
        }

        async fn mutate(
            &self,
            request: MutateMemoryRequest,
        ) -> Result<MemoryRecord, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Mutate(request));
            Ok(record())
        }

        async fn recall(
            &self,
            request: RecallMemoriesRequest,
        ) -> Result<MemoryRecall, MemoryAdministrationError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Recall(request));
            Ok(MemoryRecall {
                memories: vec![record()],
            })
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-memory"),
            TenantId::new("tenant-memory"),
            ActorId::new("actor-memory"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    fn router(memory: FakeMemory) -> Router {
        let application = Arc::new(OpenBotApplication::new(EmptyChannels).with_memory(memory));
        crate::router(
            ServerBuilder::new(application, Arc::new(FixedAuthResolver::granting(auth())))
                .with_sensitive_write_security(SensitiveWriteSecurity::new(
                    default_session_lifetime(),
                    TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                ))
                .build(),
        )
    }

    async fn send(
        router: Router,
        method: Method,
        uri: &str,
        origin: Option<&str>,
        body: &'static str,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            builder = builder.header(http::header::ORIGIN, origin);
        }
        let response = router
            .oneshot(builder.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("bounded body")
                .to_vec(),
        )
        .expect("UTF-8 body");
        (status, body)
    }

    #[tokio::test]
    async fn list_is_scoped_by_authenticated_actor_and_limit_is_application_owned() {
        let memory = FakeMemory::default();
        let (status, _) = send(
            router(memory.clone()),
            Method::GET,
            "/api/memories?limit=999999",
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            memory.calls(),
            vec![Call::List(MemoryPageRequest {
                auth_generation: AuthGeneration::new(1),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
                cursor: None,
                limit: openbot_contracts::command::MAX_MEMORY_PAGE,
            })]
        );
    }

    #[tokio::test]
    async fn memory_control_is_closed_no_store_and_origin_guarded_before_body() {
        let memory = FakeMemory::default();
        let response = router(memory.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/memories/control")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            memory.calls(),
            [Call::GetControl(MemoryControlRequest {
                auth_generation: AuthGeneration::new(1),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
            })]
        );

        let (missing_origin, _) = send(
            router(memory.clone()),
            Method::PUT,
            "/api/memories/control",
            None,
            "not-json",
        )
        .await;
        assert_eq!(missing_origin, StatusCode::FORBIDDEN);
        assert_eq!(memory.calls().len(), 1);

        let response = router(memory.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/memories/control")
                    .header(http::header::ORIGIN, "https://app.example.test")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"writesEnabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            memory.calls().last(),
            Some(&Call::UpdateControl(UpdateMemoryControlRequest {
                auth_generation: AuthGeneration::new(1),
                tenant: TenantId::new("tenant-memory"),
                actor: ActorId::new("actor-memory"),
                update: UpdateMemoryControl {
                    writes_enabled: false,
                },
            }))
        );
    }

    #[tokio::test]
    async fn origin_guard_precedes_body_parse_and_regular_user_can_remember() {
        let memory = FakeMemory::default();
        let (missing, _) = send(
            router(memory.clone()),
            Method::POST,
            "/api/memories",
            None,
            "not-json",
        )
        .await;
        assert_eq!(missing, StatusCode::FORBIDDEN);
        assert!(memory.calls().is_empty());

        let body = r#"{"memoryKind":"preference","scope":{"kind":"user"},"content":"tea","tags":[],"sensitivity":"normal","source":null,"expiresAt":null}"#;
        let (untrusted, _) = send(
            router(memory.clone()),
            Method::POST,
            "/api/memories",
            Some("https://evil.example"),
            body,
        )
        .await;
        assert_eq!(untrusted, StatusCode::FORBIDDEN);
        assert!(memory.calls().is_empty());
        let (created, _) = send(
            router(memory.clone()),
            Method::POST,
            "/api/memories",
            Some("https://app.example.test"),
            body,
        )
        .await;
        assert_eq!(created, StatusCode::CREATED);
        assert!(matches!(memory.calls().as_slice(), [Call::Remember(_)]));
    }

    #[tokio::test]
    async fn correct_forbid_and_delete_are_distinct_typed_commands() {
        let memory = FakeMemory::default();
        let origin = Some("https://app.example.test");
        let (corrected, _) = send(
            router(memory.clone()),
            Method::PUT,
            "/api/memories/memory-1",
            origin,
            r#"{"content":"coffee","tags":[],"sensitivity":"normal","expiresAt":null}"#,
        )
        .await;
        assert_eq!(corrected, StatusCode::OK);
        let (forbidden, _) = send(
            router(memory.clone()),
            Method::POST,
            "/api/memories/memory-1/forbid",
            origin,
            "",
        )
        .await;
        assert_eq!(forbidden, StatusCode::OK);
        let (deleted, _) = send(
            router(memory.clone()),
            Method::DELETE,
            "/api/memories/memory-1",
            origin,
            "",
        )
        .await;
        assert_eq!(deleted, StatusCode::OK);
        assert!(matches!(
            memory.calls().as_slice(),
            [
                Call::Correct(_),
                Call::Mutate(MutateMemoryRequest {
                    mutation: MemoryMutation::Forbid,
                    ..
                }),
                Call::Mutate(MutateMemoryRequest {
                    mutation: MemoryMutation::Delete,
                    ..
                })
            ]
        ));
    }

    #[tokio::test]
    async fn recall_is_read_only_but_still_owner_scoped() {
        let memory = FakeMemory::default();
        let (status, body) = send(
            router(memory.clone()),
            Method::POST,
            "/api/memories/recall",
            None,
            r#"{"query":"tea","tags":["drink","drink"],"botId":null,"threadId":null,"limit":10}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("memory-1"), "{body}");
        let calls = memory.calls();
        let [Call::Recall(request)] = calls.as_slice() else {
            panic!("recall 必须只进入一次 typed port：{calls:?}");
        };
        assert_eq!(request.input.tags, ["drink"]);
    }
}
