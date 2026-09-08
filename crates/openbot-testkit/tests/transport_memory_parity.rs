//! G3 memory commands 经同一个 ApplicationService 的 Axum / typed in-process 对拍。

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, CorrectMemoryRequest, MemoryAdministration,
    MemoryAdministrationError, MemoryControlRequest, MemoryPageRequest, MutateMemoryRequest,
    OpenBotApplication, PortError, RecallMemoriesRequest, RememberMemoryRequest,
    UpdateMemoryControlRequest,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::memory::{
    MemoryControl, MemoryKind, MemoryOrigin, MemoryPage, MemoryRecall, MemoryRecord, MemoryScope,
    MemorySensitivity, MemoryStatus, RecallMemories, RememberMemory, UpdateMemoryControl,
};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::{SessionLifetimePolicy, TrustedOrigins};
use openbot_server::auth::{FixedAuthResolver, SensitiveWriteSecurity};
use openbot_server::{ServerBuilder, router};
use time::OffsetDateTime;
use tower::ServiceExt as _;

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

#[derive(Clone, Copy)]
struct FixedMemory;

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
impl MemoryAdministration for FixedMemory {
    async fn memory_control(
        &self,
        _request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        Ok(MemoryControl::default())
    }

    async fn update_memory_control(
        &self,
        request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        Ok(MemoryControl {
            writes_enabled: request.update.writes_enabled,
        })
    }

    async fn remember(
        &self,
        _request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Ok(record())
    }

    async fn list_memories(
        &self,
        _request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError> {
        Ok(MemoryPage {
            memories: vec![record()],
            next_cursor: None,
        })
    }

    async fn correct(
        &self,
        _request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Ok(record())
    }

    async fn mutate(
        &self,
        _request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Ok(record())
    }

    async fn recall(
        &self,
        _request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError> {
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

struct Fixture {
    service: Arc<dyn ApplicationService>,
    transport: InProcessTransport,
}

impl Fixture {
    fn new() -> Self {
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_memory(FixedMemory));
        let transport = InProcessTransport::new(Arc::clone(&service));
        Self { service, transport }
    }

    fn server(&self) -> axum::Router {
        let state = ServerBuilder::new(
            Arc::clone(&self.service),
            Arc::new(FixedAuthResolver::granting(auth())),
        )
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            SessionLifetimePolicy::new(
                time::Duration::minutes(30),
                time::Duration::hours(8),
                time::Duration::minutes(5),
            )
            .unwrap(),
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        ))
        .build();
        assert!(core::ptr::addr_eq(
            Arc::as_ptr(&self.service),
            state.application()
        ));
        router(state)
    }

    async fn typed(&self, command: AppCommand) -> AppReply {
        assert!(Arc::ptr_eq(&self.service, self.transport.service()));
        self.transport.execute(auth(), command).await.unwrap()
    }

    async fn http(&self, command: &AppCommand) -> AppReply {
        let (method, uri, body, origin) = match command {
            AppCommand::GetMemoryControl => (
                Method::GET,
                "/api/memories/control".to_owned(),
                String::new(),
                false,
            ),
            AppCommand::UpdateMemoryControl(update) => (
                Method::PUT,
                "/api/memories/control".to_owned(),
                serde_json::to_string(update).unwrap(),
                true,
            ),
            AppCommand::ListMemories { limit, .. } => (
                Method::GET,
                format!("/api/memories?limit={}", limit.unwrap_or(50)),
                String::new(),
                false,
            ),
            AppCommand::RememberMemory(input) => (
                Method::POST,
                "/api/memories".to_owned(),
                serde_json::to_string(input).unwrap(),
                true,
            ),
            AppCommand::RecallMemories(input) => (
                Method::POST,
                "/api/memories/recall".to_owned(),
                serde_json::to_string(input).unwrap(),
                false,
            ),
            _ => panic!("本矩阵只接 memory control/list/remember/recall"),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if origin {
            request = request.header("origin", "https://app.example.test");
        }
        let response = self
            .server()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED
        ));
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        match command {
            AppCommand::GetMemoryControl | AppCommand::UpdateMemoryControl(_) => {
                AppReply::MemoryControl(serde_json::from_slice(&bytes).unwrap())
            }
            AppCommand::ListMemories { .. } => {
                AppReply::Memories(serde_json::from_slice(&bytes).unwrap())
            }
            AppCommand::RememberMemory(_) => {
                AppReply::Memory(serde_json::from_slice(&bytes).unwrap())
            }
            AppCommand::RecallMemories(_) => {
                AppReply::MemoryRecall(serde_json::from_slice(&bytes).unwrap())
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn memory_results_match_on_axum_and_typed_in_process() {
    let fixture = Fixture::new();
    for command in [
        AppCommand::GetMemoryControl,
        AppCommand::UpdateMemoryControl(UpdateMemoryControl {
            writes_enabled: false,
        }),
        AppCommand::ListMemories {
            cursor: None,
            limit: Some(10),
        },
        AppCommand::RememberMemory(RememberMemory {
            memory_kind: MemoryKind::Preference,
            scope: MemoryScope::User,
            content: "tea".to_owned(),
            tags: Vec::new(),
            sensitivity: MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        }),
        AppCommand::RecallMemories(RecallMemories {
            query: "tea".to_owned(),
            tags: Vec::new(),
            bot_id: None,
            thread_id: None,
            limit: Some(10),
        }),
    ] {
        assert_eq!(fixture.http(&command).await, fixture.typed(command).await);
    }
}
