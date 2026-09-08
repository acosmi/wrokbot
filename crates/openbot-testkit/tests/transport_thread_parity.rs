//! G3 thread 命令经同一个 ApplicationService 的 Axum / typed in-process 对拍。

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{
    AppCommand, AppReply, ChannelSummary, ThreadMinted, ThreadStatus,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
use openbot_desktop::InProcessTransport;
use openbot_server::auth::FixedAuthResolver;
use openbot_server::{ServerBuilder, router};
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

#[derive(Clone)]
struct FixedThreads {
    minted: ThreadId,
    known: bool,
}

#[async_trait]
impl ThreadDirectory for FixedThreads {
    async fn mint_thread_id(
        &self,
        _deployment: &DeploymentId,
    ) -> Result<ThreadId, ThreadDirectoryError> {
        Ok(self.minted.clone())
    }

    async fn thread_known(
        &self,
        _deployment: &DeploymentId,
        _tenant: &TenantId,
        _actor: &ActorId,
        _thread: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        Ok(self.known)
    }
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-thread-parity"),
        TenantId::new("tenant-thread-parity"),
        ActorId::new("actor-thread-parity"),
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
    fn new(known: bool) -> Self {
        let service: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels).with_threads(FixedThreads {
                minted: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                known,
            }),
        );
        let transport = InProcessTransport::new(Arc::clone(&service));
        Self { service, transport }
    }

    async fn typed(&self, command: AppCommand) -> Result<AppReply, String> {
        assert!(Arc::ptr_eq(&self.service, self.transport.service()));
        self.transport
            .execute(auth(), command)
            .await
            .map_err(|error| error.code().as_str().to_owned())
    }

    async fn http(&self, command: &AppCommand) -> Result<AppReply, String> {
        let state = ServerBuilder::new(
            Arc::clone(&self.service),
            Arc::new(FixedAuthResolver::granting(auth())),
        )
        .build();
        assert!(core::ptr::addr_eq(
            Arc::as_ptr(&self.service),
            state.application()
        ));
        let (method, uri) = match command {
            AppCommand::MintThreadId => (Method::POST, "/api/threads/mint".to_owned()),
            AppCommand::GetThreadStatus { thread_id } => {
                (Method::GET, format!("/api/threads/{thread_id}"))
            }
            _ => panic!("本矩阵只接 thread 命令"),
        };
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("bounded body");
        if status == StatusCode::OK {
            return match command {
                AppCommand::MintThreadId => serde_json::from_slice::<ThreadMinted>(&bytes)
                    .map(AppReply::ThreadMinted)
                    .map_err(|_| "malformed_success".to_owned()),
                AppCommand::GetThreadStatus { .. } => {
                    serde_json::from_slice::<ThreadStatus>(&bytes)
                        .map(AppReply::ThreadStatus)
                        .map_err(|_| "malformed_success".to_owned())
                }
                _ => unreachable!(),
            };
        }
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "malformed_error".to_owned())?;
        Err(body["code"].as_str().unwrap_or("missing_code").to_owned())
    }
}

#[tokio::test]
async fn thread_status_has_the_same_typed_answer_on_both_transports() {
    let fixture = Fixture::new(true);
    let command = AppCommand::GetThreadStatus {
        thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
    };
    assert_eq!(fixture.http(&command).await, fixture.typed(command).await);
}

#[tokio::test]
async fn malformed_thread_id_has_the_same_stable_error_on_both_transports() {
    let fixture = Fixture::new(true);
    let command = AppCommand::GetThreadStatus {
        thread_id: ThreadId::new("not-a-uuid"),
    };
    assert_eq!(fixture.http(&command).await, fixture.typed(command).await);
}

#[tokio::test]
async fn mint_has_the_same_typed_shape_on_both_transports() {
    let fixture = Fixture::new(false);
    let command = AppCommand::MintThreadId;
    assert_eq!(fixture.http(&command).await, fixture.typed(command).await);
}
