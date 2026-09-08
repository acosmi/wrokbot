//! Real managed Electron -> ScreenHub -> ApplicationService -> Server WebSocket conformance.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
};
use openbot_computer::control::ControlService;
use openbot_computer::engine::{
    ComputerSecurityScope, EngineBundle, EngineBundleDigest, EngineLaunchConfig, EngineProcess,
    EngineRole, ScreenAudience, WorkspaceScope,
};
use openbot_computer::screen::engine_owner::{ScreenEngineOwner, ScreenEngineState};
use openbot_computer::screen::{SCREEN_VIEWER_PROTOCOL, ScreenHub, ScreenSessionService};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, ChannelId, ComputerGeneration, ComputerId, CredentialPrincipalId, DeploymentId,
    TabId, TenantId,
};
use openbot_contracts::screen::{
    ScreenSessionRequest, ScreenSessionTarget, ScreenViewerBindingRequest,
};
use openbot_domain::identity::session::TrustedOrigins;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::{AuthResolver, SensitiveWriteSecurity, ServerBuilder};
use sha2::{Digest as _, Sha256};
use tokio_tungstenite::tungstenite::Message as ClientMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

const ORIGIN: &str = "https://app.example.test";

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

struct ExactAuth(AuthContext);

#[async_trait]
impl AuthResolver for ExactAuth {
    async fn resolve(&self, _parts: &http::request::Parts) -> Result<AuthContext, AppError> {
        Ok(self.0.clone())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires `cargo xtask engine bundle` and host permission to run confined Electron"]
async fn real_engine_frame_crosses_ticketed_server_binary_websocket() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let bundle_root = workspace.join("target/engine/bundle/electron-43.3.0/macos-arm64");
    let manifest = bundle_root.join("manifest.json");
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&manifest).expect("bundle manifest"))
    );
    let bundle = EngineBundle::open(
        &bundle_root,
        EngineBundleDigest::from_hex(&digest).expect("manifest digest"),
    )
    .expect("verified bundle");

    let auth = AuthContext::for_test(
        DeploymentId::new("screen-server-deployment"),
        TenantId::new("screen-server-tenant"),
        ActorId::new("screen-server-actor"),
        [Role::User],
        AuthGeneration::new(7),
        false,
    );
    let computer_id = ComputerId::new("screen-server-computer");
    let generation = ComputerGeneration::new(1);
    let tab_id = TabId::new("screen-server-tab");
    let root = std::env::temp_dir().join(format!(
        "openbot-screen-server-conformance-{}",
        std::process::id()
    ));
    let profile = root.join("profile");
    let temp = root.join("temp");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&profile).expect("profile");
    fs::create_dir_all(&temp).expect("temp");
    let role = EngineRole::BrowserComputer(ComputerSecurityScope::new(
        auth.tenant().clone(),
        BotId::new("screen-server-bot"),
        CredentialPrincipalId::new("screen-server-principal"),
        WorkspaceScope::Channel(ChannelId::new("screen-server-channel")),
    ));
    let mut process = EngineProcess::launch(EngineLaunchConfig::new(
        bundle,
        role,
        ScreenAudience::from_auth(&auth),
        computer_id.clone(),
        generation,
        &profile,
        &temp,
    ))
    .await
    .expect("engine launch");
    let started = process
        .start_session(tab_id.clone())
        .await
        .expect("engine session");

    let hub = ScreenHub::new(2).expect("hub");
    let control = Arc::new(tokio::sync::Mutex::new(ControlService::new(
        computer_id.clone(),
        tab_id.clone(),
        generation,
        time::OffsetDateTime::now_utc(),
    )));
    let owner = ScreenEngineOwner::attach(process, hub.clone(), control)
        .await
        .expect("attach engine owner and source");
    let mut owner_state = owner.observe();
    let application: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(EmptyChannels)
            .with_screen_sessions(Arc::new(ScreenSessionService::new(hub.clone()))),
    );
    let ticket = match application
        .execute(
            auth.clone(),
            AppCommand::IssueScreenSession(ScreenSessionRequest {
                target: ScreenSessionTarget {
                    computer_id,
                    computer_generation: generation,
                    tab_id: tab_id.clone(),
                },
                binding: ScreenViewerBindingRequest::Server {
                    origin: ORIGIN.to_owned(),
                },
            }),
        )
        .await
        .expect("issue screen ticket")
    {
        AppReply::ScreenSession(ticket) => ticket,
        other => panic!("unexpected screen reply: {other:?}"),
    };
    let router = ServerBuilder::new(application, Arc::new(ExactAuth(auth)))
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).expect("trusted origin"),
        ))
        .with_screen_hub(hub)
        .into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let address = listener.local_addr().expect("server address");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    let mut request = format!("ws://{address}/api/screen")
        .into_client_request()
        .expect("websocket request");
    request
        .headers_mut()
        .insert(http::header::ORIGIN, http::HeaderValue::from_static(ORIGIN));
    request.headers_mut().insert(
        http::header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_str(
            format!("{}, {}", ticket.base_protocol(), ticket.ticket_protocol()).as_str(),
        )
        .expect("protocols"),
    );
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect server");
    let (mut socket, response) = tokio_tungstenite::client_async(request, stream)
        .await
        .expect("screen websocket");
    assert_eq!(
        response.headers()[http::header::SEC_WEBSOCKET_PROTOCOL],
        SCREEN_VIEWER_PROTOCOL
    );
    let message = socket.next().await.expect("frame").expect("valid frame");
    let ClientMessage::Binary(bytes) = message else {
        panic!("screen frame was not binary: {message:?}");
    };
    assert_eq!(&bytes[..8], b"OBSCRN01");
    assert_eq!(&bytes[68..71], &[0xff, 0xd8, 0xff]);
    assert!(
        u64::from_le_bytes(bytes[28..36].try_into().expect("sequence")) >= started.frame.sequence()
    );

    // Real engine + production default liveness: a static screen must still get a host Ping.
    // Flush its matching automatic Pong once; stop reading after that, so ongoing engine output
    // cannot substitute for proof that the viewer is consuming the connection.
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        let mut sequence = u64::from_le_bytes(bytes[28..36].try_into().expect("sequence"));
        loop {
            match socket
                .next()
                .await
                .expect("heartbeat")
                .expect("valid message")
            {
                ClientMessage::Ping(payload) => {
                    assert_eq!(payload.len(), 8);
                    break;
                }
                ClientMessage::Binary(frame) => {
                    assert!(frame.starts_with(b"OBSCRN01"));
                    let next = u64::from_le_bytes(frame[28..36].try_into().expect("sequence"));
                    assert!(
                        next > sequence,
                        "capture resumed with monotonically new frames"
                    );
                    sequence = next;
                }
                other => panic!("unexpected heartbeat message: {other:?}"),
            }
        }
    })
    .await
    .expect("default heartbeat deadline");
    socket.flush().await.expect("matching automatic pong");
    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match socket
                .next()
                .await
                .expect("idle close")
                .expect("valid close")
            {
                ClientMessage::Close(Some(frame)) => {
                    assert_eq!(
                        frame.code,
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy
                    );
                    assert_eq!(frame.reason, "screen_idle");
                    break;
                }
                ClientMessage::Ping(_) | ClientMessage::Binary(_) => {}
                other => panic!("unexpected idle message: {other:?}"),
            }
        }
    })
    .await
    .expect("default idle budget closes connection");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if *owner_state.borrow_and_update() == ScreenEngineState::Paused {
                break;
            }
            owner_state.changed().await.expect("live owner");
        }
    })
    .await
    .expect("socket close stops capture within two seconds");
    let paused = owner.stats().await.expect("paused counters");
    assert_eq!(paused.received_frames(), paused.acknowledged_frames());
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        owner
            .stats()
            .await
            .expect("capture stays stopped")
            .received_frames(),
        paused.received_frames()
    );
    owner.shutdown().await.expect("shutdown engine owner");
    let _ = stop.send(());
    server.await.expect("server task").expect("server result");
    let _ = fs::remove_dir_all(root);
}
