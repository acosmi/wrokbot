//! Typed and two actual adapter framing checks with a deliberately controlled recording port.
//! Every positive here is a synthetic projection fixture, not a persisted Save, genuine Session
//! resolver, genuine Local installation, or ready SingleUser producer. Genuine PG hosts are
//! exercised in the separate Server/Desktop test children.
#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, ChannelCursor,
    ChannelReader, NoArtifactAdministration, OpenBotApplication, PortError,
};
use openbot_contracts::artifacts::*;
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::request_binding::*;
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_server::auth::FixedAuthResolver;
use openbot_server::{ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const REQUEST: &str = "019a7777-abcd-7abc-8abc-0123456789ab";
const OPERATION: &str = "019a8888-abcd-7abc-8abc-0123456789ab";
const ARTIFACT: &str = "019a9999-abcd-7abc-8abc-0123456789ab";

struct EmptyChannels;
#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("receipt framing must not enumerate channels")
    }
}
fn plain() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("controlled-receipt-framing"),
        TenantId::new("controlled-receipt-tenant"),
        ActorId::new("controlled-receipt-actor"),
        [Role::User],
        AuthGeneration::new(0),
        false,
    )
}
fn input() -> GetArtifactSaveReceipt {
    GetArtifactSaveReceipt {
        request_id: REQUEST.into(),
    }
}
struct ControlledBinding;
impl HostRequestBindingGuard for ControlledBinding {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn bound() -> (RequestBindingOwnerLease, AuthContext) {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = plain();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "controlled-framing-session".into(),
        auth.actor().clone(),
        "controlled-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(ControlledBinding))
        .unwrap();
    (owner, auth.with_verified_request_binding(binding).unwrap())
}
struct ControlledTail(AuthContext);
impl ArtifactReadTailWitness for ControlledTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        if Instant::now() >= deadline {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        if !auth
            .request_binding()
            .zip(self.0.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        Ok(())
    }
}
fn controlled_receipt(
    auth: &AuthContext,
    input: &GetArtifactSaveReceipt,
) -> ArtifactRegistrationReceipt {
    // This is intentionally only a framing fixture, never a claimed actual producer receipt.
    ArtifactRegistrationReceipt {
        operation_id: OPERATION.into(),
        artifact_id: ARTIFACT.into(),
        request_id: input.request_id.clone(),
        owner_actor_id: auth.actor().clone(),
        source_thread_id: ThreadId::new("controlled-thread"),
        source_run_id: RunId::new("controlled-run"),
        source_message_id: "controlled-run:input".into(),
        source_call_seq: None,
        source_attempt_seq: None,
    }
}
struct RecordingPort {
    error: Option<ArtifactReadCurrentError>,
    calls: Mutex<Vec<GetArtifactSaveReceipt>>,
    old_calls: AtomicUsize,
}
#[async_trait]
impl ArtifactAdministration for RecordingPort {
    async fn observe_artifact_save_receipt_current(
        &self,
        auth: &AuthContext,
        input: &GetArtifactSaveReceipt,
        _: Instant,
    ) -> ArtifactSaveReceiptCurrentOutcome {
        self.calls.lock().unwrap().push(input.clone());
        let result = self
            .error
            .map_or_else(|| Ok(controlled_receipt(auth, input)), Err);
        Ok((Box::new(ControlledTail(auth.clone())), result))
    }
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.old_calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactAdministrationError::Unavailable)
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.old_calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactAdministrationError::Unavailable)
    }
}
struct ControlledDesktop {
    protocol: DesktopTauriProtocol,
    assets: PathBuf,
}
impl ControlledDesktop {
    fn new(service: Arc<dyn ApplicationService>, auth: AuthContext) -> Self {
        let assets =
            std::env::temp_dir().join(format!("openbot-receipt-framing-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&assets).unwrap();
        std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").unwrap();
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        let protocol =
            DesktopTauriProtocol::open(&assets, Arc::new(InProcessTransport::new(service)))
                .unwrap();
        protocol.bind_window("main", auth, None).unwrap();
        Self { protocol, assets }
    }
    async fn request(&self, method: Method, uri: &str, body: &str) -> (StatusCode, Value) {
        let response = self
            .protocol
            .handle(
                "main",
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(body.as_bytes().to_vec())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        if method == Method::HEAD {
            assert!(response.body().is_empty());
        }
        let value = if response.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(response.body()).unwrap()
        };
        (response.status(), value)
    }
}
impl Drop for ControlledDesktop {
    fn drop(&mut self) {
        self.protocol.close_request_bindings();
        let removed = std::fs::remove_dir_all(&self.assets);
        assert!(
            removed.is_ok() && !self.assets.exists(),
            "owned framing asset cleanup"
        );
    }
}
async fn http(
    service: Arc<dyn ApplicationService>,
    auth: AuthContext,
    method: Method,
    uri: &str,
    body: &str,
) -> (StatusCode, Value) {
    let state = ServerBuilder::new(service, Arc::new(FixedAuthResolver::granting(auth))).build();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    if method == Method::HEAD {
        assert!(bytes.is_empty());
    }
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}
fn error_wire(error: &AppError) -> Value {
    match error {
        AppError::ArtifactGone { status } => json!({"code":error.code().as_str(),"status":status}),
        _ => json!({"code":error.code().as_str()}),
    }
}
fn route(request: &str) -> String {
    format!("/api/artifacts/save-requests/{request}")
}

#[tokio::test]
async fn typed_and_host_save_receipt_queries_share_closed_projection_and_unsupported_errors() {
    for error in [
        None,
        Some(ArtifactReadCurrentError::NotVisible),
        Some(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Deleted)),
        Some(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Expired)),
        Some(ArtifactReadCurrentError::Unavailable),
        Some(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent,
        )),
        Some(ArtifactReadCurrentError::Host(
            HostRequestBindingError::Unavailable,
        )),
    ] {
        let (_owner, auth) = bound();
        let port = Arc::new(RecordingPort {
            error,
            calls: Mutex::new(Vec::new()),
            old_calls: AtomicUsize::new(0),
        });
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_artifacts(port.clone()));
        let transport = InProcessTransport::new(service.clone());
        assert!(Arc::ptr_eq(transport.service(), &service));
        let desktop = ControlledDesktop::new(service.clone(), auth.clone());
        let aliased = GetArtifactSaveReceipt {
            request_id: REQUEST.to_uppercase(),
        };
        let typed = transport
            .execute(auth.clone(), AppCommand::GetArtifactSaveReceipt(aliased))
            .await;
        let wire = http(
            service.clone(),
            auth.clone(),
            Method::GET,
            &route(&REQUEST.to_uppercase()),
            "",
        )
        .await;
        let local = desktop
            .request(Method::GET, &route(&REQUEST.to_uppercase()), "")
            .await;
        assert_eq!(wire, local);
        match typed {
            Ok(reply) => {
                assert_eq!(wire.0, StatusCode::OK);
                assert_eq!(
                    reply,
                    AppReply::ArtifactRegistrationReceipt(
                        serde_json::from_value(wire.1.clone()).unwrap()
                    )
                );
                assert_eq!(wire.1.as_object().unwrap().len(), 9);
                for field in [
                    "body",
                    "sha256",
                    "byteLength",
                    "status",
                    "handle",
                    "authority",
                    "retry",
                    "notCommitted",
                ] {
                    assert!(wire.1.get(field).is_none());
                }
            }
            Err(error) => {
                assert_eq!(wire.0.as_u16(), error.http_status());
                assert_eq!(wire.1, error_wire(&error));
            }
        }
        assert_eq!(*port.calls.lock().unwrap(), vec![input(), input(), input()]);
        assert_eq!(port.old_calls.load(Ordering::SeqCst), 0);
        for (method, suffix, body, expected) in [
            (Method::GET, "?", "", StatusCode::BAD_REQUEST),
            (
                Method::GET,
                "?ownerActorId=forged",
                "",
                StatusCode::BAD_REQUEST,
            ),
            (Method::GET, "", "{}", StatusCode::BAD_REQUEST),
            (Method::HEAD, "", "", StatusCode::METHOD_NOT_ALLOWED),
            (Method::POST, "", "", StatusCode::METHOD_NOT_ALLOWED),
            (Method::GET, "/extra", "", StatusCode::BAD_REQUEST),
        ] {
            let uri = format!("{}{suffix}", route(REQUEST));
            let wire = http(service.clone(), auth.clone(), method.clone(), &uri, body).await;
            let local = desktop.request(method, &uri, body).await;
            assert_eq!(wire.0, expected);
            assert_eq!(local.0, expected);
            if expected == StatusCode::BAD_REQUEST {
                assert_eq!(wire.1, local.1);
            }
        }
        for raw in [
            "",
            "%ZZ",
            "%2F",
            "%252F",
            " 019a7777-abcd-7abc-8abc-0123456789ab",
            "019a7777-abcd-4abc-8abc-0123456789ab",
        ] {
            let escaped = raw.replace(' ', "%20");
            let uri = route(&escaped);
            assert_eq!(
                http(service.clone(), auth.clone(), Method::GET, &uri, "").await,
                (StatusCode::BAD_REQUEST, json!({"code":"malformed_payload"}))
            );
            assert_eq!(
                desktop.request(Method::GET, &uri, "").await,
                (StatusCode::BAD_REQUEST, json!({"code":"malformed_payload"}))
            );
        }
        assert!(
            serde_json::from_value::<GetArtifactSaveReceipt>(
                json!({"requestId":REQUEST,"sourceRunId":"forged"})
            )
            .is_err()
        );
        assert_eq!(port.calls.lock().unwrap().len(), 3);
        assert_eq!(port.old_calls.load(Ordering::SeqCst), 0);
    }
    // Single decoding accepts the maximum 108-byte encoded canonical UUID; a second encoding
    // still contains '%' after one decoding and must never reach the recording port.
    let (owner, auth) = bound();
    let port = Arc::new(RecordingPort {
        error: None,
        calls: Mutex::new(Vec::new()),
        old_calls: AtomicUsize::new(0),
    });
    let service: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_artifacts(port.clone()));
    let desktop = ControlledDesktop::new(service.clone(), auth.clone());
    let encoded = REQUEST
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<String>();
    assert_eq!(encoded.len(), 108);
    assert_eq!(
        http(
            service.clone(),
            auth.clone(),
            Method::GET,
            &route(&encoded),
            ""
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        desktop.request(Method::GET, &route(&encoded), "").await.0,
        StatusCode::OK
    );
    let doubled = encoded.replace('%', "%25");
    assert_eq!(
        http(
            service.clone(),
            auth.clone(),
            Method::GET,
            &route(&doubled),
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        desktop.request(Method::GET, &route(&doubled), "").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(port.calls.lock().unwrap().len(), 2);
    owner.close();
    let transport = InProcessTransport::new(service.clone());
    assert_eq!(
        transport
            .execute(auth.clone(), AppCommand::GetArtifactSaveReceipt(input()))
            .await,
        Err(AppError::Unauthenticated)
    );
    assert_eq!(
        http(service, auth, Method::GET, &route(REQUEST), "").await,
        (StatusCode::UNAUTHORIZED, json!({"code":"unauthenticated"}))
    );
    desktop.protocol.close_request_bindings();
    assert_eq!(
        desktop.request(Method::GET, &route(REQUEST), "").await,
        (StatusCode::UNAUTHORIZED, json!({"code":"unauthenticated"}))
    );
    assert_eq!(port.calls.lock().unwrap().len(), 2);
    assert_eq!(port.old_calls.load(Ordering::SeqCst), 0);
    let (_owner, auth) = bound();
    let unsupported: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(EmptyChannels).with_artifacts(Arc::new(NoArtifactAdministration)),
    );
    let transport = InProcessTransport::new(unsupported.clone());
    let desktop = ControlledDesktop::new(unsupported.clone(), auth.clone());
    assert!(matches!(
        transport
            .execute(auth.clone(), AppCommand::GetArtifactSaveReceipt(input()))
            .await,
        Err(AppError::DependencyUnavailable { .. })
    ));
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"code":"dependency_unavailable"}),
    );
    assert_eq!(
        http(unsupported, auth, Method::GET, &route(REQUEST), "").await,
        unavailable
    );
    assert_eq!(
        desktop.request(Method::GET, &route(REQUEST), "").await,
        unavailable
    );
    // The original explicit Save POST payload remains its own five-key closed DTO.
    let save = SaveRunMessageTextArtifact {
        request_id: REQUEST.into(),
        source_thread_id: ThreadId::new("controlled-thread"),
        source_run_id: RunId::new("controlled-run"),
        source_message_id: "controlled-run:input".into(),
        expected_sha256: "a".repeat(64),
    };
    let mut save_wire = serde_json::to_value(save).unwrap();
    assert_eq!(save_wire.as_object().unwrap().len(), 5);
    save_wire
        .as_object_mut()
        .unwrap()
        .insert("readOnly".into(), json!(true));
    assert!(serde_json::from_value::<SaveRunMessageTextArtifact>(save_wire).is_err());
}
