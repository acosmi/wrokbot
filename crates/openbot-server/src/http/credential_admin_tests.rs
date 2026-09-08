use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
use crate::http::ServerBuilder;
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
};
use http::{Request, StatusCode};
use openbot_application::credential_admin::{
    CredentialAdministration, CredentialAdministrationError as Error,
};
use openbot_application::cursor::ChannelCursor;
use openbot_application::{ChannelReader, OpenBotApplication, PortError};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::credential_admin::*;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
use openbot_infra::auth::config::default_session_lifetime;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

struct EmptyChannels;
#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<openbot_contracts::command::ChannelSummary>, PortError> {
        Ok(Vec::new())
    }
}
#[derive(Clone, Default)]
struct Credentials(Arc<Mutex<Vec<&'static str>>>);
const ID: &str = "00000000-0000-4000-8000-000000000001";
fn status(input: &CredentialWrite) -> CredentialStatus {
    CredentialStatus {
        id: ID.to_owned(),
        kind: match input.kind() {
            ManualCredentialKind::Model => CredentialRecordKind::Model,
            ManualCredentialKind::Connector => CredentialRecordKind::Connector,
            ManualCredentialKind::Mcp => CredentialRecordKind::Mcp,
        },
        provider: input.provider().to_owned(),
        key_id: input.key_id().to_owned(),
        metadata: input.metadata().clone(),
        revoked_at: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        external_revocation: CredentialExternalRevocation::NotRequested,
    }
}
#[async_trait]
impl CredentialAdministration for Credentials {
    async fn list(
        &self,
        _: &AuthContext,
        _: &CredentialPageRequest,
    ) -> Result<CredentialPage, Error> {
        self.0.lock().unwrap().push("list");
        Ok(CredentialPage {
            credentials: Vec::new(),
            next_cursor: None,
            model_reference: None,
        })
    }
    async fn create(
        &self,
        auth: &AuthContext,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, Error> {
        assert_eq!(auth.actor().as_str(), "admin");
        assert_eq!(input.expose_plaintext(), "FRAMING_CANARY");
        self.0.lock().unwrap().push("create");
        Ok(CredentialWritten {
            credential: status(input),
        })
    }
    async fn rotate(
        &self,
        _: &AuthContext,
        _: &str,
        input: &CredentialWrite,
    ) -> Result<CredentialWritten, Error> {
        self.0.lock().unwrap().push("rotate");
        Ok(CredentialWritten {
            credential: status(input),
        })
    }
    async fn revoke(&self, _: &AuthContext, id: &str) -> Result<CredentialRevoked, Error> {
        self.0.lock().unwrap().push("revoke");
        Ok(CredentialRevoked {
            id: id.to_owned(),
            revoked_at: OffsetDateTime::UNIX_EPOCH,
            external_revocation: CredentialExternalRevocation::Pending,
        })
    }
}
fn router(port: Credentials, role: Option<Role>, fresh: bool) -> Router {
    let generation = AuthGeneration::new(1);
    let now = OffsetDateTime::now_utc();
    let lifetime = default_session_lifetime();
    let resolver = match role {
        None => FixedAuthResolver::rejecting(AppError::Unauthenticated),
        Some(role) => {
            let auth = AuthContext::for_test(
                DeploymentId::new("dep"),
                TenantId::new("tenant"),
                ActorId::new("admin"),
                [role],
                generation,
                false,
            );
            if fresh {
                let live = evaluate_session(
                    lifetime,
                    SessionState::rehydrate(now - Duration::minutes(1), now, generation),
                    generation,
                    now,
                )
                .unwrap();
                FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
                    auth, live, None,
                ))
            } else {
                FixedAuthResolver::granting(auth)
            }
        }
    };
    crate::router(
        ServerBuilder::new(
            Arc::new(OpenBotApplication::new(EmptyChannels).with_credentials(Arc::new(port))),
            Arc::new(resolver),
        )
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            lifetime,
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        ))
        .build(),
    )
}

#[tokio::test]
async fn fresh_admin_origin_is_decided_before_polling_any_credential_body() {
    for (role, fresh, origin, expected) in [
        (
            None,
            false,
            "https://app.example.test",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(Role::User),
            true,
            "https://app.example.test",
            StatusCode::FORBIDDEN,
        ),
        (
            Some(Role::Admin),
            false,
            "https://app.example.test",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(Role::Admin),
            true,
            "https://other.example.test",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let port = Credentials::default();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        let body = Body::from_stream(futures_util::stream::once(async move {
            observed.store(true, Ordering::SeqCst);
            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"not-json"))
        }));
        let response = router(port.clone(), role, fresh)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/credentials")
                    .header("origin", origin)
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(!polled.load(Ordering::SeqCst));
        assert!(port.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn typed_credential_routes_reject_managed_creation_and_return_only_status() {
    let port = Credentials::default();
    let app = router(port.clone(), Some(Role::Admin), true);
    let body = serde_json::json!({"kind":"model","provider":"openai","keyId":"primary","metadata":{"label":"safe"},"plaintext":"FRAMING_CANARY"});
    for kind in ["agent", "mcp_oauth_client", "mcp_user_token"] {
        let mut value = body.clone();
        value["kind"] = serde_json::json!(kind);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/credentials")
                    .header("origin", "https://app.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(port.0.lock().unwrap().is_empty());
    for (path, expected) in [
        ("/api/admin/credentials".to_owned(), StatusCode::CREATED),
        (
            format!("/api/admin/credentials/{ID}/rotate"),
            StatusCode::OK,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("origin", "https://app.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("FRAMING_CANARY"));
        let reply: CredentialWritten = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply.credential.id, ID);
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/admin/credentials/{ID}/revoke"))
                .header("origin", "https://app.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: CredentialRevocationReceipt =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(
        receipt.credential.external_revocation,
        CredentialExternalRevocation::Pending
    );
    assert_eq!(*port.0.lock().unwrap(), ["create", "rotate", "revoke"]);
}
