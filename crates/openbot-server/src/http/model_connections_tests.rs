use super::*;
use crate::{
    auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity},
    http::ServerBuilder,
};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
};
use http::Request;
use openbot_application::{
    ChannelReader, OpenBotApplication, PortError,
    cursor::ChannelCursor,
    model_connections::{ModelConnectionAdministration, ModelConnectionError as Error},
};
use openbot_contracts::{
    auth::{AuthContext, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
};
use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
use openbot_infra::auth::config::default_session_lifetime;
use serde_json::json;
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
struct Connections(Arc<Mutex<usize>>);
fn row() -> ModelConnection {
    ModelConnection {
        id: "00000000-0000-7000-8000-000000000001".to_owned(),
        source: ModelConnectionSource::Custom,
        name: "Test".to_owned(),
        protocol: CustomModelProtocol::OpenaiChatCompletions,
        endpoint: "https://example.test/v1/chat/completions".to_owned(),
        model: "model".to_owned(),
        enabled: true,
        revision: 1,
        has_credential: true,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}
#[async_trait]
impl ModelConnectionAdministration for Connections {
    async fn list(
        &self,
        auth: &AuthContext,
        _: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, Error> {
        assert_eq!(auth.actor().as_str(), "owner");
        Ok(ModelConnectionPage {
            connections: vec![row()],
            next_cursor: None,
        })
    }
    async fn get(&self, _: &AuthContext, _: &str) -> Result<ModelConnection, Error> {
        Ok(row())
    }
    async fn create(
        &self,
        auth: &AuthContext,
        input: &CreateModelConnection,
    ) -> Result<ModelConnection, Error> {
        assert_eq!(auth.actor().as_str(), "owner");
        assert_eq!(input.api_key.expose(), "MODEL_SECRET_CANARY");
        *self.0.lock().unwrap() += 1;
        Ok(row())
    }
    async fn update(
        &self,
        _: &AuthContext,
        _: &str,
        _: &UpdateModelConnection,
    ) -> Result<ModelConnection, Error> {
        Ok(row())
    }
    async fn delete(
        &self,
        _: &AuthContext,
        id: &str,
        _: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, Error> {
        Ok(ModelConnectionDeleted {
            id: id.to_owned(),
            revision: 2,
            deleted_at: OffsetDateTime::UNIX_EPOCH,
        })
    }
}
fn router(port: Connections, authenticated: bool, fresh: bool) -> Router {
    let generation = AuthGeneration::new(7);
    let now = OffsetDateTime::now_utc();
    let lifetime = default_session_lifetime();
    let resolver = if !authenticated {
        FixedAuthResolver::rejecting(AppError::Unauthenticated)
    } else {
        let auth = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("owner"),
            [Role::User],
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
            FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(auth, live, None))
        } else {
            FixedAuthResolver::granting(auth)
        }
    };
    crate::router(
        ServerBuilder::new(
            Arc::new(OpenBotApplication::new(EmptyChannels).with_model_connections(Arc::new(port))),
            Arc::new(resolver),
        )
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            lifetime,
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        ))
        .build(),
    )
}
fn body() -> serde_json::Value {
    json!({"name":"Test","protocol":"openai_chat_completions","endpoint":"https://example.test/v1","model":"model","enabled":true,"apiKey":"MODEL_SECRET_CANARY"})
}

#[tokio::test]
async fn ordinary_owner_can_create_and_read_without_a_secret_response() {
    let port = Connections::default();
    let app = router(port.clone(), true, true);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/me/model-connections")
                .header("origin", "https://app.example.test")
                .header("content-type", "application/json")
                .body(Body::from(body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["source"], "custom");
    assert!(value.get("apiKey").is_none());
    assert!(!String::from_utf8_lossy(&bytes).contains("MODEL_SECRET_CANARY"));
    assert_eq!(*port.0.lock().unwrap(), 1);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/me/model-connections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_freshness_and_origin_reject_before_secret_body_poll() {
    for (authenticated, fresh, origin, expected) in [
        (
            false,
            false,
            "https://app.example.test",
            StatusCode::UNAUTHORIZED,
        ),
        (
            true,
            false,
            "https://app.example.test",
            StatusCode::UNAUTHORIZED,
        ),
        (
            true,
            true,
            "https://evil.example.test",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let port = Connections::default();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        let body = Body::from_stream(futures_util::stream::once(async move {
            observed.store(true, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                b"not-json-MODEL_SECRET_CANARY",
            ))
        }));
        let response = router(port.clone(), authenticated, fresh)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/model-connections")
                    .header("origin", origin)
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(!polled.load(Ordering::SeqCst));
        assert_eq!(*port.0.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn unknown_authority_fields_and_bad_endpoint_never_reach_port() {
    for (field, value) in [
        ("owner", json!("other")),
        ("source", json!("gateway")),
        (
            "endpoint",
            json!("https://user:MODEL_SECRET_CANARY@example.test"),
        ),
        ("apiKey", json!("MODEL_SECRET_CANARY\n")),
    ] {
        let port = Connections::default();
        let mut input = body();
        input[field] = value;
        let response = router(port.clone(), true, true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/model-connections")
                    .header("origin", "https://app.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(*port.0.lock().unwrap(), 0);
        let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("MODEL_SECRET_CANARY"));
    }
    let response = router(Connections::default(), true, true)
        .oneshot(
            Request::builder()
                .uri("/api/me/model-connections?owner=other")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn owner_get_update_and_delete_use_closed_routes_and_no_store() {
    let app = router(Connections::default(), true, true);
    let endpoint = "/api/me/model-connections/00000000-0000-7000-8000-000000000001";
    let mut replacement = body();
    replacement.as_object_mut().unwrap().remove("apiKey");
    replacement["expectedRevision"] = json!(1);
    for (method, body) in [
        ("GET", String::new()),
        ("PUT", replacement.to_string()),
        ("DELETE", json!({"expectedRevision":1}).to_string()),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(endpoint)
                    .header("origin", "https://app.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("{endpoint}?owner=other"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
