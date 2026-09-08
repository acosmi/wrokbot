//! Axum/Tauri framing parity for sandboxed component governance on one ApplicationService.

#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    SandboxedComponentAdministration, SandboxedComponentAdministrationError,
    SandboxedComponentDraft,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, PublishedSandboxedComponents, SandboxedComponentRecord,
    SandboxedComponents, SaveSandboxedComponentRequest,
};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::identity::session::TrustedOrigins;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::auth::{SensitiveWriteSecurity, SingleUserAuthResolver};
use openbot_server::{SINGLE_USER_ACTOR_ID, ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
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

struct FixedSandboxed;

#[async_trait]
impl SandboxedComponentAdministration for FixedSandboxed {
    async fn list_sandboxed_components(
        &self,
        auth: &AuthContext,
    ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
        Ok(SandboxedComponents {
            components: vec![draft_record(auth.actor().as_str())],
        })
    }

    async fn list_published_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
        Ok(PublishedSandboxedComponents {
            components: vec![PublishedSandboxedComponent {
                name: "custom_delivery_eta".to_owned(),
                html: "<p>ETA</p>".to_owned(),
                css: "p{}".to_owned(),
                js_functions: "function draw(){}".to_owned(),
                argument_schema: BTreeMap::from([("type".to_owned(), json!("object"))]),
            }],
        })
    }

    async fn save_sandboxed_component(
        &self,
        auth: &AuthContext,
        draft: &SandboxedComponentDraft,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        Ok(SandboxedComponentRecord {
            name: draft.name.clone(),
            title: draft.title.clone(),
            draft_description: draft.description.clone(),
            draft_html: draft.html.clone(),
            draft_css: draft.css.clone(),
            draft_js_functions: draft.js_functions.clone(),
            draft_argument_schema: draft.argument_schema.clone(),
            published_html: None,
            published_css: None,
            published_js_functions: None,
            published_argument_schema: None,
            sample_arguments: draft.sample_arguments.clone(),
            revision: 0,
            published: false,
            published_at: None,
            authored_by: Some(auth.actor().as_str().to_owned()),
            has_unpublished_changes: false,
        })
    }

    async fn publish_sandboxed_component(
        &self,
        auth: &AuthContext,
        _component_name: &str,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        let mut record = draft_record(auth.actor().as_str());
        record.published_html = Some(record.draft_html.clone());
        record.published_css = Some(record.draft_css.clone());
        record.published_js_functions = Some(record.draft_js_functions.clone());
        record.published_argument_schema = Some(record.draft_argument_schema.clone());
        record.revision = 1;
        record.published = true;
        record.published_at = Some(OffsetDateTime::UNIX_EPOCH);
        Ok(record)
    }

    async fn delete_sandboxed_component(
        &self,
        _auth: &AuthContext,
        _component_name: &str,
    ) -> Result<(), SandboxedComponentAdministrationError> {
        Ok(())
    }
}

fn draft_record(actor: &str) -> SandboxedComponentRecord {
    SandboxedComponentRecord {
        name: "custom_delivery_eta".to_owned(),
        title: "Delivery ETA".to_owned(),
        draft_description: "Delivery estimate".to_owned(),
        draft_html: "<p>ETA</p>".to_owned(),
        draft_css: "p{}".to_owned(),
        draft_js_functions: "function draw(){}".to_owned(),
        draft_argument_schema: BTreeMap::from([("type".to_owned(), json!("object"))]),
        published_html: None,
        published_css: None,
        published_js_functions: None,
        published_argument_schema: None,
        sample_arguments: BTreeMap::from([("days".to_owned(), json!(2))]),
        revision: 0,
        published: false,
        published_at: None,
        authored_by: Some(actor.to_owned()),
        has_unpublished_changes: false,
    }
}

fn admin_auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("openbot-local"),
        TenantId::new("openbot-local"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        [Role::Admin],
        AuthGeneration::new(0),
        true,
    )
}

fn dist() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "openbot-sandboxed-transport-parity-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("index.html"),
        "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
    )
    .unwrap();
    fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
    root
}

async fn axum_response(
    app: axum::Router,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(axum::http::header::ORIGIN, ORIGIN)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn tauri_response(
    protocol: &DesktopTauriProtocol,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let response = protocol
        .handle(
            "main",
            Request::builder()
                .method(method)
                .uri(path)
                .body(body)
                .unwrap(),
        )
        .await;
    (
        response.status(),
        serde_json::from_slice(response.body()).unwrap(),
    )
}

#[tokio::test]
async fn sandboxed_governance_has_exact_axum_tauri_semantic_parity_on_one_application() {
    let application: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(EmptyChannels)
            .with_sandboxed_component_administration(Arc::new(FixedSandboxed)),
    );
    let resolver = SingleUserAuthResolver::new(
        DeploymentId::new("openbot-local"),
        TenantId::new("openbot-local"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        default_session_lifetime(),
    );
    let state = ServerBuilder::new(application.clone(), Arc::new(resolver))
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).unwrap(),
        ))
        .build();
    assert!(core::ptr::addr_eq(
        state.application(),
        application.as_ref()
    ));
    let axum = router(state);

    let transport = Arc::new(InProcessTransport::new(application.clone()));
    assert!(Arc::ptr_eq(transport.service(), &application));
    let root = dist();
    let protocol = DesktopTauriProtocol::open(&root, transport).unwrap();
    protocol
        .bind_window("main", admin_auth(), Some(Duration::from_secs(60)))
        .unwrap();

    let draft = serde_json::to_vec(&SaveSandboxedComponentRequest {
        slug: "delivery_eta".to_owned(),
        title: "Delivery ETA".to_owned(),
        description: "Delivery estimate".to_owned(),
        html: "<p>ETA</p>".to_owned(),
        css: "p{}".to_owned(),
        js_functions: "function draw(){}".to_owned(),
        argument_schema: BTreeMap::from([("type".to_owned(), json!("object"))]),
        sample_arguments: BTreeMap::from([("days".to_owned(), json!(2))]),
    })
    .unwrap();
    let cases = [
        (Method::GET, "/api/sandboxed", Vec::new()),
        (Method::GET, "/api/sandboxed/published", Vec::new()),
        (Method::POST, "/api/sandboxed", draft),
        (
            Method::POST,
            "/api/sandboxed/custom_delivery_eta/publish",
            Vec::new(),
        ),
        (
            Method::DELETE,
            "/api/sandboxed/custom_delivery_eta",
            Vec::new(),
        ),
    ];
    for (method, path, body) in cases {
        let web = axum_response(axum.clone(), method.clone(), path, body.clone()).await;
        let desktop = tauri_response(&protocol, method, path, body).await;
        assert_eq!(web, desktop, "transport drift for {path}");
        assert_eq!(web.0, StatusCode::OK);
    }

    fs::remove_dir_all(root).unwrap();
}
