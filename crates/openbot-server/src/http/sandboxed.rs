//! Sandboxed-component source governance HTTP framing.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use http::header::CACHE_CONTROL;
use http::{HeaderMap, HeaderValue};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponents, SandboxedComponentDeleted, SandboxedComponentResponse,
    SandboxedComponents, SaveSandboxedComponentRequest,
};

use crate::auth::{Authenticated, SensitiveOriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// `GET /api/sandboxed`; application repeats the administrator role check.
pub async fn list_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<SandboxedComponents>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::ListSandboxedComponents)
        .await?
    {
        AppReply::SandboxedComponents(components) => Ok((no_store(), Json(components))),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/sandboxed/published`; authenticated readers receive published source only.
pub async fn published_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<PublishedSandboxedComponents>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::ListPublishedSandboxedComponents)
        .await?
    {
        AppReply::PublishedSandboxedComponents(components) => Ok((no_store(), Json(components))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/sandboxed`; fresh admin and trusted Origin are decided before JSON extraction.
pub async fn create_post(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    body: Result<Json<SaveSandboxedComponentRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<SandboxedComponentResponse>), HttpError> {
    let Json(request) = body.map_err(|error| {
        tracing::debug!(error = %error, "sandboxed component draft body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::SaveSandboxedComponent(request))
        .await?
    {
        AppReply::SandboxedComponent(component) => Ok((no_store(), Json(component))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/sandboxed/{name}/publish`; one action promotes description and source.
pub async fn publish_post(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
) -> Result<(HeaderMap, Json<SandboxedComponentResponse>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::PublishSandboxedComponent {
                component_name: name,
            },
        )
        .await?
    {
        AppReply::SandboxedComponent(component) => Ok((no_store(), Json(component))),
        _ => Err(application_contract_error()),
    }
}

/// `DELETE /api/sandboxed/{name}`; compiled identities are rejected by application and storage.
pub async fn delete(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
) -> Result<(HeaderMap, Json<SandboxedComponentDeleted>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::DeleteSandboxedComponent {
                component_name: name,
            },
        )
        .await?
    {
        AppReply::SandboxedComponentDeleted(deleted) => Ok((no_store(), Json(deleted))),
        _ => Err(application_contract_error()),
    }
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn application_contract_error() -> HttpError {
    tracing::error!("sandboxed component command received mismatched reply");
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        ChannelReader, OpenBotApplication, PortError, SandboxedComponentAdministration,
        SandboxedComponentAdministrationError, SandboxedComponentDraft,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::sandboxed::{PublishedSandboxedComponent, SandboxedComponentRecord};
    use openbot_domain::identity::session::TrustedOrigins;
    use openbot_infra::auth::config::default_session_lifetime;
    use time::OffsetDateTime;
    use tower::ServiceExt as _;

    use crate::auth::{FixedAuthResolver, SensitiveWriteSecurity, SingleUserAuthResolver};
    use crate::http::ServerBuilder;
    use crate::{SINGLE_USER_ACTOR_ID, router};

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

    #[derive(Clone, Default)]
    struct FakeSandboxed {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl SandboxedComponentAdministration for FakeSandboxed {
        async fn list_sandboxed_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
            self.calls.lock().unwrap().push("list".to_owned());
            Ok(SandboxedComponents {
                components: vec![draft_record("actor")],
            })
        }

        async fn list_published_sandboxed_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
            self.calls.lock().unwrap().push("published".to_owned());
            Ok(PublishedSandboxedComponents {
                components: vec![PublishedSandboxedComponent {
                    name: "custom_delivery_eta".to_owned(),
                    html: "<p>ETA</p>".to_owned(),
                    css: "p{}".to_owned(),
                    js_functions: "function draw(){}".to_owned(),
                    argument_schema: BTreeMap::new(),
                }],
            })
        }

        async fn save_sandboxed_component(
            &self,
            auth: &AuthContext,
            draft: &SandboxedComponentDraft,
        ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("save:{}", draft.name));
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
            component_name: &str,
        ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("publish:{component_name}"));
            Ok(published_record(auth.actor().as_str()))
        }

        async fn delete_sandboxed_component(
            &self,
            _auth: &AuthContext,
            component_name: &str,
        ) -> Result<(), SandboxedComponentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete:{component_name}"));
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
            draft_argument_schema: BTreeMap::new(),
            published_html: None,
            published_css: None,
            published_js_functions: None,
            published_argument_schema: None,
            sample_arguments: BTreeMap::new(),
            revision: 0,
            published: false,
            published_at: None,
            authored_by: Some(actor.to_owned()),
            has_unpublished_changes: false,
        }
    }

    fn published_record(actor: &str) -> SandboxedComponentRecord {
        let mut record = draft_record(actor);
        record.published_html = Some(record.draft_html.clone());
        record.published_css = Some(record.draft_css.clone());
        record.published_js_functions = Some(record.draft_js_functions.clone());
        record.published_argument_schema = Some(record.draft_argument_schema.clone());
        record.revision = 1;
        record.published = true;
        record.published_at = Some(OffsetDateTime::UNIX_EPOCH);
        record
    }

    fn security() -> SensitiveWriteSecurity {
        SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        )
    }

    fn application(sandboxed: FakeSandboxed) -> Arc<dyn openbot_application::ApplicationService> {
        Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_sandboxed_component_administration(Arc::new(sandboxed)),
        )
    }

    fn admin_router(sandboxed: FakeSandboxed) -> axum::Router {
        let resolver = SingleUserAuthResolver::new(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new(SINGLE_USER_ACTOR_ID),
            default_session_lifetime(),
        );
        router(
            ServerBuilder::new(application(sandboxed), Arc::new(resolver))
                .with_sensitive_write_security(security())
                .build(),
        )
    }

    fn user_router(sandboxed: FakeSandboxed) -> axum::Router {
        let auth = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("user"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        );
        router(
            ServerBuilder::new(
                application(sandboxed),
                Arc::new(FixedAuthResolver::granting(auth)),
            )
            .with_sensitive_write_security(security())
            .build(),
        )
    }

    async fn send(
        router: axum::Router,
        method: Method,
        path: &str,
        origin: Option<&str>,
        body: Body,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router.oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, headers, value)
    }

    #[tokio::test]
    async fn reads_are_role_scoped_no_store_and_published_never_contains_draft_or_sample() {
        let sandboxed = FakeSandboxed::default();
        let (status, _, _) = send(
            user_router(sandboxed.clone()),
            Method::GET,
            "/api/sandboxed",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(sandboxed.calls.lock().unwrap().is_empty());

        let (status, headers, value) = send(
            user_router(sandboxed.clone()),
            Method::GET,
            "/api/sandboxed/published",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        let encoded = value.to_string();
        assert!(encoded.contains("published") || encoded.contains("custom_delivery_eta"));
        assert!(!encoded.contains("draftHtml"));
        assert!(!encoded.contains("sampleArguments"));
        assert_eq!(&*sandboxed.calls.lock().unwrap(), &["published"]);
    }

    #[tokio::test]
    async fn trusted_fresh_admin_precedes_body_then_save_publish_delete_use_typed_commands() {
        let sandboxed = FakeSandboxed::default();
        let (status, _, value) = send(
            admin_router(sandboxed.clone()),
            Method::POST,
            "/api/sandboxed",
            None,
            Body::from("{"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["code"], "identity_sensitive_write_origin_missing");
        assert!(sandboxed.calls.lock().unwrap().is_empty());

        let (status, _, value) = send(
            admin_router(sandboxed.clone()),
            Method::POST,
            "/api/sandboxed",
            Some("https://app.example.test"),
            Body::from("{"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["code"], "malformed_payload");

        let body = serde_json::to_vec(&SaveSandboxedComponentRequest {
            slug: "delivery_eta".to_owned(),
            title: "Delivery ETA".to_owned(),
            description: "Delivery estimate".to_owned(),
            html: "<p>ETA</p>".to_owned(),
            css: "p{}".to_owned(),
            js_functions: "function draw(){}".to_owned(),
            argument_schema: BTreeMap::new(),
            sample_arguments: BTreeMap::new(),
        })
        .unwrap();
        let (status, headers, value) = send(
            admin_router(sandboxed.clone()),
            Method::POST,
            "/api/sandboxed",
            Some("https://app.example.test"),
            Body::from(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(value["component"]["name"], "custom_delivery_eta");

        let (status, _, value) = send(
            admin_router(sandboxed.clone()),
            Method::POST,
            "/api/sandboxed/custom_delivery_eta/publish",
            Some("https://app.example.test"),
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["component"]["revision"], 1);

        let (status, _, value) = send(
            admin_router(sandboxed.clone()),
            Method::DELETE,
            "/api/sandboxed/custom_delivery_eta",
            Some("https://app.example.test"),
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["ok"], true);
        assert_eq!(
            &*sandboxed.calls.lock().unwrap(),
            &[
                "save:custom_delivery_eta",
                "publish:custom_delivery_eta",
                "delete:custom_delivery_eta"
            ]
        );
    }
}
