//! Authenticated actor-scoped remote AG-UI interrupt HTTP framing.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use http::HeaderMap;
use http::header::{CACHE_CONTROL, HeaderValue};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::remote_interrupt::{
    PendingRemoteInterrupts, RemoteInterruptAnswer, RemoteInterruptResolved,
};

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// `GET /api/me/remote-interrupts`; scope comes only from authenticated context.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<PendingRemoteInterrupts>), HttpError> {
    let reply = state
        .application()
        .execute(auth, AppCommand::ListPendingRemoteInterrupts)
        .await?;
    match reply {
        AppReply::PendingRemoteInterrupts(pending) => Ok((no_store(), Json(pending))),
        _ => Err(application_reply_error()),
    }
}

/// `PUT /api/me/remote-interrupts/{request_id}`; Origin is checked before body parsing.
pub async fn put(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(request_id): Path<String>,
    body: Result<Json<RemoteInterruptAnswer>, JsonRejection>,
) -> Result<(HeaderMap, Json<RemoteInterruptResolved>), HttpError> {
    let Json(answer) = body.map_err(|error| {
        tracing::debug!(error = %error, "remote interrupt body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    let reply = state
        .application()
        .execute(
            auth,
            AppCommand::ResolveRemoteInterrupt { request_id, answer },
        )
        .await?;
    match reply {
        AppReply::RemoteInterruptResolved(resolved) => Ok((no_store(), Json(resolved))),
        _ => Err(application_reply_error()),
    }
}

fn application_reply_error() -> HttpError {
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        ChannelReader, OpenBotApplication, PortError, ProviderRemoteInterruptBatch,
        ProviderRemoteResume, ProviderRemoteResumeStatus, RemoteInterruptCoordinator,
        RemoteInterruptError, RemoteInterruptPending, RemoteInterruptPendingInput,
        RemoteInterruptResolutionReceipt, RunExecutionLease,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::remote_interrupt::RemoteInterruptAnswerStatus;
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

    const REQUEST_ID: &str = "018f6f8a-5f4b-7c2d-8a31-111111111111";

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

    #[derive(Default)]
    struct FakeInterrupts {
        resolves: Mutex<
            Vec<(
                String,
                ProviderRemoteResumeStatus,
                Option<serde_json::Value>,
            )>,
        >,
    }

    #[async_trait]
    impl RemoteInterruptCoordinator for FakeInterrupts {
        async fn list_pending(
            &self,
            _auth: &AuthContext,
        ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
            Ok(vec![RemoteInterruptPending::new(
                RemoteInterruptPendingInput {
                    request_id: REQUEST_ID.to_owned(),
                    run_id: "run-1".to_owned(),
                    bot_id: "bot-1".to_owned(),
                    protocol_run_id: "run-1".to_owned(),
                    interrupt_id: "remote-1".to_owned(),
                    untrusted_payload: serde_json::json!({
                        "id":"remote-1",
                        "reason":"confirmation",
                        "message":"Remote asks"
                    }),
                    requested_at: OffsetDateTime::UNIX_EPOCH,
                    expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(30),
                },
            )?])
        }

        async fn resolve(
            &self,
            _auth: &AuthContext,
            request_id: &str,
            status: ProviderRemoteResumeStatus,
            payload: Option<serde_json::Value>,
        ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
            self.resolves.lock().expect("resolve calls").push((
                request_id.to_owned(),
                status,
                payload,
            ));
            RemoteInterruptResolutionReceipt::new(request_id.to_owned(), status, false)
        }

        async fn persist_and_wait(
            &self,
            _lease: &RunExecutionLease,
            _batch: &ProviderRemoteInterruptBatch,
        ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
            Err(RemoteInterruptError::Unavailable)
        }
    }

    fn router(interrupts: Arc<FakeInterrupts>) -> Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let lifetime = default_session_lifetime();
        let live = evaluate_session(
            lifetime,
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        let application =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_remote_interrupts(interrupts));
        let trusted = TrustedOrigins::from_configured(["https://app.example.test"]).unwrap();
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(lifetime, trusted))
            .with_login_security(
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                true,
            )
            .into_router()
    }

    async fn send(
        router: Router,
        method: Method,
        origin: Option<&str>,
        uri: &str,
        body: &'static str,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(uri);
        if !body.is_empty() {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
        }
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        router
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn list_and_resolve_are_no_store_closed_and_origin_precedes_body() {
        let interrupts = Arc::new(FakeInterrupts::default());
        let blocked = send(
            router(interrupts.clone()),
            Method::PUT,
            None,
            &format!("/api/me/remote-interrupts/{REQUEST_ID}"),
            "{",
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        assert!(interrupts.resolves.lock().unwrap().is_empty());

        let listed = send(
            router(interrupts.clone()),
            Method::GET,
            None,
            "/api/me/remote-interrupts",
            "",
        )
        .await;
        assert_eq!(listed.status(), StatusCode::OK);
        assert_eq!(listed.headers()[CACHE_CONTROL], "no-store");
        let page = serde_json::from_slice::<PendingRemoteInterrupts>(
            &to_bytes(listed.into_body(), 16 * 1024).await.unwrap(),
        )
        .unwrap();
        assert_eq!(page.interrupts.len(), 1);
        assert_eq!(page.interrupts[0].request_id, REQUEST_ID);
        assert_eq!(page.interrupts[0].untrusted_reason, "confirmation");

        let resolved = send(
            router(interrupts.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            &format!("/api/me/remote-interrupts/{REQUEST_ID}"),
            r#"{"status":"resolved","payload":{"approved":true}}"#,
        )
        .await;
        assert_eq!(resolved.status(), StatusCode::OK);
        assert_eq!(resolved.headers()[CACHE_CONTROL], "no-store");
        let receipt = serde_json::from_slice::<RemoteInterruptResolved>(
            &to_bytes(resolved.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.request_id, REQUEST_ID);
        assert_eq!(receipt.status, RemoteInterruptAnswerStatus::Resolved);
        assert_eq!(interrupts.resolves.lock().unwrap().len(), 1);

        let smuggled = send(
            router(interrupts.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            &format!("/api/me/remote-interrupts/{REQUEST_ID}"),
            r#"{"status":"cancelled","payload":{"authority":"forged"}}"#,
        )
        .await;
        assert_eq!(smuggled.status(), StatusCode::BAD_REQUEST);
        assert_eq!(interrupts.resolves.lock().unwrap().len(), 1);
    }
}
