//! Authenticated session status and exact current-session sign-out.

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::header::{CACHE_CONTROL, ORIGIN, SET_COOKIE};
use http::{HeaderMap, HeaderValue, StatusCode};
use openbot_contracts::error::AppError;
use openbot_contracts::ui::SessionStatus;

use crate::auth::{SESSION_COOKIE_NAME, SensitiveAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// `GET /api/me/session`; closed capability only, never a session id/token/hash.
pub async fn status(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
) -> Result<(HeaderMap, Json<SessionStatus>), HttpError> {
    state.auth_resolver().touch(&resolved).await?;
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((
        headers,
        Json(SessionStatus {
            revocable: resolved.has_revocable_session(),
        }),
    ))
}

/// `POST /api/auth/sign-out`; trusted Origin before exact current-session deletion.
pub async fn sign_out(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let origin = headers
        .get(ORIGIN)
        .map(|value| value.to_str().unwrap_or(""));
    state
        .authorize_authenticated_origin(&resolved, origin)
        .await?;
    if !resolved.has_revocable_session() {
        return Err(AppError::RequestConflict {
            resource: "session",
        }
        .into());
    }
    state.auth_resolver().revoke_session(&resolved).await?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        SET_COOKIE,
        clear_session_cookie(state.secure_session_cookie()),
    );
    Ok(response)
}

fn clear_session_cookie(secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    ))
    .expect("fixed cookie name and attributes are a valid header")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use http::Request;
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{ApplicationService, ChannelReader, OpenBotApplication, PortError};
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{AuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

    struct EmptyChannels;

    #[async_trait]
    impl ChannelReader for EmptyChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<openbot_contracts::command::ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone)]
    struct RecordingResolver {
        resolved: ResolvedAuth,
        revocations: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AuthResolver for RecordingResolver {
        async fn resolve(&self, _parts: &http::request::Parts) -> Result<AuthContext, AppError> {
            Ok(self.resolved.context().clone())
        }

        async fn resolve_with_assurance(
            &self,
            _parts: &http::request::Parts,
        ) -> Result<ResolvedAuth, AppError> {
            Ok(self.resolved.clone())
        }

        async fn revoke_session(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
            assert!(resolved.has_revocable_session());
            self.revocations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn resolved(revocable: bool) -> ResolvedAuth {
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
        let live = evaluate_session(
            default_session_lifetime(),
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        ResolvedAuth::from_live_session(context, live, revocable.then(|| "session-1".to_owned()))
    }

    fn app(revocable: bool, secure: bool) -> (axum::Router, Arc<AtomicUsize>) {
        let revocations = Arc::new(AtomicUsize::new(0));
        let resolver = RecordingResolver {
            resolved: resolved(revocable),
            revocations: Arc::clone(&revocations),
        };
        let application: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels));
        let state = ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .with_login_security(
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                secure,
            )
            .build();
        (crate::router(state), revocations)
    }

    async fn send(
        app: axum::Router,
        method: &str,
        uri: &str,
        origin: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(origin) = origin {
            request = request.header(ORIGIN, origin);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn status_origin_revoke_and_cookie_clear_are_exact() {
        let (app, revocations) = app(true, true);
        let (status, headers, body) = send(app.clone(), "GET", "/api/me/session", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"revocable":true}"#);
        assert_eq!(headers[CACHE_CONTROL], "no-store");

        let (status, headers, body) = send(app.clone(), "POST", "/api/auth/sign-out", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("identity_sensitive_write_origin_missing"));
        assert_eq!(revocations.load(Ordering::SeqCst), 0);
        assert!(!headers.contains_key(SET_COOKIE));

        let (status, headers, body) = send(
            app,
            "POST",
            "/api/auth/sign-out",
            Some("https://app.example.test"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(
            headers[SET_COOKIE],
            "openbot_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
    }

    #[tokio::test]
    async fn stateless_single_user_is_explicitly_not_revocable() {
        let (app, revocations) = app(false, false);
        let (status, _, body) = send(app.clone(), "GET", "/api/me/session", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"revocable":false}"#);

        let (status, headers, body) = send(
            app,
            "POST",
            "/api/auth/sign-out",
            Some("https://app.example.test"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("request_conflict"));
        assert_eq!(revocations.load(Ordering::SeqCst), 0);
        assert!(!headers.contains_key(SET_COOKIE));
    }
}
