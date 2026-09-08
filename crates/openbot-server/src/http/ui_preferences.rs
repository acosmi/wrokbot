//! Authenticated Server UI preference framing and non-sensitive mirror cookie.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use http::header::{CACHE_CONTROL, SET_COOKIE};
use http::{HeaderMap, HeaderValue};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::ui::{UiPreferences, UpdateUiPreferences};

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

use super::static_app::preference_cookie;

/// `GET /api/me/preferences`; exact actor scope and no browser cache.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    request_headers: HeaderMap,
) -> Result<(HeaderMap, Json<UiPreferences>), HttpError> {
    let preferences = preference_reply(
        state
            .application()
            .execute(auth, AppCommand::GetUiPreferences)
            .await?,
    )?;
    Ok((
        response_headers(&state, preferences, &request_headers),
        Json(preferences),
    ))
}

/// `PUT /api/me/preferences`; same-origin guard runs before closed body parsing.
pub async fn put(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    request_headers: HeaderMap,
    body: Result<Json<UpdateUiPreferences>, JsonRejection>,
) -> Result<(HeaderMap, Json<UiPreferences>), HttpError> {
    let Json(update) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "UI preference body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    let preferences = preference_reply(
        state
            .application()
            .execute(auth, AppCommand::UpdateUiPreferences(update))
            .await?,
    )?;
    Ok((
        response_headers(&state, preferences, &request_headers),
        Json(preferences),
    ))
}

fn preference_reply(reply: AppReply) -> Result<UiPreferences, HttpError> {
    match reply {
        AppReply::UiPreferences(preferences) => Ok(preferences),
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

fn response_headers(
    state: &ServerState,
    preferences: UiPreferences,
    request_headers: &HeaderMap,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        SET_COOKIE,
        preference_cookie(preferences, request_headers, state.secure_session_cookie()),
    );
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
        ChannelReader, OpenBotApplication, PortError, UiPreferenceAdministration,
        UiPreferenceAdministrationError,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::ui::{UiLocale, UiTheme};
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

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
    struct FakePreferences {
        stored: Arc<Mutex<UiPreferences>>,
        updates: Arc<Mutex<Vec<UpdateUiPreferences>>>,
    }

    #[async_trait]
    impl UiPreferenceAdministration for FakePreferences {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            Ok(*self.stored.lock().unwrap())
        }

        async fn update(
            &self,
            _auth: &AuthContext,
            update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.updates.lock().unwrap().push(update);
            let mut stored = self.stored.lock().unwrap();
            stored.theme = update.theme.or(stored.theme);
            stored.locale = update.locale.or(stored.locale);
            Ok(*stored)
        }
    }

    fn router(preferences: FakePreferences) -> Router {
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
        let application = Arc::new(
            OpenBotApplication::new(EmptyChannels).with_ui_preferences(Arc::new(preferences)),
        );
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
        cookie: Option<&str>,
        accept_language: Option<&str>,
        body: &'static str,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri("/api/me/preferences");
        if !body.is_empty() {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
        }
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        if let Some(cookie) = cookie {
            request = request.header(http::header::COOKIE, cookie);
        }
        if let Some(language) = accept_language {
            request = request.header(http::header::ACCEPT_LANGUAGE, language);
        }
        router
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn preferences_are_typed_same_origin_and_mirrored_to_one_closed_cookie() {
        let preferences = FakePreferences::default();
        let get = send(
            router(preferences.clone()),
            Method::GET,
            None,
            None,
            Some("en;q=.2, zh-CN;q=.9"),
            "",
        )
        .await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            get.headers()[SET_COOKIE],
            "openbot-ui=v1.system.zh-CN; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly; Secure"
        );
        assert_eq!(
            serde_json::from_slice::<UiPreferences>(
                &to_bytes(get.into_body(), 1024).await.unwrap()
            )
            .unwrap(),
            UiPreferences::default()
        );

        let before_parse = send(
            router(preferences.clone()),
            Method::PUT,
            None,
            None,
            None,
            "{",
        )
        .await;
        assert_eq!(before_parse.status(), StatusCode::FORBIDDEN);
        assert!(preferences.updates.lock().unwrap().is_empty());

        let extra = send(
            router(preferences.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            None,
            None,
            r#"{"theme":"dark","actor":"admin"}"#,
        )
        .await;
        assert_eq!(extra.status(), StatusCode::BAD_REQUEST);
        assert!(preferences.updates.lock().unwrap().is_empty());

        let put = send(
            router(preferences.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            Some("openbot-ui=v1.system.zh-CN"),
            None,
            r#"{"theme":"dark"}"#,
        )
        .await;
        assert_eq!(put.status(), StatusCode::OK);
        assert_eq!(
            put.headers()[SET_COOKIE],
            "openbot-ui=v1.dark.zh-CN; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly; Secure"
        );
        assert_eq!(
            serde_json::from_slice::<UiPreferences>(
                &to_bytes(put.into_body(), 1024).await.unwrap()
            )
            .unwrap(),
            UiPreferences {
                theme: Some(UiTheme::Dark),
                locale: None,
            }
        );
        assert_eq!(
            preferences.updates.lock().unwrap().as_slice(),
            &[UpdateUiPreferences {
                theme: Some(UiTheme::Dark),
                locale: None,
            }]
        );

        let locale = send(
            router(preferences.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            None,
            Some("en"),
            r#"{"locale":"en"}"#,
        )
        .await;
        assert_eq!(locale.status(), StatusCode::OK);
        assert!(
            locale.headers()[SET_COOKIE]
                .to_str()
                .unwrap()
                .starts_with("openbot-ui=v1.dark.en;")
        );
        assert_eq!(
            preferences.stored.lock().unwrap().locale,
            Some(UiLocale::En)
        );
    }
}
