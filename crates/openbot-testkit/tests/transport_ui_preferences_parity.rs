//! Preference framing through one real ApplicationService and a synthetic authoritative port.
//! The fixed fixture does not persist paired writes and makes no PostgreSQL or UI timing claim.

#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    UiPreferenceAdministration, UiPreferenceAdministrationError,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::identity::session::TrustedOrigins;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::auth::{FixedAuthResolver, SensitiveWriteSecurity};
use openbot_server::{ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ORIGIN: &str = "https://app.example.test";
const PATH: &str = "/api/me/preferences";
static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct EmptyChannels;

#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct SyntheticPreferences {
    current: Mutex<UiPreferences>,
    unavailable: Mutex<bool>,
    calls: Mutex<Vec<(ActorId, UpdateUiPreferences)>>,
}

impl SyntheticPreferences {
    fn configure(&self, current: UiPreferences) {
        *self.current.lock().unwrap() = current;
        *self.unavailable.lock().unwrap() = false;
        self.calls.lock().unwrap().clear();
    }
}

#[async_trait]
impl UiPreferenceAdministration for SyntheticPreferences {
    async fn get(&self, _: &AuthContext) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        if *self.unavailable.lock().unwrap() {
            return Err(UiPreferenceAdministrationError::Unavailable);
        }
        Ok(*self.current.lock().unwrap())
    }

    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        self.calls
            .lock()
            .unwrap()
            .push((auth.actor().clone(), update));
        if *self.unavailable.lock().unwrap() {
            return Err(UiPreferenceAdministrationError::Unavailable);
        }
        let current = *self.current.lock().unwrap();
        let revision = match current.revision {
            Some(revision) if update.expected_revision != Some(revision) => {
                return Err(UiPreferenceAdministrationError::StaleSnapshot(
                    current.revision_snapshot().unwrap(),
                ));
            }
            Some(revision) => revision
                .checked_add(1)
                .ok_or(UiPreferenceAdministrationError::Corrupt { field: "revision" })?,
            None if update.expected_revision.is_some() => {
                return Err(UiPreferenceAdministrationError::NotVisible);
            }
            None => 1,
        };
        Ok(UiPreferences {
            theme: update.theme.or(current.theme),
            locale: update.locale.or(current.locale),
            revision: Some(revision),
            updated_at: Some(OffsetDateTime::UNIX_EPOCH),
        })
    }
}

fn stored(revision: i64) -> UiPreferences {
    UiPreferences {
        theme: Some(UiTheme::Dark),
        locale: Some(UiLocale::ZhCn),
        revision: Some(revision),
        updated_at: Some(OffsetDateTime::UNIX_EPOCH),
    }
}

fn web_router(application: Arc<dyn ApplicationService>, auth: &AuthContext) -> axum::Router {
    // No fresh-login assurance: the existing preference contract admits signed-in members.
    let state = ServerBuilder::new(
        application.clone(),
        Arc::new(FixedAuthResolver::granting(auth.clone())),
    )
    .with_sensitive_write_security(SensitiveWriteSecurity::new(
        default_session_lifetime(),
        TrustedOrigins::from_configured([ORIGIN]).unwrap(),
    ))
    .build();
    assert!(core::ptr::addr_eq(
        state.application(),
        application.as_ref()
    ));
    router(state)
}

async fn web_response(
    app: axum::Router,
    method: Method,
    body: Vec<u8>,
    origin: &str,
) -> (StatusCode, Value, bool) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(PATH)
                .header(header::ORIGIN, origin)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let cookie = response.headers().contains_key(header::SET_COOKIE);
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    (status, body, cookie)
}

async fn pair(
    app: axum::Router,
    protocol: &DesktopTauriProtocol,
    method: Method,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let web = web_response(app, method.clone(), body.clone(), ORIGIN).await;
    let desktop = protocol
        .handle(
            "member",
            Request::builder()
                .method(method)
                .uri(PATH)
                .body(body)
                .unwrap(),
        )
        .await;
    assert_eq!(desktop.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        (web.0, &web.1),
        (
            desktop.status(),
            &serde_json::from_slice::<Value>(desktop.body()).unwrap()
        ),
        "preference transport framing drift"
    );
    if web.0.is_client_error() || web.0.is_server_error() {
        assert!(!web.2, "failed writes must not project a mirror cookie");
    }
    (web.0, web.1)
}

#[tokio::test]
async fn preference_cas_has_exact_axum_tauri_parity_on_the_same_application() {
    let preferences = Arc::new(SyntheticPreferences::default());
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_ui_preferences(preferences.clone()));
    let member = AuthContext::for_test(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [Role::User],
        AuthGeneration::new(7),
        false,
    );
    let web = web_router(application.clone(), &member);
    let transport = Arc::new(InProcessTransport::new(application.clone()));
    assert!(Arc::ptr_eq(transport.service(), &application));
    let root = std::env::temp_dir().join(format!(
        "openbot-preferences-parity-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").unwrap();
    fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
    let protocol = DesktopTauriProtocol::open(&root, transport).unwrap();
    protocol
        .bind_window("member", member.clone(), None)
        .unwrap();

    assert_eq!(
        pair(web.clone(), &protocol, Method::GET, Vec::new()).await,
        (
            StatusCode::OK,
            serde_json::to_value(UiPreferences::default()).unwrap()
        )
    );
    for (current, body, expected) in [
        (
            UiPreferences::default(),
            json!({"theme":"light"}),
            UiPreferences {
                theme: Some(UiTheme::Light),
                locale: None,
                revision: Some(1),
                updated_at: Some(OffsetDateTime::UNIX_EPOCH),
            },
        ),
        (
            stored(4),
            json!({"locale":"en","expectedRevision":4}),
            UiPreferences {
                locale: Some(UiLocale::En),
                revision: Some(5),
                ..stored(4)
            },
        ),
    ] {
        preferences.configure(current);
        let update: UpdateUiPreferences = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(
            pair(
                web.clone(),
                &protocol,
                Method::PUT,
                serde_json::to_vec(&body).unwrap()
            )
            .await,
            (StatusCode::OK, serde_json::to_value(expected).unwrap())
        );
        assert_eq!(
            *preferences.calls.lock().unwrap(),
            [
                (member.actor().clone(), update),
                (member.actor().clone(), update)
            ]
        );
        assert_eq!(*preferences.current.lock().unwrap(), current);
    }

    let current = stored(4);
    for expected in [None, Some(1), Some(i64::MAX)] {
        preferences.configure(current);
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Light),
            locale: None,
            expected_revision: expected,
        };
        let (status, body) = pair(
            web.clone(),
            &protocol,
            Method::PUT,
            serde_json::to_vec(&update).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body,
            serde_json::to_value(current.revision_snapshot().unwrap()).unwrap()
        );
        assert_eq!(body.as_object().unwrap().len(), 3);
        assert_eq!(preferences.calls.lock().unwrap().len(), 2);
    }
    preferences.configure(UiPreferences::default());
    assert_eq!(
        pair(
            web.clone(),
            &protocol,
            Method::PUT,
            br#"{"theme":"light","expectedRevision":9223372036854775807}"#.to_vec()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(preferences.calls.lock().unwrap().len(), 2);
    preferences.configure(stored(i64::MAX));
    assert_eq!(
        pair(
            web.clone(),
            &protocol,
            Method::PUT,
            br#"{"theme":"light","expectedRevision":9223372036854775807}"#.to_vec()
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );

    for body in [
        br#"{"theme":"light","expectedRevision":0}"#.as_slice(),
        br#"{"theme":"light","expectedRevision":"4"}"#.as_slice(),
        br#"{"theme":"light","expectedRevision":4,"revision":99}"#.as_slice(),
    ] {
        preferences.configure(current);
        assert_eq!(
            pair(web.clone(), &protocol, Method::PUT, body.to_vec())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert!(preferences.calls.lock().unwrap().is_empty());
    }

    preferences.configure(current);
    *preferences.unavailable.lock().unwrap() = true;
    assert_eq!(
        pair(
            web.clone(),
            &protocol,
            Method::PUT,
            br#"{"theme":"light","expectedRevision":9223372036854775807}"#.to_vec()
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(preferences.calls.lock().unwrap().len(), 2);
    preferences.configure(current);
    assert_eq!(
        web_response(
            web,
            Method::PUT,
            b"malformed".to_vec(),
            "https://attacker.example.test"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let unbound = protocol
        .handle(
            "unbound",
            Request::builder()
                .method(Method::PUT)
                .uri(PATH)
                .body(b"malformed".to_vec())
                .unwrap(),
        )
        .await;
    assert_eq!(unbound.status(), StatusCode::UNAUTHORIZED);
    assert!(preferences.calls.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}
