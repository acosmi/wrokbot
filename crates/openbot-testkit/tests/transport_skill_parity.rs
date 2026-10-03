//! Skill editing framing through one real ApplicationService and a synthetic MCP port.
//! The port returns a fixed authoritative fixture for each pair, without persistence or PG claims.

#![cfg(any(target_os = "macos", target_os = "windows"))]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, McpConnectionAdministration,
    McpConnectionError, OpenBotApplication, PortError,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::mcp::{
    McpAdminSkill, McpConnectionDisconnected, McpConnections, McpOAuthAuthorization,
    McpOAuthClientRegistered, McpOAuthClientRegistration, McpOAuthReturnTo,
    PluginMutationAcknowledged, PluginSkillMutation, PluginSkills,
};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
use openbot_server::{ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ORIGIN: &str = "https://app.example.test";
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Save(ActorId, PluginSkillMutation),
    Delete(ActorId, String, i64),
}

#[derive(Default)]
struct SyntheticSkills {
    current: Mutex<Option<McpAdminSkill>>,
    calls: Mutex<Vec<Call>>,
}

impl SyntheticSkills {
    fn configure(&self, current: Option<McpAdminSkill>) {
        *self.current.lock().unwrap() = current;
        self.calls.lock().unwrap().clear();
    }

    fn authorized_current(
        &self,
        auth: &AuthContext,
    ) -> Result<Option<McpAdminSkill>, McpConnectionError> {
        let current = self.current.lock().unwrap().clone();
        if current.as_ref().is_some_and(|skill| {
            !auth.has_role(Role::Admin)
                && skill.owner_user_id.as_deref() != Some(auth.actor().as_str())
        }) {
            return Err(McpConnectionError::NotVisible);
        }
        Ok(current)
    }
}

#[async_trait]
impl McpConnectionAdministration for SyntheticSkills {
    async fn list_connections(
        &self,
        _: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn begin_oauth(
        &self,
        _: &AuthContext,
        _: &str,
        _: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn disconnect(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn register_oauth_client(
        &self,
        _: &AuthContext,
        _: &str,
        _: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }

    async fn save_skill(
        &self,
        auth: &AuthContext,
        mutation: &PluginSkillMutation,
    ) -> Result<PluginSkills, McpConnectionError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Save(auth.actor().clone(), mutation.clone()));
        let current = self.authorized_current(auth)?;
        let mut saved = match current {
            Some(skill) => {
                if skill.slug != mutation.slug {
                    return Err(McpConnectionError::NotVisible);
                }
                if mutation.expected_revision != Some(skill.revision) {
                    return Err(McpConnectionError::StaleSnapshot(
                        skill.revision_snapshot().unwrap(),
                    ));
                }
                skill
            }
            None if mutation.expected_revision.is_some() => {
                return Err(McpConnectionError::NotVisible);
            }
            None => current_skill(
                (!mutation.deployment_wide).then(|| auth.actor().as_str()),
                0,
            ),
        };
        saved.revision = saved
            .revision
            .checked_add(1)
            .ok_or(McpConnectionError::Conflict { resource: "skill" })?;
        saved.slug.clone_from(&mutation.slug);
        saved.title.clone_from(&mutation.title);
        saved.summary.clone_from(&mutation.summary);
        saved.instructions.clone_from(&mutation.instructions);
        Ok(PluginSkills {
            skills: vec![saved],
        })
    }

    async fn remove_skill(
        &self,
        auth: &AuthContext,
        slug: &str,
        expected_revision: i64,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        self.calls.lock().unwrap().push(Call::Delete(
            auth.actor().clone(),
            slug.to_owned(),
            expected_revision,
        ));
        let skill = self
            .authorized_current(auth)?
            .ok_or(McpConnectionError::NotVisible)?;
        if skill.slug != slug {
            return Err(McpConnectionError::NotVisible);
        }
        if expected_revision != skill.revision {
            return Err(McpConnectionError::StaleSnapshot(
                skill.revision_snapshot().unwrap(),
            ));
        }
        Ok(PluginMutationAcknowledged::success())
    }
}

fn current_skill(owner: Option<&str>, revision: i64) -> McpAdminSkill {
    McpAdminSkill {
        id: "skill-row".into(),
        slug: "review".into(),
        owner_user_id: owner.map(str::to_owned),
        title: "Original".into(),
        summary: "Original summary".into(),
        instructions: "Original instruction".into(),
        origin: "yours".into(),
        installed_by: Some("installer".into()),
        revision,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        granted_to: vec!["bot-1".into()],
    }
}

fn auth(role: Role) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        [role],
        AuthGeneration::new(7),
        false,
    )
}

fn web_router(
    application: Arc<dyn ApplicationService>,
    actor: Option<(&AuthContext, bool)>,
) -> axum::Router {
    let lifetime = default_session_lifetime();
    let resolver = match actor {
        Some((actor, true)) => {
            let now = OffsetDateTime::now_utc();
            let live = evaluate_session(
                lifetime,
                SessionState::rehydrate(
                    now - time::Duration::minutes(1),
                    now,
                    actor.auth_generation(),
                ),
                actor.auth_generation(),
                now,
            )
            .unwrap();
            FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
                actor.clone(),
                live,
                None,
            ))
        }
        Some((actor, false)) => FixedAuthResolver::granting(actor.clone()),
        None => FixedAuthResolver::rejecting(AppError::Unauthenticated),
    };
    let state = ServerBuilder::new(application.clone(), Arc::new(resolver))
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            lifetime,
            TrustedOrigins::from_configured([ORIGIN]).unwrap(),
        ))
        .build();
    assert!(core::ptr::addr_eq(
        state.application(),
        application.as_ref()
    ));
    router(state)
}

fn dist() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "openbot-skill-transport-parity-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").unwrap();
    fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
    root
}

async fn web_response(
    app: axum::Router,
    method: Method,
    path: &str,
    body: Vec<u8>,
    origin: &str,
) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(axum::http::header::ORIGIN, origin)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 256 * 1024).await.unwrap()).unwrap(),
    )
}

async fn pair(
    app: axum::Router,
    protocol: &DesktopTauriProtocol,
    window: &str,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let web = web_response(app, method.clone(), path, body.clone(), ORIGIN).await;
    let desktop = protocol
        .handle(
            window,
            Request::builder()
                .method(method)
                .uri(path)
                .body(body)
                .unwrap(),
        )
        .await;
    assert_eq!(
        desktop.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    assert_eq!(
        web,
        (
            desktop.status(),
            serde_json::from_slice(desktop.body()).unwrap()
        ),
        "framing drift for {path}"
    );
    web
}

fn mutation(expected_revision: Option<i64>, deployment_wide: bool) -> PluginSkillMutation {
    PluginSkillMutation {
        slug: "review".into(),
        title: "Review".into(),
        summary: "Sources".into(),
        instructions: "\nKeep exact source citations.\n".into(),
        deployment_wide,
        expected_revision,
    }
}

#[tokio::test]
async fn skill_editing_has_exact_axum_tauri_parity_on_the_same_application() {
    let skills = Arc::new(SyntheticSkills::default());
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_mcp_connections(skills.clone()));
    let member = auth(Role::User);
    let administrator = auth(Role::Admin);
    let web = web_router(application.clone(), Some((&member, true)));
    let admin_web = web_router(application.clone(), Some((&administrator, true)));
    let transport = Arc::new(InProcessTransport::new(application.clone()));
    assert!(Arc::ptr_eq(transport.service(), &application));
    let root = dist();
    let protocol = DesktopTauriProtocol::open(&root, transport).unwrap();
    protocol
        .bind_window("member", member.clone(), Some(Duration::from_secs(60)))
        .unwrap();
    protocol
        .bind_window("admin", administrator, Some(Duration::from_secs(60)))
        .unwrap();
    protocol.bind_window("stale", member.clone(), None).unwrap();

    for (current, input, admin, expected_owner, expected_revision) in [
        (None, mutation(None, false), false, Some("actor"), 1),
        (None, mutation(None, true), true, None, 1),
        (
            Some(current_skill(Some("actor"), 4)),
            mutation(Some(4), false),
            false,
            Some("actor"),
            5,
        ),
        (
            Some(current_skill(Some("original-owner"), 4)),
            mutation(Some(4), true),
            true,
            Some("original-owner"),
            5,
        ),
    ] {
        skills.configure(current);
        let (status, body) = pair(
            if admin {
                admin_web.clone()
            } else {
                web.clone()
            },
            &protocol,
            if admin { "admin" } else { "member" },
            Method::POST,
            "/api/plugins/skills",
            serde_json::to_vec(&input).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let reply: PluginSkills = serde_json::from_value(body).unwrap();
        assert_eq!(reply.skills.len(), 1);
        let saved = &reply.skills[0];
        assert_eq!(saved.revision, expected_revision);
        assert_eq!(saved.owner_user_id.as_deref(), expected_owner);
        assert_eq!(
            (
                &saved.slug,
                &saved.title,
                &saved.summary,
                &saved.instructions
            ),
            (
                &input.slug,
                &input.title,
                &input.summary,
                &input.instructions
            )
        );
        assert_eq!(
            *skills.calls.lock().unwrap(),
            [
                Call::Save(ActorId::new("actor"), input.clone()),
                Call::Save(ActorId::new("actor"), input)
            ]
        );
    }

    let current = current_skill(Some("actor"), 4);
    let snapshot = serde_json::to_value(current.revision_snapshot().unwrap()).unwrap();
    for expected in [None, Some(1), Some(i64::MAX)] {
        skills.configure(Some(current.clone()));
        let (status, body) = pair(
            web.clone(),
            &protocol,
            "member",
            Method::POST,
            "/api/plugins/skills",
            serde_json::to_vec(&mutation(expected, false)).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, snapshot);
        assert_eq!(
            body.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["currentRevision", "currentSha256", "updatedAt"]
        );
        assert!(!body.to_string().contains("instruction"));
    }
    skills.configure(Some(current.clone()));
    let (status, body) = pair(
        web.clone(),
        &protocol,
        "member",
        Method::DELETE,
        "/api/plugins/skills/review",
        br#"{"expectedRevision":1}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, snapshot);
    skills.configure(Some(current));
    let (status, body) = pair(
        web.clone(),
        &protocol,
        "member",
        Method::DELETE,
        "/api/plugins/skills/review",
        br#"{"expectedRevision":4}"#.to_vec(),
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, json!({"ok":true})));
    assert_eq!(
        *skills.calls.lock().unwrap(),
        [
            Call::Delete(ActorId::new("actor"), "review".into(), 4),
            Call::Delete(ActorId::new("actor"), "review".into(), 4)
        ]
    );

    for body in [
        "",
        "{}",
        r#"{"expectedRevision":0}"#,
        r#"{"expectedRevision":"4"}"#,
        r#"{"expectedRevision":4,"actor":"forged"}"#,
        r#"{"expectedRevision":4,"expectedRevision":5}"#,
    ] {
        skills.configure(Some(current_skill(Some("actor"), 4)));
        assert_eq!(
            pair(
                web.clone(),
                &protocol,
                "member",
                Method::DELETE,
                "/api/plugins/skills/review",
                body.as_bytes().to_vec()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert!(skills.calls.lock().unwrap().is_empty());
    }
    for (input, status) in [
        (mutation(Some(0), false), StatusCode::BAD_REQUEST),
        (mutation(Some(4), true), StatusCode::FORBIDDEN),
    ] {
        skills.configure(Some(current_skill(Some("actor"), 4)));
        assert_eq!(
            pair(
                web.clone(),
                &protocol,
                "member",
                Method::POST,
                "/api/plugins/skills",
                serde_json::to_vec(&input).unwrap()
            )
            .await
            .0,
            status
        );
        assert!(skills.calls.lock().unwrap().is_empty());
    }
    skills.configure(Some(current_skill(Some("other-owner"), 4)));
    assert_eq!(
        pair(
            web.clone(),
            &protocol,
            "member",
            Method::POST,
            "/api/plugins/skills",
            serde_json::to_vec(&mutation(Some(1), false)).unwrap()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    for (method, path) in [
        (Method::POST, "/api/plugins/skills"),
        (Method::DELETE, "/api/plugins/skills/review"),
    ] {
        skills.configure(Some(current_skill(Some("actor"), 4)));
        let stale = web_router(application.clone(), Some((&member, false)));
        assert_eq!(
            pair(
                stale,
                &protocol,
                "stale",
                method.clone(),
                path,
                b"not-json".to_vec()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let absent = web_router(application.clone(), None);
        assert_eq!(
            pair(
                absent,
                &protocol,
                "absent",
                method.clone(),
                path,
                b"not-json".to_vec()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            web_response(
                web.clone(),
                method,
                path,
                b"not-json".to_vec(),
                "https://evil.example.test"
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert!(skills.calls.lock().unwrap().is_empty());
    }
    fs::remove_dir_all(root).unwrap();
}
