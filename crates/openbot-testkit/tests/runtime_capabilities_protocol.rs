//! Actual Protocol/window registry with real owned Server session/canonical upstreams.
//! These are finite delegation and missing-source tests, not actual Desktop Local producers.
//! Actual Local installation/service/grant collection is tested in the private Desktop module.

#![cfg(target_os = "macos")]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use async_trait::async_trait;
use axum::http::{Method, Request, StatusCode};
use harness::{admin_config, with_temp_database};
use openbot_application::{AppEventStream, ApplicationService, OpenBotApplication};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder};
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::request_binding::HostRequestBindingError;
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::channels::ChannelRepo;
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, SingleUserAuthResolver};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;

const PATH: &str = "/api/me/capabilities";
const OWNER: &str = "protocol-capability-owner";
const COOKIE_A: &str = "owned-protocol-capability-session-a";
const COOKIE_B: &str = "owned-protocol-capability-session-b";
const SESSION_KEY: &[u8] = b"owned-protocol-capability-session-key-32";
fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn column(token: &str) -> String {
    SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value()
}

struct OwnedAssets(PathBuf);
impl OwnedAssets {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let root = std::env::temp_dir().join(format!(
            "openbot-capability-protocol-{}",
            Uuid::now_v7().simple()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|_| "owned Protocol assets create failed".to_owned())?;
        std::fs::write(root.join("index.html"),"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|_|"owned Protocol index write failed".to_owned())?;
        std::fs::write(root.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|_| "owned Protocol bootstrap write failed".to_owned())?;
        Ok(Self(root))
    }
    fn finish(self) -> Result<(), String> {
        let path = self.0.clone();
        std::fs::remove_dir_all(&path)
            .map_err(|_| "owned Protocol assets remove failed".to_owned())?;
        require(!path.exists(), "owned Protocol assets remain")?;
        Ok(())
    }
}
impl Drop for OwnedAssets {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ObservedApplication {
    actual: Arc<dyn ApplicationService>,
    observed: Mutex<Vec<AuthContext>>,
    last_error: Mutex<Option<AppError>>,
}
#[async_trait]
impl ApplicationService for ObservedApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        if matches!(&command, AppCommand::GetRuntimeCapabilities) {
            self.observed
                .lock()
                .map_err(|_| AppError::DependencyUnavailable {
                    dependency: "test_observer",
                })?
                .push(auth.clone());
        }
        let result = self.actual.execute(auth, command).await;
        // Capture only this real return, clearing None on success; never replace the result.
        *self
            .last_error
            .lock()
            .expect("actual App error observer poisoned") = result.as_ref().err().cloned();
        result
    }
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        self.actual.subscribe(auth, request).await
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Sessions,
    SingleUser,
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    resolver: Arc<dyn AuthResolver>,
    application: Arc<ObservedApplication>,
    assets: OwnedAssets,
}
impl Fixture {
    async fn new(config: DatabaseConfig, mode: Mode) -> Result<Self, String> {
        let pool = pool::connect(&config.with_max_pool_size(8))
            .await
            .map_err(|_| "owned Protocol PG connect failed".to_owned())?;
        {
            let mut c = pool
                .get()
                .await
                .map_err(|_| "owned migrations acquire failed".to_owned())?;
            baseline::apply(&c)
                .await
                .map_err(|_| "owned baseline failed".to_owned())?;
            native::apply(&mut c)
                .await
                .map_err(|_| "owned native failed".to_owned())?;
        }
        let deployment = DeploymentId::new("protocol-capability-deployment");
        let tenant = TenantId::new("protocol-capability-tenant");
        let resolver: Arc<dyn AuthResolver> = match mode {
            Mode::Sessions => {
                let c = pool
                    .get()
                    .await
                    .map_err(|_| "owned session seed acquire failed".to_owned())?;
                c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('protocol-capability-owner','protocol-capability@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('protocol-capability-owner','user')").await.map_err(|_|"owned session user seed failed".to_owned())?;
                let now = OffsetDateTime::now_utc();
                for (id, token) in [
                    ("protocol-session-a", COOKIE_A),
                    ("protocol-session-b", COOKIE_B),
                ] {
                    c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",&[&id,&OWNER,&column(token),&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|_|"owned original session seed failed".to_owned())?;
                }
                drop(c);
                Arc::new(
                    PostgresSessionAuthResolver::new(
                        pool.clone(),
                        SESSION_KEY,
                        default_session_lifetime(),
                        deployment,
                        tenant,
                    )
                    .map_err(|_| "actual Protocol upstream resolver failed".to_owned())?,
                )
            }
            Mode::SingleUser => {
                initialize_single_user(&pool, true)
                    .await
                    .map_err(|_| "actual canonical setup failed".to_owned())?;
                let principal = load_single_user_principal(&pool, deployment, tenant)
                    .await
                    .map_err(|_| "actual typed canonical proof failed".to_owned())?;
                Arc::new(SingleUserAuthResolver::from_verified_principal(
                    principal,
                    default_session_lifetime(),
                ))
            }
        };
        // This assembly deliberately has no capability collector. Real session delegation
        // cannot be relabeled as a verified actual Desktop Local source.
        let actual = Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())));
        Ok(Self {
            pool,
            resolver,
            application: Arc::new(ObservedApplication {
                actual,
                observed: Mutex::new(Vec::new()),
                last_error: Mutex::new(None),
            }),
            assets: OwnedAssets::new()?,
        })
    }
    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        let (parts, ()) = Request::builder()
            .uri(PATH)
            .header("cookie", format!("openbot_session={cookie}"))
            .body(())
            .map_err(|_| "upstream request build failed".to_owned())?
            .into_parts();
        self.resolver
            .resolve_with_assurance(&parts)
            .await
            .map(|resolved| resolved.into_context())
            .map_err(|_| "actual upstream resolve failed".to_owned())
    }
    fn protocol(&self) -> Result<DesktopTauriProtocol, String> {
        DesktopTauriProtocol::open(
            &self.assets.0,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map_err(|_| "actual Protocol open failed".to_owned())
    }
    fn last(&self) -> Result<AuthContext, String> {
        self.application
            .observed
            .lock()
            .map_err(|_| "Protocol observer poisoned".to_owned())?
            .last()
            .cloned()
            .ok_or_else(|| "actual Protocol never supplied its Rust window context".to_owned())
    }
    fn calls(&self) -> Result<usize, String> {
        Ok(self
            .application
            .observed
            .lock()
            .map_err(|_| "Protocol observer poisoned".to_owned())?
            .len())
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|_|"Protocol fingerprint acquire failed".to_owned())?.query_one("SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.users x),'sessions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.sessions x),'roles',(SELECT jsonb_agg(to_jsonb(x) ORDER BY user_id,role) FROM public.user_roles x),'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.audit_events x))",&[]).await.map_err(|_|"Protocol fingerprint query failed".to_owned())?.try_get(0).map_err(|_|"Protocol fingerprint decode failed".to_owned())
    }
    async fn finish(self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        self.pool.close();
        self.assets.finish()
    }
}
async fn request(
    protocol: &DesktopTauriProtocol,
    label: &str,
    method: Method,
    path: &str,
    body: &[u8],
) -> Result<(StatusCode, Value), String> {
    let response = protocol
        .handle(
            label,
            Request::builder()
                .method(method)
                .uri(path)
                .body(body.to_vec())
                .map_err(|_| "Protocol request build failed".to_owned())?,
        )
        .await;
    require(
        response
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok())
            == Some("no-store"),
        "actual capability Protocol reply lost no-store",
    )?;
    Ok((
        response.status(),
        if response.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(response.body())
                .map_err(|_| "Protocol reply JSON invalid".to_owned())?
        },
    ))
}
async fn verify(auth: &AuthContext) -> Result<(), HostRequestBindingError> {
    auth.request_binding()
        .ok_or(HostRequestBindingError::Missing)?
        .verify_current_before(auth, Instant::now() + Duration::from_secs(5))
        .await
}
fn missing(application: &ObservedApplication, result: &(StatusCode, Value)) -> Result<(), String> {
    require(
        result.0 == StatusCode::SERVICE_UNAVAILABLE
            && result.1 == serde_json::json!({"code":"dependency_unavailable"})
            && application
                .last_error
                .lock()
                .map_err(|_| "actual App error observer poisoned".to_owned())?
                .as_ref()
                == Some(&AppError::DependencyUnavailable {
                    dependency: "host_request_binding",
                }),
        "generic Protocol claimed a real Local capability producer",
    )
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn two_real_protocol_owners_same_label_and_id_one_are_distinct_current_delegations_not_local_producers()
 {
    let admin = admin_config("capprotoowners");
    with_temp_database(&admin, "capprotoowners", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let original = fixture.auth(COOKIE_A).await?;
        let before = fixture.facts().await?;
        let a = fixture.protocol()?;
        let b = fixture.protocol()?;
        a.bind_window("main", original.clone(), None)
            .map_err(|_| "first actual window bind failed".to_owned())?;
        b.bind_window("main", original, None)
            .map_err(|_| "second actual window bind failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&a, "main", Method::GET, PATH, b"").await?,
        )?;
        let first = fixture.last()?;
        missing(
            &fixture.application,
            &request(&b, "main", Method::GET, PATH, b"").await?,
        )?;
        let second = fixture.last()?;
        require(
            first == second
                && !first
                    .request_binding()
                    .unwrap()
                    .identity()
                    .same_binding(second.request_binding().unwrap().identity()),
            "two actual owner/window epochs were aliased",
        )?;
        require(
            verify(&first).await.is_ok() && verify(&second).await.is_ok(),
            "normal actual server delegation is not current",
        )?;
        require(
            fixture.facts().await? == before,
            "delegated missing-source GET wrote PG facts",
        )?;
        drop(a);
        drop(b);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_rowless_single_user_upstream_cannot_be_mislabeled_actual_desktop_local() {
    let admin = admin_config("capprotosingle");
    with_temp_database(&admin, "capprotosingle", |config| async move {
        let fixture = Fixture::new(config, Mode::SingleUser).await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let before = fixture.facts().await?;
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("main", auth, None)
            .map_err(|_| "actual rowless window bind failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&protocol, "main", Method::GET, PATH, b"").await?,
        )?;
        require(
            verify(&fixture.last()?).await == Err(HostRequestBindingError::Missing),
            "rowless generic upstream was treated as actual Local canonical source",
        )?;
        require(
            fixture.facts().await? == before,
            "rowless missing-source observation created sessions or repaired authority",
        )?;
        drop(protocol);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn unbound_generic_context_has_missing_budget_source_and_no_collector() {
    let admin = admin_config("capprotounbound");
    with_temp_database(&admin, "capprotounbound", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let actual = fixture.auth(COOKIE_A).await?;
        let plain = AuthContextBuilder::from_verified_session(
            actual.deployment().clone(),
            actual.tenant().clone(),
            actual.actor().clone(),
            actual.auth_generation(),
            actual.is_single_user(),
        )
        .with_roles(actual.roles().iter().copied())
        .build();
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("main", plain, None)
            .map_err(|_| "generic unbound window bind failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&protocol, "main", Method::GET, PATH, b"").await?,
        )?;
        require(
            verify(&fixture.last()?).await == Err(HostRequestBindingError::Missing),
            "generic window invented current source",
        )?;
        drop(protocol);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn query_body_head_post_and_unknown_window_reject_before_actual_application() {
    let admin = admin_config("capprotoframing");
    with_temp_database(&admin, "capprotoframing", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|_| "framing window bind failed".to_owned())?;
        let before = fixture.facts().await?;
        for (method, path, body, expected) in [
            (
                Method::GET,
                "/api/me/capabilities?",
                &b""[..],
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/api/me/capabilities?actorId=foreign",
                &b""[..],
                StatusCode::BAD_REQUEST,
            ),
            (Method::GET, PATH, &b"{}"[..], StatusCode::BAD_REQUEST),
            (Method::GET, PATH, &b"\0"[..], StatusCode::BAD_REQUEST),
            (Method::HEAD, PATH, &b""[..], StatusCode::METHOD_NOT_ALLOWED),
            (
                Method::POST,
                PATH,
                &b"{}"[..],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
        ] {
            require(
                request(&protocol, "main", method, path, body).await?.0 == expected,
                "actual Protocol capability framing differs",
            )?;
        }
        require(
            request(&protocol, "unknown", Method::GET, PATH, b"")
                .await?
                .0
                == StatusCode::UNAUTHORIZED,
            "missing actual window did not refuse",
        )?;
        require(
            fixture.calls()? == 0,
            "malformed Protocol request invoked App",
        )?;
        require(
            fixture.facts().await? == before,
            "invalid Protocol framing wrote PG state",
        )?;
        drop(protocol);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn same_label_rebind_preserves_six_fact_equality_and_revokes_original_window_epoch() {
    let admin = admin_config("capprotorebind");
    with_temp_database(&admin, "capprotorebind", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let protocol = fixture.protocol()?;
        let auth = fixture.auth(COOKIE_A).await?;
        protocol
            .bind_window("main", auth.clone(), None)
            .map_err(|_| "first rebind window failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&protocol, "main", Method::GET, PATH, b"").await?,
        )?;
        let old = fixture.last()?;
        protocol
            .unbind_window("main")
            .map_err(|_| "actual old window unbind failed".to_owned())?;
        protocol
            .bind_window("main", auth, None)
            .map_err(|_| "replacement window failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&protocol, "main", Method::GET, PATH, b"").await?,
        )?;
        let current = fixture.last()?;
        require(
            old == current
                && !old
                    .request_binding()
                    .unwrap()
                    .identity()
                    .same_binding(current.request_binding().unwrap().identity()),
            "rebind epoch lost original distinction",
        )?;
        require(
            verify(&old).await == Err(HostRequestBindingError::NotCurrent)
                && verify(&current).await.is_ok(),
            "rebind retained old window or refused current real delegation",
        )?;
        drop(protocol);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_last_protocol_drop_closes_proof_while_context_clone_drop_does_not() {
    let admin = admin_config("capprotodrop");
    with_temp_database(&admin, "capprotodrop", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let protocol = Arc::new(fixture.protocol()?);
        protocol
            .bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|_| "drop window failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&protocol, "main", Method::GET, PATH, b"").await?,
        )?;
        let original = fixture.last()?;
        drop(original.clone());
        require(
            verify(&original).await.is_ok(),
            "dropping proof clone closed owner",
        )?;
        let other = protocol.clone();
        drop(protocol);
        require(
            verify(&original).await.is_ok(),
            "dropping ordinary Protocol Arc closed actual owner",
        )?;
        drop(other);
        require(
            verify(&original).await == Err(HostRequestBindingError::NotCurrent),
            "captured contexts kept actual Protocol owner alive",
        )?;
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_original_server_session_delete_revokes_only_its_delegated_window() {
    let admin = admin_config("capprotologout");
    with_temp_database(&admin, "capprotologout", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let a = fixture.protocol()?;
        let b = fixture.protocol()?;
        a.bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|_| "A window bind failed".to_owned())?;
        b.bind_window("main", fixture.auth(COOKIE_B).await?, None)
            .map_err(|_| "B window bind failed".to_owned())?;
        missing(
            &fixture.application,
            &request(&a, "main", Method::GET, PATH, b"").await?,
        )?;
        let a_context = fixture.last()?;
        missing(
            &fixture.application,
            &request(&b, "main", Method::GET, PATH, b"").await?,
        )?;
        let b_context = fixture.last()?;
        fixture
            .pool
            .get()
            .await
            .map_err(|_| "logout controller acquire failed".to_owned())?
            .execute(
                "DELETE FROM public.sessions WHERE id='protocol-session-a'",
                &[],
            )
            .await
            .map_err(|_| "original A logout failed".to_owned())?;
        require(
            verify(&a_context).await == Err(HostRequestBindingError::NotCurrent)
                && verify(&b_context).await.is_ok(),
            "actual original-session delegation was actor-wide or stale",
        )?;
        // The missing collector remains a truthful 503 independently of delegation freshness.
        missing(
            &fixture.application,
            &request(&b, "main", Method::GET, PATH, b"").await?,
        )?;
        drop(a);
        drop(b);
        fixture.finish().await?;
        Ok(())
    })
    .await;
}
