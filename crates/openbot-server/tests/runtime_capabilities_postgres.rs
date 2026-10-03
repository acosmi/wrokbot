//! R426 actual owned PostgreSQL resolver -> shared App -> actual HTTP carrier.
//! Collector decorators only count and schedule the real port; no PG results are invented.
//! Controlled model/SSO configuration is not provider, inference or full readiness evidence.

#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use harness::{admin_config, with_temp_database};
use http::{Method, Request, StatusCode};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::runtime_capabilities::{
    CapabilityDeadline, RuntimeCapabilitiesCollector, RuntimeCapabilitiesFuture,
    RuntimeCapabilityObservationResult,
};
use openbot_application::{AppEventStream, ApplicationService, OpenBotApplication};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder};
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    DataKey, KeyVersion, NONCE_BYTES, Nonce, RecordBinding, SecretBytes, SecretId, SecretKind,
    SecretPrincipal, WrappingKey, seal_v2,
};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{initialize_single_user, load_single_user_principal};
use openbot_infra::auth::sso::DynamicSsoService;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::channels::ChannelRepo;
use openbot_infra::runtime_capability_facts::{
    PostgresRuntimeCapabilityFacts, RuntimeCapabilityCollectorFactory,
};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, ServerBuilder, SingleUserAuthResolver,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const DEPLOYMENT: &str = "runtime-capabilities-deployment";
const TENANT: &str = "runtime-capabilities-tenant";
const OWNER: &str = "capability-owner";
const A_ID: &str = "capability-session-a";
const B_ID: &str = "capability-session-b";
const COOKIE_A: &str = "owned-runtime-capabilities-token-a-001";
const COOKIE_B: &str = "owned-runtime-capabilities-token-b-002";
const SESSION_KEY: &[u8] = b"owned-runtime-capabilities-session-hmac-key";
const PATH: &str = "/api/me/capabilities";

const FINGERPRINT_SQL: &str = r#"SELECT jsonb_build_object(
            'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.sessions x),
            'users',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.users x),
            'roles',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY user_id,role),'[]'::jsonb) FROM public.user_roles x),
            'deny',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY email),'[]'::jsonb) FROM public.revoked_access x),
            'policy',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.action_policy x),
            'models',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.model_connections x),
            'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets x),
            'credentials',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.credentials x),
            'sso',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY provider_id),'[]'::jsonb) FROM public.sso_providers x),
            'audit',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.audit_events x)
        )"#;

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn token_column(token: &str) -> String {
    SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value()
}
fn plain_copy(auth: &AuthContext) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        auth.deployment().clone(),
        auth.tenant().clone(),
        auth.actor().clone(),
        auth.auth_generation(),
        auth.is_single_user(),
    )
    .with_roles(auth.roles().iter().copied())
    .build()
}

/// Test scheduling at the real port boundary. It consumes no observation and changes no fact.
struct FinalizeGate {
    entered: Semaphore,
    released: Semaphore,
}
impl FinalizeGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            released: Semaphore::new(0),
        })
    }
    async fn entered(&self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(2), self.entered.acquire())
            .await
            .map_err(|_| "actual finalizer entry was not observed".to_owned())?
            .map_err(|_| "finalizer entry gate closed".to_owned())?
            .forget();
        Ok(())
    }
    fn release(&self) {
        self.released.add_permits(1);
    }
}
struct CountActualCollector {
    actual: Arc<dyn RuntimeCapabilitiesCollector>,
    observe_calls: AtomicUsize,
    finalize_calls: AtomicUsize,
    tail_calls: AtomicUsize,
    gate: Option<Arc<FinalizeGate>>,
    session_tail_clock: Mutex<Option<Arc<SessionTailClockSchedule>>>,
}
impl CountActualCollector {
    fn new(
        actual: Arc<dyn RuntimeCapabilitiesCollector>,
        gate: Option<Arc<FinalizeGate>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            actual,
            observe_calls: AtomicUsize::new(0),
            finalize_calls: AtomicUsize::new(0),
            tail_calls: AtomicUsize::new(0),
            gate,
            session_tail_clock: Mutex::new(None),
        })
    }
    fn calls(&self) -> (usize, usize, usize) {
        (
            self.observe_calls.load(Ordering::SeqCst),
            self.finalize_calls.load(Ordering::SeqCst),
            self.tail_calls.load(Ordering::SeqCst),
        )
    }
}
impl RuntimeCapabilitiesCollector for CountActualCollector {
    fn observe<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        self.observe_calls.fetch_add(1, Ordering::SeqCst);
        self.actual.observe(auth, deadline)
    }
    fn finalize<'a>(
        &'a self,
        auth: &'a AuthContext,
        observed: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        self.finalize_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.entered.add_permits(1);
                // The App retains the same absolute five-second budget around this future.
                gate.released.acquire().await.map_err(|_| openbot_application::runtime_capabilities::RuntimeCapabilitiesCollectionError::Unavailable)?.forget();
            }
            self.actual.finalize(auth, observed, deadline).await
        })
    }
    fn tail_current(
        &self,
        auth: &AuthContext,
        finalized: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilityObservationResult {
        self.tail_calls.fetch_add(1, Ordering::SeqCst);
        let result = self.actual.tail_current(auth, finalized, deadline);
        if let Some(schedule) = self
            .session_tail_clock
            .lock()
            .expect("private clock schedule poisoned")
            .as_ref()
        {
            schedule.after_real_tail(result.is_ok(), deadline);
        }
        // Return the original production observation/error, never a minted stamp or witness.
        result
    }
}

/// Private opt-in scheduling only: the actual row is seeded lawfully before HTTP resolves it.
/// No OS clock, production callback, raw stamp, observation or result is changed here.
struct SessionTailClockSchedule {
    boundary: OffsetDateTime,
    observed: Mutex<SessionTailClockObserved>,
}
#[derive(Default)]
struct SessionTailClockObserved {
    actual_tail_positive: bool,
    before_boundary: bool,
    crossed_boundary: bool,
    delay: Duration,
    within_use_case_deadline: bool,
}
impl SessionTailClockSchedule {
    fn new(boundary: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self {
            boundary,
            observed: Mutex::new(SessionTailClockObserved::default()),
        })
    }
    fn after_real_tail(&self, positive: bool, deadline: CapabilityDeadline) {
        let mut observed = self
            .observed
            .lock()
            .expect("private clock observation poisoned");
        let now = OffsetDateTime::now_utc();
        observed.actual_tail_positive = positive;
        observed.before_boundary = now < self.boundary;
        if positive
            && observed.before_boundary
            && deadline.check().is_ok()
            && let Ok(delay) =
                Duration::try_from(self.boundary - now + time::Duration::milliseconds(2))
            && delay <= Duration::from_secs(2)
        {
            let began = Instant::now();
            // No await after actual finalize/rollback and collector tail. App must
            // consume its mandatory carried-clock witness when this real wait ends.
            std::thread::sleep(delay);
            observed.delay = began.elapsed();
        }
        observed.crossed_boundary = OffsetDateTime::now_utc() >= self.boundary;
        observed.within_use_case_deadline = deadline.check().is_ok();
    }
}

struct CountActualFactory {
    actual: Arc<dyn RuntimeCapabilityCollectorFactory>,
    captured: Mutex<Option<Arc<CountActualCollector>>>,
    gate: Option<Arc<FinalizeGate>>,
}
impl RuntimeCapabilityCollectorFactory for CountActualFactory {
    fn build(
        &self,
        facts: Arc<PostgresRuntimeCapabilityFacts>,
    ) -> Result<
        Arc<dyn RuntimeCapabilitiesCollector>,
        openbot_application::runtime_capabilities::RuntimeCapabilitiesCollectionError,
    > {
        let port = CountActualCollector::new(self.actual.build(facts)?, self.gate.clone());
        *self.captured.lock().map_err(|_| openbot_application::runtime_capabilities::RuntimeCapabilitiesCollectionError::Unavailable)? = Some(port.clone());
        Ok(port)
    }
}
struct UnusedRemote;
#[async_trait]
impl RemoteAguiTransport for UnusedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        panic!("read-only capabilities must never start inference or a remote provider")
    }
}

struct ObservedApplication {
    actual: Arc<dyn ApplicationService>,
    calls: AtomicUsize,
    last_error: Mutex<Option<AppError>>,
}
#[async_trait]
impl ApplicationService for ObservedApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        if matches!(&command, AppCommand::GetRuntimeCapabilities) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.actual.execute(auth, command).await;
        // Observe the same real return, including clearing an earlier error on success.
        // Preserve the original result and perform no second Application call.
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
struct HttpFacts {
    status: StatusCode,
    value: Value,
}
struct Fixture {
    pool: deadpool_postgres::Pool,
    config: DatabaseConfig,
    resolver: Arc<dyn AuthResolver>,
    application: Arc<ObservedApplication>,
    router: axum::Router,
    port: Option<Arc<CountActualCollector>>,
    facts: Option<Arc<PostgresRuntimeCapabilityFacts>>,
    vault: CredentialRecordVault,
}
impl Fixture {
    async fn new(config: DatabaseConfig, mode: Mode) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config)
            .await
            .map_err(|_| "owned pool connect failed".to_owned())?;
        {
            let mut c = pool
                .get()
                .await
                .map_err(|_| "owned baseline acquire failed".to_owned())?;
            baseline::apply(&c)
                .await
                .map_err(|_| "owned baseline apply failed".to_owned())?;
            native::apply(&mut c)
                .await
                .map_err(|_| "owned native apply failed".to_owned())?;
        }
        let resolver: Arc<dyn AuthResolver> = match mode {
            Mode::SingleUser => {
                initialize_single_user(&pool, true)
                    .await
                    .map_err(|_| "canonical initialization failed".to_owned())?;
                let principal = load_single_user_principal(
                    &pool,
                    DeploymentId::new(DEPLOYMENT),
                    TenantId::new(TENANT),
                )
                .await
                .map_err(|_| "actual typed canonical principal failed".to_owned())?;
                Arc::new(SingleUserAuthResolver::from_verified_principal(
                    principal,
                    default_session_lifetime(),
                ))
            }
            Mode::Sessions => {
                let c = pool
                    .get()
                    .await
                    .map_err(|_| "owned session seed acquire failed".to_owned())?;
                c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('capability-owner','capability-owner@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('capability-owner','user');")
                    .await.map_err(|_| "owned session user seed failed".to_owned())?;
                let now = OffsetDateTime::now_utc();
                for (id, token) in [(A_ID, COOKIE_A), (B_ID, COOKIE_B)] {
                    c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",
                        &[&id, &OWNER, &token_column(token), &(now + time::Duration::hours(1)), &(now - time::Duration::minutes(1))])
                        .await.map_err(|_| "owned session epoch seed failed".to_owned())?;
                }
                drop(c);
                Arc::new(
                    PostgresSessionAuthResolver::new(
                        pool.clone(),
                        SESSION_KEY,
                        default_session_lifetime(),
                        DeploymentId::new(DEPLOYMENT),
                        TenantId::new(TENANT),
                    )
                    .map_err(|_| "actual session resolver failed".to_owned())?,
                )
            }
        };
        // A truthful missing capability dependency, used only by the framing/missing-source cases.
        let application = Arc::new(ObservedApplication {
            actual: Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone()))),
            calls: AtomicUsize::new(0),
            last_error: Mutex::new(None),
        });
        let router = Self::router(application.clone(), resolver.clone())?;
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x76; 32])
                .map_err(|_| "controlled fixture wrapping key rejected".to_owned())?,
        );
        Ok(Self {
            pool,
            config,
            resolver,
            application,
            router,
            port: None,
            facts: None,
            vault,
        })
    }
    fn router(
        application: Arc<ObservedApplication>,
        resolver: Arc<dyn AuthResolver>,
    ) -> Result<axum::Router, String> {
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|_| "fixture transport config failed".to_owned())?
            .transport_policy(true);
        Ok(openbot_server::router(
            ServerBuilder::new(application, resolver)
                .with_transport_policy(policy)
                .build(),
        )
        .layer(axum::Extension(ConnectInfo(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            40_006,
        ))))))
    }
    async fn install_actual(
        &mut self,
        mode: Mode,
        gate: Option<Arc<FinalizeGate>>,
    ) -> Result<(), String> {
        let tenant = TenantId::new(TENANT);
        let sso = DynamicSsoService::new(
            self.pool.clone(),
            &tenant,
            b"capabilities-ephemeral-test-key-32-bytes".to_vec(),
            SESSION_KEY.to_vec(),
            vec![0x75; 32],
            WrappingKey::from_bytes(vec![0x42; 32])
                .map_err(|_| "SSO fixture wrapping key rejected".to_owned())?,
            KeyVersion::new(1),
            default_session_lifetime(),
            AdminFloor::from_configured(["capability-admin@example.test"])
                .map_err(|_| "SSO fixture admin floor rejected".to_owned())?,
            std::iter::empty::<String>(),
            SafeDialer::new(EgressPolicy::default()),
            "https://capabilities.example.test".to_owned(),
        )
        .map_err(|_| "actual read-only SSO service source unavailable".to_owned())?;
        let factory = Arc::new(CountActualFactory {
            actual: self
                .resolver
                .runtime_capability_factory(Some(sso.capability_source()))
                .map_err(|_| "actual resolver refused capability factory".to_owned())?,
            captured: Mutex::new(None),
            gate,
        });
        let policy = PolicyStore::postgres(self.pool.clone(), None);
        policy
            .load()
            .await
            .map_err(|_| "actual PolicyStore setup failed".to_owned())?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: self.pool.clone(),
            listener_database: self.config.clone().into(),
            deployment: DeploymentId::new(DEPLOYMENT),
            tenant: tenant.clone(),
            single_user: matches!(mode, Mode::SingleUser),
            admin_floor: None,
            model: "unused-capability-fixture".to_owned(),
            credential_key_id: "capability-default-key".to_owned(),
            credential_vault: self.vault.clone(),
            audit_key: SecretBytes::new(vec![0x75; 32]),
            remote_assertions: Arc::new(
                RemoteRunAssertionSigner::new(vec![0x77; 32])
                    .map_err(|_| "fixture signer rejected".to_owned())?,
            ),
            mcp_oauth_state_key: SecretBytes::new(vec![0x78; 32]),
            policy_store: policy,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: Some(factory.clone()),
            remote_agent_probe: Arc::new(UnusedRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(|_| "controlled unused endpoint invalid".to_owned())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(|_| "actual application assembly refused capability source".to_owned())?;
        self.port = factory
            .captured
            .lock()
            .map_err(|_| "collector capture poisoned".to_owned())?
            .clone();
        require(
            self.port.is_some(),
            "real assembly did not build its collector",
        )?;
        self.facts = assembly.runtime_capability_facts;
        self.application = Arc::new(ObservedApplication {
            actual: assembly.application,
            calls: AtomicUsize::new(0),
            last_error: Mutex::new(None),
        });
        self.router = Self::router(self.application.clone(), self.resolver.clone())?;
        Ok(())
    }
    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        let (parts, ()) = Request::builder()
            .uri(PATH)
            .header("cookie", format!("openbot_session={cookie}"))
            .body(())
            .map_err(|_| "fixture auth request failed".to_owned())?
            .into_parts();
        self.resolver
            .resolve_with_assurance(&parts)
            .await
            .map(|resolved| resolved.into_context())
            .map_err(|_| "actual resolve failed".to_owned())
    }
    async fn http(
        &self,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: &[u8],
    ) -> Result<HttpFacts, String> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", format!("openbot_session={cookie}"));
        }
        let request = builder
            .body(Body::from(body.to_vec()))
            .map_err(|_| "fixture HTTP build failed".to_owned())?;
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|_| "actual HTTP dispatch failed".to_owned())?;
        require(
            response
                .headers()
                .get("cache-control")
                .and_then(|h| h.to_str().ok())
                == Some("no-store"),
            "capabilities path must always be no-store",
        )?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024)
            .await
            .map_err(|_| "bounded HTTP body failed".to_owned())?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| "actual HTTP JSON malformed".to_owned())?
        };
        Ok(HttpFacts { status, value })
    }
    async fn fingerprint(&self) -> Result<[u8; 32], String> {
        // Only digests leave this private test observation. Include full session timestamps,
        // policy, all cipher bytes, metadata, audit and user authority before/after GET.
        let c = self
            .pool
            .get()
            .await
            .map_err(|_| "fingerprint acquire failed".to_owned())?;
        let row = c
            .query_one(FINGERPRINT_SQL, &[])
            .await
            .map_err(|_| "fingerprint current SQL failed".to_owned())?;
        let facts: Value = row
            .try_get(0)
            .map_err(|_| "fingerprint decode failed".to_owned())?;
        Ok(Sha256::digest(
            serde_json::to_vec(&facts).map_err(|_| "fingerprint encode failed".to_owned())?,
        )
        .into())
    }
    async fn app(&self, auth: &AuthContext) -> Result<AppReply, AppError> {
        self.application
            .execute(auth.clone(), AppCommand::GetRuntimeCapabilities)
            .await
    }
    async fn seed_custom(&self, auth: &AuthContext) -> Result<String, String> {
        use openbot_application::model_connections::ModelConnectionAdministration as _;
        let input = serde_json::from_value(
            json!({"name":"Owned capability model","protocol":"openai_chat_completions",
            "endpoint":"https://provider.example.test/v1","model":"owned-model","enabled":true,
            "apiKey":format!("owned-{}",Uuid::now_v7().simple())}),
        )
        .map_err(|_| "controlled custom model input rejected".to_owned())?;
        let port = openbot_infra::model_connections::PostgresModelConnections::new(
            self.pool.clone(),
            self.vault.clone(),
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x75; 32]),
        )
        .map_err(|_| "actual model connection port rejected fixture".to_owned())?;
        port.create(auth, &input)
            .await
            .map(|row| row.id)
            .map_err(|_| "actual custom model setup failed".to_owned())
    }
    async fn seed_default_key(&self) -> Result<(), String> {
        let id = Uuid::now_v7();
        let stored = self
            .vault
            .seal(
                &id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &SecretBytes::new(format!("owned-{}", Uuid::now_v7().simple()).into_bytes()),
            )
            .map_err(|_| "actual vault fixture seal failed".to_owned())?;
        self.pool.get().await.map_err(|_| "default key seed acquire failed".to_owned())?.execute(
            "INSERT INTO public.credentials(id,provider,key_id,kind,encrypted_value,metadata,created_at) VALUES($1,'openai','capability-default-key','model',$2,'{}',$3)",
            &[&id,&stored,&OffsetDateTime::now_utc()]).await.map_err(|_| "controlled default key seed failed".to_owned())?;
        Ok(())
    }
    async fn finish(&self) {
        self.resolver.close_request_bindings();
        if let Some(facts) = &self.facts {
            facts.close();
            facts.drain().await;
        }
        self.pool.close();
    }
}

fn projected(
    reply: AppReply,
) -> Result<openbot_contracts::runtime_capabilities::RuntimeCapabilitiesResponse, String> {
    match reply {
        AppReply::RuntimeCapabilities(value) => Ok(value),
        _ => Err("wrong actual capability reply variant".to_owned()),
    }
}
fn entry(
    value: &openbot_contracts::runtime_capabilities::RuntimeCapabilitiesResponse,
    id: openbot_contracts::runtime_capabilities::RuntimeCapabilityId,
) -> openbot_contracts::runtime_capabilities::RuntimeCapabilityEntry {
    *value
        .capabilities()
        .iter()
        .find(|entry| entry.id() == id)
        .expect("validated exact capability vector")
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_empty_workspace_without_models_is_ready_and_reads_are_effect_free() {
    use openbot_contracts::runtime_capabilities::{
        RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
        RuntimeCapabilityState as State,
    };
    let admin = admin_config("runtime_capabilities_workspace");
    with_temp_database(&admin, "capworkspace", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        let before = fixture.fingerprint().await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let first = projected(
            fixture
                .app(&auth)
                .await
                .map_err(|_| "real empty workspace query failed".to_owned())?,
        )?;
        require(
            first.host_mode()
                == openbot_contracts::runtime_capabilities::RuntimeCapabilityHostMode::Server,
            "real factory mode differs",
        )?;
        require(
            entry(&first, Id::Workspace).state() == State::Ready
                && entry(&first, Id::Workspace).reason_code() == Reason::CurrentChecksAvailable,
            "real empty workspace borrowed model prerequisites",
        )?;
        require(
            entry(&first, Id::AgentTools).state() == State::Unconfigured,
            "missing acting model/policy facts are not closed",
        )?;
        require(
            entry(&first, Id::ModelCustomV1).state() == State::Unconfigured
                && entry(&first, Id::ModelCustomV1).reason_code() == Reason::ModelKeyMissing,
            "complete empty custom inventory was not Missing",
        )?;
        require(
            entry(&first, Id::DynamicSso).state() == State::Unconfigured
                && entry(&first, Id::DynamicSso).reason_code() == Reason::ConfigurationMissing,
            "reserved SSO identifiers were mistaken for configured providers",
        )?;
        require(
            entry(&first, Id::LocalConfirmation).reason_code() == Reason::PlatformUnimplemented,
            "Server invented native Local confirmation",
        )?;
        for id in [
            Id::ModelSelectionV2,
            Id::ModelSdkGateway,
            Id::ModelAccountBridge,
            Id::BrowserControl,
            Id::NativeControl,
            Id::PixelEgress,
            Id::BackupRestore,
            Id::DevicePairing,
        ] {
            require(
                entry(&first, id).state() == State::Unsupported
                    && entry(&first, id).reason_code() == Reason::IndependentApiMissing,
                "missing independent API reason differs",
            )?;
        }
        let second = fixture.http(Method::GET, PATH, Some(COOKIE_A), b"").await?;
        require(
            second.status == StatusCode::OK,
            "actual HTTP empty workspace failed",
        )?;
        let second: openbot_contracts::runtime_capabilities::RuntimeCapabilitiesResponse =
            serde_json::from_value(second.value)
                .map_err(|_| "direct HTTP DTO invalid".to_owned())?;
        let (prefix_a, counter_a) = first
            .revision()
            .rsplit_once('-')
            .ok_or("first revision shape invalid")?;
        let (prefix_b, counter_b) = second
            .revision()
            .rsplit_once('-')
            .ok_or("second revision shape invalid")?;
        require(
            prefix_a == prefix_b
                && prefix_a.len() == 32
                && prefix_a.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "revision is not owner random UUID prefix",
        )?;
        require(
            counter_a.parse::<u64>().ok() == Some(1) && counter_b.parse::<u64>().ok() == Some(2),
            "successful observation counter differs",
        )?;
        require(
            fixture.port.as_ref().unwrap().calls() == (2, 2, 2),
            "actual whole query did not observe/finalize/tail exactly once",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "GET wrote session activity, policy, keys/configuration or audit",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn legal_personal_config_scoped_key_without_provider_is_unavailable_not_ready() {
    use openbot_contracts::runtime_capabilities::{
        RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
        RuntimeCapabilityState as State,
    };
    let admin = admin_config("runtime_capabilities_custom_unproven");
    with_temp_database(&admin, "capcustom", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        let auth = fixture.auth(COOKIE_A).await?;
        fixture.seed_custom(&auth).await?;
        let before = fixture.fingerprint().await?;
        let value = projected(
            fixture
                .app(&auth)
                .await
                .map_err(|_| "actual scoped custom query failed".to_owned())?,
        )?;
        require(
            entry(&value, Id::ModelCustomV1).state() == State::Unavailable
                && entry(&value, Id::ModelCustomV1).reason_code() == Reason::ProviderUnproven,
            "legal key/config invented a current provider",
        )?;
        require(
            entry(&value, Id::Workspace).state() == State::Ready,
            "custom provider facts affected workspace reader",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "read-only custom observation rotated/migrated cipher or audited",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn mixed_unconfigured_policy_and_unknown_provider_refuses_entire_projection() {
    let admin = admin_config("runtime_capabilities_mixed");
    with_temp_database(&admin, "capmixed", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        fixture.seed_default_key().await?;
        let before = fixture.fingerprint().await?;
        let result = fixture.http(Method::GET, PATH, Some(COOKIE_A), b"").await?;
        require(
            result.status == StatusCode::SERVICE_UNAVAILABLE
                && result.value == json!({"code":"dependency_unavailable"})
                && fixture
                    .application
                    .last_error
                    .lock()
                    .map_err(|_| "actual App error observer poisoned".to_owned())?
                    .as_ref()
                    == Some(&AppError::DependencyUnavailable {
                        dependency: "runtime_capabilities",
                    }),
            "mixed blockers emitted a prioritized or partial success",
        )?;
        require(
            result.value.get("capabilities").is_none(),
            "failed whole query leaked partial capability vector",
        )?;
        require(
            fixture.port.as_ref().unwrap().calls() == (1, 1, 1),
            "mixed error bypassed whole-result finalization/tail",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "mixed failure wrote actual source facts",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

async fn changed_auth(tag: &str, mode: Mode, sql: &str) {
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        let mut fixture = Fixture::new(config, mode).await?;
        fixture.install_actual(mode, None).await?;
        let auth = fixture.auth(COOKIE_A).await?;
        fixture
            .pool
            .get()
            .await
            .map_err(|_| "controller acquire failed".to_owned())?
            .batch_execute(sql)
            .await
            .map_err(|_| "controlled authority change failed".to_owned())?;
        let before = fixture.fingerprint().await?;
        require(
            fixture.app(&auth).await == Err(AppError::Unauthenticated),
            "old current authority survived actual mutation",
        )?;
        require(
            fixture.port.as_ref().unwrap().calls() == (0, 0, 0),
            "revoked proof reached collector",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "refused original proof repaired or wrote authority",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn real_original_generation_zero_session_refuses_current_null() {
    changed_auth(
        "capnull",
        Mode::Sessions,
        "UPDATE public.users SET auth_generation=NULL WHERE id='capability-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn real_original_session_refuses_current_negative() {
    // This test's disposable DB alone models a corrupt legacy value. Production readers
    // must refuse it independently of the migration's normal nonnegative constraint.
    changed_auth("capnegative",Mode::Sessions,"ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='capability-owner'").await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn real_original_session_refuses_role_replacement() {
    changed_auth(
        "caprole",
        Mode::Sessions,
        "UPDATE public.user_roles SET role='admin' WHERE user_id='capability-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn real_original_session_refuses_new_current_deny() {
    changed_auth("capdeny",Mode::Sessions,"INSERT INTO public.revoked_access(email,revoked_by) VALUES('capability-owner@example.test','owned-controller')").await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn real_generation_zero_single_user_refuses_current_null_without_repair() {
    changed_auth(
        "capsinglenull",
        Mode::SingleUser,
        "UPDATE public.users SET auth_generation=NULL",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn missing_carrier_is_503_before_real_collector_even_without_roles() {
    let admin = admin_config("capmissingcarrier");
    with_temp_database(&admin, "capmissingcarrier", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        let original = fixture.auth(COOKIE_A).await?;
        let plain = plain_copy(&original);
        let zero_role = AuthContextBuilder::from_verified_session(
            original.deployment().clone(),
            original.tenant().clone(),
            original.actor().clone(),
            original.auth_generation(),
            original.is_single_user(),
        )
        .build();
        let before = fixture.fingerprint().await?;
        for auth in [&plain, &zero_role] {
            require(
                fixture.app(auth).await
                    == Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding",
                    }),
                "missing binding was not static 503 before role gates",
            )?;
        }
        require(
            fixture.port.as_ref().unwrap().calls() == (0, 0, 0),
            "missing binding called actual capability collector",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "missing carrier wrote current sources",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[derive(Clone, Copy)]
enum DuringFinalWait {
    LogoutA,
    OwnerClose,
    GenerationNull,
    RoleChange,
    DenyInsert,
    PolicyInsert,
    DefaultKeyInsert,
    CustomInsert,
    SsoInsert,
}
async fn final_joint_wait(tag: &str, change: DuringFinalWait) {
    use openbot_contracts::runtime_capabilities::{
        RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
    };
    let admin = admin_config(tag);
    with_temp_database(&admin,tag,|config|async move {
        let mut fixture=Fixture::new(config,Mode::Sessions).await?; let gate=FinalizeGate::new();
        fixture.install_actual(Mode::Sessions,Some(gate.clone())).await?; let auth=fixture.auth(COOKIE_A).await?;
        let app=fixture.application.clone(); let input=auth.clone();
        let pending=tokio::spawn(async move { app.execute(input,AppCommand::GetRuntimeCapabilities).await });
        gate.entered().await?;
        let mut controller=fixture.pool.get().await.map_err(|_| "final controller acquire failed".to_owned())?;
        let controller_pid:i32=controller.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|_| "controller PID failed".to_owned())?.get(0);
        let tx=controller.transaction().await.map_err(|_| "controller begin failed".to_owned())?;
        tx.batch_execute("SET LOCAL lock_timeout='1500ms'; LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE").await.map_err(|_| "actual source relation lock failed".to_owned())?;
        let observer=fixture.pool.get().await.map_err(|_| "final wait observer acquire failed".to_owned())?;
        gate.release();
        let producer=actual_blocked_pid(&observer,controller_pid,"%WITH policy_scan AS MATERIALIZED%").await?;
        require(producer!=controller_pid,"producer/controller identity conflated")?;
        match change {
            DuringFinalWait::LogoutA=>{ tx.execute("DELETE FROM public.sessions WHERE id=$1",&[&A_ID]).await.map_err(|_| "actual A deletion failed".to_owned())?; }
            DuringFinalWait::OwnerClose=>fixture.resolver.close_request_bindings(),
            DuringFinalWait::GenerationNull=>{tx.batch_execute("UPDATE public.users SET auth_generation=NULL WHERE id='capability-owner'").await.map_err(|_| "current gen mutation failed".to_owned())?;}
            DuringFinalWait::RoleChange=>{tx.batch_execute("UPDATE public.user_roles SET role='admin' WHERE user_id='capability-owner'").await.map_err(|_| "current role mutation failed".to_owned())?;}
            DuringFinalWait::DenyInsert=>{tx.batch_execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES('capability-owner@example.test','owned-controller')").await.map_err(|_| "current deny insertion failed".to_owned())?;}
            DuringFinalWait::PolicyInsert=>{tx.batch_execute("INSERT INTO public.action_policy(id,mode,deny,allow) VALUES('current','enforce',ARRAY['true'],'{}')").await.map_err(|_| "negative policy insertion failed".to_owned())?;}
            DuringFinalWait::DefaultKeyInsert=>fixture.seed_default_key().await?,
            DuringFinalWait::CustomInsert=>{fixture.seed_custom(&auth).await?;}
            DuringFinalWait::SsoInsert=>{seed_legal_sso(&*tx).await?;}
        }
        // Observe expected controller-only changes in the very transaction holding the lock.
        let facts:Value=tx.query_one(FINGERPRINT_SQL,&[]).await.map_err(|_| "controller-only fingerprint failed".to_owned())?.get(0);
        let expected:[u8;32]=Sha256::digest(serde_json::to_vec(&facts).map_err(|_| "controller fingerprint encode failed".to_owned())?).into();
        tx.commit().await.map_err(|_| "final relation release failed".to_owned())?;
        let result=tokio::time::timeout(Duration::from_secs(3),pending).await.map_err(|_| "actual finalizer did not complete after release".to_owned())?
            .map_err(|_| "actual use case task failed".to_owned())?;
        match change {
            DuringFinalWait::LogoutA|DuringFinalWait::OwnerClose|DuringFinalWait::GenerationNull|DuringFinalWait::RoleChange|DuringFinalWait::DenyInsert=>require(result==Err(AppError::Unauthenticated),"post-wait original authority leaked old whole projection")?,
            DuringFinalWait::DefaultKeyInsert=>require(result==Err(AppError::DependencyUnavailable{dependency:"runtime_capabilities"}),"late key/policy mixed blockers reused old missing-key projection")?,
            DuringFinalWait::PolicyInsert=>{let value=projected(result.map_err(|_| "late policy whole query failed".to_owned())?)?;require(entry(&value,Id::AgentTools).reason_code()==Reason::ModelKeyMissing,"final SQL reused old absent-policy predicate")?;}
            DuringFinalWait::CustomInsert=>{let value=projected(result.map_err(|_| "late custom whole query failed".to_owned())?)?;require(entry(&value,Id::ModelCustomV1).reason_code()==Reason::ProviderUnproven,"final SQL reused old absent-custom predicate")?;}
            DuringFinalWait::SsoInsert=>{let value=projected(result.map_err(|_| "late SSO whole query failed".to_owned())?)?;require(entry(&value,Id::DynamicSso).reason_code()==Reason::ProviderUnproven,"final SQL reused old absent-SSO predicate or invented provider readiness")?;}
        }
        require(fixture.port.as_ref().unwrap().calls()==(1,1,1),"whole-result final wait bypassed finalizer/tail")?;
        require(fixture.fingerprint().await?==expected,"capability finalization wrote beyond controller-only facts")?;
        if matches!(change,DuringFinalWait::LogoutA) {
            let b=fixture.auth(COOKIE_B).await?;
            require(b.request_binding().unwrap().verify_current_before(&b,Instant::now()+Duration::from_secs(5)).await.is_ok(),"A late revoke invalidated sibling B")?;
            require(b.auth_generation().get()==0,"A late revoke advanced actor generation")?;
        }
        fixture.finish().await; Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_sees_original_session_deletion_and_keeps_sibling() {
    final_joint_wait("capfinallogout", DuringFinalWait::LogoutA).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_retains_owner_close_401_on_whole_result() {
    final_joint_wait("capfinalclose", DuringFinalWait::OwnerClose).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_refuses_current_generation_null() {
    final_joint_wait("capfinalnull", DuringFinalWait::GenerationNull).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_refuses_current_role_change() {
    final_joint_wait("capfinalrole", DuringFinalWait::RoleChange).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_refuses_new_negative_deny() {
    final_joint_wait("capfinaldeny", DuringFinalWait::DenyInsert).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_reobserves_negative_policy_insertion() {
    final_joint_wait("capfinalpolicy", DuringFinalWait::PolicyInsert).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_reobserves_negative_default_key_insertion_and_mixed_failure() {
    final_joint_wait("capfinalkey", DuringFinalWait::DefaultKeyInsert).await;
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_reobserves_negative_custom_configuration_and_scoped_key_insertion()
{
    final_joint_wait("capfinalcustom", DuringFinalWait::CustomInsert).await;
}

/// Controlled configuration written only into this fixture's disposable database. The actual
/// Domain AEAD and current SSO source decrypt/validate it; no live IdP/preflight is represented.
async fn seed_legal_sso(c: &impl tokio_postgres::GenericClient) -> Result<(), String> {
    let provider = "owned-idp";
    let plaintext=serde_json::to_vec(&json!({"protocol":"oidc","version":2,"client_id":"owned-client",
        "client_secret":format!("owned-{}",Uuid::now_v7().simple()),"group_claim_path":null,"group_normalization":"trim_lowercase"}))
        .map_err(|_| "controlled SSO config encoding failed".to_owned())?;
    let data_key = DataKey::from_bytes(
        [
            Uuid::now_v7().as_bytes().as_slice(),
            Uuid::now_v7().as_bytes().as_slice(),
        ]
        .concat(),
    )
    .map_err(|_| "controlled SSO data key rejected".to_owned())?;
    let binding = RecordBinding::new(
        TenantId::new(TENANT),
        SecretId::new("sso-provider/owned-idp/oidc_config"),
        SecretKind::Connector,
        SecretPrincipal::Deployment,
        SecretPrincipal::Deployment,
        KeyVersion::new(1),
    );
    let stored = seal_v2(
        &WrappingKey::from_bytes(vec![0x42; 32])
            .map_err(|_| "controlled SSO key rejected".to_owned())?,
        &data_key,
        &binding,
        Nonce::from_array([0x44; NONCE_BYTES]),
        Nonce::from_array([0x45; NONCE_BYTES]),
        &plaintext,
    )
    .map_err(|_| "actual Domain SSO fixture seal failed".to_owned())?
    .to_column_value();
    c.execute("INSERT INTO public.sso_providers(id,issuer,oidc_config,user_id,provider_id,domain) VALUES($1,'https://idp.example.test',$2,$3,$4,'example.test')",
        &[&Uuid::now_v7().to_string(),&stored,&OWNER,&provider]).await.map_err(|_| "controlled current SSO insertion failed".to_owned())?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_joint_wait_reobserves_negative_sso_insertion_without_provider_probe() {
    final_joint_wait("capfinalsso", DuringFinalWait::SsoInsert).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn legal_current_sso_cipher_without_readonly_provider_observation_is_not_ready() {
    use openbot_contracts::runtime_capabilities::{
        RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
        RuntimeCapabilityState as State,
    };
    let admin = admin_config("capssounproven");
    with_temp_database(&admin, "capssounproven", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        seed_legal_sso(
            &**fixture
                .pool
                .get()
                .await
                .map_err(|_| "SSO seed acquire failed".to_owned())?,
        )
        .await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let before = fixture.fingerprint().await?;
        let value = projected(
            fixture
                .app(&auth)
                .await
                .map_err(|_| "actual legal SSO capability query failed".to_owned())?,
        )?;
        require(
            entry(&value, Id::DynamicSso).state() == State::Unavailable
                && entry(&value, Id::DynamicSso).reason_code() == Reason::ProviderUnproven,
            "legal SSO config minted provider readiness",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "SSO GET migrated cipher, probed login or appended audit",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn foreign_resolver_equal_auth_context_cannot_collect_own_pool_facts() {
    let admin = admin_config("capforeignowner");
    with_temp_database(&admin, "capforeignowner", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        let original = fixture.auth(COOKIE_A).await?;
        let foreign = PostgresSessionAuthResolver::new(
            fixture.pool.clone(),
            SESSION_KEY,
            default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
        )
        .map_err(|_| "second actual owner construction failed".to_owned())?;
        let (parts, ()) = Request::builder()
            .uri(PATH)
            .header("cookie", format!("openbot_session={COOKIE_A}"))
            .body(())
            .map_err(|_| "foreign resolve request failed".to_owned())?
            .into_parts();
        let foreign_auth = foreign
            .resolve(&parts)
            .await
            .map_err(|_| "second actual owner resolve failed".to_owned())?;
        require(
            original == foreign_auth
                && !original
                    .request_binding()
                    .unwrap()
                    .identity()
                    .same_binding(foreign_auth.request_binding().unwrap().identity()),
            "foreign provenance not distinct",
        )?;
        let before = fixture.fingerprint().await?;
        require(
            fixture.app(&foreign_auth).await == Err(AppError::Unauthenticated),
            "equal foreign AuthContext acquired real collector authority",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "foreign owner refusal wrote facts",
        )?;
        foreign.close_request_bindings();
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_single_user_factory_is_sessionless_current_canonical_and_owner_scoped() {
    let admin = admin_config("capsingleactual");
    with_temp_database(&admin, "capsingleactual", |config| async move {
        let mut fixture = Fixture::new(config, Mode::SingleUser).await?;
        fixture.install_actual(Mode::SingleUser, None).await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let before = fixture.fingerprint().await?;
        require(
            auth.is_single_user()
                && projected(
                    fixture
                        .app(&auth)
                        .await
                        .map_err(|_| "real SingleUser capability query failed".to_owned())?,
                )?
                .host_mode()
                    == openbot_contracts::runtime_capabilities::RuntimeCapabilityHostMode::Server,
            "canonical factory mode/session shape false",
        )?;
        let count: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|_| "sessionless observer acquire failed".to_owned())?
            .query_one("SELECT count(*) FROM public.sessions", &[])
            .await
            .map_err(|_| "sessionless observation failed".to_owned())?
            .get(0);
        require(
            count == 0,
            "SingleUser capability observation manufactured a session",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "canonical observation repaired or wrote state",
        )?;
        fixture.resolver.close_request_bindings();
        require(
            fixture.app(&auth).await == Err(AppError::Unauthenticated),
            "closed actual canonical owner survived through collector",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn original_total_budget_bounds_actual_pool_wait_and_never_reaches_collector() {
    let admin = admin_config("cappoolbudget");
    with_temp_database(&admin, "cappoolbudget", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(
                fixture
                    .pool
                    .get()
                    .await
                    .map_err(|_| "pool saturation acquire failed".to_owned())?,
            );
        }
        let began = Instant::now();
        let result = tokio::time::timeout(Duration::from_millis(6500), fixture.app(&auth))
            .await
            .map_err(|_| "use case exceeded original five-second pool budget".to_owned())?;
        let elapsed = began.elapsed();
        require(
            result
                == Err(AppError::DependencyUnavailable {
                    dependency: "runtime_capabilities",
                }),
            "pool wait error is not static runtime capability 503",
        )?;
        require(
            elapsed >= Duration::from_secs(4) && elapsed < Duration::from_millis(6500),
            "actual whole budget was reset or not spent",
        )?;
        require(
            fixture.port.as_ref().unwrap().calls() == (0, 0, 0),
            "exhausted preguard budget reached collector",
        )?;
        drop(held);
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_final_sql_wait_spends_original_budget_and_timeout_is_not_worker_stop() {
    let admin = admin_config("capfinalbudget");
    with_temp_database(&admin, "capfinalbudget", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        let gate = FinalizeGate::new();
        fixture
            .install_actual(Mode::Sessions, Some(gate.clone()))
            .await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let before = fixture.fingerprint().await?;
        let began = Instant::now();
        let app = fixture.application.clone();
        let task =
            tokio::spawn(
                async move { app.execute(auth, AppCommand::GetRuntimeCapabilities).await },
            );
        gate.entered().await?;
        let mut controller = fixture
            .pool
            .get()
            .await
            .map_err(|_| "timeout controller acquire failed".to_owned())?;
        let pid: i32 = controller
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|_| "timeout controller PID failed".to_owned())?
            .get(0);
        let tx = controller
            .transaction()
            .await
            .map_err(|_| "timeout controller begin failed".to_owned())?;
        tx.batch_execute("LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE")
            .await
            .map_err(|_| "timeout relation lock failed".to_owned())?;
        let observer = fixture
            .pool
            .get()
            .await
            .map_err(|_| "timeout observer acquire failed".to_owned())?;
        gate.release();
        let producer =
            actual_blocked_pid(&observer, pid, "%WITH policy_scan AS MATERIALIZED%").await?;
        let result = tokio::time::timeout(Duration::from_millis(6500), task)
            .await
            .map_err(|_| "total budget exceeded during final SQL".to_owned())?
            .map_err(|_| "timeout use case task failed".to_owned())?;
        require(
            result
                == Err(AppError::DependencyUnavailable {
                    dependency: "runtime_capabilities",
                }),
            "final SQL timeout emitted stale success or nonspecific error",
        )?;
        require(
            began.elapsed() >= Duration::from_secs(4)
                && began.elapsed() < Duration::from_millis(6500),
            "postguard/finalizer reset original budget",
        )?;
        tx.rollback()
            .await
            .map_err(|_| "timeout source lock rollback failed".to_owned())?;
        // Separate actual quiescence observation on the connection checked out before the
        // request. A timeout return alone is not SQL cancellation or worker completion.
        let mut quiescent = false;
        for _ in 0..200 {
            let row = observer
                .query_opt(
                    "SELECT state,xact_start FROM pg_stat_activity WHERE pid=$1",
                    &[&producer],
                )
                .await
                .map_err(|_| "actual timed-out producer observation failed".to_owned())?;
            quiescent = match row {
                None => true,
                Some(row) => {
                    row.get::<_, String>(0) != "active"
                        && row.get::<_, Option<OffsetDateTime>>(1).is_none()
                }
            };
            if quiescent {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        require(
            quiescent,
            "deadline returned but actual SQL producer remained active",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "timed-out capability query wrote facts",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

async fn actual_blocked_pid(
    observer: &deadpool_postgres::Object,
    blocker: i32,
    needle: &str,
) -> Result<i32, String> {
    for _ in 0..200 {
        let rows = observer.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND query LIKE $1 AND $2=ANY(pg_blocking_pids(pid))", &[&needle, &blocker])
            .await.map_err(|_| "blocking observation failed".to_owned())?;
        if rows.len() == 1 {
            return rows[0]
                .try_get(0)
                .map_err(|_| "blocking PID decode failed".to_owned());
        }
        if rows.len() > 1 {
            return Err("ambiguous actual blocked producer".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("actual bounded final SQL wait was not observed".to_owned())
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL; no silent pass without the fixture"]
async fn authenticated_http_rejects_every_query_body_and_method_before_application() {
    let admin = admin_config("runtime_capabilities_http_framing");
    with_temp_database(&admin, "capframing", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let before = fixture.fingerprint().await?;
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
            (
                Method::GET,
                "/api/me/capabilities?hostMode=desktop_local",
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
                fixture
                    .http(method, path, Some(COOKIE_A), body)
                    .await?
                    .status
                    == expected,
                "actual framing status differs",
            )?;
        }
        require(
            fixture.application.calls.load(Ordering::SeqCst) == 0,
            "invalid framing invoked Application",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "framing changed session/policy/cipher/audit",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn anonymous_malformed_get_is_401_no_store_and_zero_application() {
    let admin = admin_config("runtime_capabilities_anonymous");
    with_temp_database(&admin, "capanon", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let before = fixture.fingerprint().await?;
        for path in [
            PATH,
            "/api/me/capabilities?",
            "/api/me/capabilities?actorId=foreign",
        ] {
            require(
                fixture.http(Method::GET, path, None, b"{}").await?.status
                    == StatusCode::UNAUTHORIZED,
                "anonymous malformed GET lost auth precedence",
            )?;
        }
        require(
            fixture.application.calls.load(Ordering::SeqCst) == 0,
            "anonymous GET invoked Application",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "anonymous GET changed actual database facts",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn missing_real_factory_is_static_503_and_get_never_touches_session_activity() {
    let admin = admin_config("runtime_capabilities_missing_factory");
    with_temp_database(&admin, "capmissing", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let before = fixture.fingerprint().await?;
        let result = fixture.http(Method::GET, PATH, Some(COOKIE_A), b"").await?;
        require(
            result.status == StatusCode::SERVICE_UNAVAILABLE,
            "missing actual capability factory must be 503",
        )?;
        require(
            result.value == json!({"code":"dependency_unavailable"})
                && fixture
                    .application
                    .last_error
                    .lock()
                    .map_err(|_| "actual App error observer poisoned".to_owned())?
                    .as_ref()
                    == Some(&AppError::DependencyUnavailable {
                        dependency: "host_request_binding",
                    }),
            "missing factory error is not static host source",
        )?;
        require(
            fixture.application.calls.load(Ordering::SeqCst) == 1,
            "valid GET must use the real App once",
        )?;
        require(
            fixture.fingerprint().await? == before,
            "capability GET touched session.updated_at or wrote policy/cipher/audit",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn same_actor_sibling_sessions_are_distinct_and_logout_does_not_advance_generation() {
    let admin = admin_config("runtime_capabilities_original_epoch");
    with_temp_database(&admin, "capepoch", |config| async move {
        let fixture = Fixture::new(config, Mode::Sessions).await?;
        let a = fixture.auth(COOKIE_A).await?;
        let b = fixture.auth(COOKIE_B).await?;
        require(
            a == b
                && !a
                    .request_binding()
                    .unwrap()
                    .identity()
                    .same_binding(b.request_binding().unwrap().identity()),
            "same actor A/B lost original epoch distinction",
        )?;
        fixture
            .pool
            .get()
            .await
            .map_err(|_| "controller acquire failed".to_owned())?
            .execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID])
            .await
            .map_err(|_| "actual A revoke failed".to_owned())?;
        let generation: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|_| "generation observer acquire failed".to_owned())?
            .query_one(
                "SELECT auth_generation FROM public.users WHERE id=$1",
                &[&OWNER],
            )
            .await
            .map_err(|_| "generation observation failed".to_owned())?
            .get(0);
        require(generation == 0, "test A revoke changed user generation")?;
        require(
            a.request_binding()
                .unwrap()
                .verify_current_before(&a, Instant::now() + Duration::from_secs(5))
                .await
                == Err(openbot_contracts::request_binding::HostRequestBindingError::NotCurrent),
            "actual A proof survived row deletion",
        )?;
        require(
            b.request_binding()
                .unwrap()
                .verify_current_before(&b, Instant::now() + Duration::from_secs(5))
                .await
                .is_ok(),
            "live actual B proof was globally revoked",
        )?;
        fixture.finish().await;
        Ok(())
    })
    .await;
}

#[derive(Clone, Copy)]
enum SessionTailBoundary {
    Expires,
    Idle,
    Absolute,
}

async fn actual_session_tail_clock_crossing(tag: &str, which: SessionTailBoundary) {
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        fixture.install_actual(Mode::Sessions, None).await?;
        // Assemble every actual dependency before making the original row near its lawful
        // boundary. The incoming HTTP request then resolves and mints its real new proof.
        let now = OffsetDateTime::now_utc();
        let near = now + time::Duration::milliseconds(1500);
        let lifetime = default_session_lifetime();
        let (expires, created, updated) = match which {
            SessionTailBoundary::Expires => (near, now - time::Duration::minutes(1), now - time::Duration::minutes(1)),
            SessionTailBoundary::Idle => {
                let updated = near - lifetime.idle();
                (now + time::Duration::hours(1), updated - time::Duration::seconds(1), updated)
            }
            SessionTailBoundary::Absolute => (now + time::Duration::hours(1), near - lifetime.absolute(), now),
        };
        let row = fixture.pool.get().await.map_err(|_| "owned tail-clock seed acquire failed".to_owned())?
            .query_one("UPDATE public.sessions SET expires_at=$2,created_at=$3,updated_at=$4 WHERE id=$1 RETURNING expires_at,created_at,updated_at", &[&A_ID, &expires, &created, &updated])
            .await.map_err(|_| "owned lawful original session clock seed failed".to_owned())?;
        // Read the actual persisted timestamps, including PG precision. Never synthesize an
        // Application epoch/stamp, replace a witness or borrow a caller transaction.
        let stored_expires: OffsetDateTime = row.try_get(0).map_err(|_| "owned expiry decode failed".to_owned())?;
        let stored_created: OffsetDateTime = row.try_get(1).map_err(|_| "owned creation decode failed".to_owned())?;
        let stored_updated: OffsetDateTime = row.try_get(2).map_err(|_| "owned activity decode failed".to_owned())?;
        let boundary = match which {
            SessionTailBoundary::Expires => stored_expires,
            SessionTailBoundary::Idle => stored_updated + lifetime.idle(),
            SessionTailBoundary::Absolute => stored_created + lifetime.absolute(),
        };
        require(stored_created <= stored_updated && stored_updated <= OffsetDateTime::now_utc() && OffsetDateTime::now_utc() < stored_expires,
            "owned original session row was not lawfully live before HTTP")?;
        let schedule = SessionTailClockSchedule::new(boundary);
        let port = fixture.port.as_ref().ok_or("actual tail-clock collector not assembled")?;
        *port.session_tail_clock.lock().map_err(|_| "private clock schedule poisoned".to_owned())? = Some(schedule.clone());
        let before = fixture.fingerprint().await?;
        let began = Instant::now();
        let result = fixture.http(Method::GET, PATH, Some(COOKIE_A), b"").await?;
        let (positive, before_boundary, crossed, delay, within_budget) = {
            let observed = schedule.observed.lock().map_err(|_| "private clock observation poisoned".to_owned())?;
            (observed.actual_tail_positive, observed.before_boundary, observed.crossed_boundary, observed.delay, observed.within_use_case_deadline)
        };
        require(positive && before_boundary, "session was already invalid or real collector tail never succeeded before clock crossing")?;
        require(crossed && delay > Duration::ZERO && delay <= Duration::from_secs(2), "real same-request clock boundary was not crossed with bounded synchronous scheduling")?;
        require(within_budget && began.elapsed() < Duration::from_secs(5), "tail-clock fixture exhausted or replaced the actual total deadline")?;
        require(result.status == StatusCode::UNAUTHORIZED && result.value == json!({"code":"unauthenticated"}),
            "mandatory carried-session clock witness exposed an expired old projection")?;
        require(result.value.get("capabilities").is_none(), "session clock revocation leaked the old capability vector")?;
        require(fixture.application.last_error.lock().map_err(|_| "actual App error observer poisoned".to_owned())?.as_ref() == Some(&AppError::Unauthenticated),
            "same real App call did not classify carried clock expiry as unauthenticated")?;
        require(fixture.application.calls.load(Ordering::SeqCst) == 1 && port.calls() == (1, 1, 1),
            "actual clock test skipped or repeated App/observe/finalize/tail")?;
        require(fixture.fingerprint().await? == before, "tail-clock capability query touched original session or wrote any source fact")?;
        fixture.finish().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL; bounded real synchronous host-clock crossing"]
async fn actual_carried_session_expires_after_successful_real_tail_before_app_witness_is_401() {
    actual_session_tail_clock_crossing("captailexpires", SessionTailBoundary::Expires).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL; bounded real synchronous host-clock crossing"]
async fn actual_carried_session_idle_after_successful_real_tail_before_app_witness_is_401() {
    actual_session_tail_clock_crossing("captailidle", SessionTailBoundary::Idle).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL; bounded real synchronous host-clock crossing"]
async fn actual_carried_session_absolute_after_successful_real_tail_before_app_witness_is_401() {
    actual_session_tail_clock_crossing("captailabsolute", SessionTailBoundary::Absolute).await;
}
