//! Real owned PostgreSQL observations for the current-owner custom catalogue.
//!
//! The explicit trusted TEST Host below exercises the repository's original SQL/Tx,
//! immutable epoch comparison and rollback ownership. It is not a production Server
//! resolver or Local window, whose actual consumers have separate integration tests.
//! The original harness creates a fresh owned DB and uses FORCE on its final DB cleanup;
//! that cleanup alone does not prove an individual application's driver was joined.

#![cfg(feature = "server-runtime")]

mod harness;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use openbot_application::custom_model_catalog::{
    CustomModelCatalogError as Error, CustomModelCatalogInventory,
};
use openbot_application::{ApplicationService, OpenBotApplication};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::custom_model_catalog::{
    CustomModelCatalogPage, CustomModelCatalogPageRequest,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    CustomModelCatalogHostObservation, CustomModelCatalogHostTailFactory,
    CustomModelCatalogHostTailWitness, CustomModelCatalogHostTarget,
    CustomModelCatalogSessionFacts, HostRequestBindingError as HostError, HostRequestBindingGuard,
    HostRequestBindingIdentity, HostRequestBindingKind, RequestBindingIssuer,
    RequestBindingOwnerLease, ServerSessionBindingIdentity,
};
use openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory;
use openbot_infra::db::{fresh, pool};
use openbot_infra::repo::ChannelRepo;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;
const DEPLOYMENT: &str = "owned-inventory-deployment";
const TENANT: &str = "owned-inventory-tenant";
const CLOSE_BUDGET: Duration = Duration::from_secs(10);

fn require(value: bool, message: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn actor(user: &str, admin: bool) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(user),
        AuthGeneration::new(7),
        false,
    )
    .with_role(if admin { Role::Admin } else { Role::User })
    .build()
}

fn request(cursor: Option<String>) -> CustomModelCatalogPageRequest {
    CustomModelCatalogPageRequest { cursor }
}

fn repository(p: &pool::DatabasePool) -> TestResult<Arc<PostgresCustomModelCatalogInventory>> {
    PostgresCustomModelCatalogInventory::new(
        p.clone(),
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
    )
    .map(Arc::new)
    .map_err(|_| "inventory construction failed".to_owned())
}

async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + CLOSE_BUDGET;
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "original observed Pool connection was not actually destroyed",
        )?;
    }
    Ok(())
}

async fn owned_fixture<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(pool::DatabaseConfig, pool::DatabasePool) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(tag);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "inventory tests require explicit owned literal loopback PG",
    )
    .expect("owned PostgreSQL prerequisite");
    harness::with_temp_database(&admin, tag, |config| async move {
        require(
            config.dbname.starts_with("openbot_it_"),
            "owned database name missing",
        )?;
        let p = pool::connect(&config.clone().with_max_pool_size(4))
            .await
            .map_err(|e| e.to_string())?;
        let result = body(config, p.clone()).await;
        let closed = close_pool(p).await;
        result.and(closed)
    })
    .await;
}

async fn initialize(p: &pool::DatabasePool) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
    c.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
      ('alice','owned-inventory-alice@example.test',7),
      ('bob','owned-inventory-bob@example.test',7);
      INSERT INTO public.user_roles(user_id,role) VALUES ('alice','user'),('bob','admin')",
    )
    .await
    .map_err(|e| e.to_string())
}

/// Seed SQL-valid, scope-consistent metadata and synthetic secret records. Inventory
/// must not try to open these deliberately non-Vault fixture bytes or confer Ready.
async fn seed(
    c: &Client,
    first: u128,
    count: usize,
    owner: &str,
    deployment: &str,
    tenant: &str,
) -> TestResult {
    c.batch_execute("BEGIN; SET CONSTRAINTS ALL DEFERRED")
        .await
        .map_err(|e| e.to_string())?;
    let result: TestResult = async {
        for offset in 0..count {
            let n = first + offset as u128;
            let id = Uuid::from_u128(n);
            let secret = Uuid::from_u128(n + 100_000);
            let protocol = ["openai_chat_completions", "openai_responses", "anthropic_messages"][offset % 3];
            c.execute("INSERT INTO public.model_connections
              (id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,
               enabled,revision,current_secret_id,created_at,updated_at)
              VALUES($1,$2,$3,$4,$5,$6,'https://owned-inventory.example.test/v1',$7,true,11,$8,now(),now())",
                &[&id,&deployment,&tenant,&owner,&format!("Owned model {n}"),&protocol,
                  &format!("owned-model-{n}"),&secret]).await.map_err(|e| e.to_string())?;
            c.execute("INSERT INTO public.model_connection_secrets
              (id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at)
              VALUES($1,$2,$3,$4,$5,'owned-inventory-not-a-Vault-envelope',now())",
                &[&secret,&id,&deployment,&tenant,&owner]).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }.await;
    match result {
        Ok(()) => c.batch_execute("COMMIT").await.map_err(|e| e.to_string()),
        Err(error) => {
            c.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            Err(error)
        }
    }
}

async fn state(c: &Client) -> TestResult<Value> {
    let text: String = c.query_one("SELECT jsonb_build_object(
      'models',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM public.model_connections x),
      'catalog',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY connection_id),'[]') FROM public.custom_model_catalogs x),
      'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM public.model_connection_secrets x),
      'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM public.sessions x),
      'audit',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM public.audit_events x),
      'ledger',(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM openbot_internal.schema_migrations x)
      )::text", &[]).await.map_err(|e| e.to_string())?.get(0);
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

struct HostFamily {
    _lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
}

impl HostFamily {
    fn install(repository: &PostgresCustomModelCatalogInventory) -> TestResult<Self> {
        let (lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        repository
            .enroll_host_issuer(&issuer)
            .map_err(|_| "test issuer enrollment failed")?;
        Ok(Self {
            _lease: lease,
            issuer,
        })
    }
}

#[derive(Default)]
struct TailFacts {
    created: AtomicUsize,
    dropped: AtomicUsize,
    verified: AtomicUsize,
    premature_drop: AtomicBool,
    premature_verify: AtomicBool,
    reject: AtomicBool,
    rollback_cz: Option<Arc<AtomicUsize>>,
}

struct TestHost {
    original: AuthContext,
    issuer: RequestBindingIssuer,
    identity: OnceLock<HostRequestBindingIdentity>,
    repository: Weak<PostgresCustomModelCatalogInventory>,
    own: Weak<TestHost>,
    revoked: AtomicBool,
    tails: Arc<TailFacts>,
}

impl TestHost {
    fn check(&self, auth: &AuthContext, deadline: Instant) -> Result<(), HostError> {
        if Instant::now() >= deadline {
            return Err(HostError::Unavailable);
        }
        if self.revoked.load(Ordering::SeqCst)
            || !self.issuer.observation().is_current()
            || self.original != *auth
            || !self
                .identity
                .get()
                .zip(auth.request_binding())
                .is_some_and(|(identity, binding)| identity.same_binding(binding.identity()))
        {
            return Err(HostError::NotCurrent);
        }
        Ok(())
    }
}

impl HostRequestBindingGuard for TestHost {
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostError>> + Send + 'a>> {
        Box::pin(async move { self.check(auth, Instant::now() + Duration::from_secs(5)) })
    }

    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostError>> + Send + 'a>> {
        Box::pin(async move { self.check(auth, deadline) })
    }

    fn borrow_custom_model_catalog_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn CustomModelCatalogHostTarget,
        deadline: Instant,
    ) -> Result<CustomModelCatalogHostObservation<'a>, HostError> {
        self.check(auth, deadline)?;
        let repository = self.repository.upgrade().ok_or(HostError::NotCurrent)?;
        if !repository.matches_host_target(target, auth) {
            return Err(HostError::NotCurrent);
        }
        let identity = self.identity.get().ok_or(HostError::NotCurrent)?;
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSession,
            identity.clone(),
            Some(self.issuer.borrow_server_session_epoch(identity)?),
            Box::new(TestFactory {
                host: self.own.clone(),
            }),
        )
    }
}

struct TestFactory {
    host: Weak<TestHost>,
}

impl CustomModelCatalogHostTailFactory for TestFactory {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<CustomModelCatalogSessionFacts>,
        deadline: Instant,
    ) -> Result<Box<dyn CustomModelCatalogHostTailWitness>, HostError> {
        let host = self.host.upgrade().ok_or(HostError::NotCurrent)?;
        host.check(auth, deadline)?;
        let session = session.ok_or(HostError::NotCurrent)?;
        if session.created_at > session.updated_at
            || session.updated_at > session.observed_wall
            || session.expires_at <= session.observed_wall
            || session.observed_wall - session.updated_at > time::Duration::minutes(10)
        {
            return Err(HostError::NotCurrent);
        }
        host.tails.created.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(TestTail {
            host: self.host.clone(),
            original: auth.clone(),
            session,
            facts: host.tails.clone(),
        }))
    }
}

struct TestTail {
    host: Weak<TestHost>,
    original: AuthContext,
    session: CustomModelCatalogSessionFacts,
    facts: Arc<TailFacts>,
}

impl Drop for TestTail {
    fn drop(&mut self) {
        self.facts.dropped.fetch_add(1, Ordering::SeqCst);
        if self
            .facts
            .rollback_cz
            .as_ref()
            .is_some_and(|value| value.load(Ordering::SeqCst) == 0)
        {
            self.facts.premature_drop.store(true, Ordering::SeqCst);
        }
    }
}

impl CustomModelCatalogHostTailWitness for TestTail {
    fn verify_current(&self, auth: &AuthContext, deadline: Instant) -> Result<(), HostError> {
        self.facts.verified.fetch_add(1, Ordering::SeqCst);
        if self
            .facts
            .rollback_cz
            .as_ref()
            .is_some_and(|value| value.load(Ordering::SeqCst) == 0)
        {
            self.facts.premature_verify.store(true, Ordering::SeqCst);
        }
        if self.original != *auth || self.facts.reject.load(Ordering::SeqCst) {
            return Err(HostError::NotCurrent);
        }
        let host = self.host.upgrade().ok_or(HostError::NotCurrent)?;
        host.check(auth, deadline)?;
        let now = OffsetDateTime::now_utc();
        if now < self.session.observed_wall
            || now >= self.session.expires_at
            || Instant::now() < self.session.observed_monotonic
        {
            return Err(HostError::NotCurrent);
        }
        Ok(())
    }
}

async fn session(
    c: &Client,
    repository: &Arc<PostgresCustomModelCatalogInventory>,
    family: &HostFamily,
    id: &str,
    user: &str,
    admin: bool,
    tails: Arc<TailFacts>,
) -> TestResult<(AuthContext, Arc<TestHost>)> {
    let now = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let expires = now + time::Duration::hours(1);
    let token = format!("owned-test-token-column-{id}");
    c.execute("INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation)
      VALUES($1,$2,$3,$4,$4,$5,7)", &[&id,&user,&token,&now,&expires]).await.map_err(|e| e.to_string())?;
    // PostgreSQL stores microseconds; mint the epoch from its actual decoded row,
    // never from the higher-precision input clock value that preceded persistence.
    let created: OffsetDateTime = c
        .query_one("SELECT created_at FROM public.sessions WHERE id=$1", &[&id])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    let original = actor(user, admin);
    let host = Arc::new_cyclic(|own| TestHost {
        original: original.clone(),
        issuer: family.issuer.clone(),
        identity: OnceLock::new(),
        repository: Arc::downgrade(repository),
        own: own.clone(),
        revoked: AtomicBool::new(false),
        tails,
    });
    let binding = family
        .issuer
        .bind_server_session(
            &original,
            ServerSessionBindingIdentity::from_verified_row(
                id.to_owned(),
                ActorId::new(user),
                token,
                created,
                AuthGeneration::new(7),
            ),
            host.clone(),
        )
        .map_err(|_| "test binding construction failed")?;
    host.identity
        .set(binding.identity().clone())
        .map_err(|_| "test identity already set")?;
    let auth = original
        .with_verified_request_binding(binding)
        .map_err(|_| "test binding attach failed")?;
    Ok((auth, host))
}

fn application(
    p: &pool::DatabasePool,
    inventory: Arc<PostgresCustomModelCatalogInventory>,
) -> OpenBotApplication<ChannelRepo> {
    OpenBotApplication::new(ChannelRepo::new(p.clone()))
        .with_custom_model_catalog_inventory(inventory)
}

async fn page(
    application: &impl ApplicationService,
    auth: &AuthContext,
    cursor: Option<String>,
) -> TestResult<CustomModelCatalogPage> {
    let reply = application
        .execute(
            auth.clone(),
            AppCommand::ListCustomModelCatalog(request(cursor)),
        )
        .await
        .map_err(|e| format!("inventory execute failed: {}", e.code().as_str()))?;
    match reply {
        AppReply::CustomModelCatalog(reply) => Ok(reply.page().clone()),
        _ => Err("inventory returned wrong typed reply".to_owned()),
    }
}

async fn expect_error(
    repository: &PostgresCustomModelCatalogInventory,
    auth: &AuthContext,
    expected: Error,
) -> TestResult {
    let outcome = repository
        .list_current(
            auth,
            &request(None),
            Instant::now() + Duration::from_secs(5),
        )
        .await;
    require(
        matches!(outcome, Err(error) if error == expected),
        "wrong closed inventory error",
    )
}

#[derive(Default)]
struct WireFacts {
    pid: AtomicI32,
    begins: AtomicUsize,
    read_only_rc: AtomicUsize,
    commits: AtomicUsize,
    final_statements: AtomicUsize,
    rollback_cz: Arc<AtomicUsize>,
    drop_rollback: AtomicBool,
    schema_parse: AtomicBool,
    hold_schema: AtomicBool,
    schema_seen: Notify,
    schema_release: Notify,
    terminated: AtomicBool,
}

struct WireRelay {
    port: u16,
    facts: Arc<WireFacts>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<TestResult>>,
}

impl Drop for WireRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Failure/unwind only. An abort is never reported as a naturally joined relay.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let tag = r.read_u8().await?;
    let length = r.read_u32().await?;
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(std::io::Error::other("owned relay invalid frame length"));
    }
    let mut payload = vec![0; (length - 4) as usize];
    r.read_exact(&mut payload).await?;
    Ok((tag, payload))
}

async fn send_frame<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    tag: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    w.write_u8(tag).await?;
    w.write_u32((payload.len() + 4) as u32).await?;
    w.write_all(payload).await
}

fn sql_in_frame(tag: u8, payload: &[u8]) -> Option<&str> {
    let bytes = match tag {
        b'Q' => payload,
        b'P' => {
            let end = payload.iter().position(|byte| *byte == 0)?;
            payload.get(end + 1..)?
        }
        _ => return None,
    };
    std::str::from_utf8(bytes.split(|byte| *byte == 0).next()?).ok()
}

impl WireRelay {
    async fn start(config: &pool::DatabaseConfig) -> TestResult<Self> {
        require(
            matches!(config.host.as_str(), "127.0.0.1" | "::1")
                && config.dbname.starts_with("openbot_it_"),
            "relay requires owned loopback DB",
        )?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let upstream_host = config.host.clone();
        let upstream_port = config.port;
        let facts = Arc::new(WireFacts::default());
        let observed = facts.clone();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let operation = async move {
                let (mut downstream, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let mut upstream = TcpStream::connect((upstream_host.as_str(), upstream_port))
                    .await
                    .map_err(|e| e.to_string())?;
                let length = downstream.read_u32().await.map_err(|e| e.to_string())?;
                require((8..=64 * 1024).contains(&length), "relay invalid startup")?;
                let mut startup = vec![0; (length - 4) as usize];
                downstream
                    .read_exact(&mut startup)
                    .await
                    .map_err(|e| e.to_string())?;
                require(
                    startup.get(..4) == Some(&196_608_u32.to_be_bytes()),
                    "relay requires original NoTls v3 startup",
                )?;
                upstream
                    .write_u32(length)
                    .await
                    .map_err(|e| e.to_string())?;
                upstream
                    .write_all(&startup)
                    .await
                    .map_err(|e| e.to_string())?;
                let (mut down_read, mut down_write) = downstream.into_split();
                let (mut up_read, mut up_write) = upstream.into_split();
                let frontend_facts = observed.clone();
                let frontend = async move {
                    loop {
                        let (tag, payload) = frame(&mut down_read).await?;
                        if let Some(sql) = sql_in_frame(tag, &payload) {
                            let upper = sql.trim().to_ascii_uppercase();
                            if upper.starts_with("START TRANSACTION") || upper.starts_with("BEGIN")
                            {
                                frontend_facts.begins.fetch_add(1, Ordering::SeqCst);
                                if upper.contains("READ COMMITTED") && upper.contains("READ ONLY") {
                                    frontend_facts.read_only_rc.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            if upper == "COMMIT" {
                                frontend_facts.commits.fetch_add(1, Ordering::SeqCst);
                            }
                            if sql.contains("custom_model_catalog_current_joint_observation") {
                                frontend_facts
                                    .final_statements
                                    .fetch_add(1, Ordering::SeqCst);
                            }
                            if sql.contains("AS mapping_ok") {
                                frontend_facts.schema_parse.store(true, Ordering::SeqCst);
                            }
                        }
                        send_frame(&mut up_write, tag, &payload).await?;
                        if tag == b'X' {
                            frontend_facts.terminated.store(true, Ordering::SeqCst);
                            return Ok::<(), std::io::Error>(());
                        }
                    }
                };
                let backend_facts = observed.clone();
                let backend = async move {
                    loop {
                        let (tag, payload) = frame(&mut up_read).await?;
                        if tag == b'K' {
                            if payload.len() != 8 {
                                return Err(std::io::Error::other("relay bad BackendKeyData"));
                            }
                            backend_facts.pid.store(
                                i32::from_be_bytes(
                                    payload[..4]
                                        .try_into()
                                        .map_err(|_| std::io::Error::other("relay bad PID"))?,
                                ),
                                Ordering::SeqCst,
                            );
                        }
                        let rollback = tag == b'C' && payload == b"ROLLBACK\0";
                        let schema = tag == b'C'
                            && payload == b"SELECT 1\0"
                            && backend_facts.schema_parse.swap(false, Ordering::SeqCst)
                            && backend_facts.hold_schema.swap(false, Ordering::SeqCst);
                        if rollback || schema {
                            let (ready_tag, ready) = frame(&mut up_read).await?;
                            if ready_tag != b'Z'
                                || ready.as_slice() != if rollback { b"I" } else { b"T" }
                            {
                                return Err(std::io::Error::other("relay unexpected real C/Z"));
                            }
                            if rollback {
                                backend_facts.rollback_cz.fetch_add(1, Ordering::SeqCst);
                                if backend_facts.drop_rollback.swap(false, Ordering::SeqCst) {
                                    return Ok(());
                                }
                            } else {
                                backend_facts.schema_seen.notify_one();
                                backend_facts.schema_release.notified().await;
                            }
                            send_frame(&mut down_write, tag, &payload).await?;
                            send_frame(&mut down_write, ready_tag, &ready).await?;
                        } else {
                            send_frame(&mut down_write, tag, &payload).await?;
                        }
                    }
                };
                tokio::select! {
                    value = frontend => match value {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
                        Err(e) => Err(e.to_string()),
                    },
                    value = backend => match value {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
                            && observed.terminated.load(Ordering::SeqCst) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            tokio::select! {
                value = operation => value,
                _ = stopped => Err("relay stopped before natural closure".to_owned()),
            }
        });
        Ok(Self {
            port,
            facts,
            stop: Some(stop),
            task: Some(task),
        })
    }

    fn config(&self, original: &pool::DatabaseConfig) -> pool::DatabaseConfig {
        let mut config = original
            .clone()
            .with_application_name("owned-catalog-inventory-wire")
            .with_max_pool_size(1);
        config.host = "127.0.0.1".to_owned();
        config.port = self.port;
        config
    }

    async fn finish(mut self) -> TestResult {
        let mut task = self.task.take().ok_or("original relay task missing")?;
        match tokio::time::timeout(CLOSE_BUDGET, &mut task).await {
            Ok(joined) => {
                self.stop.take();
                joined.map_err(|e| e.to_string())?
            }
            Err(_) => {
                if let Some(stop) = self.stop.take() {
                    let _ = stop.send(());
                }
                let _ = tokio::time::timeout(CLOSE_BUDGET, &mut task).await;
                task.abort();
                Err("original relay did not naturally retire".to_owned())
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_owner_pagination_validates_101_and_preserves_independent_revisions() {
    owned_fixture("inventory_owner", |_config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 100, "alice", DEPLOYMENT, TENANT).await?;
        seed(&c, 1001, 1, "bob", DEPLOYMENT, TENANT).await?;
        seed(&c, 2001, 1, "alice", "different-deployment", TENANT).await?;
        seed(&c, 3001, 1, "alice", DEPLOYMENT, "different-tenant").await?;
        c.execute(
            "UPDATE public.model_connections SET enabled=false WHERE id=$1",
            &[&Uuid::from_u128(1)],
        )
        .await
        .map_err(|e| e.to_string())?;
        let inventory = repository(&p)?;
        let family = HostFamily::install(&inventory)?;
        let (alice, _alice_host) = session(
            &c,
            &inventory,
            &family,
            "alice-one",
            "alice",
            false,
            Arc::default(),
        )
        .await?;
        let (bob, _bob_host) = session(
            &c,
            &inventory,
            &family,
            "bob-one",
            "bob",
            true,
            Arc::default(),
        )
        .await?;
        let app = application(&p, inventory.clone());
        let before = state(&c).await?;
        let hundred = page(&app, &alice, None).await?;
        require(
            hundred.models.len() == 100 && hundred.next_cursor.is_none(),
            "exact100 must have null cursor",
        )?;
        require(
            !hundred.models[0].enabled
                && hundred.models[0].connection_revision == 11
                && hundred.models[0].catalog_revision == 2,
            "disabled/independent revisions were lost",
        )?;
        let encoded = serde_json::to_value(&hundred).map_err(|e| e.to_string())?;
        for entry in encoded["models"]
            .as_array()
            .ok_or("encoded models not array")?
        {
            require(
                entry.as_object().is_some_and(|keys| keys.len() == 9)
                    && entry.get("endpoint").is_none()
                    && entry.get("ready").is_none()
                    && entry.get("apiKey").is_none(),
                "inventory leaked private fields or Ready",
            )?;
        }
        let own_admin = page(&app, &bob, None).await?;
        require(
            own_admin.models.len() == 1
                && own_admin.models[0].connection_id == Uuid::from_u128(1001).to_string(),
            "admin must still read only its own owner",
        )?;
        require(
            state(&c).await? == before,
            "read changed model/secret/audit/session/ledger",
        )?;
        seed(&c, 101, 2, "alice", DEPLOYMENT, TENANT).await?;
        c.execute(
            "UPDATE public.model_connections SET deleted_at=now() WHERE id=$1",
            &[&Uuid::from_u128(102)],
        )
        .await
        .map_err(|e| e.to_string())?;
        let first = page(&app, &alice, None).await?;
        let cursor = Uuid::from_u128(100).to_string();
        require(
            first.models.len() == 100 && first.next_cursor.as_deref() == Some(cursor.as_str()),
            "101 lookahead wrong",
        )?;
        let second = page(&app, &alice, Some(cursor)).await?;
        require(
            second.models.len() == 1
                && second.models[0].connection_id == Uuid::from_u128(101).to_string()
                && second.next_cursor.is_none(),
            "exclusive cursor or retired exclusion failed",
        )?;
        require(
            page(&app, &alice, Some(Uuid::from_u128(9999).to_string()))
                .await?
                .models
                .is_empty(),
            "legal empty page rejected",
        )?;
        let bad = request(Some("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".to_owned()));
        require(
            matches!(
                inventory
                    .list_current(&alice, &bad, Instant::now() + Duration::from_secs(5))
                    .await,
                Err(Error::InvalidCursor)
            ),
            "typed uppercase cursor accepted",
        )?;
        drop(app);
        drop(alice);
        drop(bob);
        drop(inventory);
        drop(c);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_malformed_lookahead_rejects_whole_page_after_real_rollback() {
    owned_fixture("inventory_lookahead", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 101, "alice", DEPLOYMENT, TENANT).await?;
        c.execute("UPDATE public.model_connections SET endpoint='http://invalid.example.test/v1' WHERE id=$1",
            &[&Uuid::from_u128(101)]).await.map_err(|e| e.to_string())?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config)).await.map_err(|e| e.to_string())?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        let tails = Arc::new(TailFacts { rollback_cz: Some(relay.facts.rollback_cz.clone()), ..Default::default() });
        let (auth, _host) = session(&c, &inventory, &family, "bad101", "alice", false, tails.clone()).await?;
        expect_error(&inventory, &auth, Error::Unavailable).await?;
        require(relay.facts.begins.load(Ordering::SeqCst) == 1
            && relay.facts.read_only_rc.load(Ordering::SeqCst) == 1
            && relay.facts.final_statements.load(Ordering::SeqCst) == 1
            && relay.facts.rollback_cz.load(Ordering::SeqCst) == 1
            && relay.facts.commits.load(Ordering::SeqCst) == 0, "bad101 did not use one original rollback")?;
        require(tails.created.load(Ordering::SeqCst) == 1 && tails.dropped.load(Ordering::SeqCst) == 1
            && !tails.premature_drop.load(Ordering::SeqCst) && !tails.premature_verify.load(Ordering::SeqCst),
            "Host tail was discarded/verified before original ACK on page failure")?;
        c.execute("UPDATE public.model_connections SET endpoint='https://owned-inventory.example.test/v1',name=' leading bad lookahead' WHERE id=$1",
            &[&Uuid::from_u128(101)]).await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &auth, Error::Unavailable).await?;
        drop(auth); drop(inventory);
        close_pool(wire).await?; relay.finish().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_final_statement_rechecks_global_mapping_for_all_owners() {
    owned_fixture("inventory_global", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
        seed(&c, 1001, 2, "bob", "other-deployment", "other-tenant").await?;
        c.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1", &[&Uuid::from_u128(1001)]).await.map_err(|e| e.to_string())?;
        c.execute("UPDATE public.model_connections SET deleted_at=now() WHERE id=$1", &[&Uuid::from_u128(1002)]).await.map_err(|e| e.to_string())?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config)).await.map_err(|e| e.to_string())?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        let (auth, _host) = session(&c, &inventory, &family, "global-owner", "alice", false, Arc::default()).await?;
        // Drift is committed only after the original schema helper's last health query
        // has really completed, forcing the final joint SQL to discover each case.
        for variant in 0..4 {
            relay.facts.hold_schema.store(true, Ordering::SeqCst);
            let input = request(Some(Uuid::from_u128(9999).to_string()));
            let pending = inventory.list_current(&auth, &input, Instant::now() + Duration::from_secs(5));
            tokio::pin!(pending);
            tokio::select! {
                value = &mut pending => return Err(format!("inventory returned before schema gate: {value:?}")),
                value = tokio::time::timeout(Duration::from_secs(4), relay.facts.schema_seen.notified()) => {
                    value.map_err(|_| "actual schema mapping gate did not arrive")?;
                },
            }
            let changed = match variant {
                0 => c.execute("UPDATE public.custom_model_catalogs SET endpoint='https://unseen.example.test' WHERE connection_id=$1", &[&Uuid::from_u128(1001)]).await,
                1 => c.execute("UPDATE public.custom_model_catalogs SET retired=false WHERE connection_id=$1", &[&Uuid::from_u128(1002)]).await,
                2 => c.execute("DELETE FROM public.custom_model_catalogs WHERE connection_id=$1", &[&Uuid::from_u128(1002)]).await,
                _ => {
                    c.batch_execute("SET session_replication_role=replica").await.map_err(|e| e.to_string())?;
                    let changed = c.execute("INSERT INTO public.custom_model_catalogs
                      (connection_id,deployment_id,tenant_id,owner_user_id,model_id,catalog_revision,protocol,endpoint,model,enabled,retired)
                      VALUES($1,'orphan-deployment','orphan-tenant','bob',$2,1,'openai_responses','https://orphan.example.test','orphan',false,true)",
                      &[&Uuid::from_u128(9001),&format!("custom:{}", Uuid::from_u128(9001))]).await;
                    c.batch_execute("SET session_replication_role=origin").await.map_err(|e| e.to_string())?;
                    changed
                }
            };
            relay.facts.schema_release.notify_one();
            changed.map_err(|e| e.to_string())?;
            require(matches!(pending.await, Err(Error::Unavailable)), "last global mapping missed hidden/retired/orphan drift")?;
            // Explicit fixture restoration, outside the observed request. Production never repairs.
            c.execute("DELETE FROM public.custom_model_catalogs WHERE connection_id=$1", &[&Uuid::from_u128(9001)]).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.custom_model_catalogs(connection_id,deployment_id,tenant_id,owner_user_id,model_id,catalog_revision,protocol,endpoint,model,enabled,retired)
              SELECT id,deployment_id,tenant_id,owner_user_id,'custom:'||id::text,1,protocol,endpoint,model,enabled,deleted_at IS NOT NULL
              FROM public.model_connections m WHERE NOT EXISTS(SELECT 1 FROM public.custom_model_catalogs c WHERE c.connection_id=m.id);
              UPDATE public.custom_model_catalogs c SET endpoint=m.endpoint,retired=m.deleted_at IS NOT NULL
              FROM public.model_connections m WHERE m.id=c.connection_id").await.map_err(|e| e.to_string())?;
        }
        require(relay.facts.final_statements.load(Ordering::SeqCst) == 4, "global drift was not checked in each final statement")?;
        drop(auth); drop(inventory); close_pool(wire).await?; relay.finish().await?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_initial_schema_and_native_prefix_drift_refuse_without_repair() {
    for prefix in [false, true] {
        owned_fixture(if prefix { "inventory_prefix" } else { "inventory_schema" }, move |_config, p| async move {
            initialize(&p).await?;
            let c = p.get().await.map_err(|e| e.to_string())?;
            seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
            let inventory = repository(&p)?;
            let family = HostFamily::install(&inventory)?;
            let (auth, _host) = session(&c, &inventory, &family, "schema-drift", "alice", false, Arc::default()).await?;
            if prefix {
                c.batch_execute("UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=46")
                    .await.map_err(|e| e.to_string())?;
            } else {
                c.batch_execute("ALTER TABLE public.custom_model_catalogs ADD COLUMN inventory_unregistered boolean")
                    .await.map_err(|e| e.to_string())?;
            }
            let before = state(&c).await?;
            expect_error(&inventory, &auth, Error::Unavailable).await?;
            require(state(&c).await? == before, "inventory silently repaired initial drift")?;
            drop(auth); drop(inventory); drop(c);
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_actual_actor_and_session_changes_refuse_without_poisoning_new_session() {
    owned_fixture("inventory_revoke", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config)).await.map_err(|e| e.to_string())?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        require(inventory.enroll_host_issuer(&family.issuer) == Err(HostError::NotCurrent),
            "original issuer could be installed a second time")?;
        expect_error(&inventory, &actor("alice", false), Error::NotVisible).await?;
        let (old, _old_host) = session(&c, &inventory, &family, "revoked-old", "alice", false, Arc::default()).await?;
        c.batch_execute("DELETE FROM public.sessions WHERE id='revoked-old'").await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &old, Error::NotVisible).await?;
        let (current, host) = session(&c, &inventory, &family, "valid-new", "alice", false, Arc::default()).await?;
        require(inventory.list_current(&current, &request(None), Instant::now() + Duration::from_secs(5)).await.is_ok(),
            "old explicit rejection poisoned new valid session")?;
        c.batch_execute("UPDATE public.sessions SET token='replaced-original-token' WHERE id='valid-new'")
            .await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &current, Error::NotVisible).await?;
        let (fresh, _fresh_host) = session(&c, &inventory, &family, "still-valid", "alice", false, Arc::default()).await?;
        relay.facts.hold_schema.store(true, Ordering::SeqCst);
        {
            let input = request(None);
            let pending = inventory.list_current(&fresh, &input, Instant::now() + Duration::from_secs(5));
            tokio::pin!(pending);
            tokio::select! {
                value = &mut pending => return Err(format!("actor request returned before actual gate: {value:?}")),
                value = tokio::time::timeout(Duration::from_secs(4), relay.facts.schema_seen.notified()) => {
                    value.map_err(|_| "actor schema gate did not actually arrive")?;
                },
            }
            c.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'").await.map_err(|e| e.to_string())?;
            relay.facts.schema_release.notify_one();
            require(matches!(pending.await, Err(Error::NotVisible)), "last joint SQL missed current actor generation")?;
        }
        c.batch_execute("UPDATE public.users SET auth_generation=7 WHERE id='alice';
          INSERT INTO public.revoked_access(email,revoked_by) VALUES('owned-inventory-alice@example.test','owned-test-admin')").await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &fresh, Error::NotVisible).await?;
        c.batch_execute("DELETE FROM public.revoked_access WHERE email='owned-inventory-alice@example.test';
          UPDATE public.user_roles SET role='admin' WHERE user_id='alice'").await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &fresh, Error::NotVisible).await?;
        c.batch_execute("UPDATE public.user_roles SET role='user' WHERE user_id='alice'").await.map_err(|e| e.to_string())?;
        c.batch_execute("DELETE FROM public.revoked_access WHERE email='owned-inventory-alice@example.test';
          UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='still-valid'").await.map_err(|e| e.to_string())?;
        expect_error(&inventory, &fresh, Error::NotVisible).await?;
        host.revoked.store(true, Ordering::SeqCst);
        expect_error(&inventory, &current, Error::NotVisible).await?;
        drop(old); drop(current); drop(fresh); drop(inventory);
        close_pool(wire).await?; relay.finish().await?; drop(c);
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_rollback_ack_precedes_pure_tail_rejection() {
    owned_fixture("inventory_tail_ack", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config))
            .await
            .map_err(|e| e.to_string())?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        let tails = Arc::new(TailFacts {
            rollback_cz: Some(relay.facts.rollback_cz.clone()),
            reject: AtomicBool::new(true),
            ..Default::default()
        });
        let (auth, _host) = session(
            &c,
            &inventory,
            &family,
            "tail-rejected",
            "alice",
            false,
            tails.clone(),
        )
        .await?;
        expect_error(&inventory, &auth, Error::NotVisible).await?;
        require(
            relay.facts.rollback_cz.load(Ordering::SeqCst) == 1
                && tails.verified.load(Ordering::SeqCst) == 1
                && !tails.premature_verify.load(Ordering::SeqCst)
                && !tails.premature_drop.load(Ordering::SeqCst),
            "pure tail rejection preceded actual rollback ACK",
        )?;
        let original_pid = relay.facts.pid.load(Ordering::SeqCst);
        let reused = wire.get().await.map_err(|e| e.to_string())?;
        let actual_pid: i32 = reused
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            actual_pid == original_pid
                && !wire
                    .connection_observations()
                    .iter()
                    .any(|o| o.snapshot().retirement_requested),
            "known ACK plus explicit tail rejection poisoned the original connection",
        )?;
        drop(reused);
        tails.reject.store(false, Ordering::SeqCst);
        let (valid, _valid_host) = session(
            &c,
            &inventory,
            &family,
            "tail-new-valid",
            "alice",
            false,
            Arc::default(),
        )
        .await?;
        require(
            inventory
                .list_current(
                    &valid,
                    &request(None),
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .is_ok(),
            "new request failed after explicit pure tail rejection",
        )?;
        drop(auth);
        drop(valid);
        drop(inventory);
        close_pool(wire).await?;
        relay.finish().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_suppressed_rollback_ack_is_unproven_and_retires_original_connection() {
    owned_fixture("inventory_ack_loss", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config))
            .await
            .map_err(|e| e.to_string())?;
        let observations = wire.connection_observations();
        require(
            observations.len() == 1,
            "original wire connection not observed",
        )?;
        let original = observations
            .into_iter()
            .next()
            .ok_or("original observation absent")?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        let tails = Arc::new(TailFacts {
            rollback_cz: Some(relay.facts.rollback_cz.clone()),
            ..Default::default()
        });
        let (auth, _host) = session(
            &c,
            &inventory,
            &family,
            "lost-rollback",
            "alice",
            false,
            tails.clone(),
        )
        .await?;
        relay.facts.drop_rollback.store(true, Ordering::SeqCst);
        expect_error(&inventory, &auth, Error::Unavailable).await?;
        require(
            relay.facts.rollback_cz.load(Ordering::SeqCst) == 1
                && relay.facts.begins.load(Ordering::SeqCst) == 1
                && relay.facts.final_statements.load(Ordering::SeqCst) == 1
                && relay.facts.commits.load(Ordering::SeqCst) == 0
                && tails.verified.load(Ordering::SeqCst) == 0,
            "lost ACK was accepted or operation retried",
        )?;
        require(
            original.snapshot().retirement_requested,
            "unproven original connection was returned reusable",
        )?;
        require(
            original
                .wait_for_destruction_before(Instant::now() + CLOSE_BUDGET)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "unproven original connection not destroyed",
        )?;
        drop(auth);
        drop(inventory);
        close_pool(wire).await?;
        relay.finish().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn inventory_original_deadline_includes_checkout_and_cancellation_is_unproven() {
    owned_fixture("inventory_deadline", |config, p| async move {
        initialize(&p).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        seed(&c, 1, 1, "alice", DEPLOYMENT, TENANT).await?;
        let relay = WireRelay::start(&config).await?;
        let wire = pool::connect(&relay.config(&config)).await.map_err(|e| e.to_string())?;
        let inventory = repository(&wire)?;
        let family = HostFamily::install(&inventory)?;
        let (auth, _host) = session(&c, &inventory, &family, "deadline", "alice", false, Arc::default()).await?;
        let held = wire.get().await.map_err(|e| e.to_string())?;
        let start = Instant::now();
        require(matches!(inventory.list_current(&auth, &request(None), start + Duration::from_millis(40)).await,
            Err(Error::Unavailable)), "checkout wait reset the original deadline")?;
        require(start.elapsed() < Duration::from_secs(1) && relay.facts.begins.load(Ordering::SeqCst) == 0,
            "expired checkout started a new transaction or waited a fresh budget")?;
        drop(held);
        let original = wire.connection_observations().into_iter().next().ok_or("original observation absent")?;
        relay.facts.hold_schema.store(true, Ordering::SeqCst);
        {
            let input = request(None);
            let pending = inventory.list_current(&auth, &input, Instant::now() + Duration::from_secs(5));
            tokio::pin!(pending);
            tokio::select! {
                value = &mut pending => return Err(format!("request finished before cancellation gate: {value:?}")),
                value = tokio::time::timeout(Duration::from_secs(4), relay.facts.schema_seen.notified()) => {
                    value.map_err(|_| "schema cancellation gate did not actually arrive")?;
                },
            }
            // Actual future Drop, not timeout relabelled as a rollback acknowledgement.
        }
        // Keep the real held schema C/Z behind the gate after cancellation;
        // the original downstream closure ends the relay frontend naturally.
        require(original.snapshot().retirement_requested, "cancelled original transaction stayed reusable")?;
        require(original.wait_for_destruction_before(Instant::now() + CLOSE_BUDGET).await.map_err(|e| e.to_string())?
            == pool::ConnectionDestruction::ConnectionDestroyed, "cancelled original connection did not retire")?;
        // The destructor may enqueue a rollback, but no returned inventory success or
        // acknowledged owner state is inferred from any eventual relay C/Z count.
        drop(auth); drop(inventory); close_pool(wire).await?; relay.finish().await?;
        Ok(())
    }).await;
}
