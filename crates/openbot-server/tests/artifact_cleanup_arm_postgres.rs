//! Actual Session/Application Save -> current saved-owner arm on an owned PG and Store.
//! Fault controllers change only their named original rows. Arm is not physical deletion.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use http::Request;
use openbot_application::{ApplicationService, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_contracts::request_binding::HostRequestBindingError;
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::{
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError as Error, PostgresArtifactAdministration,
};
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::{
    ConnectionDestruction, ConnectionObservation, DatabaseConfig, DatabasePool,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const DEPLOYMENT: &str = "cleanup/deployment%成果";
const TENANT: &str = "cleanup-tenant";
const OWNER: &str = "cleanup-owner";
const ADMIN: &str = "cleanup-foreign-admin";
const COOKIE_A: &str = "owned-cleanup-original-session-cookie-a-001";
const COOKIE_B: &str = "owned-cleanup-other-session-cookie-b-002";
const COOKIE_ADMIN: &str = "owned-cleanup-foreign-admin-cookie-c-003";
const A_ID: &str = "cleanup-session-a";
const SESSION_KEY: &[u8] = b"owned-cleanup-session-hash-key";
const TEXT: &str = "  original saved cleanup text\n成果 café 🦀\t  ";
const AUDIT_LOCK: i64 = 0x4f50_454e_4155_4431;

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
async fn resolve(resolver: &dyn AuthResolver, cookie: &str) -> Result<AuthContext, String> {
    let parts = Request::builder()
        .uri("/trusted-rust-artifact-cleanup")
        .header("cookie", format!("openbot_session={cookie}"))
        .body(())
        .map_err(|e| e.to_string())?
        .into_parts()
        .0;
    resolver.resolve(&parts).await.map_err(|e| e.to_string())
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let p =
            std::env::temp_dir().join(format!("openbot-artifact-cleanup-arm-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .map_err(|e| e.to_string())?;
        Ok(Self(p))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_CLEANUP_ARM_OWNED_ROOT removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned fixture root did not close");
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ObjectFact {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    sha256: String,
}
fn object_fact(path: &Path) -> Result<ObjectFact, String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        m.is_file() && m.mode() & 0o7777 == 0o400 && m.nlink() == 1,
        "original object identity/type/0400 drifted",
    )?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(ObjectFact {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}

async fn database_facts(pool: &DatabasePool) -> Result<BTreeMap<String, Value>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let tables = c.query("SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','openbot_internal') AND c.relkind='r' ORDER BY n.nspname,c.relname", &[]).await.map_err(|e| e.to_string())?;
    let mut facts = BTreeMap::new();
    for t in tables {
        let schema: String = t.get(0);
        let name: String = t.get(1);
        let quoted = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let sql = format!(
            "SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(t),'xmin',t.xmin::text,'ctid',t.ctid::text) ORDER BY to_jsonb(t)::text,t.ctid),'[]'::jsonb) FROM {}.{} t",
            quoted(&schema),
            quoted(&name)
        );
        facts.insert(
            format!("{schema}.{name}"),
            c.query_one(&sql, &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0),
        );
    }
    Ok(facts)
}
fn only_tables_changed(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    allowed: &[&str],
) -> Result<(), String> {
    require(
        before.keys().eq(after.keys()),
        "controller or producer added/removed an ordinary table",
    )?;
    for (table, original) in before {
        if !allowed.contains(&table.as_str()) && after.get(table) != Some(original) {
            return Err(format!(
                "unexpected ordinary table or physical row change: {table}"
            ));
        }
    }
    Ok(())
}
const ARM_TABLES: &[&str] = &[
    "openbot_internal.artifact_cleanup_fences",
    "public.audit_events",
    "public.audit_checkpoints",
];
fn original_arm_append_only(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<(), String> {
    only_tables_changed(before, after, ARM_TABLES)?;
    let old_fences = before
        .get("openbot_internal.artifact_cleanup_fences")
        .and_then(Value::as_array)
        .ok_or("original fence facts missing")?;
    let new_fences = after
        .get("openbot_internal.artifact_cleanup_fences")
        .and_then(Value::as_array)
        .ok_or("current fence facts missing")?;
    require(
        old_fences.is_empty() && new_fences.len() == 1,
        "first arm did not append exactly one fence to the owned empty inventory",
    )?;
    let old_audit = before
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("original audit facts missing")?;
    let new_audit = after
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("current audit facts missing")?;
    require(
        !old_audit.is_empty()
            && new_audit.len() == old_audit.len() + 1
            && old_audit.iter().all(|r| new_audit.contains(r)),
        "first arm changed a previous audit/physical row or appended more than one event",
    )?;
    require(
        before.get("public.audit_checkpoints") == after.get("public.audit_checkpoints"),
        "arm changed the existing real Save genesis/checkpoint",
    )
}

fn controller_update_columns(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
    columns: &[&str],
) -> Result<(), String> {
    let original = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original controller table missing")?;
    let current = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current controller table missing")?;
    let selects = |v: &&Value| {
        v.get("row")
            .and_then(|r| r.get(selector))
            .and_then(Value::as_str)
            == Some(id)
    };
    let old: Vec<_> = original.iter().filter(selects).collect();
    let new: Vec<_> = current.iter().filter(selects).collect();
    require(
        old.len() == 1 && new.len() == 1,
        "controller update was not on its unique actual original row",
    )?;
    require(
        original
            .iter()
            .filter(|v| !selects(v))
            .eq(current.iter().filter(|v| !selects(v))),
        "controller changed an unrelated row or physical row carrier",
    )?;
    let mut old_payload = old[0]["row"]
        .as_object()
        .ok_or("original row is not an object")?
        .clone();
    let mut new_payload = new[0]["row"]
        .as_object()
        .ok_or("current row is not an object")?
        .clone();
    let mut changed = false;
    for column in columns {
        let previous = old_payload
            .remove(*column)
            .ok_or("registered original controller column missing")?;
        let next = new_payload
            .remove(*column)
            .ok_or("registered current controller column missing")?;
        changed |= previous != next;
    }
    require(
        changed && old_payload == new_payload,
        "controller changed undeclared columns or did not change the registered column",
    )
}
fn controller_removed_row(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
) -> Result<(), String> {
    let old = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original removed-row table missing")?;
    let new = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current removed-row table missing")?;
    let retained: Vec<_> = old
        .iter()
        .filter(|v| v["row"][selector].as_str() != Some(id))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == old.len() && retained == *new,
        "controller removal did not preserve every unrelated row/physical carrier",
    )
}
fn controller_inserted_row(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
) -> Result<(), String> {
    let old = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original inserted-row table missing")?;
    let new = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current inserted-row table missing")?;
    let retained: Vec<_> = new
        .iter()
        .filter(|v| v["row"][selector].as_str() != Some(id))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == new.len() && retained == *old,
        "controller insertion did not preserve every unrelated row/physical carrier",
    )
}

struct Fixture {
    admin: DatabasePool,
    pool: DatabasePool,
    actual: Arc<PostgresArtifactAdministration>,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    resolver: Arc<PostgresSessionAuthResolver>,
    auth: AuthContext,
    application: Arc<dyn ApplicationService>,
    receipt: ArtifactRegistrationReceipt,
    root: OwnedRoot,
    relay: Option<OwnedRelay>,
}
impl Fixture {
    async fn new(config: DatabaseConfig, relay: bool) -> Result<Self, String> {
        let direct = config.clone().with_max_pool_size(5);
        let admin = pool::connect(&direct).await.map_err(|e| e.to_string())?;
        {
            let mut c = admin.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES ('cleanup-owner','cleanup-owner@example.test',0),('cleanup-foreign-admin','cleanup-admin@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('cleanup-owner','user'),('cleanup-foreign-admin','admin'); INSERT INTO public.agents(id,name,type,configuration) VALUES('cleanup-bot','Cleanup fixture','built_in','{}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('cleanup-bot','cleanup-owner','Cleanup fixture','fixture','fixture','public');").await.map_err(|e| e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, actor, token) in [
                (A_ID, OWNER, COOKIE_A),
                ("cleanup-session-b", OWNER, COOKIE_B),
                ("cleanup-session-admin", ADMIN, COOKIE_ADMIN),
            ] {
                c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)", &[&id,&actor,&token_column(token),&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e| e.to_string())?;
            }
        }
        let relay = if relay {
            Some(OwnedRelay::start(&direct).await?)
        } else {
            None
        };
        let production = relay
            .as_ref()
            .map_or(config.clone(), |r| r.config(&config))
            .with_max_pool_size(1);
        let pool = pool::connect(&production)
            .await
            .map_err(|e| e.to_string())?;
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([18; 16]),
                run_id: RunId::new("actual/cleanup-run%成果"),
                bot_id: BotId::new("cleanup-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            admin.clone(),
            direct,
            "cleanup-arm-owned-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(|e| e.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry.clone(),
                store.clone(),
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x18; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(|e| e.to_string())?,
        );
        resolver
            .install_artifact_read_authority(&actual.read_authority())
            .map_err(|_| "actual artifact authority installation refused")?;
        let auth = resolve(resolver.as_ref(), COOKIE_A).await?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(actual.clone()),
        );
        let reply = application
            .execute(
                auth.clone(),
                AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id,
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
                }),
            )
            .await
            .map_err(|e| e.to_string())?;
        let receipt = match reply {
            AppReply::ArtifactRegistrationReceipt(r) => r,
            _ => return Err("actual Save returned another reply".to_owned()),
        };
        Ok(Self {
            admin,
            pool,
            actual,
            registry,
            store,
            resolver,
            auth,
            application,
            receipt,
            root,
            relay,
        })
    }
    fn path(&self) -> PathBuf {
        self.root.0.join("objects").join(&self.receipt.artifact_id)
    }
    async fn arm(&self) -> Result<ArmedArtifactCleanupIntent, Error> {
        self.actual
            .arm_explicit_saved_delete_before(
                &self.auth,
                &self.receipt.artifact_id,
                Instant::now() + Duration::from_secs(10),
            )
            .await
    }
    async fn original(&self) -> Result<(i32, ConnectionObservation, Arc<SocketFacts>), String> {
        let c = self.pool.get().await.map_err(|e| e.to_string())?;
        let pid = c
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let observation = c.observation();
        let socket = self
            .relay
            .as_ref()
            .ok_or("original socket requires owned relay")?
            .socket_for_pid(pid)?;
        drop(c);
        Ok((pid, observation, socket))
    }
    async fn verify_one_arm(&self) -> Result<(), String> {
        let c = self.admin.get().await.map_err(|e| e.to_string())?;
        let rows = c.query("SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase FROM openbot_internal.artifact_cleanup_fences", &[]).await.map_err(|e| e.to_string())?;
        require(
            rows.len() == 1,
            "arm did not write exactly one original fence",
        )?;
        let r = &rows[0];
        require(
            r.get::<_, String>(0) == DEPLOYMENT
                && r.get::<_, String>(1) == TENANT
                && r.get::<_, String>(2) == self.registry.binding().dataset_id()
                && r.get::<_, String>(3) == self.receipt.operation_id
                && r.get::<_, String>(4) == self.receipt.artifact_id
                && r.get::<_, String>(5) == "deleted"
                && r.get::<_, String>(6) == "armed",
            "arm rebound the original five-key or intent",
        )?;
        let a=c.query("SELECT actor_user_id,event_type,target_type,target_id,payload,row_hash FROM public.audit_events WHERE event_type='artifact.cleanup_armed'",&[]).await.map_err(|e|e.to_string())?;
        require(a.len() == 1, "arm audit was absent or duplicated")?;
        let p: Value = a[0].get("payload");
        require(
            a[0].get::<_, Option<String>>("actor_user_id").as_deref() == Some(OWNER)
                && a[0].get::<_, String>("target_type") == "artifact"
                && a[0].get::<_, Option<String>>("target_id").as_deref()
                    == Some(self.receipt.artifact_id.as_str())
                && p == serde_json::json!({"artifact_id":self.receipt.artifact_id,"artifact_operation_id":self.receipt.operation_id})
                && a[0]
                    .get::<_, Option<String>>("row_hash")
                    .is_some_and(|h| h.len() == 64),
            "arm audit changed fixed typed fields, target or owner",
        )
    }
    async fn finish(mut self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        let observations = self.pool.connection_observations();
        let relay = self.relay.take();
        drop(self);
        let deadline = Instant::now() + Duration::from_secs(3);
        for o in observations {
            let original = o.snapshot();
            let expected = if original.connection_started {
                ConnectionDestruction::ConnectionDestroyed
            } else if original.connecting_future_started {
                ConnectionDestruction::ConnectingFutureDestroyed
            } else {
                ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart
            };
            require(
                o.wait_for_destruction_before(deadline)
                    .await
                    .map_err(|e| e.to_string())?
                    == expected,
                "original production connection owner did not close its actually started resource",
            )?;
        }
        if let Some(r) = relay {
            r.finish().await?;
        }
        Ok(())
    }
}

// Only this test file owns this finite protocol relay. It forwards an already owned local PG
// endpoint, records a backend PID and three command ACK bits, and can withhold one ACK/startup.
// Startup/password/SQL packet bytes are neither logged nor retained as diagnostic evidence.
const BEGIN_BIT: u8 = 1;
const COMMIT_BIT: u8 = 2;
const ROLLBACK_BIT: u8 = 4;
#[derive(Clone, Copy)]
#[repr(u8)]
enum Hold {
    Startup = 1,
    Begin = 2,
    Commit = 3,
    Rollback = 4,
}
#[derive(Default)]
struct SocketFacts {
    pid: AtomicI32,
    frontend_eof: AtomicBool,
    entered: AtomicU8,
    server_ack: AtomicU8,
    forwarded_ack: AtomicU8,
    withheld: AtomicU8,
    release_original_ack: AtomicU8,
}
#[derive(Default)]
struct RelayState {
    next: AtomicU64,
    hold: AtomicU8,
    sockets: Mutex<BTreeMap<u64, Arc<SocketFacts>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
struct OwnedRelay {
    address: SocketAddr,
    state: Arc<RelayState>,
    accept: tokio::task::JoinHandle<()>,
}
struct AbortPump(tokio::task::JoinHandle<Result<(), std::io::Error>>);
impl Drop for AbortPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl OwnedRelay {
    fn release_original_ack(&self, socket: &SocketFacts, hold: Hold) -> Result<(), String> {
        require(
            socket.withheld.load(Ordering::SeqCst) == hold as u8,
            "release did not address the actual held original socket",
        )?;
        socket
            .release_original_ack
            .store(hold as u8, Ordering::SeqCst);
        Ok(())
    }
    async fn finish(mut self) -> Result<(), String> {
        self.accept.abort();
        require(
            (&mut self.accept).await.is_err_and(|e| e.is_cancelled()),
            "owned relay accept task did not join its requested stop",
        )?;
        let tasks = std::mem::take(
            &mut *self
                .state
                .tasks
                .lock()
                .map_err(|_| "owned relay task inventory poisoned")?,
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        for mut task in tasks {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Err("original owned relay connection task failed to join".to_owned());
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Err(
                        "original relay connection required abort rather than natural EOF"
                            .to_owned(),
                    );
                }
            }
        }
        require(
            self.state
                .sockets
                .lock()
                .map_err(|_| "owned relay socket inventory poisoned")?
                .values()
                .all(|s| s.frontend_eof.load(Ordering::SeqCst)),
            "owned relay original socket lacks natural EOF",
        )
    }
    async fn start(config: &DatabaseConfig) -> Result<Self, String> {
        let ip = config
            .host
            .parse::<IpAddr>()
            .map_err(|_| "relay requires owned numeric loopback PG".to_owned())?;
        require(ip.is_loopback(), "relay refused a non-loopback PG endpoint")?;
        let upstream = SocketAddr::new(ip, config.port);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| "owned relay bind failed".to_owned())?;
        let address = listener
            .local_addr()
            .map_err(|_| "owned relay address failed".to_owned())?;
        let state = Arc::new(RelayState::default());
        let shared = state.clone();
        let accept = tokio::spawn(async move {
            while let Ok((front, _)) = listener.accept().await {
                let id = shared.next.fetch_add(1, Ordering::SeqCst);
                let facts = Arc::new(SocketFacts::default());
                shared
                    .sockets
                    .lock()
                    .expect("relay socket facts")
                    .insert(id, facts.clone());
                let connection_state = shared.clone();
                let task = tokio::spawn(async move {
                    let _ = relay_original(front, upstream, &connection_state, &facts).await;
                });
                shared.tasks.lock().expect("relay owned tasks").push(task);
            }
        });
        Ok(Self {
            address,
            state,
            accept,
        })
    }
    fn config(&self, config: &DatabaseConfig) -> DatabaseConfig {
        let mut config = config.clone();
        config.host = self.address.ip().to_string();
        config.port = self.address.port();
        config
    }
    fn arm(&self, hold: Hold) {
        self.state.hold.store(hold as u8, Ordering::SeqCst);
    }
    fn socket_for_pid(&self, pid: i32) -> Result<Arc<SocketFacts>, String> {
        self.state
            .sockets
            .lock()
            .map_err(|_| "relay facts poisoned".to_owned())?
            .values()
            .find(|f| f.pid.load(Ordering::SeqCst) == pid)
            .cloned()
            .ok_or_else(|| "original PID did not belong to this relay socket".to_owned())
    }
    fn newest_socket(&self) -> Result<Arc<SocketFacts>, String> {
        self.state
            .sockets
            .lock()
            .map_err(|_| "relay facts poisoned".to_owned())?
            .last_key_value()
            .map(|(_, f)| f.clone())
            .ok_or_else(|| "owned relay has not accepted original socket".to_owned())
    }
}
impl Drop for OwnedRelay {
    fn drop(&mut self) {
        self.accept.abort();
        if let Ok(tasks) = self.state.tasks.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}

fn command_bit(bytes: &[u8]) -> u8 {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let text = text.trim_end_matches('\0').trim().to_ascii_uppercase();
    if text == "BEGIN" || text.starts_with("BEGIN ") || text.starts_with("START TRANSACTION") {
        BEGIN_BIT
    } else if text == "COMMIT" || text == "COMMIT;" {
        COMMIT_BIT
    } else if text == "ROLLBACK" || text == "ROLLBACK;" {
        ROLLBACK_BIT
    } else {
        0
    }
}
async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Option<Vec<u8>>> {
    let mut kind = [0u8; 1];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let n = u32::from_be_bytes(length) as usize;
    if !(4..=1024 * 1024).contains(&n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "owned PG frame bound",
        ));
    }
    let mut packet = vec![0; n + 1];
    packet[0] = kind[0];
    packet[1..5].copy_from_slice(&length);
    reader.read_exact(&mut packet[5..]).await?;
    Ok(Some(packet))
}
async fn relay_original(
    mut front: TcpStream,
    upstream: SocketAddr,
    state: &Arc<RelayState>,
    facts: &Arc<SocketFacts>,
) -> std::io::Result<()> {
    let mut length = [0u8; 4];
    front.read_exact(&mut length).await?;
    let n = u32::from_be_bytes(length) as usize;
    if !(8..=1024 * 1024).contains(&n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "owned PG startup bound",
        ));
    }
    let mut startup = vec![0; n];
    startup[..4].copy_from_slice(&length);
    front.read_exact(&mut startup[4..]).await?;
    if state
        .hold
        .compare_exchange(Hold::Startup as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        facts.withheld.store(Hold::Startup as u8, Ordering::SeqCst);
        drop(startup);
        let mut discard = [0u8; 4096];
        loop {
            if front.read(&mut discard).await? == 0 {
                facts.frontend_eof.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }
    }
    let mut backend = TcpStream::connect(upstream).await?;
    backend.write_all(&startup).await?;
    drop(startup);
    let (mut frontend_read, mut frontend_write) = front.into_split();
    let (mut backend_read, mut backend_write) = backend.into_split();
    let backend_facts = facts.clone();
    let backend_state = state.clone();
    let mut server = AbortPump(tokio::spawn(async move {
        let mut holding = 0;
        let mut original_held_packets = Vec::new();
        while let Some(packet) = frame(&mut backend_read).await? {
            if packet[0] == b'K' && packet.len() == 13 {
                backend_facts.pid.store(
                    i32::from_be_bytes(packet[5..9].try_into().expect("PID width")),
                    Ordering::SeqCst,
                );
            }
            let bit = if packet[0] == b'C' {
                command_bit(&packet[5..])
            } else {
                0
            };
            if bit != 0 {
                backend_facts.server_ack.fetch_or(bit, Ordering::SeqCst);
                let selected = match bit {
                    BEGIN_BIT => Hold::Begin,
                    COMMIT_BIT => Hold::Commit,
                    _ => Hold::Rollback,
                };
                if backend_state
                    .hold
                    .compare_exchange(selected as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    holding = selected as u8;
                    backend_facts.withheld.store(holding, Ordering::SeqCst);
                }
            }
            if holding == 0 {
                frontend_write.write_all(&packet).await?;
                if bit != 0 {
                    backend_facts.forwarded_ack.fetch_or(bit, Ordering::SeqCst);
                }
            } else {
                let ready = packet[0] == b'Z';
                original_held_packets.push(packet);
                if ready {
                    // The exact original upstream packets are retained without alteration.
                    // Loss/deadline fixtures never release them; genuine host-tail fixtures
                    // explicitly release this same accepted socket before its original budget.
                    while backend_facts.release_original_ack.load(Ordering::SeqCst) != holding {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    for original in original_held_packets.drain(..) {
                        frontend_write.write_all(&original).await?;
                        if original[0] == b'C' {
                            backend_facts
                                .forwarded_ack
                                .fetch_or(command_bit(&original[5..]), Ordering::SeqCst);
                        }
                    }
                    backend_facts
                        .release_original_ack
                        .store(0, Ordering::SeqCst);
                    holding = 0;
                }
            }
        }
        Ok::<(), std::io::Error>(())
    }));
    let outcome = async {
        let mut backend_writable = true;
        loop {
            let Some(packet) = frame(&mut frontend_read).await? else {
                facts.frontend_eof.store(true, Ordering::SeqCst);
                return Ok::<(), std::io::Error>(());
            };
            if packet[0] == b'Q' {
                facts
                    .entered
                    .fetch_or(command_bit(&packet[5..]), Ordering::SeqCst);
            }
            if backend_writable && backend_write.write_all(&packet).await.is_err() {
                backend_writable = false;
            }
        }
    }
    .await;
    server.0.abort();
    let _ = (&mut server.0).await;
    outcome
}

async fn wait_fact(
    fact: impl Fn() -> bool,
    deadline: Instant,
    message: &'static str,
) -> Result<(), String> {
    loop {
        if fact() {
            return Ok(());
        }
        require(Instant::now() < deadline, message)?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn retired_original(
    f: &Fixture,
    pid: i32,
    observation: &ConnectionObservation,
    socket: &SocketFacts,
) -> Result<(), String> {
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    require(
        observation
            .wait_for_destruction_before(cleanup_deadline)
            .await
            .map_err(|e| e.to_string())?
            == ConnectionDestruction::ConnectionDestroyed,
        "original owned Connection destructor was not observed",
    )?;
    wait_fact(
        || socket.frontend_eof.load(Ordering::SeqCst),
        cleanup_deadline,
        "corresponding original accepted socket had no EOF",
    )
    .await?;
    loop {
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        let alive = c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1)",
                &[&pid],
            )
            .await
            .map_err(|e| e.to_string())?
            .get::<_, bool>(0);
        if !alive {
            break;
        }
        require(
            Instant::now() < cleanup_deadline,
            "original owned PG backend persisted after destructor and EOF",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let c = f.pool.get().await.map_err(|e| e.to_string())?;
    require(
        c.query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get::<_, i32>(0)
            != pid,
        "failed original connection returned to the pool",
    )
}
fn original_five_seconds(started: Instant) -> Result<(), String> {
    let elapsed = started.elapsed();
    require(
        elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_millis(6250),
        "one entry's five-second deadline was shortened or renewed across an await",
    )
}

fn clear_transaction_facts(socket: &SocketFacts) {
    socket.entered.store(0, Ordering::SeqCst);
    socket.server_ack.store(0, Ordering::SeqCst);
    socket.forwarded_ack.store(0, Ordering::SeqCst);
    socket.withheld.store(0, Ordering::SeqCst);
    socket.release_original_ack.store(0, Ordering::SeqCst);
}

async fn wait_blocked(
    admin: &DatabasePool,
    pid: i32,
    query_fragment: &str,
    controller_pid: i32,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let c = admin.get().await.map_err(|e| e.to_string())?;
        let row = c
            .query_opt(
                "SELECT wait_event_type='Lock' AND position($2::text in query)>0 AND $3::integer=ANY(pg_catalog.pg_blocking_pids(pid)) AS blocked
             FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&pid, &query_fragment, &controller_pid],
            )
            .await
            .map_err(|e| e.to_string())?;
        if row.is_some_and(|r| r.get::<_, Option<bool>>(0) == Some(true)) {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "original operation did not reach its intended actual PG wait",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn with_fixture<F>(tag: &str, relay: bool, body: F)
where
    F: for<'a> FnOnce(
        &'a Fixture,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    >,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config, relay).await?;
        let outcome = body(&f).await;
        let cleaned = f.finish().await;
        outcome.and(cleaned)
    })
    .await;
}
fn owned_object_fds(path: &Path) -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return owned_macos_object_fds(path);
    }
    let original = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    let inventory = "/proc/self/fd";
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(inventory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if std::fs::metadata(entry.path())
            .is_ok_and(|m| m.is_file() && m.dev() == original.dev() && m.ino() == original.ino())
        {
            fds.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    fds.sort();
    Ok(fds)
}

// The same bounded, own-PID device/inode oracle exercised by the real 017 leased case.
// macOS /dev/fd entries have devfs metadata; they are not Linux procfs descriptor aliases.
fn owned_macos_object_fds(path: &Path) -> Result<Vec<String>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<BTreeSet<u32>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "own-PID lsof is unavailable (Unproven)".to_owned())?;
        let stdout = child.stdout.take().ok_or("lsof stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("lsof stderr unavailable")?;
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output.join();
                let _ = errors.join();
                return Err("own-PID lsof exceeded original five seconds (Unproven)".to_owned());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = output
            .join()
            .map_err(|_| "lsof output worker panicked")?
            .map_err(|error| error.to_string())?;
        let errors = errors
            .join()
            .map_err(|_| "lsof error worker panicked")?
            .map_err(|error| error.to_string())?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.len() <= 8_192
                && output.ends_with(b"\n"),
            "lsof incomplete/failed/truncated (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "lsof output invalid (Unproven)")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("lsof empty field (Unproven)")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "lsof observed another PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(inode) {
                        found.insert(
                            fd.ok_or("original inode has an ambiguous nonnumeric FD (Unproven)")?,
                        );
                    }
                    fd = value.parse::<u32>().ok();
                    dev = None;
                    ino = None;
                }
                "D" => {
                    dev = Some(
                        if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16)
                        } else {
                            value.parse::<u64>()
                        }
                        .map_err(|_| "lsof device invalid (Unproven)")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "lsof inode invalid (Unproven)")?,
                    );
                }
                _ => return Err("lsof unexpected field (Unproven)".to_owned()),
            }
        }
        require(self_pid, "lsof self-PID field missing (Unproven)")?;
        Ok(found)
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "own original FD inventory was unstable (Unproven)",
    )?;
    Ok(first.into_iter().map(|fd| fd.to_string()).collect())
}
async fn hard_delete_original_message(f: &Fixture) -> Result<(), String> {
    let before = database_facts(&f.admin).await?;
    let mut c = f.admin.get().await.map_err(|e| e.to_string())?;
    let tx = c.transaction().await.map_err(|e| e.to_string())?;
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        tx.execute(
            "DELETE FROM public.messages WHERE message_id=$1",
            &[&f.receipt.source_message_id],
        )
        .await
        .map_err(|e| e.to_string())?
            == 1,
        "source controller did not hard-delete exactly the original message",
    )?;
    tx.commit().await.map_err(|e| e.to_string())?;
    drop(c);
    let after = database_facts(&f.admin).await?;
    only_tables_changed(&before, &after, &["public.messages"])?;
    controller_removed_row(
        &before,
        &after,
        "public.messages",
        "message_id",
        &f.receipt.source_message_id,
    )?;
    require(
        before.get("public.messages") != after.get("public.messages"),
        "source controller had no actual committed row difference",
    )?;
    eprintln!(
        "ARTIFACT_CLEANUP_ARM_CONTROLLER kind=original_message_hard_delete controller_pid={pid} commit_ack=true changed_tables=public.messages retained_pair_unchanged=true"
    );
    Ok(())
}
async fn read_is_404(f: &Fixture) -> Result<(), String> {
    require(
        matches!(
            f.application
                .read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone())
                .await,
            Err(AppError::NotVisible)
        ),
        "missing source body did not remain original404",
    )?;
    require(
        matches!(
            f.application
                .execute(
                    f.auth.clone(),
                    AppCommand::GetArtifactMetadata(
                        openbot_contracts::artifacts::GetArtifactMetadata {
                            artifact_id: f.receipt.artifact_id.clone()
                        }
                    )
                )
                .await,
            Err(AppError::NotVisible)
        ),
        "cleanup owner management exposed missing-source metadata",
    )
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and owned Store; exact include-ignored only"]
async fn current_saved_owner_arms_after_source_hard_delete_and_read_stays_404() {
    with_fixture("cleanup-original-owner",false,|f|Box::pin(async move {
        let original=object_fact(&f.path())?;
        let mut operation=f.application.open_current_artifact_read(f.auth.clone(),f.receipt.artifact_id.clone()).await.map_err(|e|e.to_string())?;
        let pending=operation.next_block(&f.auth).await.map_err(|e|e.to_string())?;
        require(pending.prefix_length().map_err(|e|e.to_string())?==TEXT.len(),"original Application did not materialize its actual pending allocation")?;
        let frame=pending.handoff_frame(&f.auth).map_err(|e|e.to_string())?;
        require(frame.as_bytes()==TEXT.as_bytes(),"original leased frame differs from actual saved bytes")?;
        let original_fds=owned_object_fds(&f.path())?;
        require(original_fds.len()==1,"original leased allocation did not own exactly its real object FD")?;
        hard_delete_original_message(f).await?; read_is_404(f).await?;
        let before=database_facts(&f.admin).await?;
        let intent=f.arm().await.map_err(|e|e.to_string())?;
        f.verify_one_arm().await?;
        let after=database_facts(&f.admin).await?; original_arm_append_only(&before,&after)?;
        require(object_fact(&f.path())?==original,"arm changed or removed original bytes/charge backing")?;
        let barrier=f.actual.close_armed_artifact_reads(&intent).map_err(|e|e.to_string())?;
        require(barrier.drain_before(Instant::now()+Duration::from_millis(25)).await.is_err(),"armed bridge ACKed while the original leased allocation and FD remained")?;
        require(frame.verify_current_tail(&f.auth).is_err(),"closed original leased frame still provided a current delivery witness")?;
        require(owned_object_fds(&f.path())?==original_fds,"stop request was mistaken for actual original FD release")?;
        drop(operation);
        require(barrier.drain_before(Instant::now()+Duration::from_millis(25)).await.is_err()&&owned_object_fds(&f.path())?==original_fds,"operation Drop substituted for the original last complete allocation owner")?;
        drop(frame);
        let ack=barrier.drain_before(Instant::now()+Duration::from_secs(3)).await.map_err(|e|format!("{e:?}"))?;
        require(owned_object_fds(&f.path())?.is_empty() && object_fact(&f.path())?==original,"finite ACK did not follow actual FD drop or physically deleted object")?;
        read_is_404(f).await?;
        require(database_facts(&f.admin).await?==after,"finite close or missing-source reads wrote business facts")?;
        drop(ack);drop(barrier);drop(intent);
        eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_OWNER source_message_absent=true saved_owner_current=true original_commit_ack=true exact_arm_audit=true original_leased_allocation_materialized=true held_allocation_no_ack=true operation_drop_no_ack=true last_allocation_owner_dropped=true original_fd_drop_ack=true object_unchanged=true physical_delete=false");
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and owned Store; exact include-ignored only"]
async fn foreign_current_admin_or_namespace_cannot_arm_original_saved_pair() {
    with_fixture("cleanup-foreign-owner",false,|f|Box::pin(async move {
        let admin_auth=resolve(f.resolver.as_ref(),COOKIE_ADMIN).await?;
        let new_unenrolled=PostgresSessionAuthResolver::new(f.pool.clone(),SESSION_KEY,default_session_lifetime(),DeploymentId::new(DEPLOYMENT),TenantId::new(TENANT)).map_err(|e|e.to_string())?;
        let unenrolled_auth=resolve(&new_unenrolled,COOKIE_A).await?;
        require(unenrolled_auth==f.auth && !unenrolled_auth.request_binding().unwrap().identity().same_binding(f.auth.request_binding().unwrap().identity()),"foreign issuer fixture did not preserve six facts while changing original Host binding")?;
        let other_actual=Arc::new(PostgresArtifactAdministration::new(f.registry.clone(),f.store.clone(),ArtifactQuotaPolicy::default(),SecretBytes::new(vec![0x18;32])).map_err(|e|e.to_string())?);
        let foreign_root=OwnedRoot::new()?;
        let deployment=DeploymentId::new("foreign-cleanup-deployment");let tenant=TenantId::new("foreign-cleanup-tenant");
        let registry=Arc::new(ArtifactDatasetRegistry::from_server(f.pool.clone(),&deployment,&tenant).await.map_err(|e|e.to_string())?);
        let store=Arc::new(DatasetBoundArtifactStore::bind_host_root(std::fs::File::open(&foreign_root.0).map_err(|e|e.to_string())?,registry.clone(),ArtifactQuotaPolicy::default()).await.map_err(|e|e.to_string())?);
        let foreign=Arc::new(PostgresArtifactAdministration::new(registry,store,ArtifactQuotaPolicy::default(),SecretBytes::new(vec![0x19;32])).map_err(|e|e.to_string())?);
        let foreign_host=PostgresSessionAuthResolver::new(f.pool.clone(),SESSION_KEY,default_session_lifetime(),deployment,tenant).map_err(|e|e.to_string())?;
        foreign_host.install_artifact_read_authority(&foreign.read_authority()).map_err(|_|"foreign true authority enrollment failed")?;
        let foreign_auth=resolve(&foreign_host,COOKIE_A).await?;
        let before=database_facts(&f.admin).await?; let original=object_fact(&f.path())?;
        require(matches!(f.actual.arm_explicit_saved_delete_before(&admin_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::NotVisible)),"another current admin took over the retained saving owner")?;
        require(matches!(other_actual.arm_explicit_saved_delete_before(&f.auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::Host(HostRequestBindingError::Unavailable))),"same Store/new Administration bypassed actual enrolled authority")?;
        require(matches!(f.actual.arm_explicit_saved_delete_before(&unenrolled_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::Host(HostRequestBindingError::Unavailable))),"same six facts/new original issuer bypassed enrollment")?;
        require(matches!(foreign.arm_explicit_saved_delete_before(&foreign_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::NotVisible)),"foreign real namespace resolved the original saved pair")?;
        require(database_facts(&f.admin).await?==before && object_fact(&f.path())?==original,"foreign refusal changed rows, physical tuples or original object")?;
        foreign_host.close_request_bindings();new_unenrolled.close_request_bindings();
        drop(foreign);drop(other_actual);drop(foreign_root);
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL, original Session and controlled PG waits"]
async fn current_generation_role_deny_and_session_epoch_are_rechecked_after_wait() {
    for mutation in [
        "generation",
        "role",
        "deny",
        "session_epoch",
        "session_expiry",
        "owner_close",
    ] {
        with_fixture("cleanup-current-after-wait",false,|f|Box::pin(async move {
            let held=f.pool.get().await.map_err(|e|e.to_string())?;
            let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);drop(held);
            let before=database_facts(&f.admin).await?;
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;
            let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER]).await.map_err(|e|e.to_string())?;
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
            let original=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            wait_blocked(&f.admin,pid,"public.users",controller_pid).await?;
            let (sql,table)=match mutation {
                "generation"=>("UPDATE public.users SET auth_generation=1 WHERE id='cleanup-owner'","public.users"),
                "role"=>("DELETE FROM public.user_roles WHERE user_id='cleanup-owner'","public.user_roles"),
                "deny"=>("INSERT INTO public.revoked_access(email,revoked_by) VALUES('cleanup-owner@example.test','owned-cleanup-test-controller')","public.revoked_access"),
                "session_epoch"=>("UPDATE public.sessions SET token='owned-replaced-original-cleanup-session-token' WHERE id='cleanup-session-a'","public.sessions"),
                "session_expiry"=>("UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='cleanup-session-a'","public.sessions"),
                _=>("SELECT 1",""),
            };
            tx.batch_execute(sql).await.map_err(|e|e.to_string())?;
            if mutation=="owner_close" {f.resolver.close_request_bindings();}
            tx.commit().await.map_err(|e|e.to_string())?;drop(c);
            let outcome=original.await.map_err(|e|e.to_string())?;
            require(matches!(outcome,Err(Error::NotVisible)|Err(Error::Host(HostRequestBindingError::NotCurrent))),"resumed arm ignored current generation/role/deny/session/original owner")?;
            let after=database_facts(&f.admin).await?;
            only_tables_changed(&before,&after,if table.is_empty(){&[]}else{std::slice::from_ref(&table)})?;
            match mutation {
                "generation"=>controller_update_columns(&before,&after,table,"id",OWNER,&["auth_generation"])? ,
                "role"=>controller_removed_row(&before,&after,table,"user_id",OWNER)? ,
                "deny"=>controller_inserted_row(&before,&after,table,"email","cleanup-owner@example.test")? ,
                "session_epoch"=>controller_update_columns(&before,&after,table,"id",A_ID,&["token"])? ,
                "session_expiry"=>controller_update_columns(&before,&after,table,"id",A_ID,&["expires_at"])? ,
                _=>{},
            }
            require(object_fact(&f.path())?.sha256==format!("{:x}",Sha256::digest(TEXT.as_bytes())),"current refusal altered original object")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_AFTER_WAIT mutation={mutation} waiter_pid={pid} controller_pid={controller_pid} actual_actor_lock=true controller_commit_ack=true original_refusal_after_ack=true allowed_table={table}");
            Ok(())
        })).await;
    }
    for wait in ["quota", "audit"] {
        for mutation in ["deny", "session_epoch"] {
            with_fixture("cleanup-current-after-later-wait",false,|f|Box::pin(async move {
                let held=f.pool.get().await.map_err(|e|e.to_string())?;
                let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);drop(held);
                let before=database_facts(&f.admin).await?;
                let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
                let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
                let fragment=if wait=="quota" {tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;"artifact_workspace_quotas"} else {tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e|e.to_string())?;"pg_advisory_xact_lock"};
                let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
                let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
                wait_blocked(&f.admin,pid,fragment,controller_pid).await?;
                let table=if mutation=="deny" {
                    require(tx.execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES('cleanup-owner@example.test','owned-cleanup-test-controller')",&[]).await.map_err(|e|e.to_string())?==1,"later-wait controller did not insert its original owner deny")?;
                    "public.revoked_access"
                }else{
                    require(tx.execute("UPDATE public.sessions SET token='owned-cleanup-replaced-epoch-after-real-wait' WHERE id=$1",&[&A_ID]).await.map_err(|e|e.to_string())?==1,"later-wait controller did not replace the original session token")?;
                    "public.sessions"
                };
                tx.commit().await.map_err(|e|e.to_string())?;drop(c);
                require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::NotVisible)),"later quota/audit wait reused the old permitted Host/actor statement")?;
                let after=database_facts(&f.admin).await?;only_tables_changed(&before,&after,&[table])?;
                if mutation=="deny" {controller_inserted_row(&before,&after,table,"email","cleanup-owner@example.test")?;}else{controller_update_columns(&before,&after,table,"id",A_ID,&["token"])?;}
                eprintln!("ARTIFACT_CLEANUP_ARM_AFTER_LATER_WAIT wait={wait} mutation={mutation} waiter_pid={pid} controller_pid={controller_pid} real_blocking_pid_bound=true controller_commit_ack=true fresh_rc_refusal=true producer_rows_unchanged=true");
                Ok(())
            })).await;
        }
    }
    for noop in [false, true] {
        with_fixture("cleanup-original-ack-host-tail",true,|f|Box::pin(async move {
            if noop {drop(f.arm().await.map_err(|e|e.to_string())?);}
            let before=database_facts(&f.admin).await?;let object=object_fact(&f.path())?;
            let (_pid,_observation,socket)=f.original().await?;clear_transaction_facts(&socket);
            let hold=if noop {Hold::Rollback}else{Hold::Commit};
            let bit=if noop {ROLLBACK_BIT}else{COMMIT_BIT};
            f.relay.as_ref().unwrap().arm(hold);
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            wait_fact(||socket.withheld.load(Ordering::SeqCst)==hold as u8,Instant::now()+Duration::from_secs(2),"host-tail fixture did not hold its actual original ACK").await?;
            require(socket.entered.load(Ordering::SeqCst)&bit!=0&&socket.server_ack.load(Ordering::SeqCst)&bit!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&bit==0,"host-tail change preceded the original upstream ACK or followed a delivered ACK")?;
            f.verify_one_arm().await?;
            let confirmed=database_facts(&f.admin).await?;
            if noop {require(before==confirmed,"original no-op ACK wait changed any row")?;}else{original_arm_append_only(&before,&confirmed)?;}
            // Actual original owner retirement occurs strictly between the original real
            // upstream ACK and delivery of those unmodified ACK/ReadyForQuery packets.
            f.resolver.close_request_bindings();
            f.relay.as_ref().unwrap().release_original_ack(&socket,hold)?;
            require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::Host(HostRequestBindingError::NotCurrent))),"true original ACK minted an intent after actual original Host owner closed")?;
            require(socket.forwarded_ack.load(Ordering::SeqCst)&bit!=0,"tail refusal was obtained without releasing the true original ACK")?;
            require(database_facts(&f.admin).await?==confirmed&&object_fact(&f.path())?==object,"post-ACK Host refusal erased committed intent or changed retained charge/bytes")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_ACK_HOST_TAIL noop={noop} original_upstream_ack_before_owner_close=true original_owner_closed=true unmodified_original_ack_released=true result=HostNotCurrent usable_intent=false known_committed_arm_retained=true charge_unchanged=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original saved pair; exact include-ignored only"]
async fn same_original_armed_retry_is_noop_and_conflicting_intent_is_refused() {
    with_fixture("cleanup-noop",true,|f|Box::pin(async move {
        let before=database_facts(&f.admin).await?;
        let first=f.arm().await.map_err(|e|e.to_string())?;f.verify_one_arm().await?;
        let after=database_facts(&f.admin).await?;original_arm_append_only(&before,&after)?;
        let (_pid,_observation,socket)=f.original().await?;clear_transaction_facts(&socket);
        let retry=f.arm().await.map_err(|e|e.to_string())?;
        require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.entered.load(Ordering::SeqCst)&COMMIT_BIT==0,"exact no-op did not await the original ROLLBACK ACK")?;
        require(database_facts(&f.admin).await?==after,"exact no-op changed original row coordinates or duplicated arm audit")?;
        drop(retry);drop(first);
        let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_identity_guard").await.map_err(|e|e.to_string())?;
        require(tx.execute("UPDATE openbot_internal.artifact_cleanup_fences SET terminal_status='expired' WHERE artifact_id=$1",&[&f.receipt.artifact_id]).await.map_err(|e|e.to_string())?==1,"controlled terminal conflict did not change the actual original fence")?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences ENABLE TRIGGER artifact_cleanup_fences_identity_guard").await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e|e.to_string())?;drop(c);
        let conflict=database_facts(&f.admin).await?;only_tables_changed(&after,&conflict,&["openbot_internal.artifact_cleanup_fences"])?;
        controller_update_columns(&after,&conflict,"openbot_internal.artifact_cleanup_fences","artifact_id",&f.receipt.artifact_id,&["terminal_status"])?;
        require(matches!(f.arm().await,Err(Error::Conflict)),"delete arm coerced the existing expired intent")?;
        require(database_facts(&f.admin).await?==conflict,"conflicting arm reopened or rebound immutable intent")?;
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and controlled original row/catalog/audit faults"]
async fn original_pair_charge_or_cleanup_schema_drift_refuses_without_mutation() {
    for fault in [
        "operation_artifact",
        "request_receipt",
        "source_pair",
        "nullable_sequence_pair",
        "charge",
        "workspace_charge",
        "positive_receipt_missing",
        "store_physical",
        "cleanup_schema",
        "audit_insert",
    ] {
        with_fixture("cleanup-original-corruption",fault=="audit_insert",|f|Box::pin(async move {
            let original=object_fact(&f.path())?;
            let before=database_facts(&f.admin).await?;
            let (audit_original,audit_worker)=if fault=="audit_insert" {
                let original=f.original().await?;clear_transaction_facts(&original.2);
                f.relay.as_ref().unwrap().arm(Hold::Begin);
                let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
                let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
                let socket=&original.2;
                wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Begin as u8,Instant::now()+Duration::from_secs(2),"audit fault did not hold the actual original post-schema BEGIN ACK").await?;
                require(socket.entered.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT==0,"audit fault controller ran before the original schema check or after a delivered BEGIN ACK")?;
                (Some(original),Some(worker))
            }else{(None,None)};
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;
            let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let (allowed,expected_field)=match fault {
                "operation_artifact"|"source_pair"|"nullable_sequence_pair"|"charge"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
                    let changed=match fault {
                        "operation_artifact"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET artifact_id=$1 WHERE operation_id=$2",&[&Uuid::now_v7().to_string(),&f.receipt.operation_id]).await,
                        "source_pair"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET source_message_id='owned-different-source-message' WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                        "nullable_sequence_pair"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET source_call_seq=1,source_attempt_seq=0 WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                        _=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET charged_bytes=charged_bytes-1 WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                    }.map_err(|e|e.to_string())?;
                    require(changed==1,"controller did not corrupt exactly its actual original operation")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_save_operations",if fault=="operation_artifact"{"operation_pair"}else if fault=="charge"{"operation_pair"}else{"positive_receipt"})
                },
                "request_receipt"|"positive_receipt_missing"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_saved_receipts DISABLE TRIGGER artifact_saved_receipts_append_only").await.map_err(|e|e.to_string())?;
                    let changed=if fault=="request_receipt" { tx.execute("UPDATE openbot_internal.artifact_saved_receipts SET request_id=$1 WHERE operation_id=$2",&[&Uuid::now_v7().to_string(),&f.receipt.operation_id]).await } else {tx.execute("DELETE FROM openbot_internal.artifact_saved_receipts WHERE operation_id=$1",&[&f.receipt.operation_id]).await}.map_err(|e|e.to_string())?;
                    require(changed==1,"controller did not change exactly its actual original positive receipt")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_saved_receipts ENABLE TRIGGER artifact_saved_receipts_append_only").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_saved_receipts","positive_receipt")
                },
                "workspace_charge"=>{
                    require(tx.execute("UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=0 WHERE workspace_id=$1",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?==1,"controller did not change exactly its original workspace quota")?;
                    ("openbot_internal.artifact_workspace_quotas","workspace_quota")
                },
                "store_physical"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e|e.to_string())?;
                    require(tx.execute("UPDATE openbot_internal.artifact_store_bindings SET root_inode=(root_inode::numeric+1)::text WHERE store_id=$1",&[&f.store.store_id().to_string()]).await.map_err(|e|e.to_string())?==1,"controller did not change the actual original stored physical tuple")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_store_bindings","store_binding")
                },
                "cleanup_schema"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences RENAME CONSTRAINT artifact_cleanup_fences_phase TO owned_cleanup_test_phase_drift").await.map_err(|e|e.to_string())?;
                    ("","schema")
                },
                _=>{
                    // Install only while the genuine original BEGIN ACK is withheld: that
                    // same production connection has already passed its exact schema check.
                    // The controller's real COMMIT ACK precedes release of the original ACK.
                    // This sequence is controlled test instrumentation, not a business table.
                    // Its nontransactional advance proves the original real audit INSERT reached
                    // this trigger even though that same transaction must roll back all writes.
                    tx.batch_execute("CREATE SEQUENCE public.owned_cleanup_arm_audit_fault_seen; CREATE FUNCTION public.owned_cleanup_arm_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='artifact.cleanup_armed' THEN PERFORM nextval('public.owned_cleanup_arm_audit_fault_seen'); RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='owned cleanup arm audit insert fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_cleanup_arm_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_cleanup_arm_audit_fault();").await.map_err(|e|e.to_string())?;
                    ("","")
                },
            };
            tx.commit().await.map_err(|e|e.to_string())?;drop(c);
            let controlled=database_facts(&f.admin).await?;
            only_tables_changed(&before,&controlled,if allowed.is_empty(){&[]}else{std::slice::from_ref(&allowed)})?;
            if !allowed.is_empty() {require(before.get(allowed)!=controlled.get(allowed),"declared row corruption was never actually committed")?;}
            match fault {
                "operation_artifact"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["artifact_id"])? ,
                "source_pair"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["source_message_id"])? ,
                "nullable_sequence_pair"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["source_call_seq","source_attempt_seq"])? ,
                "charge"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["charged_bytes"])? ,
                "request_receipt"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["request_id"])? ,
                "positive_receipt_missing"=>controller_removed_row(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id)? ,
                "workspace_charge"=>controller_update_columns(&before,&controlled,allowed,"workspace_id",f.receipt.source_thread_id.as_str(),&["charged_bytes"])? ,
                "store_physical"=>controller_update_columns(&before,&controlled,allowed,"store_id",&f.store.store_id().to_string(),&["root_inode"])? ,
                _=>{},
            }
            let result=if let Some(worker)=audit_worker {
                let socket=&audit_original.as_ref().ok_or("actual audit original socket missing")?.2;
                f.relay.as_ref().unwrap().release_original_ack(socket,Hold::Begin)?;
                let result=worker.await.map_err(|e|e.to_string())?;
                require(socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0,"audit fault did not resume using the same unmodified original BEGIN ACK")?;
                result
            }else{f.arm().await};
            if fault=="audit_insert" {
                require(matches!(result,Err(Error::Unavailable)),"actual failing audit INSERT returned an accepted arm or was never reached")?;
                let socket=&audit_original.as_ref().ok_or("actual audit original socket missing")?.2;
                require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.entered.load(Ordering::SeqCst)&COMMIT_BIT==0,"actual audit fault did not await the same original ROLLBACK ACK")?;
                let c=f.admin.get().await.map_err(|e|e.to_string())?;
                let seen=c.query_one("SELECT last_value,is_called FROM public.owned_cleanup_arm_audit_fault_seen",&[]).await.map_err(|e|e.to_string())?;
                require(seen.get::<_,i64>(0)==1 && seen.get::<_,bool>(1),"original audit failure was inferred from a catalog name rather than its actual INSERT")?;
                eprintln!("ARTIFACT_CLEANUP_ARM_AUDIT_FAULT original_schema_passed_before_begin_ack=true original_begin_ack_held=true controller_fault_install_commit_ack=true same_original_begin_ack_released=true original_audit_insert_seen=true original_rollback_ack=true schema_guard_unchanged=true");
            }else{
                require(matches!(result,Err(Error::Corrupt{field}) if field==expected_field),"arm did not reject the precise original pair/charge/schema corruption")?;
            }
            require(database_facts(&f.admin).await?==controlled && object_fact(&f.path())?==original,"refused or audit-failed arm left fence/audit/charge/state/object mutation")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_FAULT kind={fault} controller_pid={controller_pid} controller_commit_ack=true original_row_actual=true allowed_table={allowed} producer_ordinary_rows_unchanged=true object_unchanged=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original connections/loopback fault relay"]
async fn original_arm_deadline_and_cancel_retire_unacknowledged_connection() {
    for wait in ["actor", "quota", "operation", "fence_fk_record", "audit"] {
        with_fixture("cleanup-original-budget",true,|f|Box::pin(async move {
            let before=database_facts(&f.admin).await?;let original_object=object_fact(&f.path())?;
            let held=f.pool.get().await.map_err(|e|e.to_string())?;
            let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let observation=held.observation();let socket=f.relay.as_ref().unwrap().socket_for_pid(pid)?;
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let fragment=match wait {
                "actor"=>{tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER]).await.map_err(|e|e.to_string())?;"public.users"},
                "quota"=>{tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;"artifact_workspace_quotas"},
                "operation"=>{tx.query_one("SELECT operation_id FROM openbot_internal.artifact_save_operations WHERE operation_id=$1 FOR UPDATE",&[&f.receipt.operation_id]).await.map_err(|e|e.to_string())?;"artifact_save_operations"},
                // The real uncommitted fence INSERT takes its exact original FK KEY SHARE.
                // The producer therefore waits at record FOR UPDATE first, not at a later
                // unique/fence statement. Observe that real coupled wait without relabelling it.
                "fence_fk_record"=>{tx.execute("INSERT INTO openbot_internal.artifact_cleanup_fences(deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) VALUES($1,$2,$3,$4,$5,'deleted','armed')",&[&DEPLOYMENT,&TENANT,&f.registry.binding().dataset_id(),&f.receipt.operation_id,&f.receipt.artifact_id]).await.map_err(|e|e.to_string())?;"artifact_records"},
                _=>{tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e|e.to_string())?;"pg_advisory_xact_lock"},
            };
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(30)).await});
            tokio::time::sleep(Duration::from_secs(2)).await;
            require(!worker.is_finished(),"original entry did not actually wait for its original Pool slot")?;drop(held);
            wait_blocked(&f.admin,pid,fragment,controller_pid).await?;
            let result=worker.await.map_err(|e|e.to_string())?;
            require(matches!(result,Err(Error::Unavailable)|Err(Error::RollbackAcknowledgedAfterDeadline)),"original deadline minted an intent or renewed its budget")?;
            original_five_seconds(started)?;
            let deadline=Instant::now()+Duration::from_secs(2);
            require(observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectionDestroyed,"absolute deadline lacked original driver destruction")?;
            wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),deadline,"original deadline lacked corresponding relay socket EOF").await?;
            // Original destructor/EOF are proved before releasing this owned test lock.
            // Backend disappearance is checked only after its true rollback ACK.
            tx.rollback().await.map_err(|e|e.to_string())?;drop(c);
            retired_original(f,pid,&observation,&socket).await?;
            require(database_facts(&f.admin).await?==before && object_fact(&f.path())?==original_object,"expired original arm committed fence/audit or refunded/changed original bytes")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_BUDGET wait={wait} waiter_pid={pid} controller_pid={controller_pid} pool_wait_ms=2000 absolute_original5s=true original_error={:?} original_driver_destroyed=true matching_socket_eof=true lock_rollback_ack=true backend_gone=true",result.err());
            Ok(())
        })).await;
    }
    for mode in ["begin_deadline", "begin_cancel", "cold_connect"] {
        with_fixture("cleanup-original-cancel",true,|f|Box::pin(async move {
            let before=database_facts(&f.admin).await?;
            let (pid,observation,socket)=f.original().await?;clear_transaction_facts(&socket);
            if mode=="cold_connect" {
                let c=f.admin.get().await.map_err(|e|e.to_string())?;
                require(c.query_one("SELECT pg_terminate_backend($1)",&[&pid]).await.map_err(|e|e.to_string())?.get(0),"owned cached backend could not be retired for cold connect")?;drop(c);
                let deadline=Instant::now()+Duration::from_secs(2);
                require(observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectionDestroyed,"controlled cold cache lacked original driver destruction")?;
                wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),deadline,"controlled cold cache lacked original socket EOF").await?;
                loop {
                    let c=f.admin.get().await.map_err(|e|e.to_string())?;
                    let alive:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1)",&[&pid]).await.map_err(|e|e.to_string())?.get(0);
                    if !alive {break;}
                    require(Instant::now()<deadline,"controlled cold original backend persisted after driver destruction and EOF")?;
                    drop(c);tokio::time::sleep(Duration::from_millis(10)).await;
                }
                f.relay.as_ref().unwrap().arm(Hold::Startup);
            }else{f.relay.as_ref().unwrap().arm(Hold::Begin);}
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            let (operation_observation,operation_socket)=if mode=="cold_connect" {
                wait_fact(||f.pool.connection_observations().iter().any(|o|{let s=o.snapshot();s.connecting_future_started&&!s.connection_started&&s.destruction.is_none()}),Instant::now()+Duration::from_secs(2),"arm did not start its real owned Config::connect future").await?;
                let connecting=f.pool.connection_observations().into_iter().find(|o|{let s=o.snapshot();s.connecting_future_started&&!s.connection_started&&s.destruction.is_none()}).ok_or("original connecting owner missing")?;
                wait_fact(||f.relay.as_ref().unwrap().newest_socket().is_ok_and(|s|s.withheld.load(Ordering::SeqCst)==Hold::Startup as u8),Instant::now()+Duration::from_secs(2),"arm cold connect did not reach original accepted socket").await?;
                (connecting,f.relay.as_ref().unwrap().newest_socket()?)
            }else{
                wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Begin as u8,Instant::now()+Duration::from_secs(2),"arm BEGIN did not reach a true original upstream ACK").await?;
                require(socket.entered.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT==0,"arm BEGIN fault was not original ACK loss")?;
                (observation,socket)
            };
            if mode=="begin_cancel" {worker.abort();require(worker.await.is_err_and(|e|e.is_cancelled()),"caller cancellation did not join the original arm future")?;}else{
                require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::Unavailable)),"BEGIN/connect deadline returned intent or a definite transaction outcome")?;original_five_seconds(started)?;
            }
            if mode=="cold_connect" {
                let deadline=Instant::now()+Duration::from_secs(2);
                require(operation_observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectingFutureDestroyed,"arm cold deadline lacked Config::connect future destruction")?;
                wait_fact(||operation_socket.frontend_eof.load(Ordering::SeqCst),deadline,"original cold-connect accepted socket did not reach EOF").await?;
                require(operation_socket.pid.load(Ordering::SeqCst)==0,"held original startup was silently forwarded to PostgreSQL")?;
            }else{retired_original(f,pid,&operation_observation,&operation_socket).await?;}
            require(database_facts(&f.admin).await?==before,"original connect/BEGIN/cancel attempt committed any business row")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_RETIRE mode={mode} original_resource_destroyed=true corresponding_socket_eof=true no_intent=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original COMMIT framed ACK-loss relay"]
async fn lost_original_arm_commit_ack_remains_unknown_without_cleanup_grant() {
    with_fixture("cleanup-original-commit-unknown",true,|f|Box::pin(async move {
        let before=database_facts(&f.admin).await?;let object=object_fact(&f.path())?;
        let (pid,observation,socket)=f.original().await?;clear_transaction_facts(&socket);
        f.relay.as_ref().unwrap().arm(Hold::Commit);
        let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
        let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
        wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Commit as u8,Instant::now()+Duration::from_secs(2),"original arm COMMIT did not reach true upstream ACK").await?;
        require(socket.entered.load(Ordering::SeqCst)&COMMIT_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&COMMIT_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&COMMIT_BIT==0,"commit uncertainty was not actual original ACK loss")?;
        f.verify_one_arm().await?;
        let durable=database_facts(&f.admin).await?;original_arm_append_only(&before,&durable)?;
        require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::CommitUnknown)),"lost original arm ACK minted an intent, claimed not-written or relabelled definite late ACK")?;
        original_five_seconds(started)?;
        retired_original(f,pid,&observation,&socket).await?;
        require(database_facts(&f.admin).await?==durable&&object_fact(&f.path())?==object,"unknown arm erased durable intent, repeated IO, changed charge or deleted original object")?;
        eprintln!("ARTIFACT_CLEANUP_ARM_COMMIT_UNKNOWN original_upstream_commit_ack=true original_forwarded_commit_ack=false original_error=CommitUnknown durable_fence_and_audit=true original_driver_destroyed=true matching_frontend_eof=true original_backend_gone=true usable_intent=false physical_delete=false retry=false");
        Ok(())
    })).await;
}
