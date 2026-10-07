//! Actual Session/Application Save -> current saved-owner arm on an owned PG and Store.
//! Fault controllers change only their named original rows. Arm is not physical deletion.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use http::Request;
use openbot_application::{ApplicationService, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifact_read_protocol::OpenArtifactRead;
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
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError as Error,
    ArtifactCleanupPhysicalError as PhysicalError, ArtifactCleanupPhysicalIoPhase as PhysicalPhase,
    ArtifactCleanupPhysicalObserver, ArtifactCleanupPhysicalState as PhysicalState,
    PostgresArtifactAdministration,
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
use std::sync::{Arc, Condvar, Mutex};
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
        // This is the original fixture's real stock admission shutdown, after
        // every body assertion. Only the observations below prove destruction.
        self.pool.close();
        self.admin.close();
        let relay = self.relay.take();
        drop(self);
        let deadline = Instant::now() + Duration::from_secs(3);
        let observation_count = observations.len();
        for (index, o) in observations.into_iter().enumerate() {
            let original = o.snapshot();
            let expected = if original.connection_started {
                ConnectionDestruction::ConnectionDestroyed
            } else if original.connecting_future_started {
                ConnectionDestruction::ConnectingFutureDestroyed
            } else {
                ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart
            };
            let destroyed = o.wait_for_destruction_before(deadline).await.map_err(|error| {
                eprintln!("ARTIFACT_CLEANUP_ARM_FIXTURE_TAIL_ERROR index={index} count={observation_count} before={original:?} after={:?}", o.snapshot());
                error.to_string()
            })?;
            require(
                destroyed == expected,
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
    hold_next_begin_after_forwarded_rollback: AtomicBool,
    forwarded_host_rollback_before_source_begin: AtomicBool,
    post_schema_source_begin_held: AtomicBool,
    post_schema_source_begin_forwarded: AtomicBool,
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
                    if selected as u8 == Hold::Begin as u8
                        && backend_facts
                            .forwarded_host_rollback_before_source_begin
                            .load(Ordering::SeqCst)
                    {
                        backend_facts
                            .post_schema_source_begin_held
                            .store(true, Ordering::SeqCst);
                    }
                }
            }
            if holding == 0 {
                frontend_write.write_all(&packet).await?;
                if bit != 0 {
                    backend_facts.forwarded_ack.fetch_or(bit, Ordering::SeqCst);
                    if bit == ROLLBACK_BIT
                        && backend_facts
                            .hold_next_begin_after_forwarded_rollback
                            .swap(false, Ordering::SeqCst)
                    {
                        // This same original ACK was actually written. Arm the following
                        // BEGIN before forwarding ReadyForQuery lets the caller continue.
                        backend_state
                            .hold
                            .compare_exchange(
                                0,
                                Hold::Begin as u8,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .map_err(|_| {
                                std::io::Error::other(
                                    "original source BEGIN gate collided with another hold",
                                )
                            })?;
                        backend_facts
                            .forwarded_host_rollback_before_source_begin
                            .store(true, Ordering::SeqCst);
                    }
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
                            let original_bit = command_bit(&original[5..]);
                            backend_facts
                                .forwarded_ack
                                .fetch_or(original_bit, Ordering::SeqCst);
                            if original_bit == BEGIN_BIT
                                && holding == Hold::Begin as u8
                                && backend_facts
                                    .post_schema_source_begin_held
                                    .load(Ordering::SeqCst)
                            {
                                backend_facts
                                    .post_schema_source_begin_forwarded
                                    .store(true, Ordering::SeqCst);
                            }
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

async fn original_session_revocation_read_leg(
    f: &Fixture,
    operation_path: bool,
) -> Result<(), String> {
    let phase = if operation_path { "operation" } else { "chunk" };
    let original_object = object_fact(&f.path())?;
    let before = database_facts(&f.admin).await?;
    let (original_pid, _original_connection, socket) = f.original().await?;
    clear_transaction_facts(&socket);
    let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        transaction
            .execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID])
            .await
            .map_err(|error| error.to_string())?
            == 1,
        "P1 controller did not revoke exactly the actual original Session",
    )?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    drop(controller);
    let revoked = database_facts(&f.admin).await?;
    only_tables_changed(&before, &revoked, &["public.sessions"])?;
    let old_sessions = before["public.sessions"]
        .as_array()
        .ok_or("P1 original sessions missing")?;
    let retained: Vec<_> = old_sessions
        .iter()
        .filter(|row| row["row"]["id"].as_str() != Some(A_ID))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == old_sessions.len()
            && revoked["public.sessions"].as_array() == Some(&retained),
        "P1 Session revoke changed another session or physical row carrier",
    )?;

    // Construct this actual operation after revocation so the real preliminary Host
    // port, rather than a preceding close_binding stop, produces the refusal.
    let old_error = if operation_path {
        let mut operation = f
            .application
            .open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 old operation construction: {error}"))?;
        let result = operation.next_block(&f.auth).await;
        drop(operation);
        result.err()
    } else {
        f.application
            .read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone())
            .await
            .err()
    };
    require(
        matches!(old_error, Some(AppError::Unauthenticated)),
        "P1 revoked original Session did not preserve its actual Host refusal",
    )?;
    let rollback = Hold::Rollback as u8;
    require(
        socket.server_ack.load(Ordering::SeqCst) & rollback != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & rollback != 0
            && socket.withheld.load(Ordering::SeqCst) == 0,
        "P1 known Session refusal lacked the original forwarded ROLLBACK ACK",
    )?;
    require(
        database_facts(&f.admin).await? == revoked && object_fact(&f.path())? == original_object,
        "P1 old Session refusal changed original business rows or object",
    )?;

    let fresh = resolve(f.resolver.as_ref(), COOKIE_B).await?;
    require(
        fresh == f.auth
            && !fresh
                .request_binding()
                .ok_or("P1 new Session binding missing")?
                .identity()
                .same_binding(
                    f.auth
                        .request_binding()
                        .ok_or("P1 old Session binding missing")?
                        .identity(),
                ),
        "P1 new real Session changed six Auth facts or reused the revoked Session identity",
    )?;
    fresh
        .request_binding()
        .ok_or("P1 fresh Session missing")?
        .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|error| format!("P1 new real Session was not current: {error:?}"))?;
    let after_auth = database_facts(&f.admin).await?;
    only_tables_changed(&revoked, &after_auth, &["public.sessions"])?;
    let mut expected_sessions = revoked["public.sessions"]
        .as_array()
        .ok_or("P1 revoked sessions missing")?
        .clone();
    let fresh_sessions = after_auth["public.sessions"]
        .as_array()
        .ok_or("P1 fresh sessions missing")?;
    require(
        expected_sessions.len() == fresh_sessions.len(),
        "P1 new authentication changed the Session inventory",
    )?;
    for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
        if old["row"]["id"].as_str() == Some("cleanup-session-b") {
            old["row"]["updated_at"] = new["row"]["updated_at"].clone();
            old["xmin"] = new["xmin"].clone();
            old["ctid"] = new["ctid"].clone();
        }
    }
    require(
        expected_sessions == *fresh_sessions,
        "P1 new Session authentication changed fields beyond its original idle clock",
    )?;

    // Exercise the same original first-chunk path with the new valid Host. A raw
    // returned Vec is outside the finite allocation ACK and is never used as its proof.
    if !operation_path {
        let chunk = f
            .application
            .read_current_artifact_chunk(fresh.clone(), f.receipt.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 fresh same-Store chunk remained refused: {error}"))?;
        require(
            owned_object_fds(&f.path())?.len() == 1,
            "P1 real legacy chunk did not retain its original target FD before handoff",
        )?;
        let bytes = chunk.handoff(&fresh).map_err(|error| error.to_string())?;
        require(
            bytes == TEXT.as_bytes(),
            "P1 new Session chunk changed original saved bytes",
        )?;
        drop(bytes);
        require(
            owned_object_fds(&f.path())?.is_empty(),
            "P1 original legacy target FD did not close after its synchronous handoff",
        )?;
    }
    let mut operation = f
        .application
        .open_current_artifact_read(fresh.clone(), f.receipt.artifact_id.clone())
        .await
        .map_err(|error| format!("P1 fresh same-Store operation remained refused: {error}"))?;
    let pending = operation
        .next_block(&fresh)
        .await
        .map_err(|error| format!("P1 fresh same-Store block remained refused: {error}"))?;
    require(
        pending.prefix_length().map_err(|error| error.to_string())? == TEXT.len(),
        "P1 new Session did not materialize the genuine full leased allocation",
    )?;
    let frame = pending
        .handoff_frame(&fresh)
        .map_err(|error| error.to_string())?;
    require(
        frame.as_bytes() == TEXT.as_bytes(),
        "P1 new Session leased frame changed original saved bytes",
    )?;
    let held_fds = owned_object_fds(&f.path())?;
    require(
        held_fds.len() == 1,
        "P1 new real Session did not own exactly its original object FD",
    )?;
    let record = f
        .actual
        .observe_read_record(&fresh, &f.receipt.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let barrier = f
        .actual
        .close_observed_artifact_reads(&record)
        .map_err(|error| error.to_string())?;
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ),
        "P1 fresh Session inventory ACKed a held real allocation or stayed poisoned",
    )?;
    drop(operation);
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ) && owned_object_fds(&f.path())? == held_fds,
        "P1 operation Drop substituted for the original last allocation owner",
    )?;
    drop(frame);
    let ack = barrier
        .drain_before(Instant::now() + Duration::from_secs(3))
        .await
        .map_err(|error| {
            format!("P1 same original Store failed its real finite drain: {error:?}")
        })?;
    require(
        owned_object_fds(&f.path())?.is_empty()
            && object_fact(&f.path())? == original_object
            && database_facts(&f.admin).await? == after_auth,
        "P1 actual frame/FD closure changed original business facts or retained its FD",
    )?;
    drop(ack);
    drop(barrier);
    eprintln!(
        "ARTIFACT_READ_P1_SESSION leg={phase} original_pid={original_pid} revoke_controller_pid={controller_pid} original_session_delete_commit_ack=true original_read_unauthenticated=true original_rollback_ack_forwarded=true new_real_session_current=true same_store_same_pair=true new_actual_bytes=true held_allocation_no_ack=true last_original_owner_dropped=true original_fd_absent=true finite_controlled_ack=true physical_delete=false legacy_returned_vec_lifetime=UNTRACKED"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL, original Session revocation and same owned Store"]
async fn revoked_original_server_session_does_not_poison_new_same_store_artifact_reads_and_drain() {
    let failures = Arc::new(Mutex::new(Vec::new()));
    for operation_path in [false, true] {
        let tag = if operation_path {
            "p1_session_operation"
        } else {
            "p1_session_chunk"
        };
        let failures = Arc::clone(&failures);
        with_fixture(tag, true, move |fixture| {
            Box::pin(async move {
                let outcome = original_session_revocation_read_leg(fixture, operation_path).await;
                if let Err(error) = outcome {
                    eprintln!("ARTIFACT_READ_P1_SESSION leg={tag} actual_result=FAILED");
                    failures
                        .lock()
                        .map_err(|_| "P1 failure aggregation poisoned")?
                        .push(format!("{tag}: {error}"));
                }
                // Preserve both real sub-leg failures while letting the original fixture
                // close before the final single libtest result is asserted below.
                Ok(())
            })
        })
        .await;
    }
    let failures = failures.lock().expect("P1 original failure records");
    assert!(
        failures.is_empty(),
        "genuine old/new Session read and finite drain regressions: {failures:?}"
    );
}

#[tokio::test]
#[ignore = "requires actual original guarded read, withheld ROLLBACK ACK and same owned Store"]
async fn lost_original_guarded_read_rollback_ack_keeps_same_store_unproven_after_owner_revocation()
{
    with_fixture("p1-original-read-rollback-unknown", true, |f| Box::pin(async move {
        // This genuine original record supplies only the existing finite close key.
        // It neither replaces the Store nor proves deletion or a public read grant.
        let original_record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await
            .map_err(|error| error.to_string())?;
        let original_object = object_fact(&f.path())?;
        let before = database_facts(&f.admin).await?;
        let (original_pid, original_connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let relay = f.relay.as_ref().ok_or("P1 original guarded read relay missing")?;
        let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
        let transaction = controller.transaction().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = transaction.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.get(0);
        socket.hold_next_begin_after_forwarded_rollback.store(true, Ordering::SeqCst);
        let application = Arc::clone(&f.application);
        let original_auth = f.auth.clone();
        let artifact_id = f.receipt.artifact_id.clone();
        let started = Instant::now();
        let worker = tokio::spawn(async move {
            application.execute(original_auth, AppCommand::OpenArtifactRead(OpenArtifactRead { artifact_id })).await
        });
        let controlled = async {
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8
                && socket.forwarded_host_rollback_before_source_begin.load(Ordering::SeqCst)
                && socket.post_schema_source_begin_held.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 original source BEGIN ACK was not held after the actual forwarded Host ROLLBACK").await?;
            require(socket.pid.load(Ordering::SeqCst) == original_pid
                && !socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                "P1 source BEGIN hold changed original producer or had already forwarded its ACK")?;
            let observer = f.admin.get().await.map_err(|error| error.to_string())?;
            let row = observer.query_one(
                "SELECT pg_catalog.pg_backend_pid() AS observer_pid,state,query,xact_start IS NOT NULL AS actual_transaction FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&original_pid],
            ).await.map_err(|error| error.to_string())?;
            let begin_observer_pid: i32 = row.get("observer_pid");
            let begin_query: String = row.get("query");
            require(begin_observer_pid != original_pid && begin_observer_pid != controller_pid && original_pid != controller_pid
                && row.get::<_, Option<String>>("state").as_deref() == Some("idle in transaction")
                && row.get::<_, bool>("actual_transaction")
                && (begin_query.trim_start().starts_with("BEGIN") || begin_query.trim_start().starts_with("START TRANSACTION"))
                && begin_query.contains("READ COMMITTED") && begin_query.contains("READ ONLY"),
                "P1 held post-schema source BEGIN was not the original read-only transaction with distinct observer/controller")?;
            drop(observer);
            // The original source schema is now complete; its actual BEGIN ACK remains
            // withheld so no source table query can preempt this genuine controller lock.
            transaction.batch_execute("LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE").await
                .map_err(|error| error.to_string())?;
            relay.release_original_ack(&socket, Hold::Begin)?;
            wait_fact(|| socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 did not release exactly the held original post-schema source BEGIN ACK").await?;
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            let observer_pid = loop {
                let observer = f.admin.get().await.map_err(|error| error.to_string())?;
                let row = observer.query_opt(
                    "SELECT pg_catalog.pg_backend_pid() AS observer_pid,query,wait_event_type,pg_catalog.pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                    &[&original_pid],
                ).await.map_err(|error| error.to_string())?;
                if let Some(row) = row {
                    let query: String = row.get("query");
                    let wait_type: Option<String> = row.get("wait_event_type");
                    let blockers: Vec<i32> = row.get("blockers");
                    if wait_type.as_deref() == Some("Lock")
                        && blockers.contains(&controller_pid)
                        && query.contains("artifact_private_read_record_snapshot")
                        && query.contains("FROM visible_run r JOIN openbot_internal.artifact_records a")
                        && query.contains("LEFT JOIN openbot_internal.artifact_cleanup_fences c")
                    {
                        let observer_pid: i32 = row.get("observer_pid");
                        require(original_pid != controller_pid && observer_pid != original_pid && observer_pid != controller_pid,
                            "P1 source query producer/controller/observer were not distinct actual backends")?;
                        break observer_pid;
                    }
                }
                require(Instant::now() < wait_deadline,
                    "P1 original guarded read never reached the complete source snapshot at its actual controller lock")?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            // Preliminary Host and schema queries are already past. Withhold only the
            // ensuing original guarded read's ROLLBACK, after the proven source wait.
            clear_transaction_facts(&socket);
            relay.arm(Hold::Rollback);
            transaction.rollback().await.map_err(|error| error.to_string())?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2),
                "P1 actual original guarded read ROLLBACK did not reach its upstream ACK").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
                && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P1 read uncertainty was not its actual original upstream ROLLBACK ACK withheld from the driver")?;
            Ok::<i32, String>(observer_pid)
        }.await;
        drop(controller);
        // Reap the original task even when a control assertion fails. A requested stop
        // on that failure path is never a substitute for the evidence below.
        if controlled.is_err() {
            let _ = f.application.close_public_artifact_reads();
        }
        let original_outcome = worker.await.map_err(|error| error.to_string())?;
        let observer_pid = controlled?;
        require(matches!(original_outcome, Err(AppError::DependencyUnavailable { .. })),
            "P1 missing original read ROLLBACK ACK returned a byte/control grant or definite Host refusal")?;
        original_five_seconds(started)?;
        retired_original(f, original_pid, &original_connection, &socket).await?;
        require(socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
            "P1 original held read ACK was later forwarded or credited after retirement")?;
        require(database_facts(&f.admin).await? == before && object_fact(&f.path())? == original_object
            && owned_object_fds(&f.path())?.is_empty(),
            "P1 original uncertain read changed business/object facts or opened an unowned object FD")?;

        // Revoke the actual old issuer only after its original connection has truly
        // retired. Install a fresh real resolver on the SAME Administration/Store.
        f.resolver.close_request_bindings();
        let fresh_resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY, default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT)).map_err(|error| error.to_string())?;
        fresh_resolver.install_artifact_read_authority(&f.actual.read_authority())
            .map_err(|_| "P1 new genuine Session issuer enrollment failed")?;
        let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("P1 recovery Session binding missing")?.identity()
                .same_binding(f.auth.request_binding().ok_or("P1 original Session binding missing")?.identity()),
                "P1 uncertain read recovery reused the closed owner or changed six Auth facts")?;
            fresh.request_binding().ok_or("P1 new valid Session missing")?.verify_current_before(&fresh,
                Instant::now() + Duration::from_secs(5)).await
                .map_err(|error| format!("P1 new actual Session was not valid independently of Store poison: {error:?}"))?;
            let after_auth = database_facts(&f.admin).await?;
            only_tables_changed(&before, &after_auth, &["public.sessions"])?;
            let mut expected_sessions = before["public.sessions"].as_array().ok_or("P1 original session facts missing")?.clone();
            let fresh_sessions = after_auth["public.sessions"].as_array().ok_or("P1 recovery session facts missing")?;
            require(expected_sessions.len() == fresh_sessions.len(), "P1 recovery changed original Session inventory")?;
            for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
                if old["row"]["id"].as_str() == Some("cleanup-session-b") {
                    old["row"]["updated_at"] = new["row"]["updated_at"].clone();
                    old["xmin"] = new["xmin"].clone();
                    old["ctid"] = new["ctid"].clone();
                }
            }
            require(expected_sessions == *fresh_sessions,
                "P1 recovery changed fields beyond the named new Session idle observation")?;
            let refused = f.application.read_current_artifact_chunk(fresh.clone(), f.receipt.artifact_id.clone()).await;
            require(matches!(refused, Err(AppError::DependencyUnavailable { .. })),
                "P1 valid new owner erased original read uncertainty or gained actual bytes")?;
            let barrier = f.actual.close_observed_artifact_reads(&original_record).map_err(|error| error.to_string())?;
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_secs(3)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)),
                "P1 new Host or original driver retirement fabricated a finite Store drain ACK")?;
            require(database_facts(&f.admin).await? == after_auth && object_fact(&f.path())? == original_object
                && owned_object_fds(&f.path())?.is_empty(),
                "P1 permanent uncertain refusal wrote producer rows, changed object or retained its FD")?;
            drop(barrier);
            eprintln!("ARTIFACT_READ_P1_ROLLBACK_UNKNOWN original_producer_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_host_rollback_forwarded_before_source_begin=true actual_post_schema_source_begin_held_and_released=true complete_original_source_query_lock_wait=true controller_rollback_ack=true original_upstream_read_rollback_ack=true original_forwarded_read_rollback_ack=false original_five_second_error=true original_driver_destroyed=true corresponding_frontend_eof=true original_backend_gone=true original_owner_closed_after_retirement=true new_true_owner_valid=true same_original_store_pair=true byte_grant=false finite_store_ack=false business_object_unchanged=true held_read_rollback_ack_released=false physical_delete=false");
            Ok::<(), String>(())
        }.await;
        fresh_resolver.close_request_bindings();
        recovery
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

// Task020: this oracle follows only the originally saved dev/inode, including nlink=0.
fn physical_macos_inode_fds_for(
    original_device: u64,
    original_inode: u64,
) -> Result<Vec<String>, String> {
    let device = original_device & u64::from(u32::MAX);
    let sample = || -> Result<Vec<String>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "finite original own-PID lsof unavailable (Unproven)")?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("finite original lsof streams unavailable (Unproven)".to_owned());
        };
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let waited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => break Err("finite original own-PID lsof timed out (Unproven)"),
                Err(_) => break Err("finite original own-PID lsof wait failed (Unproven)"),
            }
        };
        // All error paths still reap this original child and both original pipe workers.
        // A killed/timed-out/error child is never credited as a natural successful sample.
        if waited.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let output = output.join();
        let errors = errors.join();
        let status = waited?;
        let output = output
            .map_err(|_| "original lsof stdout worker failed")?
            .map_err(|_| "original lsof stdout read failed")?;
        let errors = errors
            .map_err(|_| "original lsof stderr worker failed")?
            .map_err(|_| "original lsof stderr read failed")?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.is_empty()
                && output.ends_with(b"\n"),
            "original lsof was failed, incomplete, truncated or emitted stderr (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "original lsof output invalid")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("original lsof empty field")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "original lsof observed a peer PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(original_inode) {
                        found.insert(fd.ok_or("original inode had a nonnumeric ambiguous FD")?);
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
                        .map_err(|_| "original lsof device invalid")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "original lsof inode invalid")?,
                    );
                }
                _ => return Err("original lsof unexpected field".to_owned()),
            }
        }
        require(self_pid, "original lsof self-PID field missing")?;
        Ok(found.into_iter().map(|fd| fd.to_string()).collect())
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "original inode FD inventory changed between two actual samples (Unproven)",
    )?;
    Ok(first)
}

#[derive(Default)]
struct PhysicalPhaseFacts {
    seen: [usize; 4],
    original_fd: Option<i32>,
    nlink_after_unlink: Option<u64>,
    error: Option<String>,
    released: bool,
}
struct PhysicalPhaseGate {
    artifact: Uuid,
    original: ObjectFact,
    pause: usize,
    absent_at_entry: bool,
    facts: Mutex<PhysicalPhaseFacts>,
    changed: Condvar,
}
impl PhysicalPhaseGate {
    fn new(
        f: &Fixture,
        original: ObjectFact,
        pause: usize,
        absent_at_entry: bool,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            artifact: Uuid::parse_str(&f.receipt.artifact_id).map_err(|e| e.to_string())?,
            original,
            pause,
            absent_at_entry,
            facts: Mutex::new(PhysicalPhaseFacts::default()),
            changed: Condvar::new(),
        }))
    }
    fn release(&self) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.released = true;
            self.changed.notify_all();
        }
    }
    fn saw(&self, phase: usize) -> bool {
        self.facts.lock().is_ok_and(|f| f.seen[phase - 1] > 0)
    }
    fn check(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "original physical observer poisoned")?;
        match &facts.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    async fn wait(&self, phase: usize, deadline: Instant) -> Result<(), String> {
        wait_fact(
            || self.saw(phase),
            deadline,
            "actual original physical phase was not reached",
        )
        .await?;
        self.check()
    }
    fn after_unlink_is_original_zero_link(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "original physical observer poisoned")?;
        require(
            facts.seen[2] == 1
                && facts.original_fd.is_some()
                && facts.nlink_after_unlink == Some(0),
            "AfterUnlink did not observe the actually held original inode with nlink=0",
        )
    }
}
impl ArtifactCleanupPhysicalObserver for PhysicalPhaseGate {
    fn on_phase(&self, phase: PhysicalPhase, artifact_id: Uuid, original_leaf_fd: Option<i32>) {
        let index = match phase {
            PhysicalPhase::PreflightReady => 1,
            PhysicalPhase::BeforeFirstUnlink => 2,
            PhysicalPhase::AfterUnlinkBeforeSync => 3,
            PhysicalPhase::WorkerEnded => 4,
        };
        // A finite duplicate of the explicitly supplied live original FD is metadata-only.
        // It closes before the callback pauses or WorkerEnded is accepted; it is not an
        // original-worker closure receipt, nor does it read body bytes.
        let observed = (|| -> Result<Option<u64>, String> {
            require(
                artifact_id == self.artifact,
                "physical observer rebound artifact UUID",
            )?;
            if index == 4 {
                require(
                    original_leaf_fd.is_none(),
                    "WorkerEnded still exported a live leaf FD",
                )?;
                return Ok(None);
            }
            let Some(fd) = original_leaf_fd else {
                require(
                    self.absent_at_entry
                        || self
                            .facts
                            .lock()
                            .is_ok_and(|f| f.nlink_after_unlink == Some(0)),
                    "retained preflight did not hold its actual original leaf FD",
                )?;
                return Ok(None);
            };
            let duplicate = std::fs::File::open(format!("/dev/fd/{fd}"))
                .map_err(|_| "original physical FD duplicate failed")?;
            let metadata = duplicate
                .metadata()
                .map_err(|_| "original physical FD metadata failed")?;
            let valid = metadata.is_file()
                && metadata.dev() == self.original.dev
                && metadata.ino() == self.original.ino
                && metadata.uid() == self.original.uid
                && metadata.mode() == self.original.mode
                && metadata.len() == self.original.len;
            let nlink = metadata.nlink();
            drop(duplicate);
            require(
                valid,
                "phase FD was not the originally saved physical inode",
            )?;
            require(
                if index == 3 { nlink == 0 } else { nlink == 1 },
                "original phase FD had unexpected actual link count",
            )?;
            Ok(Some(nlink))
        })();
        let Ok(mut facts) = self.facts.lock() else {
            return;
        };
        facts.seen[index - 1] += 1;
        match observed {
            Ok(nlink) => {
                if let Some(fd) = original_leaf_fd {
                    facts.original_fd = Some(fd);
                }
                if index == 3 {
                    facts.nlink_after_unlink = nlink;
                }
            }
            Err(error) => facts.error = Some(error),
        }
        self.changed.notify_all();
        // The producer's deadline is unchanged. This separate finite fixture wait can
        // retain a worker after its main query expires, for genuine unproven cleanup.
        let stop = Instant::now() + Duration::from_secs(8);
        while index == self.pause && !facts.released {
            let remaining = stop.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                facts.error =
                    Some("original physical phase controller was not released".to_owned());
                break;
            }
            match self.changed.wait_timeout(facts, remaining) {
                Ok((next, _)) => facts = next,
                Err(_) => return,
            }
        }
    }
}
struct PhysicalGateRelease(Arc<PhysicalPhaseGate>);
impl Drop for PhysicalGateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn install_physical_gate(
    f: &Fixture,
    original: ObjectFact,
    pause: usize,
    absent: bool,
) -> Result<Arc<PhysicalPhaseGate>, String> {
    let gate = PhysicalPhaseGate::new(f, original, pause, absent)?;
    f.actual
        .install_cleanup_physical_observer(gate.clone())
        .map_err(|e| format!("{e:?}"))?;
    Ok(gate)
}
fn physical_inode_fds(original: &ObjectFact) -> Result<Vec<String>, String> {
    physical_inode_fds_for(original.dev, original.ino)
}
fn physical_inode_fds_for(device: u64, inode: u64) -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return physical_macos_inode_fds_for(device, inode);
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if std::fs::metadata(entry.path()).is_ok_and(|m| m.dev() == device && m.ino() == inode) {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found.sort();
    Ok(found)
}
async fn physical_original_fd_closed(gate: &Arc<PhysicalPhaseGate>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    gate.wait(4, deadline).await?;
    let original = gate.original.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        loop {
            if physical_inode_fds(&original)?.is_empty() {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "WorkerEnded label did not close the actual original inode FD",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    gate.check()
}
async fn physical_normal_original_ack(
    f: &Fixture,
    pid: i32,
    socket: &SocketFacts,
) -> Result<(), String> {
    require(
        socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
        "normal physical observation lacked this original query's true BEGIN/ROLLBACK ACK",
    )?;
    let current = f.pool.get().await.map_err(|e| e.to_string())?;
    let current_pid: i32 = current
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        current_pid == pid,
        "normal original acknowledged query was retired rather than reusable",
    )
}
fn physical_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
async fn physical_poison_refuses(
    f: &Fixture,
    auth: &AuthContext,
    intent: &ArmedArtifactCleanupIntent,
    original_record: &openbot_infra::artifact_administration::ObservedArtifactReadRecord,
) -> Result<(), String> {
    require(
        f.actual
            .remove_armed_explicit_saved_bytes_before(
                auth,
                intent,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .is_err(),
        "new remove erased original physical/read uncertainty",
    )?;
    require(
        f.actual
            .observe_armed_explicit_saved_bytes_before(
                auth,
                intent,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .is_err(),
        "new observe erased original physical/read uncertainty",
    )?;
    let barrier = f
        .actual
        .close_observed_artifact_reads(original_record)
        .map_err(|e| e.to_string())?;
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_secs(2))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)
        ),
        "original poisoned shared Store fabricated a finite drain ACK",
    )
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL and original armed Store; actual finite physical IO only"]
async fn actual_original_armed_object_unlink_and_directory_sync_prove_absence_without_refund() {
    with_fixture("physical-original-source-deleted", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        hard_delete_original_message(f).await?;
        read_is_404(f).await?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        f.verify_one_arm().await?;
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 0, false)?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let started = Instant::now();
        let result = f.actual.remove_armed_explicit_saved_bytes_before(&f.auth, &intent,
            started + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        require(started.elapsed() < Duration::from_secs(5) && result.state() == PhysicalState::DurableAbsent,
            "actual original cleanup lacked a normal in-budget DurableAbsent observation")?;
        gate.after_unlink_is_original_zero_link()?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
            "actual producer did not leave both canonical names absent")?;
        require(database_facts(&f.admin).await? == armed, "physical IO changed original charge/Run32/pair/fence/audit rows or physical carriers")?;
        let retry = f.application.execute(f.auth.clone(), AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
            request_id: Uuid::now_v7().to_string(), source_thread_id: f.receipt.source_thread_id.clone(),
            source_run_id: f.receipt.source_run_id.clone(), source_message_id: f.receipt.source_message_id.clone(),
            expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
        })).await;
        require(matches!(retry, Err(AppError::NotVisible)), "source-deleted locator Save recreated its armed object")?;
        read_is_404(f).await?;
        require(database_facts(&f.admin).await? == armed && physical_absent(&f.path()), "source-deleted retry mutated original armed facts")?;
        let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(2)).await.map_err(|e| format!("{e:?}"))?;
        drop(ack); drop(barrier); drop(result); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P01 actual_original_unlink=true original_fd_nlink_zero=true original_fd_closed=true guarded_directory_sync_and_double_absence=true original_query_rollback_ack=true business_charge_fence_audit_unchanged=true source_save_404=true terminal_refund=false");
        Ok(())
    })).await;
}

async fn physical_genuine_original_read_ack_loss(f: &Fixture) -> Result<(), String> {
    // This genuine original record supplies only the existing finite close key.
    // It neither replaces the Store nor proves deletion or a public read grant.
    let original_record = f
        .actual
        .observe_read_record(&f.auth, &f.receipt.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let original_object = object_fact(&f.path())?;
    let before = database_facts(&f.admin).await?;
    let (original_pid, original_connection, socket) = f.original().await?;
    clear_transaction_facts(&socket);
    let relay = f
        .relay
        .as_ref()
        .ok_or("P1 original guarded read relay missing")?;
    let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    socket
        .hold_next_begin_after_forwarded_rollback
        .store(true, Ordering::SeqCst);
    let application = Arc::clone(&f.application);
    let original_auth = f.auth.clone();
    let artifact_id = f.receipt.artifact_id.clone();
    let started = Instant::now();
    let worker = tokio::spawn(async move {
        application
            .execute(
                original_auth,
                AppCommand::OpenArtifactRead(OpenArtifactRead { artifact_id }),
            )
            .await
    });
    let controlled = async {
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8
                && socket.forwarded_host_rollback_before_source_begin.load(Ordering::SeqCst)
                && socket.post_schema_source_begin_held.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 original source BEGIN ACK was not held after the actual forwarded Host ROLLBACK").await?;
            require(socket.pid.load(Ordering::SeqCst) == original_pid
                && !socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                "P1 source BEGIN hold changed original producer or had already forwarded its ACK")?;
            let observer = f.admin.get().await.map_err(|error| error.to_string())?;
            let row = observer.query_one(
                "SELECT pg_catalog.pg_backend_pid() AS observer_pid,state,query,xact_start IS NOT NULL AS actual_transaction FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&original_pid],
            ).await.map_err(|error| error.to_string())?;
            let begin_observer_pid: i32 = row.get("observer_pid");
            let begin_query: String = row.get("query");
            require(begin_observer_pid != original_pid && begin_observer_pid != controller_pid && original_pid != controller_pid
                && row.get::<_, Option<String>>("state").as_deref() == Some("idle in transaction")
                && row.get::<_, bool>("actual_transaction")
                && (begin_query.trim_start().starts_with("BEGIN") || begin_query.trim_start().starts_with("START TRANSACTION"))
                && begin_query.contains("READ COMMITTED") && begin_query.contains("READ ONLY"),
                "P1 held post-schema source BEGIN was not the original read-only transaction with distinct observer/controller")?;
            drop(observer);
            // The original source schema is now complete; its actual BEGIN ACK remains
            // withheld so no source table query can preempt this genuine controller lock.
            transaction.batch_execute("LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE").await
                .map_err(|error| error.to_string())?;
            relay.release_original_ack(&socket, Hold::Begin)?;
            wait_fact(|| socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 did not release exactly the held original post-schema source BEGIN ACK").await?;
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            let observer_pid = loop {
                let observer = f.admin.get().await.map_err(|error| error.to_string())?;
                let row = observer.query_opt(
                    "SELECT pg_catalog.pg_backend_pid() AS observer_pid,query,wait_event_type,pg_catalog.pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                    &[&original_pid],
                ).await.map_err(|error| error.to_string())?;
                if let Some(row) = row {
                    let query: String = row.get("query");
                    let wait_type: Option<String> = row.get("wait_event_type");
                    let blockers: Vec<i32> = row.get("blockers");
                    if wait_type.as_deref() == Some("Lock")
                        && blockers.contains(&controller_pid)
                        && query.contains("artifact_private_read_record_snapshot")
                        && query.contains("FROM visible_run r JOIN openbot_internal.artifact_records a")
                        && query.contains("LEFT JOIN openbot_internal.artifact_cleanup_fences c")
                    {
                        let observer_pid: i32 = row.get("observer_pid");
                        require(original_pid != controller_pid && observer_pid != original_pid && observer_pid != controller_pid,
                            "P1 source query producer/controller/observer were not distinct actual backends")?;
                        break observer_pid;
                    }
                }
                require(Instant::now() < wait_deadline,
                    "P1 original guarded read never reached the complete source snapshot at its actual controller lock")?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            // Preliminary Host and schema queries are already past. Withhold only the
            // ensuing original guarded read's ROLLBACK, after the proven source wait.
            clear_transaction_facts(&socket);
            relay.arm(Hold::Rollback);
            transaction.rollback().await.map_err(|error| error.to_string())?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2),
                "P1 actual original guarded read ROLLBACK did not reach its upstream ACK").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
                && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P1 read uncertainty was not its actual original upstream ROLLBACK ACK withheld from the driver")?;
            Ok::<i32, String>(observer_pid)
        }.await;
    drop(controller);
    // Reap the original task even when a control assertion fails. A requested stop
    // on that failure path is never a substitute for the evidence below.
    if controlled.is_err() {
        let _ = f.application.close_public_artifact_reads();
    }
    let original_outcome = worker.await.map_err(|error| error.to_string())?;
    let observer_pid = controlled?;
    require(
        matches!(
            original_outcome,
            Err(AppError::DependencyUnavailable { .. })
        ),
        "P1 missing original read ROLLBACK ACK returned a byte/control grant or definite Host refusal",
    )?;
    original_five_seconds(started)?;
    retired_original(f, original_pid, &original_connection, &socket).await?;
    require(
        socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
        "P1 original held read ACK was later forwarded or credited after retirement",
    )?;
    require(
        database_facts(&f.admin).await? == before
            && object_fact(&f.path())? == original_object
            && owned_object_fds(&f.path())?.is_empty(),
        "P1 original uncertain read changed business/object facts or opened an unowned object FD",
    )?;

    // Revoke the actual old issuer only after its original connection has truly
    // retired. Install a fresh real resolver on the SAME Administration/Store.
    f.resolver.close_request_bindings();
    let fresh_resolver = PostgresSessionAuthResolver::new(
        f.pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
    )
    .map_err(|error| error.to_string())?;
    fresh_resolver
        .install_artifact_read_authority(&f.actual.read_authority())
        .map_err(|_| "P1 new genuine Session issuer enrollment failed")?;
    let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("P1 recovery Session binding missing")?.identity()
                .same_binding(f.auth.request_binding().ok_or("P1 original Session binding missing")?.identity()),
                "P1 uncertain read recovery reused the closed owner or changed six Auth facts")?;
            fresh.request_binding().ok_or("P1 new valid Session missing")?.verify_current_before(&fresh,
                Instant::now() + Duration::from_secs(5)).await
                .map_err(|error| format!("P1 new actual Session was not valid independently of Store poison: {error:?}"))?;
            let after_auth = database_facts(&f.admin).await?;
            only_tables_changed(&before, &after_auth, &["public.sessions"])?;
            let mut expected_sessions = before["public.sessions"].as_array().ok_or("P1 original session facts missing")?.clone();
            let fresh_sessions = after_auth["public.sessions"].as_array().ok_or("P1 recovery session facts missing")?;
            require(expected_sessions.len() == fresh_sessions.len(), "P1 recovery changed original Session inventory")?;
            for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
                if old["row"]["id"].as_str() == Some("cleanup-session-b") {
                    old["row"]["updated_at"] = new["row"]["updated_at"].clone();
                    old["xmin"] = new["xmin"].clone();
                    old["ctid"] = new["ctid"].clone();
                }
            }
            require(expected_sessions == *fresh_sessions,
                "P1 recovery changed fields beyond the named new Session idle observation")?;
            let intent = f.actual.arm_explicit_saved_delete_before(&fresh, &f.receipt.artifact_id,
                Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("genuine fresh-owner arm: {error:?}"))?;
            f.verify_one_arm().await?;
            let armed = database_facts(&f.admin).await?;
            original_arm_append_only(&after_auth, &armed)?;
            physical_poison_refuses(f, &fresh, &intent, &original_record).await?;
            require(database_facts(&f.admin).await? == armed && object_fact(&f.path())? == original_object
                && owned_object_fds(&f.path())?.is_empty(),
                "P02 permanent uncertain refusal mutated armed business facts or original object")?;
            drop(intent);
            eprintln!("ARTIFACT_PHYSICAL_P02_ORIGINAL_READ_ROLLBACK_UNKNOWN original_producer_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_host_rollback_forwarded_before_source_begin=true actual_post_schema_source_begin_held_and_released=true complete_original_source_query_lock_wait=true controller_rollback_ack=true original_upstream_read_rollback_ack=true original_forwarded_read_rollback_ack=false original_five_second_error=true original_driver_destroyed=true corresponding_frontend_eof=true original_backend_gone=true original_owner_closed_after_retirement=true new_true_owner_valid=true same_original_store_pair=true byte_grant=false finite_store_ack=false business_object_unchanged=true held_read_rollback_ack_released=false physical_delete=false");
            Ok::<(), String>(())
        }.await;
    fresh_resolver.close_request_bindings();
    recovery
}

struct PhysicalFrameBytesOwner(
    openbot_application::artifact_read_lifecycle::CurrentArtifactReadFrame,
);
impl AsRef<[u8]> for PhysicalFrameBytesOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[tokio::test]
#[ignore = "requires genuine leased frame/Bytes owners and a real original read rollback-ACK loss"]
async fn actual_original_leased_owner_and_query_unproven_block_physical_cleanup() {
    with_fixture("physical-held-original-allocation", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let mut operation = f.application.open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone()).await.map_err(|e| e.to_string())?;
        let pending = operation.next_block(&f.auth).await.map_err(|e| e.to_string())?;
        require(pending.prefix_length().map_err(|e| e.to_string())? == TEXT.len(), "P02 did not obtain the genuine full leased allocation")?;
        let frame = pending.handoff_frame(&f.auth).map_err(|e| e.to_string())?;
        require(frame.as_bytes() == TEXT.as_bytes(), "P02 genuine frame changed saved bytes")?;
        let bytes = axum::body::Bytes::from_owner(PhysicalFrameBytesOwner(frame));
        let held = bytes.clone();
        let sliced = bytes.slice(1..bytes.len());
        drop(bytes);
        let object = object_fact(&f.path())?;
        let original_fds = owned_object_fds(&f.path())?;
        require(original_fds.len() == 1, "P02 original leased owner did not retain its actual object FD")?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object.clone(), 0, false)?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            wait_fact(|| socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
                Instant::now() + Duration::from_secs(2), "P02 physical invocation never obtained its actual original BEGIN ACK").await?;
            let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)), "P02 shared ACK ignored held original Bytes owners")?;
            require(!gate.saw(1) && object_fact(&f.path())? == object && owned_object_fds(&f.path())? == original_fds,
                "P02 worker preflight/unlink preceded actual original allocation/FD drain")?;
            drop(operation);
            drop(held);
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)), "P02 clone Drop ignored a real surviving Bytes slice")?;
            require(!gate.saw(1) && object_fact(&f.path())? == object, "P02 surviving slice allowed physical IO")?;
            drop(sliced);
            drop(barrier);
            Ok::<(), String>(())
        }.await;
        let outcome = task.await.map_err(|e| e.to_string())?;
        controlled?;
        let observed = outcome.map_err(|e| format!("{e:?}"))?;
        require(started.elapsed() < Duration::from_secs(5) && observed.state() == PhysicalState::DurableAbsent,
            "P02 same original invocation did not continue normally after in-budget last-owner release")?;
        gate.after_unlink_is_original_zero_link()?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P02 original invocation changed armed business facts or retained canonical bytes")?;
        drop(observed); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P02_LEASE held_frame_bytes_clone_slice=true held_original_fd=true no_preflight_while_owned=true same_original_invocation_continued=true original_query_excluded_old_read_inventory=true original_post_io_rollback_ack=true actual_original_fd_closed=true no_refund=true");
        Ok(())
    })).await;
    with_fixture("physical-old-read-query-unproven", true, |f| {
        Box::pin(physical_genuine_original_read_ack_loss(f))
    })
    .await;
}

#[tokio::test]
#[ignore = "requires actual original preflight FD and controlled leaf/fixed-child replacement"]
async fn actual_foreign_store_or_preflight_replaced_object_refuses_cleanup_without_unlink() {
    with_fixture("physical-foreign-original-store", true, |f| Box::pin(async move {
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let foreign_root = OwnedRoot::new()?;
        let foreign_store = Arc::new(DatasetBoundArtifactStore::bind_host_root(
            std::fs::File::open(&foreign_root.0).map_err(|e| e.to_string())?, f.registry.clone(), ArtifactQuotaPolicy::default()).await.map_err(|e| e.to_string())?);
        let foreign = Arc::new(PostgresArtifactAdministration::new(f.registry.clone(), foreign_store,
            ArtifactQuotaPolicy::default(), SecretBytes::new(vec![0x18; 32])).map_err(|e| e.to_string())?);
        let original = object_fact(&f.path())?;
        let gate = install_physical_gate(f, original.clone(), 0, false)?;
        let before = database_facts(&f.admin).await?;
        require(matches!(foreign.remove_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await, Err(PhysicalError::Conflict)),
            "foreign Store accepted original mechanical intent or refused only after fake Host IO")?;
        require(!gate.saw(1) && !gate.saw(2) && !gate.saw(3) && !gate.saw(4), "foreign mechanical intent started the original worker")?;
        require(database_facts(&f.admin).await? == before && object_fact(&f.path())? == original && owned_object_fds(&f.path())?.is_empty(),
            "foreign Store refusal changed original business/object facts")?;
        drop(foreign); drop(foreign_root); drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P03_FOREIGN original_store_identity_mismatch=true mechanical_conflict=true worker_not_started=true zero_unlink=true business_original_object_unchanged=true");
        Ok(())
    })).await;
    for kind in [0_u8, 1, 2] {
        let tag = match kind {
            0 => "physical-preflight-leaf-replaced",
            1 => "physical-preflight-objects-replaced",
            _ => "physical-preflight-staging-symlink",
        };
        with_fixture(tag, true, move |f| Box::pin(async move {
            let original = object_fact(&f.path())?;
            let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
            let before = database_facts(&f.admin).await?;
            let gate = install_physical_gate(f, original.clone(), 2, false)?;
            let release = PhysicalGateRelease(gate.clone());
            let (pid, _, socket) = f.original().await?;
            clear_transaction_facts(&socket);
            let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
            let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth,
                &original_intent, Instant::now() + Duration::from_secs(5)).await });
            let controlled = async {
                gate.wait(2, Instant::now() + Duration::from_secs(2)).await?;
                require(gate.saw(1) && !gate.saw(3), "drift controller did not run after actual full preflight and before unlink")?;
                let kept;
                let replaced;
                if kind == 0 {
                    kept = f.root.0.join("controller-original-retained-object");
                    std::fs::rename(f.path(), &kept).map_err(|e| e.to_string())?;
                    std::fs::write(f.path(), TEXT.as_bytes()).map_err(|e| e.to_string())?;
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
                    replaced = object_fact(&f.path())?;
                    require(replaced.ino != original.ino && replaced.sha256 == original.sha256 && object_fact(&kept)? == original,
                        "preflight leaf replacement was not a distinct actual inode with original retained")?;
                } else if kind == 1 {
                    kept = f.root.0.join("controller-original-objects");
                    std::fs::rename(f.root.0.join("objects"), &kept).map_err(|e| e.to_string())?;
                    std::fs::DirBuilder::new().mode(0o700).create(f.root.0.join("objects")).map_err(|e| e.to_string())?;
                    std::fs::write(f.path(), TEXT.as_bytes()).map_err(|e| e.to_string())?;
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
                    replaced = object_fact(&f.path())?;
                    require(replaced.ino != original.ino && replaced.sha256 == original.sha256
                        && object_fact(&kept.join(&f.receipt.artifact_id))? == original,
                        "fixed objects child replacement did not preserve original and distinct replacement inodes")?;
                } else {
                    kept = f.root.0.join("controller-original-staging");
                    std::fs::rename(f.root.0.join("staging"), &kept).map_err(|e| e.to_string())?;
                    std::os::unix::fs::symlink(&kept, f.root.0.join("staging")).map_err(|e| e.to_string())?;
                    require(std::fs::symlink_metadata(f.root.0.join("staging")).map_err(|e| e.to_string())?.file_type().is_symlink(),
                        "fixed staging child was not an actual NOFOLLOW symlink counterexample")?;
                    replaced = object_fact(&f.path())?;
                }
                Ok::<(PathBuf, ObjectFact), String>((kept, replaced))
            }.await;
            drop(release);
            let result = task.await.map_err(|e| e.to_string())?;
            let (kept, replacement) = controlled?;
            require(matches!(result, Err(PhysicalError::Corrupt { field: "object" | "store_binding" })),
                "actual preflight leaf/fixed-child drift gained unlink or a normal observation")?;
            physical_original_fd_closed(&gate).await?;
            physical_normal_original_ack(f, pid, &socket).await?;
            require(!gate.saw(3) && object_fact(&f.path())? == replacement && database_facts(&f.admin).await? == before,
                "drift refusal unlinked replacement or mutated original armed business facts")?;
            if kind == 0 { require(object_fact(&kept)? == original, "leaf drift refusal damaged retained original")?; }
            if kind == 1 { require(object_fact(&kept.join(&f.receipt.artifact_id))? == original, "child drift refusal damaged original held directory object")?; }
            if kind == 2 { require(object_fact(&f.path())? == original, "staging NOFOLLOW refusal damaged original object")?; }
            if kind != 0 {
                let original_child = std::fs::symlink_metadata(&kept).map_err(|e| e.to_string())?;
                require(original_child.is_dir(), "fixed-child controller lost the original retained directory")?;
                let device = original_child.dev(); let inode = original_child.ino();
                let held_directory = tokio::task::spawn_blocking(move || physical_inode_fds_for(device, inode)).await.map_err(|e| e.to_string())??;
                require(!held_directory.is_empty(), "still-live original Store lost its actual held root-child FD identity")?;
            }
            drop(intent);
            eprintln!("ARTIFACT_PHYSICAL_P03_DRIFT kind={kind} original_preflight_fd_fullsha=true distinct_controller_replacement=true zero_unlink=true original_leaf_fd_closed=true held_store_directory_inventory_not_claimed_zero=true original_query_rollback_ack=true business_unchanged=true");
            Ok(())
        })).await;
    }
}

async fn physical_schema_wait(f: &Fixture, pid: i32, controller_pid: i32) -> Result<(), String> {
    wait_blocked(
        &f.admin,
        pid,
        "openbot_internal.schema_migrations",
        controller_pid,
    )
    .await?;
    let observer = f.admin.get().await.map_err(|e| e.to_string())?;
    let row = observer.query_one("SELECT pg_backend_pid() AS observer_pid,query,wait_event_type,pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1", &[&pid]).await.map_err(|e| e.to_string())?;
    let observer_pid: i32 = row.get("observer_pid");
    require(
        observer_pid != pid
            && observer_pid != controller_pid
            && pid != controller_pid
            && row.get::<_, Option<String>>("wait_event_type").as_deref() == Some("Lock")
            && row.get::<_, Vec<i32>>("blockers").contains(&controller_pid)
            && row
                .get::<_, String>("query")
                .contains("SELECT version,name,checksum FROM openbot_internal.schema_migrations"),
        "original physical schema waiter did not have a unique actual producer/controller/observer",
    )
}
async fn physical_connection_check_interval(f: &Fixture) -> Result<(), String> {
    let c = f.pool.get().await.map_err(|e| e.to_string())?;
    c.batch_execute("SET client_connection_check_interval='10ms'")
        .await
        .map_err(|e| e.to_string())?;
    let setting: String = c
        .query_one(
            "SELECT current_setting('client_connection_check_interval')",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        setting == "10ms",
        "owned connection did not enable actual finite server-side disappearance checks",
    )
}

#[tokio::test]
#[ignore = "requires actual unlink, caller-only cancel, original expiry and main-runtime owner Drop"]
async fn actual_original_physical_worker_cancel_and_expiry_keep_armed_charge_without_relabelling_effects()
 {
    with_fixture("physical-caller-wait-only-cancel", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()
        }.await;
        // This JoinHandle owns only the public caller waiter, not the implementation's
        // independently owned main/query supervisor. Actual cancellation is reaped.
        task.abort();
        let joined = task.await;
        drop(release);
        controlled?;
        require(joined.is_err_and(|e| e.is_cancelled()), "P04-A original caller waiter was not actually cancelled and reaped")?;
        physical_original_fd_closed(&gate).await?;
        wait_fact(|| socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0,
            started + Duration::from_secs(5), "P04-A retained original supervisor did not forward its real in-budget ROLLBACK ACK").await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(database_facts(&f.admin).await? == armed && physical_absent(&f.path()), "P04-A waiter cancellation relabelled true unlink or changed charge/fence")?;
        let observed = f.actual.observe_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("P04-A new acknowledged reobservation: {e:?}"))?;
        require(observed.state() == PhysicalState::DurableAbsent, "P04-A new observe did not independently prove actual double absence")?;
        require(database_facts(&f.admin).await? == armed && gate.facts.lock().map_err(|_| "P04-A observer poisoned")?.seen[2] == 1, "P04-A reobservation repeated unlink or changed armed facts")?;
        gate.check()?;
        let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(2)).await.map_err(|e| format!("{e:?}"))?;
        drop(ack); drop(barrier); drop(observed); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_A original_waiter_cancelled_reaped=true original_unlink_effect_kept=true original_main_supervisor_retained=true original_on_time_rollback_ack=true actual_original_fd_closed=true later_new_observe_only_durable_absent=true original_waiter_not_relabelled=true no_poison_clear=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-original-post-unlink-expiry", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()
        }.await;
        let result = task.await.map_err(|e| e.to_string())?;
        drop(release); controlled?;
        require(result.is_err(), "P04-B expired original invocation produced a normal physical witness")?;
        original_five_seconds(started)?;
        physical_original_fd_closed(&gate).await?;
        retired_original(f, pid, &connection, &socket).await?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P04-B late resource end erased actual unlink or changed original armed facts")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_B actual_unlink_before_expiry=true original_fd_nlink_zero=true original_five_second_fail=true late_worker_fd_closed=true original_driver_backend_gone=true permanent_same_store_poison=true no_normal_reobservation=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-main-runtime-owner-drop", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object.clone(), 0, false)?;
        physical_connection_check_interval(f).await?;
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        tx.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|e| e.to_string())?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let original = runtime.spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth,
            &original_intent, Instant::now() + Duration::from_secs(5)).await });
        let controlled = physical_schema_wait(f, pid, controller_pid).await;
        // Normal Drop of THIS fixture-owned runtime destroys the actual main supervisor,
        // while the external original Store/Pool/Host and its driver remain owned here.
        tokio::task::spawn_blocking(move || drop(runtime)).await.map_err(|e| e.to_string())?;
        let joined = original.await;
        let controller_ack = tx.rollback().await.map_err(|e| e.to_string()); drop(controller);
        controlled?; controller_ack?;
        require(joined.is_err_and(|e| e.is_cancelled()), "P04-C actual runtime-owner Drop did not destroy and reap the original task")?;
        retired_original(f, pid, &connection, &socket).await?;
        require(!gate.saw(1) && !gate.saw(3) && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0,
            "P04-C main owner Drop was mistaken for an original ACK or physical worker")?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(database_facts(&f.admin).await? == armed && object_fact(&f.path())? == object && owned_object_fds(&f.path())?.is_empty(),
            "P04-C genuine main owner retirement changed rows/object or retained original leaf FD")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_C actual_original_schema_lock_pid=true actual_main_runtime_owner_dropped=true original_task_cancelled_reaped=true original_query_ack=false original_driver_backend_gone=true permanent_same_store_poison=true zero_unlink=true charge_fence_unchanged=true");
        Ok(())
    })).await;
}

fn physical_session_b_idle_only(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<(), String> {
    only_tables_changed(before, after, &["public.sessions"])?;
    let mut expected = before["public.sessions"]
        .as_array()
        .ok_or("physical original Session facts missing")?
        .clone();
    let actual = after["public.sessions"]
        .as_array()
        .ok_or("physical fresh Session facts missing")?;
    require(
        expected.len() == actual.len(),
        "physical Session observation changed row inventory",
    )?;
    for (old, new) in expected.iter_mut().zip(actual) {
        if old["row"]["id"].as_str() == Some("cleanup-session-b") {
            old["row"]["updated_at"] = new["row"]["updated_at"].clone();
            old["xmin"] = new["xmin"].clone();
            old["ctid"] = new["ctid"].clone();
        }
    }
    require(
        expected == *actual,
        "physical current Session changed more than original B idle touch",
    )
}

#[tokio::test]
#[ignore = "requires actual absent names, original current refusal/unknown and post-IO rollback-ACK loss"]
async fn actual_already_absent_armed_pair_requires_current_authority_and_acknowledged_reobservation()
 {
    with_fixture("physical-original-already-absent", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let armed = database_facts(&f.admin).await?;
        std::fs::remove_file(f.path()).map_err(|e| e.to_string())?;
        require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
            "P05-A controlled fixture names were not actually absent")?;
        let gate = install_physical_gate(f, original, 0, true)?;
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let observed = f.actual.observe_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        require(observed.state() == PhysicalState::DurableAbsent && !gate.saw(2) && !gate.saw(3),
            "P05-A ordinary absence falsely reported a retained leaf or performed unlink")?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(database_facts(&f.admin).await? == armed, "P05-A actual observe mutated original charge/receipt/fence/audit")?;
        drop(observed); drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P05_A both_names_actually_absent_before_call=true new_current_original_query=true guarded_three_directory_sync=true original_worker_ended=true original_rollback_ack=true zero_unlink=true durable_absent=true no_refund=true");
        Ok(())
    })).await;
    with_fixture("physical-pregrant-known-session-refusal", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original.clone(), 1, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent,
            started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(1, Instant::now() + Duration::from_secs(2)).await?;
            let mut c = f.admin.get().await.map_err(|e| e.to_string())?;
            let tx = c.transaction().await.map_err(|e| e.to_string())?;
            let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            require(controller_pid != pid && tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await.map_err(|e| e.to_string())? == 1,
                "P05-B-known did not revoke the actual original Session row independently")?;
            tx.commit().await.map_err(|e| e.to_string())?;
            let changed = database_facts(&f.admin).await?;
            only_tables_changed(&armed, &changed, &["public.sessions"])?;
            controller_removed_row(&armed, &changed, "public.sessions", "id", A_ID)?;
            Ok::<BTreeMap<String, Value>, String>(changed)
        }.await;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        let revoked = controlled?;
        require(matches!(result, Err(PhysicalError::Host(HostRequestBindingError::NotCurrent))) && started.elapsed() < Duration::from_secs(5),
            "P05-B-known current committed Session refusal was not definite original HostNotCurrent")?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(!gate.saw(2) && !gate.saw(3) && object_fact(&f.path())? == original && database_facts(&f.admin).await? == revoked,
            "P05-B-known rejection started unlink or changed rows beyond the actual Session controller")?;
        f.resolver.close_request_bindings();
        let fresh_resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY, default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT)).map_err(|e| e.to_string())?;
        fresh_resolver.install_artifact_read_authority(&f.actual.read_authority()).map_err(|_| "P05-B-known fresh issuer enrollment failed")?;
        let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("fresh Session missing")?.identity().same_binding(f.auth.request_binding().ok_or("original Session missing")?.identity()),
                "P05-B-known reobservation reused the revoked original Host")?;
            fresh.request_binding().ok_or("fresh Session missing")?.verify_current_before(&fresh, Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
            let touched = database_facts(&f.admin).await?; physical_session_b_idle_only(&revoked, &touched)?;
            let observed = f.actual.observe_armed_explicit_saved_bytes_before(&fresh, &intent, Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("known ACK must not invent poison: {e:?}"))?;
            require(observed.state() == PhysicalState::Retained && !gate.saw(3) && object_fact(&f.path())? == original
                && database_facts(&f.admin).await? == touched, "P05-B-known normal new observation changed bytes/business or retained false poison")?;
            physical_original_fd_closed(&gate).await?; gate.check()?;
            drop(observed);
            Ok::<(), String>(())
        }.await;
        fresh_resolver.close_request_bindings(); recovery?;
        drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P05_B_KNOWN preflight_original_fd=true actual_session_controller_commit=true original_current_host_refusal=true original_on_time_rollback_ack=true actual_original_fd_closed=true zero_unlink=true new_true_session_retained_observation=true unknown_not_inferred_from_error=true no_poison_clear=true");
        Ok(())
    })).await;
    with_fixture("physical-pregrant-original-schema-unknown", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original.clone(), 0, false)?;
        physical_connection_check_interval(f).await?;
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        tx.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = physical_schema_wait(f, pid, controller_pid).await;
        let result = task.await.map_err(|e| e.to_string())?;
        let controller_ack = tx.rollback().await.map_err(|e| e.to_string()); drop(controller);
        controlled?; controller_ack?;
        require(result.is_err(), "P05-B-unknown original schema timeout produced a normal observation")?;
        original_five_seconds(started)?;
        retired_original(f, pid, &connection, &socket).await?;
        require(!gate.saw(1) && !gate.saw(3) && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0,
            "P05-B-unknown timeout fabricated worker effects or an original query ACK")?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(object_fact(&f.path())? == original && database_facts(&f.admin).await? == armed && owned_object_fds(&f.path())?.is_empty(),
            "P05-B-unknown retirement changed original object/business facts")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P05_B_UNKNOWN actual_original_schema_lock=true original_five_second_error=true original_query_ack=false original_driver_backend_gone=true permanent_same_store_poison=true zero_worker_unlink=true later_resources_not_normal_ack=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-post-io-original-rollback-ack-loss", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()?;
            require(socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
                "P05-C held IO did not belong to this original acknowledged BEGIN")?;
            f.relay.as_ref().ok_or("P05-C original relay missing")?.arm(Hold::Rollback);
            Ok::<(), String>(())
        }.await;
        drop(release);
        let held = async {
            controlled?;
            gate.wait(4, Instant::now() + Duration::from_secs(2)).await?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2), "P05-C actual post-IO original rollback ACK was not withheld").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0 && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0 && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P05-C uncertainty was not this original physical query's upstream rollback ACK")?;
            physical_original_fd_closed(&gate).await?;
            require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
                "P05-C lost ACK preceded actual physical unlink/sync/double absence")?;
            Ok::<(), String>(())
        }.await;
        let result = task.await.map_err(|e| e.to_string())?;
        held?;
        require(result.is_err(), "P05-C missing original rollback ACK produced a normal physical witness")?;
        original_five_seconds(started)?;
        retired_original(f, pid, &connection, &socket).await?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0 && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0 && physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P05-C late retirement/observation laundered original missing ACK or true physical effects")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P05_C actual_io_worker_ended_before_ack_loss=true actual_original_fd_closed=true both_names_absent=true original_upstream_rollback_ack=true forwarded_original_ack=false original_driver_backend_gone=true permanent_same_store_poison=true physical_effects_kept=true normal_witness=false refund=false");
        Ok(())
    })).await;
}
