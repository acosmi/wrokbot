//! Real owned-PG/Begin/Save/FD tests through the new CORE consumer.
//! The Session host issuer below is a test seam; real Server/Desktop acceptance is separate.
//! Static phases and gate ACK are not substitutes for actual PG Lock/PID/COMMIT evidence.

use std::fs::{self, File, OpenOptions, Permissions};
use std::future::Future;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use openbot_application::ArtifactAdministration;
use openbot_application::{BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{ArtifactGoneStatus, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingGuard, RequestBindingIssuer, RequestBindingOwnerLease,
    ServerSessionBindingIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::SecretBytes;
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::artifact_bytes::{ArtifactByteError, MAX_ARTIFACT_READ_CHUNK_BYTES};
use crate::artifact_store::{ArtifactReadBridgeError, StoreBoundArtifactReader};
use crate::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore,
};
use crate::db::pool::DatabaseConfig;
use crate::db::{baseline, native, pool};
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

mod harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}

const DEPLOYMENT: &str = "artifact-read-owned-deployment";
const TENANT: &str = "artifact-read-owned-tenant";
const OWNER: &str = "read-owner";
const OTHER: &str = "read-other";
const EXACT: &str = "  PRIVATE_READ_SOURCE_CANARY\n成果 café 🦀\t  ";

fn require(ok: bool, message: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-read-bridge-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self(fs::canonicalize(path).map_err(|e| e.to_string())?))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_READ_BRIDGE_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned read-root cleanup failed");
        }
    }
}

struct Fixture {
    pool: Pool,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    administration: Arc<PostgresArtifactAdministration>,
    _lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    created: OffsetDateTime,
    begin: BeginThreadRunRequest,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, channel: bool) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation,groups) VALUES
              ('read-owner','read-owner@example.test',0,ARRAY['read-fixture']),
              ('read-other','read-other@example.test',0,ARRAY['read-fixture']);
              INSERT INTO public.user_roles(user_id,role) VALUES('read-owner','user'),('read-other','admin');
              INSERT INTO public.agents(id,name,type,configuration) VALUES('read-bot','Read fixture','built_in','{}');
              INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('read-bot','read-owner','Read fixture','fixture','fixture','public');
              INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000051','artifact-read-owned-tenant','fixture','fixture');
              INSERT INTO public.channels(id,name,description,allowed_groups)
                VALUES('read-channel','Read fixture','fixture',ARRAY['read-fixture']);
              INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner'),('read-channel','read-other');
              INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot');")
                .await.map_err(|e| e.to_string())?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment,
            tenant,
            actor: ActorId::new(OWNER),
            command: BeginThreadRun {
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT))
                    .mint_from_entropy([9; 16]),
                run_id: RunId::new("read/source%成果"),
                bot_id: BotId::new("read-bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("read-channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: EXACT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "read-bridge-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|e| e.to_string())?,
                Arc::clone(&registry),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                Arc::clone(&registry),
                Arc::clone(&store),
                policy,
                SecretBytes::new(vec![0x83; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let created = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let expires = created + time::Duration::hours(1);
        pool.get().await.map_err(|e| e.to_string())?.execute(
            "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,$3,$4,$4,$5,0),($6,$2,$7,$4,$4,$5,0)",
            &[&"core-read-session-a", &OWNER, &"owned-test-session-column-a", &created, &expires, &"core-read-session-b", &"owned-test-session-column-b"],
        ).await.map_err(|e| e.to_string())?;
        // PostgreSQL stores microseconds. The immutable epoch is copied from the actual row,
        // rather than comparing a pre-insert nanosecond clock value against that row.
        let created: OffsetDateTime = pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT created_at FROM public.sessions WHERE id='core-read-session-a'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let (_lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        administration.read_authority();
        Ok(Self {
            pool,
            registry,
            store,
            administration,
            _lease,
            issuer,
            created,
            begin,
            root,
        })
    }

    fn auth_as(&self, actor: &str, generation: u64) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            ActorId::new(actor),
            AuthGeneration::new(generation),
            false,
        )
        .with_role(if actor == OTHER {
            Role::Admin
        } else {
            Role::User
        })
        .build()
    }
    fn auth(&self) -> AuthContext {
        self.session_auth("core-read-session-a", "owned-test-session-column-a")
    }
    fn session_auth(&self, id: &str, token: &str) -> AuthContext {
        let auth = self.auth_as(OWNER, 0);
        let guard = CoreSessionGuard {
            issuer: self.issuer.clone(),
            authority: Arc::downgrade(&self.administration.read_authority()),
            lifetime: lifetime(),
        };
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            id.into(),
            auth.actor().clone(),
            token.into(),
            self.created,
            auth.auth_generation(),
        );
        let binding = self
            .issuer
            .bind_server_session(&auth, epoch, Arc::new(guard))
            .expect("owned real-row epoch");
        auth.with_verified_request_binding(binding)
            .expect("owned attachment")
    }
    fn message_id(&self) -> String {
        format!("{}:input", self.begin.command.run_id.as_str())
    }
    async fn save(&self) -> Result<ArtifactRegistrationReceipt, String> {
        self.administration
            .save_run_message_text(
                &self.auth(),
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: self.message_id(),
                    expected_sha256: Sha256Digest::of(EXACT.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|e| e.to_string())
    }
    async fn observe(
        &self,
        id: &str,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        self.administration
            .observe_read_record(&self.auth(), id)
            .await
    }
    fn object(&self, id: &str) -> PathBuf {
        self.root.0.join("objects").join(id)
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|e| e.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
              'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
              'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))", &[])
            .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())
    }
    async fn reader(&self, id: &str) -> Result<StoreBoundArtifactReader, String> {
        let record = self.observe(id).await.map_err(|e| e.to_string())?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.open_observed_record(record))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
    async fn read_all(&self, id: &str) -> Result<Vec<u8>, String> {
        let mut reader = self.reader(id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            let mut chunk = [0; 11];
            loop {
                let n = reader
                    .read_observed_chunk(&mut chunk)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

async fn with_fixture<F, Fut>(tag: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, channel).await?).await
    })
    .await;
}

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        time::Duration::minutes(30),
        time::Duration::hours(1),
        time::Duration::seconds(1),
    )
    .unwrap()
}
struct CoreSessionGuard {
    issuer: RequestBindingIssuer,
    authority: Weak<PostgresArtifactReadAuthority>,
    lifetime: SessionLifetimePolicy,
}
impl HostRequestBindingGuard for CoreSessionGuard {
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            let authority = self
                .authority
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let administration = authority
                .administration
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let identity = auth
                .request_binding()
                .ok_or(HostRequestBindingError::Missing)?
                .identity();
            let epoch = self.issuer.borrow_server_session_epoch(identity)?;
            let client = administration
                .registry
                .pool()
                .get()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = client.query_one(
                "SELECT u.id AS read_host_user,u.auth_generation AS read_host_generation, \
                  u.email AS read_host_email,EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked, \
                  ARRAY(SELECT role::text FROM public.user_roles WHERE user_id=u.id ORDER BY role::text) AS read_host_roles, \
                  s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token, \
                  s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,s.auth_generation AS read_session_generation \
                 FROM (SELECT 1) a LEFT JOIN public.users u ON u.id=$1 LEFT JOIN public.sessions s ON s.id=$2 AND s.user_id=u.id",
                &[&auth.actor().as_str(), &epoch.lookup_id()],
            ).await.map_err(|_| HostRequestBindingError::Unavailable)?;
            let result = decode_host(
                &administration,
                auth,
                &row,
                &CurrentHost::Session {
                    epoch,
                    lifetime: self.lifetime,
                },
            );
            match result {
                Ok(tail) => tail
                    .verify_current(auth, Instant::now() + Duration::from_secs(5))
                    .map_err(|error| match error {
                        ArtifactReadCurrentError::Host(error) => error,
                        _ => HostRequestBindingError::Unavailable,
                    }),
                Err(ArtifactReadCurrentError::Host(error)) => Err(error),
                Err(_) => Err(HostRequestBindingError::Unavailable),
            }
        })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let authority = self.authority.upgrade().ok_or_else(host_unavailable)?;
            let identity = auth
                .request_binding()
                .ok_or_else(host_unavailable)?
                .identity();
            let epoch = self
                .issuer
                .borrow_server_session_epoch(identity)
                .map_err(ArtifactReadCurrentError::Host)?;
            authority
                .observe_server_session(auth, target, epoch, self.lifetime, deadline)
                .await
        })
    }
}

#[test]
fn joint_sql_keeps_original_source_cte_and_host_anchor() {
    for desktop in [false, true] {
        let sql = current_read_sql(desktop);
        assert!(
            sql.strip_prefix("/* artifact_current_host_joint_read_after_io */ ")
                .unwrap()
                .starts_with(crate::thread_directory::reconciliation_visibility::VISIBLE_RUN)
        );
        assert!(
            sql.contains(
                super::super::observed_read_sql()
                    .strip_prefix(crate::thread_directory::reconciliation_visibility::VISIBLE_RUN)
                    .unwrap()
            )
        );
        assert!(sql.contains("FROM (SELECT 1) anchor LEFT JOIN public.users"));
        assert!(sql.contains("LEFT JOIN current_artifact a ON true"));
        assert!(sql.contains("u.auth_generation AS read_host_generation"));
        assert!(!sql.contains("coalesce(u.auth_generation,0) AS read_host_generation"));
        assert!(sql.contains("artifact_current_host_joint_read_after_io"));
        assert_eq!(sql.contains("pg_control_system()"), desktop);
    }
}

struct CarrierGuard;
impl HostRequestBindingGuard for CarrierGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn carrier_auth() -> (RequestBindingOwnerLease, AuthContext) {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(OWNER),
        AuthGeneration::new(0),
        false,
    )
    .with_role(Role::User)
    .build();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "clock-seam".into(),
        auth.actor().clone(),
        "clock-test-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(CarrierGuard))
        .unwrap();
    (lease, auth.with_verified_request_binding(binding).unwrap())
}

#[test]
fn current_tail_rejects_expiry_clock_reversal_and_binding_swap() {
    let (_a_lease, auth) = carrier_auth();
    let (_b_lease, other_binding) = carrier_auth();
    let now = OffsetDateTime::now_utc();
    let mut tail = CurrentReadTail {
        auth: auth.clone(),
        identity: auth.request_binding().unwrap().identity().clone(),
        observed_wall: now,
        observed_monotonic: Instant::now(),
        session: Some((
            now - time::Duration::seconds(2),
            now - time::Duration::seconds(1),
            now + time::Duration::hours(1),
            lifetime(),
        )),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(tail.verify_current(&auth, deadline), Ok(()));
    assert_eq!(
        tail.verify_current(&other_binding, deadline),
        Err(host_not_current())
    );
    tail.observed_wall = now + time::Duration::hours(1);
    assert_eq!(
        tail.verify_current(&auth, deadline),
        Err(host_not_current())
    );
    tail.observed_wall = now;
    tail.session.as_mut().unwrap().2 = now - time::Duration::seconds(1);
    assert_eq!(
        tail.verify_current(&auth, deadline),
        Err(host_not_current())
    );
    assert_eq!(
        tail.verify_current(&auth, Instant::now()),
        Err(host_unavailable())
    );
}

async fn wait_final_lock(pool: &Pool, blocker: i32) -> Result<i32, String> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let client = pool.get().await.map_err(|e| e.to_string())?;
            let rows = client.query("SELECT pid,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event_type='Lock' AND query LIKE '%artifact_current_host_joint_read_after_io%' AND pid<>pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?;
            for row in rows {
                let blockers: Vec<i32> = row.get("blockers");
                if blockers.contains(&blocker) { return Ok(row.get("pid")); }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| "actual final statement Lock/PID was not observed".to_owned())?
}

async fn start_after_io(
    f: &Fixture,
    id: &str,
) -> Result<
    (
        tokio::task::JoinHandle<Result<CurrentArtifactReadChunk, AppError>>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    String,
> {
    let (reached, acknowledged) = tokio::sync::oneshot::channel();
    let (proceed, release) = tokio::sync::oneshot::channel();
    let authority = f.administration.read_authority();
    *authority
        .final_query_gate
        .lock()
        .map_err(|_| "gate poisoned".to_owned())? = Some((reached, release));
    let administration = Arc::clone(&f.administration);
    let auth = f.auth();
    let id = id.to_owned();
    let worker =
        tokio::spawn(async move { administration.read_host_bound_chunk(&auth, &id).await });
    Ok((worker, acknowledged, proceed))
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_current_read_and_sync_fd_tail() {
    with_fixture("arc_positive", false, |f| async move {
        let saved = f.save().await?;
        let before = f.facts().await?;
        let authority = f.administration.read_authority();
        require(
            authority.matches_pool_scope(
                &f.pool,
                &DeploymentId::new(DEPLOYMENT),
                &TenantId::new(TENANT),
            ),
            "actual pool enrollment refused",
        )?;
        require(
            Arc::ptr_eq(&f.registry, &f.administration.registry),
            "registry owner changed",
        )?;
        let auth = f.auth();
        let chunk = f
            .administration
            .read_host_bound_chunk(&auth, &saved.artifact_id)
            .await
            .map_err(|e| e.to_string())?;
        require(
            chunk.handoff(&auth).map_err(|e| e.to_string())? == EXACT.as_bytes(),
            "real first-chunk bytes differed",
        )?;
        require(
            f.read_all(&saved.artifact_id).await? == EXACT.as_bytes(),
            "retained original snapshot differed",
        )?;
        let mut reader = f.reader(&saved.artifact_id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES];
            let length = reader
                .read_observed_chunk(&mut bytes)
                .map_err(|e| e.to_string())?;
            require(
                length == EXACT.len() && &bytes[..length] == EXACT.as_bytes(),
                "real full-capacity reader refused first chunk",
            )?;
            let mut oversized = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES + 1];
            require(
                matches!(
                    reader.read_observed_chunk(&mut oversized),
                    Err(ArtifactReadBridgeError::Bytes(
                        ArtifactByteError::InvalidChunk
                    ))
                ) && oversized.iter().all(|byte| *byte == 0),
                "actual >4MiB buffer was not refused and wholly wiped",
            )
        })
        .await
        .map_err(|e| e.to_string())??;
        require(
            f.facts().await? == before,
            "read mutated registration, quotas, audit or receipts",
        )?;
        let chunk = f
            .administration
            .read_host_bound_chunk(&auth, &saved.artifact_id)
            .await
            .map_err(|e| e.to_string())?;
        let mut object = OpenOptions::new()
            .append(true)
            .open(f.object(&saved.artifact_id))
            .map_err(|e| e.to_string())?;
        object.write_all(b"changed").map_err(|e| e.to_string())?;
        object.sync_all().map_err(|e| e.to_string())?;
        require(
            matches!(
                chunk.handoff(&auth),
                Err(AppError::DependencyUnavailable {
                    dependency: "artifacts"
                })
            ),
            "original FD drift survived sync handoff",
        )
    })
    .await;
}

#[derive(Clone, Copy)]
enum SourceMutation {
    DirectMembership,
    ThreadTenant,
    ProfileVisibility,
    ChannelMembership,
    ChannelAssignment,
    PackageTenant,
    MessageRole,
    MessageActor,
    MessageRun,
    MessageDelete,
    OperationPayload,
    DatasetTuple,
    StoreTuple,
    OriginalFd,
    RootMode,
    Marker,
}
impl SourceMutation {
    fn identity(self) -> &'static str {
        match self {
            Self::DirectMembership => "direct_membership",
            Self::ThreadTenant => "thread_tenant",
            Self::ProfileVisibility => "profile_visibility",
            Self::ChannelMembership => "channel_membership",
            Self::ChannelAssignment => "channel_assignment",
            Self::PackageTenant => "package_tenant",
            Self::MessageRole => "message_role",
            Self::MessageActor => "message_actor",
            Self::MessageRun => "message_run",
            Self::MessageDelete => "message_delete",
            Self::OperationPayload => "operation_payload",
            Self::DatasetTuple => "dataset_tuple",
            Self::StoreTuple => "store_tuple",
            Self::OriginalFd => "original_fd",
            Self::RootMode => "root_mode",
            Self::Marker => "marker",
        }
    }
    fn channel(self) -> bool {
        matches!(
            self,
            Self::ChannelMembership | Self::ChannelAssignment | Self::PackageTenant
        )
    }
    fn lock_sql(self) -> &'static str {
        match self {
            Self::OperationPayload => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_save_operations IN ACCESS EXCLUSIVE MODE"
            }
            Self::DatasetTuple => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_dataset_bindings IN ACCESS EXCLUSIVE MODE"
            }
            Self::StoreTuple => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_store_bindings IN ACCESS EXCLUSIVE MODE"
            }
            _ => "LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE",
        }
    }
    async fn apply(self, f: &Fixture, tx: &tokio_postgres::Transaction<'_>) -> Result<(), String> {
        match self {
            Self::DirectMembership => tx.batch_execute("DELETE FROM public.thread_memberships WHERE user_id='read-owner'").await.map_err(|e| e.to_string()),
            Self::ThreadTenant => tx.batch_execute("UPDATE public.threads SET tenant_id='foreign'").await.map_err(|e| e.to_string()),
            Self::ProfileVisibility => tx.batch_execute("UPDATE public.agent_profiles SET visibility='private',owner_user_id='read-other'").await.map_err(|e| e.to_string()),
            Self::ChannelMembership => tx.batch_execute("DELETE FROM public.channel_memberships WHERE user_id='read-owner'").await.map_err(|e| e.to_string()),
            Self::ChannelAssignment => tx.batch_execute("DELETE FROM public.channel_agents WHERE channel_id='read-channel'").await.map_err(|e| e.to_string()),
            Self::PackageTenant => tx.batch_execute("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000051'; UPDATE public.deployment_packages SET tenant_id='foreign'").await.map_err(|e| e.to_string()),
            Self::MessageRole => tx.batch_execute("UPDATE public.messages SET role='assistant'").await.map_err(|e| e.to_string()),
            Self::MessageActor => tx.batch_execute("UPDATE public.messages SET actor_id='read-other'").await.map_err(|e| e.to_string()),
            Self::MessageRun => tx.batch_execute("UPDATE public.messages SET run_id='another-run'").await.map_err(|e| e.to_string()),
            Self::MessageDelete => tx.batch_execute("DELETE FROM public.messages").await.map_err(|e| e.to_string()),
            // Closed corruption controls only in this disposable DB. Restore the registered
            // trigger in the same transaction before the real controller COMMIT ACK.
            Self::OperationPayload => tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET actual_sha256=repeat('0',64); ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e| e.to_string()),
            Self::DatasetTuple => tx.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only; UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary'; ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e| e.to_string()),
            Self::StoreTuple => tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only; UPDATE openbot_internal.artifact_store_bindings SET root_inode='0'; ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e| e.to_string()),
            Self::OriginalFd => {
                let object = OpenOptions::new().write(true).open(f.object(&f.saved_id().await?)).map_err(|e| e.to_string())?;
                let inode = object.metadata().map_err(|e| e.to_string())?.ino();
                object.set_len(1).map_err(|e| e.to_string())?;
                object.sync_all().map_err(|e| e.to_string())?;
                require(object.metadata().map_err(|e| e.to_string())?.ino() == inode, "FD mutation replaced inode instead of touching retained FD")
            }
            Self::RootMode => fs::set_permissions(&f.root.0, Permissions::from_mode(0o755)).map_err(|e| e.to_string()),
            Self::Marker => fs::write(f.root.0.join(".artifact-store-v1"), b"changed-owned-marker").map_err(|e| e.to_string()),
        }
    }
    fn expected(self, error: &AppError) -> bool {
        if matches!(
            self,
            Self::OperationPayload
                | Self::DatasetTuple
                | Self::StoreTuple
                | Self::OriginalFd
                | Self::RootMode
                | Self::Marker
        ) {
            matches!(
                error,
                AppError::DependencyUnavailable {
                    dependency: "artifacts"
                }
            )
        } else {
            matches!(error, AppError::NotVisible)
        }
    }
}
impl Fixture {
    async fn saved_id(&self) -> Result<String, String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT artifact_id FROM openbot_internal.artifact_records",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_post_io_source_and_physical_mutation_matrix() {
    for mutation in [
        SourceMutation::DirectMembership,
        SourceMutation::ThreadTenant,
        SourceMutation::ProfileVisibility,
        SourceMutation::ChannelMembership,
        SourceMutation::ChannelAssignment,
        SourceMutation::PackageTenant,
        SourceMutation::MessageRole,
        SourceMutation::MessageActor,
        SourceMutation::MessageRun,
        SourceMutation::MessageDelete,
        SourceMutation::OperationPayload,
        SourceMutation::DatasetTuple,
        SourceMutation::StoreTuple,
        SourceMutation::OriginalFd,
        SourceMutation::RootMode,
        SourceMutation::Marker,
    ] {
        with_fixture("arc_source", mutation.channel(), |f| async move {
            let saved = f.save().await?;
            let (worker, reached, proceed) = start_after_io(&f, &saved.artifact_id).await?;
            tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "post-IO gate timed out".to_owned())?.map_err(|_| "post-IO gate sender gone".to_owned())?;
            let mut controller = f.pool.get().await.map_err(|e| e.to_string())?;
            let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            let tx = controller.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute(mutation.lock_sql()).await.map_err(|e| e.to_string())?;
            proceed.send(()).map_err(|_| "post-IO gate release gone".to_owned())?;
            let reader_pid = wait_final_lock(&f.pool, controller_pid).await?;
            mutation.apply(&f, &tx).await?;
            tx.commit().await.map_err(|e| e.to_string())?;
            let error = worker.await.map_err(|e| e.to_string())?.err().ok_or_else(|| "post-IO mutation released bytes".to_owned())?;
            require(mutation.expected(&error), "post-IO mutation returned wrong closed failure")?;
            eprintln!("ARTIFACT_CURRENT_CORE_SOURCE case={} final_lock_pid={reader_pid} blocker_pid={controller_pid} controller_commit_ack=true denied=true", mutation.identity());
            Ok(())
        }).await;
    }
}

#[derive(Clone, Copy)]
enum SessionMutation {
    DeleteOriginal,
    Token,
    Created,
    Issued,
    CurrentNull,
    CurrentNegative,
    IssuedNull,
    IssuedNegative,
    Roles,
    Revoked,
    Expires,
    Idle,
}
impl SessionMutation {
    fn identity(self) -> &'static str {
        match self {
            Self::DeleteOriginal => "delete_original",
            Self::Token => "same_id_token",
            Self::Created => "same_id_created",
            Self::Issued => "same_id_issued",
            Self::CurrentNull => "current_null",
            Self::CurrentNegative => "current_negative",
            Self::IssuedNull => "issued_null",
            Self::IssuedNegative => "issued_negative",
            Self::Roles => "roles",
            Self::Revoked => "revoked",
            Self::Expires => "expires",
            Self::Idle => "idle",
        }
    }
    fn sql(self) -> &'static str {
        match self {
            Self::DeleteOriginal => "DELETE FROM public.sessions WHERE id='core-read-session-a'",
            Self::Token => {
                "UPDATE public.sessions SET token='changed-owned-test-column' WHERE id='core-read-session-a'"
            }
            Self::Created => {
                "UPDATE public.sessions SET created_at=created_at-interval '1 second' WHERE id='core-read-session-a'"
            }
            Self::Issued => {
                "UPDATE public.sessions SET auth_generation=1 WHERE id='core-read-session-a'"
            }
            Self::CurrentNull => {
                "UPDATE public.users SET auth_generation=NULL WHERE id='read-owner'"
            }
            Self::CurrentNegative => {
                "ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='read-owner'"
            }
            Self::IssuedNull => {
                "UPDATE public.sessions SET auth_generation=NULL WHERE id='core-read-session-a'"
            }
            Self::IssuedNegative => {
                "ALTER TABLE public.sessions DROP CONSTRAINT sessions_auth_generation_nonnegative; UPDATE public.sessions SET auth_generation=-1 WHERE id='core-read-session-a'"
            }
            Self::Roles => "DELETE FROM public.user_roles WHERE user_id='read-owner'",
            Self::Revoked => {
                "INSERT INTO public.revoked_access(email) VALUES('read-owner@example.test')"
            }
            Self::Expires => {
                "UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='core-read-session-a'"
            }
            Self::Idle => {
                "UPDATE public.sessions SET updated_at=now()-interval '31 minutes' WHERE id='core-read-session-a'"
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_post_io_session_epoch_and_generation_matrix() {
    for mutation in [
        SessionMutation::DeleteOriginal,
        SessionMutation::Token,
        SessionMutation::Created,
        SessionMutation::Issued,
        SessionMutation::CurrentNull,
        SessionMutation::CurrentNegative,
        SessionMutation::IssuedNull,
        SessionMutation::IssuedNegative,
        SessionMutation::Roles,
        SessionMutation::Revoked,
        SessionMutation::Expires,
        SessionMutation::Idle,
    ] {
        with_fixture("arc_session", false, |f| async move {
            let mut f = f;
            if matches!(mutation, SessionMutation::Idle) {
                f.sql("UPDATE public.sessions SET created_at=now()-interval '59 minutes' WHERE id='core-read-session-a'").await?;
                f.created = f.pool.get().await.map_err(|e| e.to_string())?.query_one("SELECT created_at FROM public.sessions WHERE id='core-read-session-a'", &[]).await.map_err(|e| e.to_string())?.get(0);
            }
            let saved = f.save().await?;
            let (worker, reached, proceed) = start_after_io(&f, &saved.artifact_id).await?;
            tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "post-IO session gate timed out".to_owned())?.map_err(|_| "post-IO session gate gone".to_owned())?;
            let mut controller = f.pool.get().await.map_err(|e| e.to_string())?;
            let blocker: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            let tx = controller.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute("LOCK TABLE public.sessions,public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
            proceed.send(()).map_err(|_| "post-IO session release gone".to_owned())?;
            let pid = wait_final_lock(&f.pool, blocker).await?;
            tx.batch_execute(mutation.sql()).await.map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            require(matches!(worker.await.map_err(|e| e.to_string())?, Err(AppError::Unauthenticated)), "post-IO original Session mutation was accepted")?;
            if matches!(mutation, SessionMutation::DeleteOriginal | SessionMutation::Token | SessionMutation::Created | SessionMutation::Issued | SessionMutation::IssuedNull) {
                let b = f.session_auth("core-read-session-b", "owned-test-session-column-b");
                let chunk = f.administration.read_host_bound_chunk(&b, &saved.artifact_id).await.map_err(|e| e.to_string())?;
                require(chunk.handoff(&b).map_err(|e| e.to_string())? == EXACT.as_bytes(), "unchanged same-actor/generation Session B lost its own read")?;
            }
            eprintln!("ARTIFACT_CURRENT_CORE_SESSION case={} final_lock_pid={pid} blocker_pid={blocker} controller_commit_ack=true denied=true", mutation.identity());
            Ok(())
        }).await;
    }
}

/// Only the owned test PostgreSQL TCP leg is proxied. Drop or hold the selected backend ROLLBACK
/// CommandComplete after the server actually rolled back; SQL and durable effects remain real.
struct RollbackAckProxy {
    port: u16,
    remaining: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    held: Arc<AtomicUsize>,
    hold_at_rollback: Arc<tokio::sync::Mutex<Option<RollbackHold>>>,
    task: tokio::task::JoinHandle<()>,
}

struct RollbackHold {
    arrived: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

struct HeldRollbackAck {
    arrived: tokio::sync::oneshot::Receiver<()>,
    release: tokio::sync::oneshot::Sender<()>,
}

impl HeldRollbackAck {
    async fn wait(&mut self) -> Result<(), String> {
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.arrived)
            .await
            .map_err(|_| "owned proxy did not observe the selected rolled back ACK".to_owned())?
            .map_err(|_| "owned proxy ACK arrival controller closed".to_owned())
    }

    fn release(self) -> Result<(), String> {
        self.release
            .send(())
            .map_err(|()| "owned proxy ACK release receiver closed".to_owned())
    }
}

impl RollbackAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let proxy_port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let remaining = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let hold_at_rollback = Arc::new(tokio::sync::Mutex::new(None::<RollbackHold>));
        let countdown = Arc::clone(&remaining);
        let count = Arc::clone(&dropped);
        let held_count = Arc::clone(&held);
        let hold_controller = Arc::clone(&hold_at_rollback);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let countdown = Arc::clone(&countdown);
                let count = Arc::clone(&count);
                let held_count = Arc::clone(&held_count);
                let hold_controller = Arc::clone(&hold_controller);
                children.spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err(std::io::Error::other("invalid owned proxy frame"));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C' && payload == b"ROLLBACK\0" {
                                let previous = countdown.fetch_update(
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                    |value| value.checked_sub(1),
                                );
                                if previous == Ok(1) {
                                    let hold = hold_controller.lock().await.take();
                                    if let Some(hold) = hold {
                                        held_count.fetch_add(1, Ordering::SeqCst);
                                        hold.arrived.send(()).map_err(|()| {
                                            std::io::Error::other("owned ACK controller closed")
                                        })?;
                                        tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            hold.release,
                                        )
                                        .await
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK hold timed out")
                                        })?
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK release closed")
                                        })?;
                                        // Forward this exact successful backend frame only after
                                        // the direct observer's real rolled back mutation.
                                    } else {
                                        count.fetch_add(1, Ordering::SeqCst);
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = backend => {},
                    }
                });
            }
        });
        Ok(Self {
            port: proxy_port,
            remaining,
            dropped,
            held,
            hold_at_rollback,
            task,
        })
    }

    async fn hold(&self, ordinal: usize) -> Result<HeldRollbackAck, String> {
        require(ordinal > 0, "owned ACK ordinal must be positive")?;
        let (arrived_sender, arrived) = tokio::sync::oneshot::channel();
        let (release, release_receiver) = tokio::sync::oneshot::channel();
        let mut controller = self.hold_at_rollback.lock().await;
        require(controller.is_none(), "owned ACK hold already armed")?;
        *controller = Some(RollbackHold {
            arrived: arrived_sender,
            release: release_receiver,
        });
        self.remaining.store(ordinal, Ordering::SeqCst);
        Ok(HeldRollbackAck { arrived, release })
    }
}

impl Drop for RollbackAckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn with_rollback_ack<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture, RollbackAckProxy) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let proxy = RollbackAckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config;
        proxied.host = "127.0.0.1".to_owned();
        proxied.port = proxy.port;
        body(Fixture::new(proxied, false).await?, proxy).await
    })
    .await;
}

#[derive(Clone, Copy)]
enum SourceOutcome {
    Missing,
    Invisible,
    Deleted,
    Expired,
}
impl SourceOutcome {
    fn identity(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invisible => "invisible",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
        }
    }
    async fn prepare(self, f: &Fixture) -> Result<String, String> {
        if matches!(self, Self::Missing) {
            return Ok(Uuid::now_v7().to_string());
        }
        let saved = f.save().await?;
        match self {
            Self::Invisible => {
                f.sql("DELETE FROM public.thread_memberships WHERE user_id='read-owner'")
                    .await?
            }
            Self::Deleted | Self::Expired => {
                let status = if matches!(self, Self::Deleted) {
                    "deleted"
                } else {
                    "expired"
                };
                let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
                let tx = client.transaction().await.map_err(|e| e.to_string())?;
                tx.execute("UPDATE openbot_internal.artifact_records SET status=$1,workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL", &[&status]).await.map_err(|e| e.to_string())?;
                tx.execute("UPDATE openbot_internal.artifact_save_operations SET state=$1,store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL", &[&status]).await.map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
            Self::Missing => {}
        }
        Ok(saved.artifact_id)
    }
    fn expected(self, error: &AppError) -> bool {
        match self {
            Self::Missing | Self::Invisible => matches!(error, AppError::NotVisible),
            Self::Deleted => matches!(
                error,
                AppError::ArtifactGone {
                    status: ArtifactGoneStatus::Deleted
                }
            ),
            Self::Expired => matches!(
                error,
                AppError::ArtifactGone {
                    status: ArtifactGoneStatus::Expired
                }
            ),
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_host_first_missing_invisible_gone_and_final_clock() {
    for outcome in [
        SourceOutcome::Missing,
        SourceOutcome::Invisible,
        SourceOutcome::Deleted,
        SourceOutcome::Expired,
    ] {
        for failure in [
            "none",
            "session_delete_before_statement",
            "owner_close_during_rollback_ack",
            "session_expiry_during_rollback_ack",
        ] {
            with_rollback_ack("arc_error_tail", |f, proxy| async move {
                let id = outcome.prepare(&f).await?;
                let (worker, reached, proceed) = start_after_io(&f, &id).await?;
                tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "source outcome final gate timed out".to_owned())?.map_err(|_| "source outcome final gate closed".to_owned())?;
                // This source-error path intentionally had no byte worker. The gate proves real
                // final own-Pool setup/seed, not IO completion or SQL Lock/PID observation.
                let mut held = proxy.hold(1).await?;
                if failure == "session_delete_before_statement" {
                    f.sql("DELETE FROM public.sessions WHERE id='core-read-session-a'").await?;
                }
                if failure == "session_expiry_during_rollback_ack" {
                    f.sql("UPDATE public.sessions SET expires_at=now()+interval '300 milliseconds' WHERE id='core-read-session-a'").await?;
                }
                proceed.send(()).map_err(|_| "source outcome gate release closed".to_owned())?;
                held.wait().await?;
                require(proxy.held.load(Ordering::SeqCst) == 1 && proxy.dropped.load(Ordering::SeqCst) == 0, "real rollback ACK was not held")?;
                if failure == "owner_close_during_rollback_ack" { f._lease.close(); }
                if failure == "session_expiry_during_rollback_ack" {
                    let expires: OffsetDateTime = f.pool.get().await.map_err(|e| e.to_string())?.query_one(
                        "SELECT expires_at FROM public.sessions WHERE id='core-read-session-a'", &[],
                    ).await.map_err(|e| e.to_string())?.get(0);
                    let now = OffsetDateTime::now_utc();
                    require(now < expires, "session was already expired before actual rollback ACK hold")?;
                    let wait = std::time::Duration::try_from(expires - now).map_err(|_| "expiry interval was invalid".to_owned())? + Duration::from_millis(30);
                    tokio::time::sleep(wait).await;
                    require(OffsetDateTime::now_utc() >= expires, "held rollback ACK did not cross real expiry")?;
                }
                held.release()?;
                let error = worker.await.map_err(|e| e.to_string())?.err().ok_or_else(|| "source error released a chunk".to_owned())?;
                require(if failure == "none" { outcome.expected(&error) } else { matches!(error, AppError::Unauthenticated) }, "host/clock precedence lost across real explicit rollback ACK")?;
                eprintln!("ARTIFACT_CURRENT_CORE_ERROR_TAIL source={} failure={failure} actual_rollback_ack_held=true ack_released=true no_body=true", outcome.identity());
                Ok(())
            }).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_cancelled_waiter_retains_worker_fd_and_raii_result() {
    with_fixture("arc_cancel", false, |f| async move {
        let saved = f.save().await?;
        // Cancel the actual production consumer at its registered common final gate after
        // real snapshot/worker ACK. Dropping this future owns the pending buffer's Drop path;
        // it does not certify an acknowledged PostgreSQL rollback or inspect freed memory.
        let (production, reached, proceed) = start_after_io(&f, &saved.artifact_id).await?;
        tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "actual production cancel gate timed out".to_owned())?.map_err(|_| "actual production cancel gate closed".to_owned())?;
        production.abort();
        require(production.await.is_err(), "actual production pending waiter was not cancelled")?;
        drop(proceed);
        let snapshot = f.observe(&saved.artifact_id).await.map_err(|e| e.to_string())?;
        let authority = f.administration.read_authority();
        let identity = Arc::clone(&authority.identity);
        let store = Arc::clone(&f.store);
        let store_weak = Arc::downgrade(&store);
        let (release_worker, worker_release) = std::sync::mpsc::channel();
        let (io_done, observed_io) = tokio::sync::oneshot::channel();
        let (completed, worker_completed) = tokio::sync::oneshot::channel();
        // The same real snapshot/open/chunk/RAII target composition as the registered producer.
        // A test-only wrapper holds this real result after IO, making waiter cancellation
        // deterministic. The wrapper is not a fake current-host or production timing grant.
        let physical = tokio::task::spawn_blocking(move || {
            let mut pending = PendingArtifactReadBuffer::new_initialized().map_err(|_| "RAII allocation failed".to_owned())?;
            let mut reader = store.open_observed_record(snapshot).map_err(|e| e.to_string())?;
            let length = reader.read_observed_chunk(pending.initialized_mut()).map_err(|e| e.to_string())?;
            pending.record_actual_length(length).map_err(|_| "actual length failed".to_owned())?;
            let target = Arc::new(ActualArtifactReadTarget::from_reader(identity, reader));
            let result = ArtifactReadWorkerResult { pending, target };
            io_done.send(()).map_err(|_| "IO observer gone".to_owned())?;
            worker_release.recv_timeout(Duration::from_secs(5)).map_err(|_| "bounded worker hold was not released".to_owned())?;
            result.pending.actual_length().ok_or_else(|| "RAII result was lost before completion".to_owned())?;
            completed.send(()).map_err(|_| "completion observer gone".to_owned())?;
            Ok::<_, String>(result)
        });
        let waiter = tokio::spawn(async move { physical.await });
        observed_io.await.map_err(|_| "real IO did not finish before barrier".to_owned())?;
        waiter.abort();
        require(waiter.await.is_err(), "waiter was not cancelled")?;
        let administration_weak = Arc::downgrade(&f.administration);
        let Fixture { pool, registry, store, administration, _lease, root, .. } = f;
        drop(administration);
        drop(registry);
        drop(store);
        require(administration_weak.upgrade().is_none(), "worker prolonged actual administration")?;
        require(store_weak.upgrade().is_some(), "cancelled waiter dropped worker's store Arc after all composition owners dropped")?;
        _lease.close();
        drop(_lease);
        // Cancellation of the JoinHandle neither stops this actual worker nor acknowledges it.
        release_worker.send(()).map_err(|_| "actual worker release receiver gone".to_owned())?;
        worker_completed.await.map_err(|_| "actual worker completion ACK was absent".to_owned())?;
        // This assembled worker wrapper measures a real JoinHandle/RAII completion and store
        // Arc reclamation; Weak<Store> is not a kernel FD census. Production physical-worker
        // cancellation and continuous original-FD kernel occupancy remain lifecycle follow-up.
        // The abandoned result is dropped by Tokio, with its whole initialized pending buffer
        // still owned by Zeroizing. No body extraction or freed-memory inspection is used.
        tokio::time::timeout(Duration::from_secs(2), async {
            while store_weak.upgrade().is_some() { tokio::task::yield_now().await; }
        }).await.map_err(|_| "abandoned RAII result retained store Arc after worker completion".to_owned())?;
        drop(pool);
        drop(root);
        eprintln!("ARTIFACT_CURRENT_CORE_CANCEL cancelled_waiter=true actual_io_ack=true actual_worker_completion_ack=true store_arc_owners_absent=true owned_root_cleanup=true body_handoff=false");
        Ok(())
    }).await;
}

async fn actual_pool(config: &pool::DatabaseConfig) -> Result<pool::DatabasePool, String> {
    let pool = pool::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    drop(client);
    Ok(pool)
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_server_registry_cannot_mint_desktop_read_provenance() {
    harness::with_temp_database(&harness::admin_config("arc_desktop_provenance"), "arc_desktop_provenance", |config| async move {
        let pool = actual_pool(&config).await?;
        let installation_root = OwnedRoot::new()?;
        let installation = DesktopLocalAuthorityStore::new(CurrentOsUserAppDataRoot::from_current_os_user_app_data(&installation_root.0).map_err(|error| error.to_string())?).load_or_create().map_err(|error| error.to_string())?;
        let scope = installation.auth_context();
        let registry = ArtifactDatasetRegistry::from_server(pool.clone(), scope.deployment(), scope.tenant()).await.map_err(|error| error.to_string())?;
        assert!(registry.matches_pool_scope(&pool, scope.deployment(), scope.tenant()));
        assert_eq!(registry.binding().initial_origin(), "server_first_adoption");
        assert!(!registry.matches_desktop_read_installation(&installation));
        // Neither the exact same Pool/namespace nor changing immutable history can manufacture
        // Some(sealed VerifiedCanary provenance). The mutation is test-owned corruption only.
        pool.get().await.map_err(|error| error.to_string())?.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only; UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary'; ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|error| error.to_string())?;
        assert!(!registry.matches_desktop_read_installation(&installation));
        drop(registry);
        pool.close();
        drop(installation_root);
        Ok(())
    }).await;
}
