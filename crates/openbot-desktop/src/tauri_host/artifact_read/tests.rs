//! Actual installation, live numeric-loopback/SCRAM sidecar, persisted Vault canary proof,
//! original Window/Local source, actual Application/PG/FS and Rust-only chunk handoff.
//! Test-owned process launch does not certify the release supervisor, UI or Keychain.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use async_trait::async_trait;
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest,
    CurrentArtifactReadChunk, OpenBotApplication, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{BotId, RunId};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    seal_desktop_vault_canary,
};
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
use openbot_infra::db::desktop_vault_canary;
use openbot_infra::db::{fresh, pool};
use openbot_infra::repo::channels::ChannelRepo;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_listener::ThreadListenerDatabase;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TEXT: &str = "  OWNED_CURRENT_BINDING_ARTIFACT_CANARY\n成果 café 🦀\t  ";
const SHA256: &str = "67f316d58f706da6dce7dd1f9c20937d723ebf772a24fa9298f8da6e402eefb2";
fn require(value: bool, error: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(error.to_owned()) }
}

const TEST_USER: &str = "desktop_admin";
const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn postgres_binary(name: &str) -> Result<PathBuf, String> {
    let directory = std::env::var_os("OPENBOT_TEST_PG_BIN")
        .map(PathBuf::from)
        .ok_or_else(|| "owned runner must set OPENBOT_TEST_PG_BIN".to_owned())?;
    if !directory.is_absolute() {
        return Err(
            "OPENBOT_TEST_PG_BIN must be an absolute owned test binary directory".to_owned(),
        );
    }
    let binary = directory.join(name);
    if !binary.is_file() {
        return Err(format!("owned PostgreSQL binary missing: {name}"));
    }
    Ok(binary)
}

fn run(command: &mut Command, phase: &'static str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|_| format!("{phase}: process unavailable"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{phase}: exit={:?}", output.status.code()))
    }
}

fn mutate_owned_read_only_file<M, E>(
    path: &std::path::Path,
    mutation: M,
    expected: E,
) -> Result<(), String>
where
    M: FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    E: FnOnce(&[u8], &[u8]) -> bool,
{
    let original = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        original.is_file() && original.mode() & 0o7777 == 0o400 && original.nlink() == 1,
        "owned mutation requires the original regular0400 single-link file",
    )?;
    let anchor = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let anchored = anchor.metadata().map_err(|error| error.to_string())?;
    require(
        anchored.is_file()
            && anchored.dev() == original.dev()
            && anchored.ino() == original.ino()
            && anchored.uid() == original.uid()
            && anchored.mode() & 0o7777 == 0o400
            && anchored.nlink() == 1,
        "owned mutation read FD is not the original0400 inode",
    )?;
    let mut before = Vec::new();
    (&anchor)
        .read_to_end(&mut before)
        .map_err(|error| error.to_string())?;
    struct RestoreReadOnly<'a> {
        file: &'a std::fs::File,
        armed: bool,
    }
    impl Drop for RestoreReadOnly<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = self
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o400));
                let _ = self.file.sync_all();
            }
        }
    }
    let mut restore = RestoreReadOnly {
        file: &anchor,
        armed: true,
    };
    anchor
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let writable = writer.metadata().map_err(|error| error.to_string())?;
    require(
        writable.is_file()
            && writable.dev() == original.dev()
            && writable.ino() == original.ino()
            && writable.uid() == original.uid()
            && writable.mode() & 0o7777 == 0o600
            && writable.nlink() == 1,
        "owned mutation write FD is not the original temporary0600 inode",
    )?;
    let mutation_result = mutation(&mut writer, &before);
    let mutation_sync = writer.sync_all();
    // Restore even when mutation or its sync failed; the anchored guard also covers early errors.
    let restored = writer.set_permissions(std::fs::Permissions::from_mode(0o400));
    let restore_sync = writer.sync_all();
    if restored.is_ok() && restore_sync.is_ok() {
        restore.armed = false;
    }
    restored.map_err(|error| error.to_string())?;
    restore_sync.map_err(|error| error.to_string())?;
    let actual = writer.metadata().map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        actual.is_file()
            && installed.is_file()
            && actual.dev() == original.dev()
            && actual.ino() == original.ino()
            && actual.uid() == original.uid()
            && installed.dev() == original.dev()
            && installed.ino() == original.ino()
            && actual.mode() & 0o7777 == 0o400
            && installed.mode() & 0o7777 == 0o400
            && actual.nlink() == 1
            && installed.nlink() == 1,
        "owned mutation did not restore original inode and0400 permissions",
    )?;
    mutation_result.map_err(|error| error.to_string())?;
    mutation_sync.map_err(|error| error.to_string())?;
    (&anchor)
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut after = Vec::new();
    (&anchor)
        .read_to_end(&mut after)
        .map_err(|error| error.to_string())?;
    require(
        before != after && expected(&before, &after),
        "owned mutation did not cause exact real byte drift",
    )
}

/// 只清理本测试 create_new 的路径，先停自己的 PG；不接触用户目录。
struct OwnedSidecar {
    pg_ctl: PathBuf,
    app_root: PathBuf,
    data_dir: PathBuf,
    socket_dir: PathBuf,
    socket_created: bool,
    started: bool,
    postmaster_pid: Option<u32>,
}

impl OwnedSidecar {
    fn read_owned_postmaster_pid(&self) -> Result<u32, String> {
        let content = fs::read_to_string(self.data_dir.join("postmaster.pid"))
            .map_err(|_| "read owned postmaster.pid failed".to_owned())?;
        content
            .lines()
            .next()
            .and_then(|line| line.parse::<u32>().ok())
            .filter(|pid| *pid > 1 && *pid <= i32::MAX as u32)
            .ok_or_else(|| "owned postmaster PID is not a positive process identity".to_owned())
    }

    fn stop_verified(&mut self) -> Result<u32, String> {
        let pid = self
            .postmaster_pid
            .map_or_else(|| self.read_owned_postmaster_pid(), Ok)?;
        if self.read_owned_postmaster_pid()? != pid {
            return Err("owned postmaster.pid changed before stop".to_owned());
        }
        // success() means actual exit 0; no Drop result stands in for this acceptance.
        run(
            Command::new(&self.pg_ctl)
                .arg("-D")
                .arg(&self.data_dir)
                .args(["-t", "15", "-m", "fast", "-w", "stop"]),
            "owned pg_ctl stop",
        )?;
        match fs::symlink_metadata(self.data_dir.join("postmaster.pid")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(
                    "owned postmaster.pid remains or cannot be observed after stop".to_owned(),
                );
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // Signal 0 only queries the PID captured from this test's own PG data directory.
            // Require ESRCH text in a fixed locale; EPERM or a missing tool proves nothing.
            let probe = Command::new("/bin/kill")
                .env("LC_ALL", "C")
                .args(["-0", &pid.to_string()])
                .output()
                .map_err(|_| "query owned stopped PID failed".to_owned())?;
            if probe.status.code() == Some(1)
                && String::from_utf8_lossy(&probe.stderr).contains("No such process")
            {
                break;
            }
            if !probe.status.success() || std::time::Instant::now() >= deadline {
                return Err(
                    "owned old postmaster PID is still present or absence was not proved"
                        .to_owned(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        self.started = false;
        Ok(pid)
    }

    fn cleanup_owned_paths(&mut self) -> Result<(), String> {
        match fs::remove_dir_all(&self.app_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("remove owned stopped app root failed".to_owned()),
        }
        if self.socket_created {
            match fs::remove_dir_all(&self.socket_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("remove owned stopped socket root failed".to_owned()),
            }
            self.socket_created = false;
        }
        Ok(())
    }

    fn finish(&mut self, test: &'static str) -> Result<(), String> {
        if !self.started {
            return Err("owned successful fixture must explicitly stop its started PG".to_owned());
        }
        let pid = self.stop_verified()?;
        self.cleanup_owned_paths()?;
        println!(
            "artifact_read_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
        );
        Ok(())
    }
}

impl Drop for OwnedSidecar {
    fn drop(&mut self) {
        // Failed tests/startups retain this best-effort fallback. A successful test must use
        // explicit finish, and only that path emits its acceptance receipt.
        let stopped = !self.started || self.stop_verified().is_ok();
        if stopped {
            let _ = self.cleanup_owned_paths();
        }
    }
}

struct OwnedDesktop {
    database: DesktopLocalDatabase,
    installation: DesktopLocalInstallation,
    port: u16,
    _sidecar: OwnedSidecar,
}

impl OwnedDesktop {
    fn finish(mut self, test: &'static str) -> Result<(), String> {
        self.database.close();
        self._sidecar.finish(test)
    }
}

fn append_postgres_config(data_dir: &Path, socket_dir: &Path, port: u16) -> Result<(), String> {
    let socket = socket_dir
        .to_str()
        .filter(|s| !s.contains('\''))
        .ok_or_else(|| "owned socket path is not a safe setting".to_owned())?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(data_dir.join("postgresql.conf"))
        .map_err(|_| "open owned postgresql.conf failed".to_owned())?;
    writeln!(file, "\nlisten_addresses = '127.0.0.1'\ntrack_activity_query_size=16384\nlog_lock_waits=on\ndeadlock_timeout=\'25ms\'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700")
        .map_err(|_| "write owned postgresql.conf failed".to_owned())?;
    file.sync_all()
        .map_err(|_| "sync owned postgresql.conf failed".to_owned())
}

async fn start_owned_desktop() -> Result<OwnedDesktop, String> {
    let pg_ctl = postgres_binary("pg_ctl")?;
    let initdb = postgres_binary("initdb")?;
    let id = uuid::Uuid::now_v7().simple().to_string();
    let app_root = std::env::temp_dir().join(format!("openbot-binding-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obbind-{id}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&app_root)
        .map_err(|_| "create owned app root failed".to_owned())?;
    let mut sidecar = OwnedSidecar {
        pg_ctl,
        data_dir: app_root.join("not-started"),
        app_root,
        socket_dir,
        socket_created: false,
        started: false,
        postmaster_pid: None,
    };
    let store = DesktopLocalAuthorityStore::new(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&sidecar.app_root)
            .map_err(|e| e.to_string())?,
    );
    let installation = store
        .load_or_create_installation()
        .map_err(|e| e.to_string())?;
    sidecar.data_dir = installation.sidecar_data_dir().to_owned();
    let password_file = sidecar.app_root.join(".test-postgres-password");
    let mut password = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&password_file)
        .map_err(|_| "create owned initdb credential failed".to_owned())?;
    writeln!(password, "{TEST_PASSWORD}")
        .map_err(|_| "write owned initdb credential failed".to_owned())?;
    password
        .sync_all()
        .map_err(|_| "sync owned initdb credential failed".to_owned())?;
    drop(password);
    run(
        Command::new(initdb)
            .arg("--pgdata")
            .arg(&sidecar.data_dir)
            .arg(format!("--username={TEST_USER}"))
            .arg("--pwfile")
            .arg(&password_file)
            .args([
                "--auth-host=scram-sha-256",
                "--auth-local=trust",
                "--encoding=UTF8",
                "--no-locale",
            ]),
        "initdb",
    )?;
    fs::remove_file(password_file)
        .map_err(|_| "remove owned initdb credential failed".to_owned())?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&sidecar.socket_dir)
        .map_err(|_| "create owned socket root failed".to_owned())?;
    sidecar.socket_created = true;
    let probe = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "allocate owned loopback port failed".to_owned())?;
    let port = probe
        .local_addr()
        .map_err(|_| "read owned loopback port failed".to_owned())?
        .port();
    drop(probe);
    append_postgres_config(&sidecar.data_dir, &sidecar.socket_dir, port)?;
    sidecar.started = true;
    run(
        Command::new(&sidecar.pg_ctl)
            .arg("-D")
            .arg(&sidecar.data_dir)
            .arg("-l")
            .arg(sidecar.app_root.join("postgres.log"))
            .args(["-w", "start"]),
        "pg_ctl start",
    )?;
    sidecar.postmaster_pid = Some(sidecar.read_owned_postmaster_pid()?);
    let admin = connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
        .await
        .map_err(|e| e.to_string())?;
    let admin = installation
        .attest_postgres_admin(admin)
        .await
        .map_err(|e| e.to_string())?;
    let database = admin
        .connect_application(true)
        .await
        .map_err(|e| e.to_string())?;
    let mut c = database.pool().get().await.map_err(|e| e.to_string())?;
    fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
    drop(c);
    Ok(OwnedDesktop {
        database,
        installation,
        port,
        _sidecar: sidecar,
    })
}

struct CountActualArtifactPort {
    actual: Arc<PostgresArtifactAdministration>,
    reads: AtomicUsize,
    pending_gate: Mutex<Option<Arc<PendingGate>>>,
}
#[async_trait]
impl ArtifactAdministration for CountActualArtifactPort {
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.actual.save_run_message_text(auth, input).await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let gate = self
            .pending_gate
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?
            .take();
        let pending = self.actual.read_host_bound_chunk(auth, id).await?;
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        Ok(pending)
    }
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.actual.get_metadata(auth, id).await
    }
}

struct LocalFixture {
    desktop: OwnedDesktop,
    source: Arc<PostgresLocalConfirmationAuthority>,
    original: AuthContext,
    application: Arc<dyn ApplicationService>,
    port: Arc<CountActualArtifactPort>,
    receipt: ArtifactRegistrationReceipt,
    assets: PathBuf,
    artifact_root: PathBuf,
}
impl LocalFixture {
    async fn new() -> Result<Self, String> {
        let desktop = start_owned_desktop().await?;
        let database = desktop.database.pool();
        // Actual canonical provisioning is setup-only, after exact live-sidecar attestation and
        // migrations. Runtime checks below never call it or repair the controlled mutations.
        desktop
            .installation
            .authority()
            .provision_postgres(database)
            .await
            .map_err(|e| e.to_string())?;
        let original = desktop
            .installation
            .authority()
            .load_runtime_auth_context(database)
            .await
            .map_err(|e| e.to_string())?;
        require(
            original.auth_generation().get() == 0 && original.is_single_user(),
            "actual fresh Local canonical principal was not generation zero",
        )?;
        let dataset = "d".repeat(32);
        let key_id = "b".repeat(32);
        let master = SecretBytes::new(vec![0x5a; 32]);
        let binding = DesktopVaultCanaryBinding::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            KeyVersion::new(1),
        )
        .map_err(|e| e.to_string())?;
        let envelope =
            seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x33; NONCE_BYTES]))
                .map_err(|e| e.to_string())?;
        let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            envelope.to_column_value(),
        )
        .map_err(|e| e.to_string())?;
        desktop_vault_canary::insert_once(database, &row)
            .await
            .map_err(|e| e.to_string())?;
        let proof = desktop_vault_canary::verify_persisted(
            &desktop.database,
            &master,
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
        )
        .await
        .map_err(|e| e.to_string())?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_desktop(&desktop.database, &proof)
                .await
                .map_err(|e| e.to_string())?,
        );
        {
            let c = database.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('local-binding-bot','Binding fixture','built_in','{}')").await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000005',$1,'fixture','fixture')",&[&original.tenant().as_str()]).await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('local-binding-bot',$1,'Binding fixture','fixture','fixture','public')",&[&original.actor().as_str()]).await.map_err(|e|e.to_string())?;
        }
        let begin = BeginThreadRunRequest {
            deployment: original.deployment().clone(),
            tenant: original.tenant().clone(),
            actor: original.actor().clone(),
            auth_generation: original.auth_generation(),
            command: BeginThreadRun {
                thread_id: ThreadIdentity::new(original.deployment()).mint_from_entropy([6; 16]),
                run_id: RunId::new("actual/local-binding-run%成果"),
                bot_id: BotId::new("local-binding-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let listener =
            ThreadListenerDatabase::desktop_local(desktop.port, TEST_PASSWORD.as_bytes())
                .map_err(|e| e.to_string())?;
        PostgresThreadDirectory::with_runtime(
            database.clone(),
            listener,
            "local-binding-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let artifact_root = desktop._sidecar.app_root.join("artifacts");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&artifact_root)
            .map_err(|e| e.to_string())?;
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                fs::File::open(&artifact_root).map_err(|e| e.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x75; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let receipt = actual
            .save_run_message_text(
                &original,
                SaveRunMessageTextArtifact {
                    request_id: uuid::Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id.clone(),
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: SHA256.to_owned(),
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let port = Arc::new(CountActualArtifactPort {
            actual,
            reads: AtomicUsize::new(0),
            pending_gate: Mutex::new(None),
        });
        // The selected real OpenBotApplication uses its production metadata use case and actual
        // artifact repository. Other uninvolved adapters are unavailable, never canned replies.
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(ChannelRepo::new(database.clone()))
                .with_artifacts(port.clone()),
        );
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            database.clone(),
        ));
        source
            .install_artifact_read_authority(&port.actual.read_authority())
            .map_err(|_| "actual same-Pool Local authority enrollment refused".to_owned())?;
        let assets = desktop._sidecar.app_root.join("assets");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|e| e.to_string())?;
        fs::write(assets.join("index.html"),"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e|e.to_string())?;
        fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").map_err(|e| e.to_string())?;
        Ok(Self {
            desktop,
            source,
            original,
            application,
            port,
            receipt,
            assets,
            artifact_root,
        })
    }
    fn pool(&self) -> &pool::DatabasePool {
        self.desktop.database.pool()
    }
    fn protocol(&self) -> Result<DesktopTauriProtocol, String> {
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map(|protocol| protocol.with_current_identity_source(self.source.clone()))
        .map_err(|e| e.to_string())
    }
    fn bound_auth(
        &self,
        protocol: &DesktopTauriProtocol,
        label: &str,
    ) -> Result<AuthContext, String> {
        protocol
            .windows
            .read()
            .map_err(|_| "actual Local window map unreadable")?
            .get(label)
            .map(|authority| authority.auth.clone())
            .ok_or_else(|| "actual Local window map entry missing".to_owned())
    }
    fn pending_gate(&self) -> Result<Arc<PendingGate>, String> {
        let gate = Arc::new(PendingGate {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *self
            .port
            .pending_gate
            .lock()
            .map_err(|_| "pending gate poisoned".to_owned())? = Some(gate.clone());
        Ok(gate)
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool()
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|error| error.to_string())
    }
    fn finish(self, test: &'static str) -> Result<(), String> {
        drop(self.application);
        drop(self.port);
        drop(self.source);
        self.desktop.finish(test)
    }
}
struct PendingGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
type FixtureFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;
async fn with_fixture<F>(name: &'static str, body: F)
where
    F: for<'a> FnOnce(&'a LocalFixture) -> FixtureFuture<'a>,
{
    let fixture = LocalFixture::new()
        .await
        .unwrap_or_else(|error| panic!("{name} actual Local setup failed: {error}"));
    let outcome = body(&fixture).await;
    let cleanup = fixture.finish(name);
    outcome.unwrap_or_else(|error| panic!("{name} failed: {error}"));
    cleanup.unwrap_or_else(|error| panic!("{name} actual owned stop/cleanup failed: {error}"));
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_canary_window_application_and_protocol_release_exact_first_chunk() {
    with_fixture("local_read_positive", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let body = protocol
                .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                body == TEXT.as_bytes(),
                "actual Local protocol did not return original artifact bytes",
            )?;
            require(
                fixture.port.reads.load(Ordering::SeqCst) == 1,
                "actual Local artifact producer port was not called",
            )?;
            let auth = fixture.bound_auth(&protocol, "main")?;
            let transport = InProcessTransport::new(fixture.application.clone());
            require(
                Arc::ptr_eq(transport.service(), &fixture.application),
                "Local transport did not retain the same ApplicationService",
            )?;
            let pending = transport
                .read_current_artifact_chunk(auth.clone(), fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                pending.handoff(&auth).map_err(|error| error.to_string())? == TEXT.as_bytes(),
                "actual typed Local transport changed current body",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_two_local_protocols_same_label_and_id_one_cannot_exchange_pending_body() {
    with_fixture("local_read_owner_collision", |fixture| {
        Box::pin(async move {
            let a = fixture.protocol()?;
            let b = fixture.protocol()?;
            for protocol in [&a, &b] {
                protocol
                    .bind_window("main", fixture.original.clone(), None)
                    .map_err(|error| error.to_string())?;
            }
            let auth_a = fixture.bound_auth(&a, "main")?;
            let auth_b = fixture.bound_auth(&b, "main")?;
            require(
                auth_a == auth_b,
                "actual collision fixture six facts differed",
            )?;
            require(
                a.windows
                    .read()
                    .map_err(|_| "A map unavailable".to_owned())?["main"]
                    .binding_id
                    == 1
                    && b.windows
                        .read()
                        .map_err(|_| "B map unavailable".to_owned())?["main"]
                        .binding_id
                        == 1,
                "collision fixture did not use original id-one epochs",
            )?;
            let pending = fixture
                .application
                .read_current_artifact_chunk(auth_a, fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                matches!(pending.handoff(&auth_b), Err(AppError::Unauthenticated)),
                "pending body crossed genuine protocol owners",
            )?;
            for protocol in [&a, &b] {
                require(
                    protocol
                        .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                        .await
                        .map_err(|error| error.to_string())?
                        == TEXT.as_bytes(),
                    "a genuine current owner lost its own bytes",
                )?;
            }
            Ok(())
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_current_raw_generation_email_role_and_deny_refuse_without_repair() {
    with_fixture("local_read_current_matrix", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        let mutations = [
            ("UPDATE public.users SET auth_generation=NULL WHERE id='desktop-local-user'", "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'"),
            ("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='desktop-local-user'", "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'; ALTER TABLE public.users ADD CONSTRAINT users_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation>=0)"),
            ("UPDATE public.users SET email='changed-local@example.test' WHERE id='desktop-local-user'", "UPDATE public.users SET email='desktop-local@localhost.invalid' WHERE id='desktop-local-user'"),
            ("UPDATE public.user_roles SET role='user' WHERE user_id='desktop-local-user'", "UPDATE public.user_roles SET role='admin' WHERE user_id='desktop-local-user'"),
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('desktop-local@localhost.invalid','desktop-local-user')", "DELETE FROM public.revoked_access WHERE email='desktop-local@localhost.invalid'"),
        ];
        for (mutation, restore) in mutations {
            fixture.sql(mutation).await?;
            require(matches!(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await, Err(AppError::Unauthenticated)), "changed Local current authority released bytes")?;
            fixture.sql(restore).await?;
            require(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())? == TEXT.as_bytes(), "unmodified original Local authority was repaired/rebound instead of observed")?;
        }
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_rebind_during_last_await_never_receives_original_pending_body() {
    with_fixture("local_read_rebind", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            require(
                protocol
                    .unbind_window("main")
                    .map_err(|error| error.to_string())?,
                "original window was not physically removed",
            )?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::Unauthenticated)
                ),
                "replacement Local window received pending old bytes",
            )?;
            require(
                protocol
                    .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                    .await
                    .map_err(|error| error.to_string())?
                    == TEXT.as_bytes(),
                "new genuine window failed fresh current read",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_protocol_close_during_last_await_refuses_pending_body() {
    with_fixture("local_read_owner_close", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            protocol.close_request_bindings();
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::Unauthenticated)
                ),
                "closed actual protocol released old body",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_last_protocol_drop_does_not_let_pending_witness_retain_real_owner() {
    with_fixture("local_read_last_owner_drop", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let auth = fixture.bound_auth(&protocol, "main")?;
            let pending = fixture
                .application
                .read_current_artifact_chunk(auth.clone(), fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            drop(protocol);
            require(
                matches!(pending.handoff(&auth), Err(AppError::Unauthenticated)),
                "pending witness retained the last actual protocol lease",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_original_fd_mutation_during_last_await_refuses_pending_body() {
    with_fixture("local_read_retained_fd", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            mutate_owned_read_only_file(
                &fixture
                    .artifact_root
                    .join("objects")
                    .join(&fixture.receipt.artifact_id),
                |fd, _| fd.write_all(b"X"),
                |before, after| {
                    before.first() == Some(&b' ')
                        && after.first() == Some(&b'X')
                        && after.len() == before.len()
                        && after[1..] == before[1..]
                },
            )?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::DependencyUnavailable {
                        dependency: "artifacts"
                    })
                ),
                "changed original Local FD released bytes",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_map_contention_refuses_initial_and_pending_handoff() {
    with_fixture("local_read_map_contention", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            {
                let _held = OwnedWindowWriteHold::new(&protocol)?;
                require(
                    matches!(
                        protocol
                            .read_current_artifact_chunk(
                                "main",
                                fixture.receipt.artifact_id.clone()
                            )
                            .await,
                        Err(AppError::DependencyUnavailable {
                            dependency: "host_request_binding"
                        })
                    ),
                    "busy map waited or released bytes",
                )?;
                require(
                    fixture.port.reads.load(Ordering::SeqCst) == 0,
                    "initial busy map reached the actual read producer",
                )?;
            }
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            let _held = OwnedWindowWriteHold::new(&protocol)?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "busy original map released pending bytes",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_map_poison_is_unavailable_before_any_read_port() {
    with_fixture("local_read_map_poison", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let windows = protocol.windows.clone();
            require(
                std::thread::spawn(move || {
                    let _write = windows.write().unwrap();
                    panic!("controlled owned window-map poison");
                })
                .join()
                .is_err(),
                "actual map was not poisoned",
            )?;
            require(
                matches!(
                    protocol
                        .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                        .await,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "poisoned original map did not fail closed",
            )?;
            require(
                fixture.port.reads.load(Ordering::SeqCst) == 0,
                "poisoned map reached actual artifact port",
            )
        })
    })
    .await;
}

struct OwnedWindowWriteHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl OwnedWindowWriteHold {
    fn new(protocol: &DesktopTauriProtocol) -> Result<Self, String> {
        let windows = protocol.windows.clone();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _map = windows.write().unwrap();
            entered.send(()).unwrap();
            finish.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        ready
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "owned map write holder did not acquire original map".to_owned())?;
        Ok(Self {
            release: Some(release),
            worker: Some(worker),
        })
    }
}
impl Drop for OwnedWindowWriteHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            assert!(
                worker.join().is_ok(),
                "owned map write holder did not physically finish"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_final_canary_cipher_row_is_rechecked_after_installation_proof() {
    with_fixture("local_read_current_canary", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        require(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())? == TEXT.as_bytes(), "original genuine canary could not read")?;
        fixture.sql("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=encrypted_canary||'-controlled-change'").await?;
        require(matches!(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await, Err(AppError::Unauthenticated)), "changed current persisted canary was replaced by old proof")
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local final-query Lock/COMMIT ACK"]
async fn actual_local_worker_ack_then_final_joint_wait_observes_current_generation_commit() {
    use tracing::instrument::WithSubscriber as _;
    with_fixture("local_read_real_final_wait", |fixture| Box::pin(async move {
        let protocol = Arc::new(fixture.protocol()?);
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        let gate = TracePhaseGate::new();
        let dispatch = tracing::Dispatch::new(ReadPhaseSubscriber(gate.clone()));
        let called = protocol.clone(); let id = fixture.receipt.artifact_id.clone();
        let task = tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await }.with_subscriber(dispatch));
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await.map_err(|_| "actual Local IO/final-ready phases were not observed".to_owned())?;
        require(gate.io_seen.load(Ordering::SeqCst) && gate.ready_seen.load(Ordering::SeqCst), "actual Local worker ACK did not precede final-ready")?;
        let mut controller = fixture.pool().get().await.map_err(|error| error.to_string())?;
        let transaction = controller.transaction().await.map_err(|error| error.to_string())?;
        let blocker: i32 = transaction.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|error| error.to_string())?.get(0);
        transaction.batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|error| error.to_string())?;
        gate.release();
        let waiter = actual_final_wait(fixture.pool(), blocker).await?;
        require(!gate.timed_out.load(Ordering::SeqCst), "Local trace barrier timed out instead of controller release")?;
        transaction.execute("UPDATE public.users SET auth_generation=NULL WHERE id=$1", &[&fixture.original.actor().as_str()]).await.map_err(|error| error.to_string())?;
        transaction.commit().await.map_err(|error| error.to_string())?;
        eprintln!("ARTIFACT_CURRENT_LOCAL_FINAL_WAIT io_ack=true final_marker=true wait_type=Lock blocker_pid={blocker} waiter_pid={waiter} controller_commit_ack=true");
        require(matches!(task.await.map_err(|error| error.to_string())?, Err(AppError::Unauthenticated)), "actual Local final statement did not observe committed NULL current generation")
    })).await;
}

struct TracePhaseGate {
    io_seen: std::sync::atomic::AtomicBool,
    ready_seen: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
    timed_out: std::sync::atomic::AtomicBool,
}
impl TracePhaseGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            io_seen: std::sync::atomic::AtomicBool::new(false),
            ready_seen: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
            timed_out: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
struct PhaseVisitor(Option<&'static str>);
impl tracing::field::Visit for PhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "artifact_read_phase" {
            self.0 = match value {
                "actual_io_completed_before_joint" => Some("actual_io_completed_before_joint"),
                "joint_statement_ready" => Some("joint_statement_ready"),
                _ => None,
            };
        }
    }
}
struct ReadPhaseSubscriber(Arc<TracePhaseGate>);
impl tracing::Subscriber for ReadPhaseSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = PhaseVisitor(None);
        event.record(&mut visitor);
        match visitor.0 {
            Some("actual_io_completed_before_joint") => {
                self.0.io_seen.store(true, Ordering::SeqCst);
            }
            Some("joint_statement_ready")
                if self.0.io_seen.load(Ordering::SeqCst)
                    && !self.0.ready_seen.swap(true, Ordering::SeqCst) =>
            {
                self.0.entered.notify_one();
                let released = self.0.released.lock().unwrap();
                let (_released, timeout) = self
                    .0
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                    .unwrap();
                if timeout.timed_out() {
                    self.0.timed_out.store(true, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }
}
async fn actual_final_wait(pool: &pool::DatabasePool, blocker: i32) -> Result<i32, String> {
    let width: i64 = pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(
            "SELECT pg_size_bytes(current_setting('track_activity_query_size'))",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        width >= 16_384,
        "owned Local activity query width was not actually sixteen KiB",
    )?;
    for _ in 0..150 {
        let rows = pool.get().await.map_err(|error| error.to_string())?.query(
            "SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database()
                AND a.pid<>pg_backend_pid() AND a.query LIKE '%/* artifact_current_host_joint_read_after_io */%'
                AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))", &[&blocker],
        ).await.map_err(|error| error.to_string())?;
        if rows.len() == 1 {
            return rows[0].try_get(0).map_err(|error| error.to_string());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("actual final joint statement/controller Lock wait was not observed".to_owned())
}
