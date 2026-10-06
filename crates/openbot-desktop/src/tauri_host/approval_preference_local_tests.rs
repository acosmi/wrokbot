//! 真实 Local 安装、sidecar attestation、canary、私有窗口和同 Pool repository 的定向测试。
//! 测试只创建自己的 PG17/loopback relay 和 create_new 路径；不接触用户数据库或 Keychain。
//! 原 Connection 析构、relay socket EOF、原事务结果分别观察，不互相替代。

use super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use openbot_application::approval_preferences::{
    RememberPreferenceRepository, RememberPreferenceRepositoryError as RepositoryError,
};
use openbot_application::{ApplicationService, OpenBotApplication};
use openbot_contracts::approval_preferences::{
    RememberPreference, RememberPreferenceState, RememberPreferenceTarget,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::BotId;
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    seal_desktop_vault_canary,
};
use openbot_infra::approval_preferences::PostgresRememberPreferenceRepository;
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
use openbot_infra::db::desktop_vault_canary;
use openbot_infra::db::{fresh, pool};
use openbot_infra::repo::channels::ChannelRepo;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

const BOT: &str = "local-preference-bot";
const AUDIT_CHAIN_LOCK_KEY: i64 = 0x4f50_454e_4155_4431;

fn require(value: bool, error: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(error.to_owned()) }
}

/// 这里只监督本测试创建的两端 socket。PID 来自实际 BackendKeyData，仅作 owned PG
/// 的协议对应；不用于生产 Pool owner、Host 授权或窗口身份。取消 secret 不保存。
#[derive(Default)]
struct RelaySocket {
    backend_pid: AtomicI32,
    peer_eof: AtomicBool,
    server_eof: AtomicBool,
    read_failed: AtomicBool,
    rollback_acks: AtomicUsize,
    commit_acks: AtomicUsize,
}

#[derive(Default)]
struct BackendFrameProbe {
    bytes: Vec<u8>,
}

impl BackendFrameProbe {
    fn observe(&mut self, bytes: &[u8], socket: &RelaySocket) -> Result<(), String> {
        self.bytes.extend_from_slice(bytes);
        loop {
            if self.bytes.len() < 5 {
                return Ok(());
            }
            let length = u32::from_be_bytes(
                self.bytes[1..5]
                    .try_into()
                    .map_err(|_| "owned relay frame header invalid")?,
            ) as usize;
            if !(4..=8 * 1024 * 1024).contains(&length) {
                return Err("owned relay backend frame size invalid".to_owned());
            }
            let total = length + 1;
            if self.bytes.len() < total {
                return Ok(());
            }
            match self.bytes[0] {
                b'K' if length == 12 => {
                    let pid = i32::from_be_bytes(
                        self.bytes[5..9]
                            .try_into()
                            .map_err(|_| "owned backend PID invalid")?,
                    );
                    require(pid > 1, "owned backend PID is not positive")?;
                    require(
                        socket
                            .backend_pid
                            .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok(),
                        "owned relay received more than one BackendKeyData",
                    )?;
                    // bytes[9..13] contains the cancel secret; it is never extracted or retained.
                }
                b'C' if &self.bytes[5..total] == b"ROLLBACK\0" => {
                    socket.rollback_acks.fetch_add(1, Ordering::SeqCst);
                }
                b'C' if &self.bytes[5..total] == b"COMMIT\0" => {
                    socket.commit_acks.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            self.bytes.drain(..total);
        }
    }
}

async fn relay_socket(
    downstream: tokio::net::TcpStream,
    upstream_port: u16,
    socket: Arc<RelaySocket>,
) -> Result<(), String> {
    let upstream = tokio::net::TcpStream::connect(("127.0.0.1", upstream_port))
        .await
        .map_err(|_| "owned relay upstream connect failed")?;
    let (mut client_read, mut client_write) = downstream.into_split();
    let (mut server_read, mut server_write) = upstream.into_split();
    let outbound = async {
        let mut buffer = [0_u8; 8192];
        let mut forwarding = true;
        loop {
            let length = client_read
                .read(&mut buffer)
                .await
                .map_err(|_| "owned relay client read failed")?;
            if length == 0 {
                socket.peer_eof.store(true, Ordering::SeqCst);
                server_write
                    .shutdown()
                    .await
                    .map_err(|_| "owned relay upstream shutdown failed")?;
                return Ok::<(), String>(());
            }
            if forwarding && server_write.write_all(&buffer[..length]).await.is_err() {
                // Continue reading for an actual peer EOF; a failed write is not EOF evidence.
                forwarding = false;
            }
        }
    };
    let inbound = async {
        let mut buffer = [0_u8; 8192];
        let mut frames = BackendFrameProbe::default();
        let mut forwarding = true;
        loop {
            let length = server_read
                .read(&mut buffer)
                .await
                .map_err(|_| "owned relay server read failed")?;
            if length == 0 {
                socket.server_eof.store(true, Ordering::SeqCst);
                client_write
                    .shutdown()
                    .await
                    .map_err(|_| "owned relay client shutdown failed")?;
                return Ok::<(), String>(());
            }
            frames.observe(&buffer[..length], &socket)?;
            if forwarding && client_write.write_all(&buffer[..length]).await.is_err() {
                forwarding = false;
            }
        }
    };
    let (outbound, inbound) = tokio::join!(outbound, inbound);
    if outbound.is_err() || inbound.is_err() {
        socket.read_failed.store(true, Ordering::SeqCst);
    }
    outbound?;
    inbound
}

struct OwnedRelay {
    port: u16,
    sockets: Arc<Mutex<Vec<Arc<RelaySocket>>>>,
    stop: watch::Sender<bool>,
    listener: Option<JoinHandle<Result<(), String>>>,
}

impl OwnedRelay {
    async fn start(upstream_port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|_| "owned relay loopback bind failed")?;
        let port = listener
            .local_addr()
            .map_err(|_| "owned relay address unreadable")?
            .port();
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&sockets);
        let (stop, mut stopped) = watch::channel(false);
        let listener = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    changed = stopped.changed() => {
                        changed.map_err(|_| "owned relay stop observation lost")?;
                        if *stopped.borrow_and_update() { break; }
                    }
                    accepted = listener.accept() => {
                        let (downstream, peer) = accepted.map_err(|_| "owned relay accept failed")?;
                        require(peer.ip().is_loopback(), "owned relay received a non-loopback peer")?;
                        let socket = Arc::new(RelaySocket::default());
                        recorded.lock().map_err(|_| "owned relay records poisoned")?.push(Arc::clone(&socket));
                        children.spawn(relay_socket(downstream, upstream_port, socket));
                    }
                    completed = children.join_next(), if !children.is_empty() => {
                        completed.ok_or("owned relay child receipt missing")?
                            .map_err(|_| "owned relay child join failed")??;
                    }
                }
            }
            drop(listener);
            while let Some(result) = children.join_next().await {
                result.map_err(|_| "owned relay child join failed")??;
            }
            Ok(())
        });
        Ok(Self {
            port,
            sockets,
            stop,
            listener: Some(listener),
        })
    }

    fn socket_for_pid(&self, pid: i32) -> Result<Arc<RelaySocket>, String> {
        let sockets = self
            .sockets
            .lock()
            .map_err(|_| "owned relay records poisoned")?;
        let mut matching = sockets
            .iter()
            .filter(|socket| socket.backend_pid.load(Ordering::SeqCst) == pid);
        let socket = Arc::clone(
            matching
                .next()
                .ok_or("owned relay socket for actual backend absent")?,
        );
        require(
            matching.next().is_none(),
            "owned relay PID correspondence is ambiguous",
        )?;
        Ok(socket)
    }

    async fn wait_eof(socket: &RelaySocket, deadline: Instant) -> Result<(), String> {
        loop {
            require(
                !socket.read_failed.load(Ordering::SeqCst),
                "owned relay ended with a read failure",
            )?;
            if socket.peer_eof.load(Ordering::SeqCst) && socket.server_eof.load(Ordering::SeqCst) {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "owned relay actual two-sided EOF not observed",
            )?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn finish(&mut self) -> Result<(), String> {
        let sockets = self
            .sockets
            .lock()
            .map_err(|_| "owned relay records poisoned")?
            .clone();
        require(
            !sockets.is_empty(),
            "owned relay observed no actual sockets",
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        for socket in sockets {
            Self::wait_eof(&socket, deadline).await?;
        }
        self.stop
            .send(true)
            .map_err(|_| "owned relay stop failed")?;
        self.listener
            .take()
            .ok_or("owned relay listener missing")?
            .await
            .map_err(|_| "owned relay listener join failed")??;
        Ok(())
    }
}

impl Drop for OwnedRelay {
    fn drop(&mut self) {
        // Failure cleanup has no closure receipt; successful tests use explicit finish above.
        let _ = self.stop.send(true);
        if let Some(listener) = self.listener.take() {
            listener.abort();
        }
    }
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
            "preference_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    relay: OwnedRelay,
    _sidecar: OwnedSidecar,
}

impl OwnedDesktop {
    async fn finish(mut self, test: &'static str) -> Result<(), String> {
        let observations = self.database.pool().connection_observations();
        self.database.close();
        drop(self.database);
        let deadline = Instant::now() + Duration::from_secs(10);
        for observation in observations {
            require(
                observation
                    .wait_for_destruction_before(deadline)
                    .await
                    .map_err(|_| "original pool Connection destruction not observed")?
                    == pool::ConnectionDestruction::ConnectionDestroyed,
                "owned application pool ended without original Connection destruction",
            )?;
        }
        self.relay.finish().await?;
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
    writeln!(file, "\nlisten_addresses = '127.0.0.1'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700")
        .map_err(|_| "write owned postgresql.conf failed".to_owned())?;
    file.sync_all()
        .map_err(|_| "sync owned postgresql.conf failed".to_owned())
}

async fn start_owned_desktop() -> Result<OwnedDesktop, String> {
    let pg_ctl = postgres_binary("pg_ctl")?;
    let initdb = postgres_binary("initdb")?;
    let id = uuid::Uuid::now_v7().simple().to_string();
    let app_root = std::env::temp_dir().join(format!("openbot-preference-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obpref-{id}"));
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
    let relay = OwnedRelay::start(port).await?;
    let admin = connect_for_attestation(
        relay.port,
        SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()),
    )
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
        relay,
        _sidecar: sidecar,
    })
}

struct LocalFixture {
    desktop: OwnedDesktop,
    repository: Arc<PostgresRememberPreferenceRepository>,
    source: Arc<PostgresLocalConfirmationAuthority>,
    original: AuthContext,
    application: Arc<dyn ApplicationService>,
    assets: PathBuf,
    dataset: String,
    key_id: String,
    pending: Mutex<Vec<Arc<Mutex<Option<WriteTask>>>>>,
}

impl LocalFixture {
    async fn new() -> Result<Self, String> {
        let desktop = start_owned_desktop().await?;
        let database = desktop.database.pool();
        // 只在初始化实际 attested 自有库时 provision；运行场景不修复任何控制变更。
        desktop
            .installation
            .authority()
            .provision_postgres(database)
            .await
            .map_err(|_| "actual owned Local principal setup failed")?;
        let original = desktop
            .installation
            .authority()
            .load_runtime_auth_context(database)
            .await
            .map_err(|_| "actual owned Local runtime principal unavailable")?;
        require(
            original.is_single_user() && original.auth_generation().get() == 0,
            "actual fresh Local runtime principal did not retain canonical generation zero",
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
        .map_err(|_| "actual owned Local canary binding invalid")?;
        let envelope =
            seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x33; NONCE_BYTES]))
                .map_err(|_| "actual owned Local canary sealing failed")?;
        let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            envelope.to_column_value(),
        )
        .map_err(|_| "actual owned Local canary row invalid")?;
        desktop_vault_canary::insert_once(database, &row)
            .await
            .map_err(|_| "actual owned Local canary insertion failed")?;
        let proof = desktop_vault_canary::verify_persisted(
            &desktop.database,
            &master,
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
        )
        .await
        .map_err(|_| "actual persisted Local canary verification failed")?;
        let provenance = proof
            .remember_preference_provenance(&desktop.database)
            .ok_or("actual canary proof lost its original Desktop database owner")?;
        let repository = Arc::new(
            PostgresRememberPreferenceRepository::new(
                database.clone(),
                original.deployment().clone(),
                original.tenant().clone(),
                SecretBytes::new(vec![0x75; 32]),
            )
            .map_err(|_| "actual Local preference repository construction failed")?,
        );
        repository
            .adopt_desktop_provenance(provenance)
            .map_err(|_| "actual Local preference provenance adoption failed")?;
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            database.clone(),
        ));
        source
            .install_remember_preference_repository(&repository)
            .map_err(|_| "actual Local preference repository installation failed")?;
        {
            let client = database
                .get()
                .await
                .map_err(|_| "owned fixture Bot checkout failed")?;
            client.execute(
                "INSERT INTO public.agents(id,name,type,configuration) VALUES($1,'Preference fixture','built_in','{}')",
                &[&BOT],
            ).await.map_err(|_| "owned fixture Bot insertion failed")?;
            client.execute(
                "INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES($1,$2,'Preference fixture','fixture','fixture','public')",
                &[&BOT, &original.actor().as_str()],
            ).await.map_err(|_| "owned fixture Bot profile insertion failed")?;
        }
        let application: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(ChannelRepo::new(database.clone())));
        let assets = desktop._sidecar.app_root.join("assets");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|_| "owned fixture asset directory creation failed")?;
        fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>")
            .map_err(|_| "owned fixture index write failed")?;
        fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|_| "owned fixture bootstrap write failed")?;
        Ok(Self {
            desktop,
            repository,
            source,
            original,
            application,
            assets,
            dataset,
            key_id,
            pending: Mutex::new(Vec::new()),
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
        .map_err(|_| "actual Local protocol construction failed")?
        .with_remember_preference_identity_source(self.source.clone())
        .map_err(|_| "actual Local preference window issuer enrollment failed".to_owned())
    }

    fn foreign_protocol(&self) -> Result<DesktopTauriProtocol, String> {
        // 实际另一个 Protocol/issuer 使用同安装和同 PG source。没有 enroll 到本 repo，
        // 其 live 私有窗口 guard 不能借相同 label/id/六事实冒充原 owner。
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map(|protocol| protocol.with_current_identity_source(self.source.clone()))
        .map_err(|_| "actual foreign Local protocol construction failed".to_owned())
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
            .map(|entry| entry.auth.clone())
            .ok_or_else(|| "actual Local window map entry missing".to_owned())
    }

    fn bind(&self, protocol: &DesktopTauriProtocol) -> Result<AuthContext, String> {
        protocol
            .bind_window("main", self.original.clone(), None)
            .map_err(|_| "actual Local private window binding failed")?;
        self.bound_auth(protocol, "main")
    }

    async fn facts(&self) -> Result<Value, String> {
        self.pool().get().await.map_err(|_| "owned preference facts checkout failed")?
            .query_one(
                "SELECT jsonb_build_object(\
                    'rows',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY preference_id),'[]') FROM openbot_internal.approval_preferences p),\
                    'audit',(SELECT coalesce(jsonb_agg(jsonb_build_object('eventType',event_type,'targetType',target_type,'targetId',target_id,'payload',payload) ORDER BY (payload->>'approval_preference_revision')::bigint),'[]') FROM public.audit_events WHERE target_type='approval_preference'))",
                &[],
            ).await.map_err(|_| "owned preference facts query failed")?
            .try_get(0).map_err(|_| "owned preference facts decode failed".to_owned())
    }

    async fn no_preference_facts(&self) -> Result<(), String> {
        require(
            self.facts().await? == json!({"rows":[], "audit":[]}),
            "refused or absent Local operation wrote preference/audit facts",
        )
    }

    async fn finish(self, name: &'static str) -> Result<(), String> {
        let pending = self
            .pending
            .into_inner()
            .map_err(|_| "owned pending registry poisoned")?;
        let mut unfinished = false;
        for pending in pending {
            let task = pending
                .lock()
                .map_err(|_| "owned pending write receipt poisoned")?
                .take();
            if let Some(task) = task {
                unfinished = true;
                task.abort();
                // 失败清理仍等待自己创建的原 task；不把 abort 请求当成它的结束。
                let _ = task.await;
            }
        }
        drop(self.application);
        drop(self.repository);
        drop(self.source);
        self.desktop.finish(name).await?;
        require(
            !unfinished,
            "successful scenario left an owned write task unjoined",
        )
    }
}

type FixtureFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;

async fn with_fixture<F>(name: &'static str, body: F)
where
    F: for<'a> FnOnce(&'a LocalFixture) -> FixtureFuture<'a>,
{
    let fixture = LocalFixture::new()
        .await
        .unwrap_or_else(|error| panic!("{name} actual owned Local setup failed: {error}"));
    let outcome = body(&fixture).await;
    let cleanup = fixture.finish(name).await;
    outcome.unwrap_or_else(|error| panic!("{name} failed: {error}"));
    cleanup.unwrap_or_else(|error| panic!("{name} explicit owned Local cleanup failed: {error}"));
}

/// 控制连接占住原 idle client 后，单独取得唯一可借用 client 的真实 observation。
/// 后续 PG blocking row 必须和这个实际 client 的 PID 一致；否则不宣称原连接对应。
struct OriginalConnection {
    pid: i32,
    observation: pool::ConnectionObservation,
    socket: Arc<RelaySocket>,
    rollback_acks: usize,
    commit_acks: usize,
}

impl OriginalConnection {
    async fn prepare(fixture: &LocalFixture) -> Result<Self, String> {
        let client = fixture
            .pool()
            .get()
            .await
            .map_err(|_| "prepare original owned client failed")?;
        let observation = client.observation();
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|_| "prepare original owned backend query failed")?
            .try_get::<_, i32>(0)
            .map_err(|_| "prepare original owned backend decode failed")?;
        let snapshot = observation.snapshot();
        require(
            snapshot.connection_started
                && !snapshot.connection_destroyed
                && !snapshot.retirement_requested,
            "prepared original client has no live original Connection",
        )?;
        let socket = fixture.desktop.relay.socket_for_pid(pid)?;
        require(
            !socket.peer_eof.load(Ordering::SeqCst),
            "prepared original owned relay peer already ended",
        )?;
        let rollback_acks = socket.rollback_acks.load(Ordering::SeqCst);
        let commit_acks = socket.commit_acks.load(Ordering::SeqCst);
        drop(client);
        Ok(Self {
            pid,
            observation,
            socket,
            rollback_acks,
            commit_acks,
        })
    }

    fn rollback_ack(&self) -> Result<(), String> {
        require(
            self.socket.rollback_acks.load(Ordering::SeqCst) == self.rollback_acks + 1,
            "original rejected write did not produce its own definite ROLLBACK CommandComplete",
        )?;
        require(
            !self.observation.snapshot().retirement_requested,
            "normally acknowledged original rollback was retired before result",
        )
    }

    fn commit_acks(&self, expected: usize) -> Result<(), String> {
        require(
            self.socket.commit_acks.load(Ordering::SeqCst) == self.commit_acks + expected,
            "original Local writes did not produce the exact definite COMMIT CommandComplete count",
        )?;
        require(
            !self.observation.snapshot().retirement_requested,
            "normally acknowledged original commits retired their original connection",
        )
    }

    async fn local_retirement(&self, deadline: Instant) -> Result<(), String> {
        require(
            self.observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|_| "cancelled original Connection destruction not observed")?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "cancelled original owner did not destroy the actual Connection",
        )?;
        let snapshot = self.observation.snapshot();
        require(
            snapshot.retirement_requested && snapshot.connection_destroyed,
            "cancelled original Connection lost retirement/destruction facts",
        )?;
        loop {
            require(
                !self.socket.read_failed.load(Ordering::SeqCst),
                "owned relay local EOF ended in a read failure",
            )?;
            if self.socket.peer_eof.load(Ordering::SeqCst) {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "cancelled original relay client EOF not observed",
            )?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn retired(
        &self,
        controller: &tokio_postgres::Client,
        deadline: Instant,
    ) -> Result<(), String> {
        OwnedRelay::wait_eof(&self.socket, deadline).await?;
        loop {
            controller
                .query_one("SELECT pg_stat_clear_snapshot()", &[])
                .await
                .map_err(|_| "clear owned backend crosscheck snapshot failed")?;
            let present: bool = controller.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND datname=current_database())",
                &[&self.pid],
            ).await.map_err(|_| "owned original backend disappearance query failed")?
                .try_get(0).map_err(|_| "owned original backend disappearance decode failed")?;
            if !present {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "owned cancelled backend remains after real Connection destruction and relay EOF",
            )?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn wait_audit_block(
    controller: &tokio_postgres::Transaction<'_>,
    controller_pid: i32,
    original: &OriginalConnection,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        controller
            .query_one("SELECT pg_stat_clear_snapshot()", &[])
            .await
            .map_err(|_| "clear actual owned audit wait snapshot failed")?;
        let rows = controller
            .query(
                "SELECT pid FROM pg_catalog.pg_stat_activity \
             WHERE datname=current_database() AND pid<>pg_backend_pid() \
             AND query='SELECT pg_advisory_xact_lock($1)' \
             AND $1=ANY(pg_catalog.pg_blocking_pids(pid))",
                &[&controller_pid],
            )
            .await
            .map_err(|_| "actual audit wait query failed")?;
        if let [row] = rows.as_slice() {
            let pid: i32 = row
                .try_get(0)
                .map_err(|_| "actual audit wait PID decode failed")?;
            require(
                pid == original.pid,
                "actual pending write did not retain its prepared original connection",
            )?;
            return Ok(());
        }
        require(
            rows.is_empty(),
            "actual audit wait has more than one pending original",
        )?;
        require(
            Instant::now() < deadline,
            "original write never reached the actual audit chain wait",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

type WriteResult =
    Result<openbot_contracts::approval_preferences::StoredRememberPreference, RepositoryError>;
type WriteTask = JoinHandle<WriteResult>;

struct PendingWrite {
    task: Arc<Mutex<Option<WriteTask>>>,
}

impl PendingWrite {
    async fn join(self) -> Result<WriteResult, String> {
        let task = self
            .task
            .lock()
            .map_err(|_| "owned write receipt poisoned")?
            .take()
            .ok_or("owned original write receipt missing")?;
        task.await
            .map_err(|_| "owned original write join failed".to_owned())
    }

    async fn cancel_and_join(self) -> Result<(), String> {
        let task = self
            .task
            .lock()
            .map_err(|_| "owned write receipt poisoned")?
            .take()
            .ok_or("owned original cancellation receipt missing")?;
        task.abort();
        require(
            task.await.is_err_and(|error| error.is_cancelled()),
            "original write caller cancellation was not observed",
        )
    }
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        // 原 JoinHandle 留在 fixture registry，失败退出仍由明确 finish 等待。
        if let Ok(task) = self.task.lock()
            && let Some(task) = task.as_ref()
        {
            task.abort();
        }
    }
}

fn spawn_write(fixture: &LocalFixture, auth: AuthContext) -> Result<PendingWrite, String> {
    let repository = Arc::clone(&fixture.repository);
    let task = tokio::spawn(async move {
        repository
            .write(
                &auth,
                &BotId::new(BOT),
                RememberPreferenceTarget::User,
                RememberPreference::Never,
                None,
            )
            .await
    });
    let task = Arc::new(Mutex::new(Some(task)));
    fixture
        .pending
        .lock()
        .map_err(|_| "owned write registry poisoned")?
        .push(Arc::clone(&task));
    Ok(PendingWrite { task })
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly closes its own Local sidecar and relay"]
async fn actual_local_verified_canary_window_reads_absent_and_commits_cas() {
    with_fixture("preference_local_absent_cas", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        let auth = fixture.bind(&protocol)?;
        let bot = BotId::new(BOT);
        let original = OriginalConnection::prepare(fixture).await?;
        let absent = fixture.repository.read(&auth, &bot, RememberPreferenceTarget::User).await
            .map_err(|_| "actual verified Local absent read failed")?;
        require(absent == RememberPreferenceState::Absent && absent.stored().is_none()
            && absent.effective_preference() == RememberPreference::Ask,
            "actual absent read fabricated a row, revision, ID or non-Ask preference")?;
        fixture.no_preference_facts().await?;
        let first = fixture.repository.write(&auth, &bot, RememberPreferenceTarget::User,
            RememberPreference::Ask, None).await.map_err(|_| "actual Local create CAS failed")?;
        require(first.revision().get() == 1 && first.preference() == RememberPreference::Ask
            && first.key().actor_id() == auth.actor() && first.key().bot_id() == &bot
            && first.key().target_kind() == "memory_user" && first.key().target_id() == auth.actor().as_str()
            && first.created_at() == first.updated_at(), "actual Local created Ask record is incomplete")?;
        let second = fixture.repository.write(&auth, &bot, RememberPreferenceTarget::User,
            RememberPreference::Ask, Some(1)).await.map_err(|_| "actual same-value Local update CAS failed")?;
        original.commit_acks(2)?;
        require(second.id() == first.id() && second.key() == first.key()
            && second.created_at() == first.created_at() && second.updated_at() >= second.created_at()
            && second.revision().get() == 2 && second.preference() == RememberPreference::Ask,
            "actual same-value CAS changed immutable fields or failed to advance revision")?;
        let committed = fixture.facts().await?;
        for expected in [None, Some(1)] {
            let error = fixture.repository.write(&auth, &bot, RememberPreferenceTarget::User,
                RememberPreference::AllowIfPolicy, expected).await;
            let Err(RepositoryError::Conflict { snapshot }) = error else {
                return Err("actual stale or None existing Local CAS did not return conflict".to_owned());
            };
            require(snapshot == second.revision_snapshot().map_err(|_| "committed Local snapshot encoding failed")?,
                "actual Local conflict did not return exact current three-field snapshot")?;
        }
        require(fixture.facts().await? == committed, "Local conflict mutated committed business/audit facts")?;
        require(fixture.repository.read(&auth, &bot, RememberPreferenceTarget::User).await
            .map_err(|_| "actual Local stored read failed")? == RememberPreferenceState::Stored(second.clone()),
            "actual Local read lost its complete stored Ask record")?;
        require(fixture.repository.read(&auth, &bot, RememberPreferenceTarget::Bot).await
            .map_err(|_| "actual Local separate Bot-key read failed")? == RememberPreferenceState::Absent,
            "actual Local six-key User row leaked into distinct Bot target")?;
        let rows = committed.get("rows").and_then(Value::as_array).ok_or("owned preference facts rows absent")?;
        require(rows.len() == 1, "actual Local CAS did not retain exactly one stored row")?;
        require(committed.get("audit") == Some(&json!([
            {"eventType":"configuration.changed", "targetType":"approval_preference", "targetId":first.id(),
             "payload":{"change":"approval_preference_saved", "approval_preference_revision":1}},
            {"eventType":"configuration.changed", "targetType":"approval_preference", "targetId":first.id(),
             "payload":{"change":"approval_preference_saved", "approval_preference_revision":2}}
        ])), "actual Local CAS audit payload/target/revision is not the closed two-field record")?;
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly closes its own Local sidecar and relay"]
async fn actual_local_foreign_owner_or_changed_canary_tuple_is_refused() {
    with_fixture("preference_local_foreign_canary", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        let auth = fixture.bind(&protocol)?;
        let foreign = fixture.foreign_protocol()?;
        let foreign_auth = fixture.bind(&foreign)?;
        require(auth == foreign_auth && !auth.request_binding().ok_or("original Local attachment absent")?
            .identity().same_binding(foreign_auth.request_binding().ok_or("foreign Local attachment absent")?.identity()),
            "actual equal Local facts collapsed two distinct Protocol owners")?;
        let bot = BotId::new(BOT);
        require(fixture.repository.read(&foreign_auth, &bot, RememberPreferenceTarget::User).await
            == Err(RepositoryError::NotVisible), "foreign actual Local owner borrowed the enrolled issuer")?;
        require(fixture.repository.write(&foreign_auth, &bot, RememberPreferenceTarget::User,
            RememberPreference::Never, None).await == Err(RepositoryError::NotVisible),
            "foreign actual Local owner wrote through the enrolled issuer")?;
        fixture.no_preference_facts().await?;
        require(fixture.repository.read(&auth, &bot, RememberPreferenceTarget::User).await
            == Ok(RememberPreferenceState::Absent), "enrolled actual owner was not current before canary mutation")?;
        {
            let client = fixture.pool().get().await.map_err(|_| "owned canary mutation checkout failed")?;
            require(client.execute(
                "UPDATE openbot_internal.desktop_vault_canaries SET dataset_id=$1,key_id=$2,encrypted_canary=$3 \
                 WHERE dataset_id=$4 AND key_id=$5 AND deployment_id=$6 AND tenant_id=$7",
                &[&"e".repeat(32), &"c".repeat(32), &"unverified-owned-canary", &fixture.dataset, &fixture.key_id,
                  &auth.deployment().as_str(), &auth.tenant().as_str()],
            ).await.map_err(|_| "owned canary tuple mutation failed")? == 1,
                "owned canary tuple mutation did not change the original row")?;
        }
        require(fixture.repository.read(&auth, &bot, RememberPreferenceTarget::User).await
            == Err(RepositoryError::NotVisible), "changed original Local canary tuple remained current")?;
        require(fixture.repository.write(&auth, &bot, RememberPreferenceTarget::User,
            RememberPreference::Never, None).await == Err(RepositoryError::NotVisible),
            "changed original Local canary tuple allowed a preference write")?;
        fixture.no_preference_facts().await?;
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly closes its own Local sidecar and relay"]
async fn actual_local_window_unbind_rebind_during_audit_wait_rolls_back_original() {
    with_fixture("preference_local_window_rebind", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        let auth = fixture.bind(&protocol)?;
        let mut client = fixture.pool().get().await.map_err(|_| "owned audit controller checkout failed")?;
        let controller = client.build_postgres_transaction().start().await
            .map_err(|_| "owned audit controller BEGIN failed")?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|_| "owned audit controller PID query failed")?.try_get(0)
            .map_err(|_| "owned audit controller PID decode failed")?;
        controller.query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY]).await
            .map_err(|_| "owned audit chain control lock failed")?;
        let original = OriginalConnection::prepare(fixture).await?;
        let pending = spawn_write(fixture, auth.clone())?;
        wait_audit_block(&controller, controller_pid, &original).await?;
        require(protocol.unbind_window("main").map_err(|_| "actual original window unbind failed")?,
            "actual original window was not unbound")?;
        let rebound = fixture.bind(&protocol)?;
        require(!auth.request_binding().ok_or("old Local attachment absent")?.identity()
            .same_binding(rebound.request_binding().ok_or("rebound Local attachment absent")?.identity()),
            "actual rebound window retained the old binding epoch")?;
        controller.rollback().await.map_err(|_| "owned audit lock release ROLLBACK failed")?;
        require(pending.join().await?
            == Err(RepositoryError::NotVisible), "original inflight Local write adopted the rebound window")?;
        original.rollback_ack()?;
        fixture.no_preference_facts().await?;
        let saved = fixture.repository.write(&rebound, &BotId::new(BOT), RememberPreferenceTarget::User,
            RememberPreference::Ask, None).await.map_err(|_| "actual rebound current write failed")?;
        require(saved.revision().get() == 1, "rolled-back old window left a preference revision behind")?;
        let facts = fixture.facts().await?;
        require(facts.get("rows").and_then(Value::as_array).is_some_and(|rows| rows.len() == 1)
            && facts.get("audit").and_then(Value::as_array).is_some_and(|events| events.len() == 1),
            "rebound write did not commit exactly one preference and one audit after original rollback")?;
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly closes its own Local sidecar and relay"]
async fn actual_local_last_protocol_drop_closes_original_inflight_window() {
    with_fixture("preference_local_last_protocol", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            let auth = fixture.bind(&protocol)?;
            // 独立机械子场景：实际等待 audit 的原写被调用者取消。不能替代后面的 Host tail 场景。
            {
                let mut client = fixture
                    .pool()
                    .get()
                    .await
                    .map_err(|_| "owned cancellation controller checkout failed")?;
                let controller = client
                    .build_postgres_transaction()
                    .start()
                    .await
                    .map_err(|_| "owned cancellation controller BEGIN failed")?;
                let controller_pid: i32 = controller
                    .query_one("SELECT pg_backend_pid()", &[])
                    .await
                    .map_err(|_| "owned cancellation controller PID query failed")?
                    .try_get(0)
                    .map_err(|_| "owned cancellation controller PID decode failed")?;
                controller
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])
                    .await
                    .map_err(|_| "owned cancellation audit lock failed")?;
                let original = OriginalConnection::prepare(fixture).await?;
                let pending = spawn_write(fixture, auth.clone())?;
                wait_audit_block(&controller, controller_pid, &original).await?;
                // original.observation 在取消前来自实际 PooledClient，非事后数量/标签推导。
                pending.cancel_and_join().await?;
                let closure_deadline = Instant::now() + Duration::from_secs(3);
                original.local_retirement(closure_deadline).await?;
                // 原 client 已实际析构且自己的 TCP peer EOF 已收到。PG 锁等待可能延后
                // 处理 FIN，先明确放自己的控制锁，再核 server EOF/PG backend 消失。
                controller
                    .rollback()
                    .await
                    .map_err(|_| "owned cancellation audit lock release failed")?;
                original.retired(&client, closure_deadline).await?;
                fixture.no_preference_facts().await?;
            }
            // 生产 tail 场景：旧 auth/guard 保持在原调用内，最后一个真实 Protocol 被实际销毁。
            let mut client = fixture
                .pool()
                .get()
                .await
                .map_err(|_| "owned final Protocol controller checkout failed")?;
            let controller = client
                .build_postgres_transaction()
                .start()
                .await
                .map_err(|_| "owned final Protocol controller BEGIN failed")?;
            let controller_pid: i32 = controller
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|_| "owned final Protocol controller PID query failed")?
                .try_get(0)
                .map_err(|_| "owned final Protocol controller PID decode failed")?;
            controller
                .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK_KEY])
                .await
                .map_err(|_| "owned final Protocol audit lock failed")?;
            let original = OriginalConnection::prepare(fixture).await?;
            let pending = spawn_write(fixture, auth.clone())?;
            wait_audit_block(&controller, controller_pid, &original).await?;
            drop(protocol);
            controller
                .rollback()
                .await
                .map_err(|_| "owned final Protocol lock release ROLLBACK failed")?;
            // 不取消这一原调用；只有真实尾证拒绝并原 ROLLBACK ACK 后的返回才算本场景事实。
            require(
                pending.join().await? == Err(RepositoryError::NotVisible),
                "last Protocol drop was not observed by the real original write tail",
            )?;
            original.rollback_ack()?;
            fixture.no_preference_facts().await?;
            require(
                fixture
                    .repository
                    .read(&auth, &BotId::new(BOT), RememberPreferenceTarget::User)
                    .await
                    == Err(RepositoryError::NotVisible),
                "old attached Local auth remained current after the last Protocol drop",
            )?;
            fixture.no_preference_facts().await?;
            Ok(())
        })
    })
    .await;
}
