//! Self-contained Desktop Local app-data → PostgreSQL sidecar → package membership vertical.

#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DESKTOP_LOCAL_ACTOR_ID, DesktopLocalAuthorityStore,
    DesktopLocalBootstrapError,
};
use openbot_infra::db::initialization::DatabaseOrigin;
use openbot_infra::db::pool::{self, DatabaseConfig};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEST_USER: &str = "openbot_admin";
const TEST_PASSWORD: &str = "openbot-desktop-bootstrap-test-only";

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "openbot-desktop-sidecar-bootstrap-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn socket_root() -> PathBuf {
    PathBuf::from("/tmp").join(format!(
        "obpg-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn postgres_binary(name: &str) -> PathBuf {
    std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR")
        .map(PathBuf::from)
        .map_or_else(|| PathBuf::from(name), |directory| directory.join(name))
}

fn run(command: &mut Command, phase: &'static str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|_| format!("{phase}: process unavailable"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{phase}: exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

struct RunningPostgres {
    pg_ctl: PathBuf,
    data_dir: PathBuf,
    app_root: PathBuf,
    socket_dir: PathBuf,
    stopped: bool,
}

impl RunningPostgres {
    fn stop(&mut self) -> Result<(), String> {
        if !self.stopped {
            run(
                Command::new(&self.pg_ctl)
                    .arg("-D")
                    .arg(&self.data_dir)
                    .args(["-m", "fast", "-w", "stop"]),
                "pg_ctl stop",
            )?;
            self.stopped = true;
        }
        Ok(())
    }
}

impl Drop for RunningPostgres {
    fn drop(&mut self) {
        if self.stop().is_ok() {
            let _ = fs::remove_dir_all(&self.app_root);
            let _ = fs::remove_dir_all(&self.socket_dir);
        }
    }
}

fn loaded_package(tenant_id: &str) -> LoadedTenantPackage {
    let files = TenantPackageFiles {
        brand: format!("tenant: {{ id: {tenant_id}, product_name: Desktop Local }}"),
        agents: "agents: [{ id: desktop-assistant, name: Assistant, title: Local Assistant, role_description: Help locally., type: built-in, system_prompt: Answer carefully. }]".to_owned(),
        channels: "channels: [{ id: desktop-home, name: Home, description: Local home., permitted_agents: [desktop-assistant], allowed_groups: [all] }]".to_owned(),
        model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }".to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files).unwrap(),
        "/desktop-local/package".to_owned(),
        "d".repeat(64),
    )
    .unwrap()
}

fn append_postgres_config(data_dir: &Path, socket_dir: &Path, port: u16) -> Result<(), String> {
    let socket = socket_dir
        .to_str()
        .filter(|value| !value.contains('\''))
        .ok_or_else(|| "socket path is not a safe UTF-8 setting".to_owned())?;
    let mut config = OpenOptions::new()
        .append(true)
        .open(data_dir.join("postgresql.conf"))
        .map_err(|_| "open postgresql.conf failed".to_owned())?;
    writeln!(
        config,
        "\nlisten_addresses = '127.0.0.1'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700"
    )
    .map_err(|_| "write postgresql.conf failed".to_owned())?;
    config
        .sync_all()
        .map_err(|_| "sync postgresql.conf failed".to_owned())
}

#[tokio::test]
#[ignore = "需要本机 PostgreSQL 17 binaries；设置 OPENBOT_TEST_POSTGRES_BIN_DIR 后运行"]
async fn exact_instance_data_dir_bootstraps_fresh_then_rust_managed_membership() {
    let app_root = test_root();
    let store = DesktopLocalAuthorityStore::new(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&app_root).unwrap(),
    );
    let installation = store.load_or_create_installation().unwrap();
    let data_dir = installation.sidecar_data_dir().to_owned();
    let password_file = app_root.join(".test-postgres-password");
    let mut password_options = OpenOptions::new();
    password_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        password_options.mode(0o600);
    }
    let mut password = password_options.open(&password_file).unwrap();
    writeln!(password, "{TEST_PASSWORD}").unwrap();
    password.sync_all().unwrap();
    drop(password);
    let initdb = postgres_binary("initdb");
    if let Err(error) = run(
        Command::new(&initdb)
            .arg("--pgdata")
            .arg(&data_dir)
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
    ) {
        let _ = fs::remove_dir_all(&app_root);
        panic!("{error}");
    }
    fs::remove_file(password_file).unwrap();

    let socket_dir = socket_root();
    fs::create_dir(&socket_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    append_postgres_config(&data_dir, &socket_dir, port).unwrap();

    let pg_ctl = postgres_binary("pg_ctl");
    let log = app_root.join("postgres.log");
    if let Err(error) = run(
        Command::new(&pg_ctl)
            .arg("-D")
            .arg(&data_dir)
            .arg("-l")
            .arg(log)
            .args(["-w", "start"]),
        "pg_ctl start",
    ) {
        panic!("{error}");
    }
    let mut running = RunningPostgres {
        pg_ctl,
        data_dir: data_dir.clone(),
        app_root: app_root.clone(),
        socket_dir: socket_dir.clone(),
        stopped: false,
    };

    let base = DatabaseConfig::new("127.0.0.1", port, TEST_USER, "postgres")
        .with_password(TEST_PASSWORD)
        .with_application_name("openbot-desktop-bootstrap-test")
        .with_max_pool_size(4);
    let admin = pool::connect(&base).await.unwrap();
    admin
        .get()
        .await
        .unwrap()
        .batch_execute("CREATE DATABASE openbot")
        .await
        .unwrap();
    admin.close();

    let pool = pool::connect(&base.with_dbname("openbot")).await.unwrap();
    let package = loaded_package(installation.authority().auth_context().tenant().as_str());
    let first = installation
        .bootstrap_postgres(&pool, &package)
        .await
        .unwrap();
    assert_eq!(first.database_origin, DatabaseOrigin::Fresh);
    assert_eq!(first.package.memberships_granted, 1);
    assert!(first.package.single_user_groups_ignored);

    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT count(*)::bigint, \
                    EXISTS(SELECT 1 FROM public.user_roles WHERE user_id=$1 AND role='admin'), \
                    EXISTS(SELECT 1 FROM public.channel_memberships WHERE user_id=$1 AND channel_id='desktop-home') \
             FROM public.users WHERE id=$1",
            &[&DESKTOP_LOCAL_ACTOR_ID],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert!(row.get::<_, bool>(1));
    assert!(row.get::<_, bool>(2));
    let callback_columns: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='agent_profiles' AND (\
               (column_name='callback_token_hash' AND data_type='text' AND is_nullable='YES') OR \
               (column_name='callback_token_issued_at' AND data_type='timestamp with time zone' AND is_nullable='YES'))",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(callback_columns, 2, "T-TEST-0912 schema columns drifted");
    drop(client);

    let second = installation
        .bootstrap_postgres(&pool, &package)
        .await
        .unwrap();
    assert_eq!(second.database_origin, DatabaseOrigin::RustManaged);
    assert_eq!(second.package.memberships_granted, 0);

    let other_root = test_root();
    let other = DesktopLocalAuthorityStore::new(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&other_root).unwrap(),
    )
    .load_or_create_installation()
    .unwrap();
    let other_package = loaded_package(other.authority().auth_context().tenant().as_str());
    assert!(matches!(
        other.bootstrap_postgres(&pool, &other_package).await,
        Err(DesktopLocalBootstrapError::PostgresDataDirectoryMismatch)
    ));
    fs::remove_dir_all(other_root).unwrap();

    pool.close();
    running.stop().unwrap();
}
