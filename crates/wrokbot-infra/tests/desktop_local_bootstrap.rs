//! Self-contained Desktop Local app-data → PostgreSQL sidecar → package membership vertical.

#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use wrokbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use wrokbot_domain::vault::{
    DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    seal_desktop_vault_canary,
};
use wrokbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DESKTOP_LOCAL_ACTOR_ID, DesktopLocalAuthorityStore,
    DesktopLocalBootstrapError, DesktopLocalInstallation,
};
use wrokbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
use wrokbot_infra::db::initialization::DatabaseOrigin;
use wrokbot_infra::db::{baseline, desktop_vault_canary, initialization, native};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEST_USER: &str = "desktop_admin";
const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "wrokbot-desktop-sidecar-bootstrap-{}-{}",
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
    std::env::var_os("WROK_BOT_TEST_POSTGRES_BIN_DIR")
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

struct DesktopFixture {
    database: DesktopLocalDatabase,
    installation: DesktopLocalInstallation,
    port: u16,
    running: RunningPostgres,
}

#[derive(Debug, PartialEq, Eq)]
struct BootstrapWriteCounts {
    ledger: i64,
    ledger_fingerprint: String,
    users: i64,
    agents: i64,
    channels: i64,
    memberships: i64,
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

async fn bootstrap_write_counts(database: &DesktopLocalDatabase) -> BootstrapWriteCounts {
    let client = database.pool().get().await.unwrap();
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*)::bigint FROM openbot_internal.schema_migrations), \
               (SELECT coalesce(string_agg(version::text || ':' || name || ':' || checksum || ':' || applied_at::text,'|' ORDER BY version),'') FROM openbot_internal.schema_migrations), \
               (SELECT count(*)::bigint FROM public.users), \
               (SELECT count(*)::bigint FROM public.agent_profiles), \
               (SELECT count(*)::bigint FROM public.channels), \
               (SELECT count(*)::bigint FROM public.channel_memberships)",
            &[],
        )
        .await
        .unwrap();
    BootstrapWriteCounts {
        ledger: row.get(0),
        ledger_fingerprint: row.get(1),
        users: row.get(2),
        agents: row.get(3),
        channels: row.get(4),
        memberships: row.get(5),
    }
}

fn copy_installation_identity(source_root: &Path, target_root: &Path) {
    fs::create_dir(target_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(target_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let target = target_root.join("desktop-instance-v1");
    fs::copy(source_root.join("desktop-instance-v1"), &target).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

async fn start_desktop_fixture(identity_source: Option<&Path>) -> DesktopFixture {
    let app_root = test_root();
    if let Some(source_root) = identity_source {
        copy_installation_identity(source_root, &app_root);
    }
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
    let running = RunningPostgres {
        pg_ctl,
        data_dir,
        app_root,
        socket_dir,
        stopped: false,
    };
    let admin = connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
        .await
        .unwrap();
    let admin = installation.attest_postgres_admin(admin).await.unwrap();
    let database = admin.connect_application(true).await.unwrap();
    DesktopFixture {
        database,
        installation,
        port,
        running,
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

async fn verified_canary(
    database: &DesktopLocalDatabase,
    installation: &wrokbot_infra::auth::single_user::desktop_local::DesktopLocalInstallation,
) -> desktop_vault_canary::VerifiedDesktopVaultCanary {
    let dataset = format!("{:032x}", TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1);
    let key_id = format!("{:032x}", TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1);
    let deployment = installation
        .authority()
        .auth_context()
        .deployment()
        .as_str();
    let tenant = installation.authority().auth_context().tenant().as_str();
    let master = SecretBytes::new(vec![0x5a; 32]);
    let binding =
        DesktopVaultCanaryBinding::new(&dataset, deployment, tenant, &key_id, KeyVersion::new(1))
            .unwrap();
    let envelope =
        seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x33; NONCE_BYTES]))
            .unwrap();
    let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
        &dataset,
        deployment,
        tenant,
        &key_id,
        envelope.to_column_value(),
    )
    .unwrap();
    if desktop_vault_canary::read(database.pool(), deployment, tenant)
        .await
        .unwrap()
        .is_none()
    {
        desktop_vault_canary::insert_once(database.pool(), &row)
            .await
            .unwrap();
    }
    desktop_vault_canary::verify_persisted(database, &master, &dataset, deployment, tenant, &key_id)
        .await
        .unwrap()
}

async fn completion_refusal_is_read_only(
    installation: &DesktopLocalInstallation,
    database: &DesktopLocalDatabase,
    package: &LoadedTenantPackage,
    database_origin: DatabaseOrigin,
    proof: &desktop_vault_canary::VerifiedDesktopVaultCanary,
) {
    let before = bootstrap_write_counts(database).await;
    assert!(
        installation
            .complete_postgres_after_vault(database, package, database_origin, proof)
            .await
            .is_err()
    );
    assert_eq!(bootstrap_write_counts(database).await, before);
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

async fn install_historical_0032(database: &DesktopLocalDatabase) {
    let mut client = database.pool().get().await.unwrap();
    baseline::apply(&client).await.unwrap();
    native::apply_through(&mut client, native::NATIVE_0032_VERSION)
        .await
        .unwrap();
}

async fn native_0033_restart_facts(
    database: &DesktopLocalDatabase,
) -> (String, Vec<(String, u32)>) {
    let client = database.pool().get().await.unwrap();
    let applied_at: String = client
        .query_one(
            "SELECT applied_at::text FROM openbot_internal.schema_migrations WHERE version=33",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let relations = client
        .query(
            "SELECT c.relname,c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relname IN \
             ('sdk_gateway_connections','sdk_gateway_operations','sdk_gateway_secrets') \
             ORDER BY c.relname",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    (applied_at, relations)
}

#[tokio::test]
#[ignore = "需要本机 PostgreSQL 17 binaries；设置 WROK_BOT_TEST_POSTGRES_BIN_DIR 后运行"]
async fn existing_0032_canary_upgrades_once_and_0033_restart_runs_no_ddl() {
    let DesktopFixture {
        database,
        installation,
        port,
        mut running,
    } = start_desktop_fixture(None).await;
    install_historical_0032(&database).await;
    let package = loaded_package(installation.authority().auth_context().tenant().as_str());
    let proof = verified_canary(&database, &installation).await;
    assert_eq!(
        desktop_vault_canary::verify_pre_upgrade_layout(database.pool())
            .await
            .unwrap()
            .native_version(),
        native::NATIVE_0032_VERSION
    );
    let before = bootstrap_write_counts(&database).await;
    assert_eq!(before.ledger, 20);
    assert_eq!(
        (
            before.users,
            before.agents,
            before.channels,
            before.memberships
        ),
        (0, 0, 0, 0)
    );

    let first = installation
        .complete_postgres_after_vault(&database, &package, DatabaseOrigin::RustManaged, &proof)
        .await
        .unwrap();
    assert_eq!(first.package.memberships_granted, 1);
    desktop_vault_canary::verify_current_layout(database.pool())
        .await
        .unwrap();
    let after = bootstrap_write_counts(&database).await;
    assert_eq!(after.ledger, 21);
    let first_facts = native_0033_restart_facts(&database).await;
    assert_eq!(first_facts.1.len(), 3);

    let second_admin =
        connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
            .await
            .unwrap();
    let second_admin = installation
        .attest_postgres_admin(second_admin)
        .await
        .unwrap();
    let second_database_owner = second_admin.connect_application(false).await.unwrap();
    let master = SecretBytes::new(vec![0x5a; 32]);
    let second_proof = desktop_vault_canary::verify_persisted(
        &second_database_owner,
        &master,
        proof.dataset_id(),
        proof.deployment_id(),
        proof.tenant_id(),
        proof.key_id(),
    )
    .await
    .unwrap();
    let second = installation
        .complete_postgres_after_vault(
            &second_database_owner,
            &package,
            DatabaseOrigin::RustManaged,
            &second_proof,
        )
        .await
        .unwrap();
    assert_eq!(second.package.memberships_granted, 0);
    assert_eq!(
        native_0033_restart_facts(&second_database_owner).await,
        first_facts
    );
    assert_eq!(bootstrap_write_counts(&second_database_owner).await, after);

    second_database_owner.close();
    database.close();
    running.stop().unwrap();
}

#[tokio::test]
#[ignore = "需要本机 PostgreSQL 17 binaries；设置 WROK_BOT_TEST_POSTGRES_BIN_DIR 后运行"]
async fn existing_0032_bad_master_or_changed_canary_performs_zero_0033_ddl() {
    let DesktopFixture {
        database,
        installation,
        port: _,
        mut running,
    } = start_desktop_fixture(None).await;
    install_historical_0032(&database).await;
    let package = loaded_package(installation.authority().auth_context().tenant().as_str());
    let proof = verified_canary(&database, &installation).await;
    let before = bootstrap_write_counts(&database).await;
    assert_eq!(before.ledger, 20);
    let wrong_master = SecretBytes::new(vec![0xa5; 32]);
    assert!(
        desktop_vault_canary::verify_persisted(
            &database,
            &wrong_master,
            proof.dataset_id(),
            proof.deployment_id(),
            proof.tenant_id(),
            proof.key_id(),
        )
        .await
        .is_err()
    );
    assert_eq!(bootstrap_write_counts(&database).await, before);

    let client = database.pool().get().await.unwrap();
    client
        .execute(
            "UPDATE openbot_internal.desktop_vault_canaries \
             SET encrypted_canary=encrypted_canary || '0' \
             WHERE deployment_id=$1 AND tenant_id=$2",
            &[&proof.deployment_id(), &proof.tenant_id()],
        )
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(
        &installation,
        &database,
        &package,
        DatabaseOrigin::RustManaged,
        &proof,
    )
    .await;
    assert_eq!(bootstrap_write_counts(&database).await, before);
    let client = database.pool().get().await.unwrap();
    let new_relations: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relname IN \
             ('sdk_gateway_connections','sdk_gateway_operations','sdk_gateway_secrets')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(new_relations, 0);
    let migration_0033: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM openbot_internal.schema_migrations WHERE version=33",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(migration_0033, 0);
    drop(client);

    database.close();
    running.stop().unwrap();
}

#[tokio::test]
#[ignore = "需要本机 PostgreSQL 17 binaries；设置 WROK_BOT_TEST_POSTGRES_BIN_DIR 后运行"]
async fn exact_instance_data_dir_bootstraps_fresh_then_rust_managed_membership() {
    let DesktopFixture {
        database,
        installation,
        port,
        mut running,
    } = start_desktop_fixture(None).await;
    let app_root = running.app_root.clone();
    let pool = database.pool();
    let package = loaded_package(installation.authority().auth_context().tenant().as_str());
    let fresh = database.fresh_initialization_proof().unwrap();
    let first_origin = installation
        .initialize_postgres_schema(&database, &package, &fresh)
        .await
        .unwrap();
    let proof = verified_canary(&database, &installation).await;
    let layout = desktop_vault_canary::verify_pre_upgrade_layout(pool)
        .await
        .unwrap();
    assert_eq!(layout.native_version(), native::NATIVE_LATEST_VERSION);
    let before_failures = bootstrap_write_counts(&database).await;
    assert_eq!(
        before_failures.ledger,
        i64::try_from(native::NATIVE_MIGRATION_COUNT).unwrap()
    );
    assert_eq!(before_failures.users, 0);
    assert_eq!(before_failures.agents, 0);
    assert_eq!(before_failures.channels, 0);
    assert_eq!(before_failures.memberships, 0);

    let wrong_master = SecretBytes::new(vec![0xa5; 32]);
    assert!(
        desktop_vault_canary::verify_persisted(
            &database,
            &wrong_master,
            proof.dataset_id(),
            proof.deployment_id(),
            proof.tenant_id(),
            proof.key_id(),
        )
        .await
        .is_err()
    );
    assert_eq!(bootstrap_write_counts(&database).await, before_failures);

    let persisted = desktop_vault_canary::read(pool, proof.deployment_id(), proof.tenant_id())
        .await
        .unwrap()
        .unwrap();
    let encrypted_canary = persisted.encrypted_canary().to_owned();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE openbot_internal.desktop_vault_canaries \
             SET encrypted_canary=encrypted_canary || '0' \
             WHERE deployment_id=$1 AND tenant_id=$2",
            &[&proof.deployment_id(), &proof.tenant_id()],
        )
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(&installation, &database, &package, first_origin, &proof).await;
    assert_eq!(
        desktop_vault_canary::read(pool, proof.deployment_id(), proof.tenant_id())
            .await
            .unwrap()
            .unwrap()
            .encrypted_canary(),
        format!("{encrypted_canary}0")
    );
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1 \
             WHERE deployment_id=$2 AND tenant_id=$3",
            &[
                &encrypted_canary,
                &proof.deployment_id(),
                &proof.tenant_id(),
            ],
        )
        .await
        .unwrap();
    drop(client);

    let client = pool.get().await.unwrap();
    client
        .execute(
            "DELETE FROM openbot_internal.desktop_vault_canaries \
             WHERE deployment_id=$1 AND tenant_id=$2",
            &[&proof.deployment_id(), &proof.tenant_id()],
        )
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(&installation, &database, &package, first_origin, &proof).await;
    assert!(
        desktop_vault_canary::read(pool, proof.deployment_id(), proof.tenant_id())
            .await
            .unwrap()
            .is_none()
    );
    let restored = desktop_vault_canary::DesktopVaultCanaryRow::new(
        persisted.dataset_id(),
        persisted.deployment_id(),
        persisted.tenant_id(),
        persisted.key_id(),
        encrypted_canary,
    )
    .unwrap();
    desktop_vault_canary::insert_once(pool, &restored)
        .await
        .unwrap();

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE public.r357_unexpected(id integer)")
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(&installation, &database, &package, first_origin, &proof).await;
    let client = pool.get().await.unwrap();
    assert!(
        client
            .query_one(
                "SELECT to_regclass('public.r357_unexpected') IS NOT NULL",
                &[],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    client
        .batch_execute("DROP TABLE public.r357_unexpected")
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE FUNCTION openbot_internal.r357_canary_hook() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; \
             CREATE TRIGGER r357_canary_hook BEFORE UPDATE ON \
             openbot_internal.desktop_vault_canaries FOR EACH ROW \
             EXECUTE FUNCTION openbot_internal.r357_canary_hook()",
        )
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(&installation, &database, &package, first_origin, &proof).await;
    let client = pool.get().await.unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*)::bigint FROM pg_trigger \
                 WHERE tgname='r357_canary_hook' AND NOT tgisinternal",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    client
        .batch_execute(
            "DROP TRIGGER r357_canary_hook ON openbot_internal.desktop_vault_canaries; \
             DROP FUNCTION openbot_internal.r357_canary_hook()",
        )
        .await
        .unwrap();
    drop(client);

    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) \
             WHERE version=32",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    completion_refusal_is_read_only(&installation, &database, &package, first_origin, &proof).await;
    let client = pool.get().await.unwrap();
    let checksum = native::native_0032_checksum();
    client
        .execute(
            "UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=32",
            &[&checksum],
        )
        .await
        .unwrap();
    drop(client);

    let second_admin =
        connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
            .await
            .unwrap();
    let second_admin = installation
        .attest_postgres_admin(second_admin)
        .await
        .unwrap();
    let second_database_owner = second_admin.connect_application(false).await.unwrap();
    assert!(matches!(
        installation
            .initialize_postgres_schema(&second_database_owner, &package, &fresh)
            .await,
        Err(DesktopLocalBootstrapError::VaultCanaryMismatch)
    ));
    completion_refusal_is_read_only(
        &installation,
        &second_database_owner,
        &package,
        first_origin,
        &proof,
    )
    .await;
    second_database_owner.close();
    let first = installation
        .complete_postgres_after_vault(&database, &package, first_origin, &proof)
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

    let second_origin = initialization::initialize(pool).await.unwrap();
    let second = installation
        .complete_postgres_after_vault(&database, &package, second_origin, &proof)
        .await
        .unwrap();
    assert_eq!(second.database_origin, DatabaseOrigin::RustManaged);
    assert_eq!(second.package.memberships_granted, 0);

    let DesktopFixture {
        database: other_database,
        installation: other_database_installation,
        port: _,
        running: mut other_running,
    } = start_desktop_fixture(Some(&app_root)).await;
    assert_eq!(
        other_database_installation.authority().instance_id(),
        installation.authority().instance_id()
    );
    let other_database_package = loaded_package(
        other_database_installation
            .authority()
            .auth_context()
            .tenant()
            .as_str(),
    );
    let other_database_fresh = other_database.fresh_initialization_proof().unwrap();
    let other_database_origin = other_database_installation
        .initialize_postgres_schema(
            &other_database,
            &other_database_package,
            &other_database_fresh,
        )
        .await
        .unwrap();
    completion_refusal_is_read_only(
        &other_database_installation,
        &other_database,
        &other_database_package,
        other_database_origin,
        &proof,
    )
    .await;
    other_database.close();
    other_running.stop().unwrap();

    let other_root = test_root();
    let other = DesktopLocalAuthorityStore::new(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&other_root).unwrap(),
    )
    .load_or_create_installation()
    .unwrap();
    let other_package = loaded_package(other.authority().auth_context().tenant().as_str());
    let other_proof = verified_canary(&database, &other).await;
    assert!(matches!(
        other
            .complete_postgres_after_vault(
                &database,
                &other_package,
                DatabaseOrigin::RustManaged,
                &other_proof,
            )
            .await,
        Err(DesktopLocalBootstrapError::PostgresDataDirectoryMismatch)
    ));
    fs::remove_dir_all(other_root).unwrap();

    database.close();
    running.stop().unwrap();
}
