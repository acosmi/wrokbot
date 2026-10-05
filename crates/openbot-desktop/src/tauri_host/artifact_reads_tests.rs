//! New public reader tests prepare genuine Local/Window authority and only owned sidecar roots.
//! This fixture is not release-signing, provider-network, or full R414 acceptance.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::desktop_vault::ReviewedDesktopVaultKeyStoreService;
use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
use crate::postgres_sidecar::{
    POSTGRES_SOURCE_SHA256, POSTGRES_VERSION, PostgresBundleDigest,
    ReviewedPostgresKeyStoreService, ReviewedPostgresSigningIdentity, VerifiedPostgresBundle,
};
use crate::tauri_background::{
    DesktopLocalApplicationInput, DesktopLocalReleaseInput, DesktopLocalRuntimeConfig,
    PreparedDesktopLocalRuntime, prepare_desktop_local_runtime,
};
use crate::{DesktopAgentBudgets, DesktopOpenAiProviderInput};
use http::{Method, Request, Response, StatusCode};
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_contracts::artifact_read_protocol::{
    ArtifactReadAcknowledged, ArtifactReadClosed, ArtifactReadOpened,
};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::ids::{BotId, RunId, thread::ThreadIdentity};
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

const PAYLOAD: &str = "genuine Local public artifact text";

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct OwnedRoot(PathBuf, bool);
impl OwnedRoot {
    fn new(label: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "openbot-public-read-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        let mut owned = Self(path, true);
        let before = std::fs::symlink_metadata(&owned.0).map_err(|error| error.to_string())?;
        let canonical = std::fs::canonicalize(&owned.0).map_err(|error| error.to_string())?;
        let after = std::fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
        require(
            before.file_type().is_dir()
                && !before.file_type().is_symlink()
                && after.file_type().is_dir()
                && !after.file_type().is_symlink()
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.uid() == after.uid()
                && before.mode() & 0o7777 == 0o700
                && after.mode() & 0o7777 == 0o700,
            "owned Local root canonicalization changed the original private inode",
        )?;
        owned.0 = canonical;
        Ok(owned)
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if !self.1 {
            eprintln!("PUBLIC_ARTIFACT_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "PUBLIC_ARTIFACT_LOCAL_OWNED_ROOT removed={} absent={}",
            removed.is_ok(),
            !self.0.exists()
        );
        if !std::thread::panicking() {
            assert!(
                removed.is_ok() && !self.0.exists(),
                "owned lifecycle root cleanup failed"
            );
        }
    }
}

#[derive(Default)]
struct MemorySecretStore(Mutex<BTreeMap<(String, String), Vec<u8>>>);
impl OsSecretStore for MemorySecretStore {
    fn read(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        self.0
            .lock()
            .map(|values| {
                values
                    .get(&(service.to_owned(), account.to_owned()))
                    .cloned()
                    .map(SecretBytes::new)
            })
            .map_err(|_| OsSecretStoreError::Unknown)
    }
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        self.0
            .lock()
            .map_err(|_| OsSecretStoreError::Unknown)?
            .insert((service.to_owned(), account.to_owned()), secret.to_vec());
        Ok(())
    }
}

struct OwnedBundle {
    root: OwnedRoot,
    digest: PostgresBundleDigest,
    signing: ReviewedPostgresSigningIdentity,
}
impl OwnedBundle {
    fn materialize() -> Result<Self, String> {
        let bin = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_PG_BIN")
                .ok_or("Root-owned PostgreSQL binary directory is required")?,
        );
        require(
            bin.is_absolute(),
            "owned PostgreSQL bin directory is not absolute",
        )?;
        let configuration = |option: &str| -> Result<String, String> {
            let output = Command::new(bin.join("pg_config"))
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .arg(option)
                .stdin(Stdio::null())
                .output()
                .map_err(|_| "matching pg_config unavailable")?;
            require(
                output.status.success()
                    && output.stdout.len() <= 4096
                    && output.stderr.len() <= 4096,
                "owned pg_config failed or was unbounded",
            )?;
            String::from_utf8(output.stdout)
                .map(|value| value.trim().to_owned())
                .map_err(|_| "pg_config output invalid".to_owned())
        };
        require(
            configuration("--version")? == format!("PostgreSQL {POSTGRES_VERSION}"),
            "owned PG installation is not the exact pinned version",
        )?;
        require(
            std::fs::canonicalize(configuration("--bindir")?).map_err(|error| error.to_string())?
                == std::fs::canonicalize(&bin).map_err(|error| error.to_string())?,
            "pg_config and actual binary installation differ",
        )?;
        let share = PathBuf::from(configuration("--sharedir")?);
        let library = PathBuf::from(configuration("--pkglibdir")?);
        require(
            share.is_absolute() && library.is_absolute(),
            "owned PG resource paths are not absolute",
        )?;
        let mut root = OwnedRoot::new("bundle")?;
        // Keep the actual sidecar bundle through any startup or shutdown uncertainty.
        root.1 = false;
        std::fs::create_dir(root.0.join("bin")).map_err(|error| error.to_string())?;
        std::fs::create_dir(root.0.join("share")).map_err(|error| error.to_string())?;
        std::fs::create_dir(root.0.join("lib")).map_err(|error| error.to_string())?;
        let mut copied_files = 0;
        let mut copied_bytes = 0;
        for name in ["postgres", "initdb", "pg_ctl"] {
            copy_resources(
                &bin.join(name),
                &root.0.join("bin").join(name),
                0,
                &mut copied_files,
                &mut copied_bytes,
            )?;
        }
        copy_resources(
            &share,
            &root.0.join("share/postgresql"),
            0,
            &mut copied_files,
            &mut copied_bytes,
        )?;
        copy_resources(
            &library,
            &root.0.join("lib/postgresql"),
            0,
            &mut copied_files,
            &mut copied_bytes,
        )?;
        for required in [
            "share/postgresql/postgres.bki",
            "share/postgresql/information_schema.sql",
            "lib/postgresql/plpgsql.dylib",
        ] {
            require(
                root.0.join(required).is_file(),
                "actual PG bootstrap resource missing",
            )?;
        }
        let mut files = BTreeMap::new();
        inventory_hashes(&root.0, &root.0, &mut files)?;
        let signing_text = "Developer ID Application: Example Product (ABCDE12345)";
        let signing = ReviewedPostgresSigningIdentity::from_reviewed_release(signing_text)
            .map_err(|error| error.to_string())?;
        let manifest = serde_json::json!({
            "schema": "openbot-postgres-sidecar-bundle", "schema_version": 1,
            "platform": "macos", "arch": std::env::consts::ARCH,
            "postgresql_version": POSTGRES_VERSION, "source_archive_sha256": POSTGRES_SOURCE_SHA256,
            "release_epoch": ENGINE_RELEASE_EPOCH, "minimum_compatible_core": env!("CARGO_PKG_VERSION"),
            "signing_identity": signing_text,
            "programs": { "postgres": "bin/postgres", "initdb": "bin/initdb", "pg_ctl": "bin/pg_ctl" },
            "files": files,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= 1024 * 1024,
            "owned PG manifest exceeded the existing bound",
        )?;
        std::fs::write(root.0.join("manifest.json"), &bytes).map_err(|error| error.to_string())?;
        let digest = PostgresBundleDigest::from_hex(&format!("{:x}", Sha256::digest(&bytes)))
            .map_err(|error| error.to_string())?;
        // Exact inventory/hash verification is real; this controlled fixture is not release-signing acceptance.
        VerifiedPostgresBundle::open(&root.0, digest, &signing)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            root,
            digest,
            signing,
        })
    }
    fn open(&self) -> Result<VerifiedPostgresBundle, String> {
        VerifiedPostgresBundle::open(&self.root.0, self.digest, &self.signing)
            .map_err(|error| error.to_string())
    }
}

fn copy_resources(
    source: &Path,
    destination: &Path,
    depth: usize,
    files: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    require(depth <= 32, "owned PG resource depth exceeded")?;
    let metadata = std::fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        std::fs::create_dir(destination).map_err(|error| error.to_string())?;
        for entry in std::fs::read_dir(source).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            copy_resources(
                &entry.path(),
                &destination.join(entry.file_name()),
                depth + 1,
                files,
                bytes,
            )?;
        }
    } else {
        require(
            metadata.is_file() && *files < 8192,
            "owned PG resource is not regular or file budget exceeded",
        )?;
        *bytes = bytes
            .checked_add(metadata.len())
            .filter(|bytes| *bytes <= 2 * 1024 * 1024 * 1024)
            .ok_or("owned PG resource byte budget exceeded")?;
        std::fs::copy(source, destination).map_err(|error| error.to_string())?;
        *files += 1;
    }
    Ok(())
}
fn inventory_hashes(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if std::fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            inventory_hashes(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "owned inventory escaped root")?
                .to_str()
                .ok_or("owned inventory is not UTF-8")?
                .to_owned();
            let mut file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 65_536];
            loop {
                let length = file.read(&mut buffer).map_err(|error| error.to_string())?;
                if length == 0 {
                    break;
                }
                digest.update(&buffer[..length]);
            }
            files.insert(relative, format!("{:x}", digest.finalize()));
        }
    }
    Ok(())
}

fn package(
    tenant: &str,
) -> Result<LoadedTenantPackage, openbot_application::tenant::package::TenantPackageError> {
    let files = TenantPackageFiles {
        brand: format!("tenant: {{ id: {tenant}, product_name: Desktop Local }}"),
        agents: "agents: [{ id: desktop-assistant, name: Assistant, title: Local Assistant, role_description: Help locally., type: built-in, system_prompt: Answer carefully. }]".to_owned(),
        channels: "channels: [{ id: desktop-home, name: Home, description: Local home., permitted_agents: [desktop-assistant], allowed_groups: [all] }]".to_owned(),
        model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }".to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files)?,
        "/controlled/public-artifact-read-local-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    assets: PathBuf,
    prepared: Option<PreparedDesktopLocalRuntime>,
    artifact: ArtifactRegistrationReceipt,
    postmaster_pid: u32,
}
impl LocalFixture {
    async fn new(bundle: &OwnedBundle, label: &str) -> Result<Self, String> {
        let mut root = OwnedRoot::new(label)?;
        let assets = root.0.join("assets");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|error| error.to_string())?;
        std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|error| error.to_string())?;
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|error| error.to_string())?;
        let release = DesktopLocalReleaseInput::new(
            &assets,
            "openbot",
            "main",
            bundle.open()?,
            ReviewedPostgresKeyStoreService::from_reviewed_release(
                "com.example.review.lifecycle-scram",
            )
            .map_err(|error| error.to_string())?,
            ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
                "com.example.review.lifecycle-vault",
            )
            .map_err(|error| error.to_string())?,
            Arc::new(MemorySecretStore::default()),
        )
        .map_err(|error| error.to_string())?;
        // No provider credential is stored, and this fixture never supplies a network reply.
        let application = DesktopLocalApplicationInput::new(
            DesktopOpenAiProviderInput::new(
                "https://api.example.test/v1",
                vec!["203.0.113.0/24".to_owned()],
            )
            .map_err(|error| error.to_string())?,
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        root.1 = false;
        let prepared = prepare_desktop_local_runtime(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root.0)
                .map_err(|error| error.to_string())?,
            DesktopLocalRuntimeConfig::new(release, application, |authority| {
                package(authority.auth_context().tenant().as_str())
            }),
        )
        .await
        .map_err(|error| error.to_string())?;
        let populated = async {
            prepared
                .protocol()
                .bind_window("main", prepared.auth_context().clone(), None)
                .map_err(|error| error.to_string())?;
            let auth = prepared
                .protocol()
                .windows
                .try_read()
                .map_err(|_| "actual window lock unavailable")?
                .get("main")
                .ok_or("actual main missing")?
                .auth
                .clone();
            let payload = PAYLOAD.to_owned();
            let begin = BeginThreadRun {
                thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy([9; 16]),
                run_id: RunId::new("actual/local-lifecycle-run"),
                bot_id: BotId::new("desktop-assistant"),
                anchor: ThreadRunAnchor::DirectBot,
                message: payload.clone(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            };
            require(
                matches!(
                    prepared
                        .application()
                        .execute(auth.clone(), AppCommand::BeginThreadRun(begin.clone()))
                        .await
                        .map_err(|error| error.to_string())?,
                    AppReply::ThreadRunStarted(_)
                ),
                "actual Local Begin did not return its durable receipt",
            )?;
            let source = format!("{}:input", begin.run_id.as_str());
            let receipt = prepared
                .application()
                .execute(
                    auth,
                    AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                        request_id: uuid::Uuid::now_v7().to_string(),
                        source_thread_id: begin.thread_id,
                        source_run_id: begin.run_id,
                        source_message_id: source,
                        expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
                    }),
                )
                .await
                .map_err(|error| error.to_string())?;
            let artifact = match receipt {
                AppReply::ArtifactRegistrationReceipt(receipt) => receipt,
                _ => return Err("actual Local Save returned another reply".to_owned()),
            };
            let mut pids = Vec::new();
            for entry in std::fs::read_dir(&root.0).map_err(|error| error.to_string())? {
                let path = entry.map_err(|error| error.to_string())?.path();
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("postgresql-17-"))
                    && path.is_dir()
                {
                    let pid = std::fs::read_to_string(path.join("postmaster.pid"))
                        .map_err(|error| error.to_string())?
                        .lines()
                        .next()
                        .ok_or("actual postmaster PID missing")?
                        .parse::<u32>()
                        .map_err(|_| "actual postmaster PID invalid")?;
                    require(pid > 1, "owned postmaster PID is invalid")?;
                    pids.push(pid);
                }
            }
            require(
                pids.len() == 1,
                "genuine Prepared did not own exactly one controlled sidecar",
            )?;
            Ok::<_, String>((artifact, pids[0]))
        }
        .await;
        match populated {
            Ok((artifact, postmaster_pid)) => {
                // Active sidecar resources must survive an unexpected test panic. Only
                // finish() may permit root removal after genuine shutdown and PID-gone proof.
                root.1 = false;
                eprintln!(
                    "PUBLIC_ARTIFACT_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={}",
                    root.0.display()
                );
                Ok(Self {
                    root,
                    assets,
                    prepared: Some(prepared),
                    artifact,
                    postmaster_pid,
                })
            }
            Err(error) => {
                let cleaned = prepared.shutdown().await;
                if cleaned.is_ok() {
                    root.1 = true;
                }
                require(
                    cleaned.is_ok(),
                    "failed real Prepared fixture setup cleanup did not ACK",
                )?;
                Err(error)
            }
        }
    }
    fn prepared(&self) -> &PreparedDesktopLocalRuntime {
        self.prepared
            .as_ref()
            .expect("actual Prepared not transferred yet")
    }
    fn new_protocol(&self) -> Result<Arc<DesktopTauriProtocol>, String> {
        let source = self
            .prepared()
            .protocol()
            .local_capability_authority
            .clone()
            .ok_or("actual Local identity source missing")?;
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(
                self.prepared().application().clone(),
            )),
        )
        .map(|protocol| Arc::new(protocol.with_current_identity_source(source)))
        .map_err(|error| error.to_string())
    }
    async fn finish(mut self) -> Result<(), String> {
        let closing_ok = match self.prepared.take() {
            Some(prepared) => prepared.shutdown().await.is_ok(),
            None => true,
        };
        self.root.1 = false;
        require(
            !owned_postmaster_live(self.postmaster_pid)?,
            "original owned postmaster PID survived real shutdown",
        )?;
        require(closing_ok, "genuine BackgroundOwner cleanup did not ACK")?;
        self.root.1 = true;
        eprintln!(
            "PUBLIC_ARTIFACT_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true",
            self.postmaster_pid
        );
        Ok(())
    }
}

fn owned_postmaster_live(pid: u32) -> Result<bool, String> {
    let status = Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "owned postmaster liveness observation failed")?;
    Ok(status.success())
}

fn request(
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Request<Vec<u8>>, String> {
    let body = body
        .map(|value| serde_json::to_vec(&value))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    Request::builder()
        .method(method)
        .uri(format!("openbot://localhost{path}"))
        .header("content-type", "application/json")
        .body(body)
        .map_err(|error| error.to_string())
}

fn open_request(artifact: &str) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        super::PREFIX,
        Some(serde_json::json!({"artifactId": artifact})),
    )
}

fn next_request(handle: &str, sequence: u32) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        &format!("{}/{handle}/next", super::PREFIX),
        Some(serde_json::json!({"sequence": sequence})),
    )
}

fn ack_request(handle: &str, sequence: u32) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        &format!("{}/{handle}/ack", super::PREFIX),
        Some(serde_json::json!({"sequence": sequence})),
    )
}

fn close_request(handle: &str) -> Result<Request<Vec<u8>>, String> {
    request(Method::DELETE, &format!("{}/{handle}", super::PREFIX), None)
}

async fn bridge(
    protocol: &DesktopTauriProtocol,
    label: &str,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let prepared = protocol
        .prepare_public_artifact_read_response(label, request)
        .await;
    protocol.finish_public_artifact_read_response(label, prepared, |response| response)
}

fn no_store(response: &Response<Vec<u8>>) -> Result<(), String> {
    require(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "actual Desktop public-reader response omitted no-store",
    )
}

fn control<T: serde::de::DeserializeOwned>(response: Response<Vec<u8>>) -> Result<T, String> {
    no_store(&response)?;
    require(
        response.status() == StatusCode::OK,
        "actual Desktop control did not succeed",
    )?;
    serde_json::from_slice(response.body()).map_err(|error| error.to_string())
}

fn status(response: Response<Vec<u8>>, expected: StatusCode) -> Result<(), String> {
    no_store(&response)?;
    require(
        response.status() == expected,
        "actual Desktop refusal had unexpected status",
    )?;
    require(
        !response
            .body()
            .windows(PAYLOAD.len())
            .any(|part| part == PAYLOAD.as_bytes()),
        "actual Desktop refusal exposed source text",
    )
}

fn data(
    response: &Response<Vec<u8>>,
    handle: &str,
    sequence: u32,
    eof: bool,
) -> Result<(), String> {
    no_store(response)?;
    require(
        response.status() == StatusCode::OK,
        "actual Desktop byte handoff did not succeed",
    )?;
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or("actual Desktop block header missing".to_owned())
    };
    require(
        header("x-artifact-read-handle")? == handle,
        "Desktop changed original handle",
    )?;
    require(
        header("x-artifact-read-sequence")?
            .parse::<u32>()
            .map_err(|error| error.to_string())?
            == sequence,
        "Desktop changed original sequence",
    )?;
    require(
        header("x-artifact-read-length")?
            .parse::<usize>()
            .map_err(|error| error.to_string())?
            == response.body().len(),
        "Desktop copy length differed from actual original descriptor",
    )?;
    require(
        header("x-artifact-read-eof")? == if eof { "true" } else { "false" },
        "Desktop EOF framing changed actual zero observation",
    )?;
    require(
        response.body().len() <= 4 * 1024 * 1024 && eof == response.body().is_empty(),
        "Desktop copy violated bounded actual block shape",
    )
}

struct CarrierGate {
    entered: tokio::sync::Notify,
    reached: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    release_changed: Condvar,
}

impl CarrierGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            reached: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            release_changed: Condvar::new(),
        })
    }

    fn hold_actual_thread(&self) {
        self.reached.store(true, Ordering::SeqCst);
        self.entered.notify_one();
        let held = self.released.lock().expect("owned gate mutex poisoned");
        let (released, timeout) = self
            .release_changed
            .wait_timeout_while(held, Duration::from_secs(5), |released| !*released)
            .expect("owned gate wait poisoned");
        self.timed_out
            .store(timeout.timed_out() && !*released, Ordering::SeqCst);
    }

    fn release(&self) {
        *self.released.lock().expect("owned gate mutex poisoned") = true;
        self.release_changed.notify_all();
    }

    async fn await_entered(&self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
            .await
            .map_err(|_| "actual same-response gate was not reached".to_owned())?;
        require(
            self.reached.load(Ordering::SeqCst) && !self.timed_out.load(Ordering::SeqCst),
            "actual same-response gate timed out",
        )
    }
}

struct ReleaseCarrierGate(Arc<CarrierGate>);
impl Drop for ReleaseCarrierGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct CopyTailSubscriber(Arc<CarrierGate>);
impl tracing::Subscriber for CopyTailSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Phase(bool);
        impl tracing::field::Visit for Phase {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "public_artifact_read_host_phase"
                    && value == "desktop_copy_complete_before_final_tail"
                {
                    self.0 = true;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut phase = Phase(false);
        event.record(&mut phase);
        if phase.0 {
            self.0.hold_actual_thread();
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local PostgreSQL bundle"]
async fn actual_prepared_local_public_reader_uses_shared_responder_bridge_and_eof() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-bridge")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        let opened: ArtifactReadOpened = control(
            bridge(
                protocol,
                "main",
                open_request(&fixture.artifact.artifact_id)?,
            )
            .await,
        )?;
        require(
            opened.artifact_id == fixture.artifact.artifact_id
                && opened.byte_length == PAYLOAD.len() as u64
                && opened.sha256 == format!("{:x}", Sha256::digest(PAYLOAD.as_bytes()))
                && opened.remaining_millis > 0
                && opened.remaining_millis <= 600_000,
            "Local Open did not use actual original prepared facts",
        )?;
        let prepared = protocol
            .prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?)
            .await;
        let called = AtomicBool::new(false);
        let response =
            protocol.finish_public_artifact_read_response("main", prepared, |response| {
                called.store(true, Ordering::SeqCst);
                response
            });
        require(
            called.load(Ordering::SeqCst),
            "shared real responder bridge was bypassed",
        )?;
        data(&response, &opened.handle_id, 0, false)?;
        require(
            response.body().as_slice() == PAYLOAD.as_bytes(),
            "actual Local bytes changed original text",
        )?;
        // This callback's returned Vec is a framework/test copy, not the original RAII carrier.
        // The real finish path has now returned and dropped its controlled original owner.
        status(
            protocol
                .handle("main", next_request(&opened.handle_id, 0)?)
                .await,
            StatusCode::CONFLICT,
        )?;
        let ack: ArtifactReadAcknowledged = control(
            protocol
                .handle("main", ack_request(&opened.handle_id, 0)?)
                .await,
        )?;
        let duplicate: ArtifactReadAcknowledged =
            control(bridge(protocol, "main", ack_request(&opened.handle_id, 0)?).await)?;
        require(
            ack == duplicate && ack.handle_id == opened.handle_id && ack.sequence == 0,
            "Local matching ACK retry changed original accepted sequence",
        )?;
        status(
            protocol
                .handle(
                    "main",
                    request(
                        Method::DELETE,
                        &format!("{}/{}/", super::PREFIX, opened.handle_id),
                        None,
                    )?,
                )
                .await,
            StatusCode::NOT_FOUND,
        )?;
        let eof = protocol
            .handle("main", next_request(&opened.handle_id, 1)?)
            .await;
        data(&eof, &opened.handle_id, 1, true)?;
        require(
            response.body().as_slice() == PAYLOAD.as_bytes(),
            "original cleanup falsely claimed framework-transferred Vec destruction",
        )?;
        Ok(())
    }
    .await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local public bridge/eof and resource closure");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local and actual bounded copy-tail barrier"]
async fn actual_prepared_local_public_reader_copy_tail_and_rebinding_withhold_data() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-copy-tail")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        let opened: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)?;
        let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?).await;
        let gate = CarrierGate::new();
        let release = ReleaseCarrierGate(gate.clone());
        let worker_protocol = protocol.clone();
        let worker_gate = gate.clone();
        let worker = tokio::task::spawn_blocking(move || {
            tracing::subscriber::with_default(CopyTailSubscriber(worker_gate), || {
                worker_protocol.finish_public_artifact_read_response("main", prepared, |response| response)
            })
        });
        let changed = async {
            gate.await_entered().await?;
            protocol.unbind_window("main").map_err(|error| error.to_string())?;
            protocol.bind_window("main", fixture.prepared().auth_context().clone(), None)
                .map_err(|error| error.to_string())?;
            require(!gate.timed_out.load(Ordering::SeqCst), "real copy gate expired before original rebinding")
        }.await;
        gate.release();
        let response = worker.await.map_err(|error| error.to_string())?;
        drop(release);
        changed?;
        require(!gate.timed_out.load(Ordering::SeqCst), "real copy tail resumed only after timeout")?;
        status(response, StatusCode::UNAUTHORIZED)?;
        let fresh: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)?;
        let foreign = fixture.new_protocol()?;
        foreign.bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        status(foreign.handle("main", next_request(&fresh.handle_id, 0)?).await,
            StatusCode::NOT_FOUND)?;
        foreign.close_request_bindings();
        let response = protocol.handle("main", next_request(&fresh.handle_id, 0)?).await;
        data(&response, &fresh.handle_id, 0, false)?;
        require(response.body().as_slice() == PAYLOAD.as_bytes(), "foreign owner closure destroyed current original reader")?;
        let closed: ArtifactReadClosed = control(bridge(protocol, "main", close_request(&fresh.handle_id)?).await)?;
        require(closed.handle_id == fresh.handle_id, "Local Close changed original handle")?;
        let prepared_control = protocol.prepare_public_artifact_read_response("main", open_request(&fixture.artifact.artifact_id)?).await;
        protocol.unbind_window("main").map_err(|error| error.to_string())?;
        protocol.bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        status(protocol.finish_public_artifact_read_response("main", prepared_control, |response| response),
            StatusCode::UNAUTHORIZED)?;
        status(protocol.handle("main", request(Method::POST, "/api/artifact-reads?", Some(
            serde_json::json!({"artifactId": fixture.artifact.artifact_id})))?).await, StatusCode::BAD_REQUEST)?;
        status(protocol.handle("main", request(Method::POST, super::PREFIX, Some(
            serde_json::json!({"artifactId": fixture.artifact.artifact_id, "path": "/forbidden"})))?).await,
            StatusCode::BAD_REQUEST)?;
        status(protocol.handle("main", request(Method::HEAD, super::PREFIX, None)?).await,
            StatusCode::METHOD_NOT_ALLOWED)?;
        let oversized = Request::builder().method(Method::POST).uri("openbot://localhost/api/artifact-reads")
            .header("content-type", "application/json").body(vec![b'x'; super::API_BODY_MAX_BYTES + 1])
            .map_err(|error| error.to_string())?;
        status(protocol.handle("main", oversized).await, StatusCode::PAYLOAD_TOO_LARGE)?;
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local copy/window tail and physical cleanup");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local and held actual responder carrier"]
async fn actual_prepared_local_public_reader_close_isolated_original_resources() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-own-close")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        protocol.bind_window("peer", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        let original: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)?;
        let peer: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)?;
        status(protocol.handle("peer", next_request(&original.handle_id, 0)?).await, StatusCode::NOT_FOUND)?;
        let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&original.handle_id, 0)?).await;
        let original_close_request = close_request(&original.handle_id)?;
        let gate = CarrierGate::new();
        let release = ReleaseCarrierGate(gate.clone());
        let worker_protocol = protocol.clone();
        let worker_gate = gate.clone();
        let responder = tokio::task::spawn_blocking(move || {
            worker_protocol.finish_public_artifact_read_response("main", prepared, |response| {
                // The original transport block remains truly owned until this actual callback returns.
                worker_gate.hold_actual_thread();
                response
            })
        });
        let mut closing = Box::pin(protocol.handle("main", original_close_request));
        let while_held = async {
            gate.await_entered().await?;
            require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                "Local Close falsely ACKed while the actual responder still owned original allocation")?;
            let peer_data = protocol.handle("peer", next_request(&peer.handle_id, 0)?).await;
            data(&peer_data, &peer.handle_id, 0, false)?;
            require(peer_data.body().as_slice() == PAYLOAD.as_bytes(), "own Close blocked another real Window's bytes")?;
            let peer_closed: ArtifactReadClosed = control(protocol.handle("peer", close_request(&peer.handle_id)?).await)?;
            require(peer_closed.handle_id == peer.handle_id, "peer Close borrowed original resource inventory")?;
            require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                "peer completion falsely closed a still-held original responder owner")
        }.await;
        gate.release();
        let response = responder.await.map_err(|error| error.to_string())?;
        drop(release);
        let closed = tokio::time::timeout(Duration::from_secs(4), &mut closing).await
            .map_err(|_| "original real responder return did not unblock own Close")?;
        while_held?;
        require(!gate.timed_out.load(Ordering::SeqCst), "actual responder was released only by timeout")?;
        data(&response, &original.handle_id, 0, false)?;
        let closed: ArtifactReadClosed = control(closed)?;
        require(closed.handle_id == original.handle_id, "real original Close returned another Window's handle")?;
        protocol.unbind_window("main").map_err(|error| error.to_string())?;
        let surviving: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)?;
        let survived = protocol.handle("peer", next_request(&surviving.handle_id, 0)?).await;
        data(&survived, &surviving.handle_id, 0, false)?;
        let _: ArtifactReadClosed = control(protocol.handle("peer", close_request(&surviving.handle_id)?).await)?;
        protocol.unbind_window("peer").map_err(|error| error.to_string())?;
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local isolated original resource closure");
}
