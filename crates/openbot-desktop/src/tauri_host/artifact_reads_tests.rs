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
use std::time::{Duration, Instant};

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
                        .map_err(|error| {
                            if label == "public-read-cached-cleanup" {
                                eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC phase=BeginThreadRun original_app_error={error}");
                            }
                            error.to_string()
                        })?,
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
                .await;
            if label == "public-read-cached-cleanup" {
                if let Err(error) = &receipt {
                    eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC phase=SaveRunMessageTextArtifact original_app_error={error}");
                    let schema = openbot_infra::artifact_administration::verify_artifact_registration_schema(prepared.pool()).await;
                    eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC phase=post_original_Save_error legacy41_42={schema:?}");
                    if matches!(&schema, Err(openbot_application::ArtifactAdministrationError::Corrupt { field: "registration_schema" })) {
                        let expected = serde_json::from_str::<serde_json::Value>(include_str!("../../../../fixtures/db/artifact-registration-0042.json"));
                        let actual = openbot_infra::artifact_administration::capture_artifact_registration_schema(prepared.pool()).await;
                        match (expected, actual) {
                            (Ok(expected), Ok(actual)) => {
                                let mut paths = Vec::new();
                                cleanup_cached_schema_difference_paths(&expected, &actual, "", &mut paths);
                                eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC legacy42_difference_paths={paths:?} path_limit=16 values_omitted=true");
                            }
                            (Err(_), _) => eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC fixed_original_oracle_decode_failed=true"),
                            (_, Err(error)) => eprintln!("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC legacy42_capture_error={error:?}"),
                        }
                    }
                }
            }
            // Preserve the original Save outcome; diagnostics never retry or replace it.
            let receipt = receipt.map_err(|error| error.to_string())?;
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
    )
    .map_err(|message| format!("{message}: status={}", response.status().as_u16()))?;
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
        let original: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("original_open: {error}"))?;
        let peer: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("peer_open: {error}"))?;
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
            let peer_closed: ArtifactReadClosed = control(protocol.handle("peer", close_request(&peer.handle_id)?).await)
                .map_err(|error| format!("peer_close: {error}"))?;
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
        let closed: ArtifactReadClosed = control(closed)
            .map_err(|error| format!("original_close: {error}"))?;
        require(closed.handle_id == original.handle_id, "real original Close returned another Window's handle")?;
        protocol.unbind_window("main").map_err(|error| error.to_string())?;
        let surviving: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("surviving_open: {error}"))?;
        let survived = protocol.handle("peer", next_request(&surviving.handle_id, 0)?).await;
        data(&survived, &surviving.handle_id, 0, false)?;
        let _: ArtifactReadClosed = control(protocol.handle("peer", close_request(&surviving.handle_id)?).await)
            .map_err(|error| format!("surviving_close: {error}"))?;
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

// Controlled 0044 rows are consumer inputs only. These observations never assert deletion,
// directory sync, refund, cleanup authorization or a producer receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine owned Prepared Local and actual shared copy/responder owners"]
async fn shared_read_barrier_waits_for_desktop_copy_and_responder_tail() {
    use tracing::instrument::WithSubscriber as _;
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "shared-local-copy-responder")
        .await
        .expect("genuine owned Prepared Local setup");
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let outcome = async {
        let auth = {
            protocol.windows.try_read().map_err(|_| "actual original window registry unavailable")?
                .get("main").ok_or("actual original main Window missing")?.auth.clone()
        };
        // Both keys are materialized by the real already-assembled Local Application/Save.
        let saved_b = fixture.prepared().application().execute(auth.clone(),
            AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: uuid::Uuid::now_v7().to_string(),
                source_thread_id: fixture.artifact.source_thread_id.clone(),
                source_run_id: fixture.artifact.source_run_id.clone(),
                source_message_id: fixture.artifact.source_message_id.clone(),
                expected_sha256: format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
            }),
        ).await.map_err(|error| error.to_string())?;
        let saved_b = match saved_b {
            AppReply::ArtifactRegistrationReceipt(saved) => saved,
            _ => return Err("second actual Local Save returned another receipt".to_owned()),
        };
        require(saved_b.artifact_id != fixture.artifact.artifact_id && saved_b.operation_id != fixture.artifact.operation_id,
            "Local responder leg did not use a different actual saved key")?;
        for (saved, copy_tail) in [(&fixture.artifact, true), (&saved_b, false)] {
            let record = actual.observe_read_record(&auth, &saved.artifact_id).await.map_err(|error| error.to_string())?;
            let path = fixture.root.0.join("artifacts/objects").join(&saved.artifact_id);
            require(cleanup_owned_inode_fds(&path)?.is_empty(), "Local key began with an unexpected reader FD")?;
            let phases = Arc::new(CleanupCachedIoPhases::default());
            let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
            let opened: ArtifactReadOpened = control(bridge(&protocol, "main", open_request(&saved.artifact_id)?)
                .with_subscriber(dispatch.clone()).await)?;
            let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?)
                .with_subscriber(dispatch).await;
            let io_before = phases.io.load(Ordering::SeqCst);
            let joint_before = phases.joint.load(Ordering::SeqCst);
            let segments_before = phases.segments.load(Ordering::SeqCst);
            require(io_before == 1 && joint_before >= 2,
                "real Local preparation/cached refresh did not complete its original IO and final joint query")?;
            let client = fixture.prepared().pool().get().await.map_err(|error| error.to_string())?;
            let before = cleanup_public_read_facts_on(&client).await?;
            drop(client);
            let gate = CarrierGate::new();
            let release = ReleaseCarrierGate(gate.clone());
            let worker_protocol = protocol.clone();
            let worker_gate = gate.clone();
            let worker = tokio::task::spawn_blocking(move || {
                if copy_tail {
                    tracing::subscriber::with_default(CopyTailSubscriber(worker_gate), || {
                        worker_protocol.finish_public_artifact_read_response("main", prepared, |response| response)
                    })
                } else {
                    worker_protocol.finish_public_artifact_read_response("main", prepared, |response| {
                        // Keep the actual original transport allocation until the real callback returns.
                        worker_gate.hold_actual_thread();
                        response
                    })
                }
            });
            let observed = async {
                gate.await_entered().await?;
                require(cleanup_owned_inode_fds(&path)?.len() == 1, "held actual Local copy/responder did not retain its original FD")?;
                let barrier = actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
                require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(),
                    "shared Local close ACKed before the original actual copy/responder owner ended")?;
                require(cleanup_owned_inode_fds(&path)?.len() == 1, "shared close dropped a still-used Local FD")?;
                Ok::<_, String>(barrier)
            }.await;
            gate.release();
            let response = worker.await.map_err(|error| error.to_string())?;
            drop(release);
            let barrier = observed?;
            require(!gate.timed_out.load(Ordering::SeqCst), "actual Local owner ended only because its gate timed out")?;
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(4)).await.map_err(|error| format!("{error:?}"))?;
            require(cleanup_owned_inode_fds(&path)?.is_empty() && path.is_file(),
                "actual Local original block ended without FD closure or deleted the object")?;
            if copy_tail {
                status(response, StatusCode::SERVICE_UNAVAILABLE)?;
            } else {
                data(&response, &opened.handle_id, 0, false)?;
                require(response.body().as_slice() == PAYLOAD.as_bytes(),
                    "controlled Local ACK falsely claimed returned response Vec destruction")?;
                drop(response);
            }
            require(phases.io.load(Ordering::SeqCst) == io_before
                && phases.joint.load(Ordering::SeqCst) == joint_before
                && phases.segments.load(Ordering::SeqCst) == segments_before,
                "shared synchronous Local copy/responder was mistaken for another IO or PG wait")?;
            let client = fixture.prepared().pool().get().await.map_err(|error| error.to_string())?;
            let after = cleanup_public_read_facts_on(&client).await?;
            drop(client);
            require(before == after, "shared Local close mutated original business/charge/receipt/fence/audit/identity facts")?;
            drop(ack); drop(barrier); drop(record);
            eprintln!("ARTIFACT_SHARED_LOCAL copy_tail={copy_tail} actual_owner_held_no_ack=true real_callback_joined=true original_fd_absent=true controlled_ack=true io_joint_unchanged=true pg_wait=false returned_response_lifetime=UNTRACKED");
        }
        Ok::<_, String>(())
    }.await;
    // Retire every extra test owner before the actual runtime shutdown/PID proof.
    drop(protocol);
    drop(actual);
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual shared Local copy/responder owners and original physical closure");
}

const CLEANUP_PUBLIC_READ_FACTS: &str = "SELECT jsonb_build_object( \
 'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY to_jsonb(b)::text),'[]') FROM openbot_internal.artifact_dataset_bindings b), \
 'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
 'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
 'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
 'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]') FROM openbot_internal.artifact_store_bindings s), \
 'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
 'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
 'fences',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]') FROM openbot_internal.artifact_cleanup_fences f), \
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text),'[]') FROM public.audit_events e), \
 'users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY to_jsonb(u)::text),'[]') FROM public.users u), \
 'roles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM public.user_roles r), \
 'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.sessions s), \
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]') FROM public.messages m))";

async fn cleanup_public_read_facts_on(
    client: &tokio_postgres::Client,
) -> Result<serde_json::Value, String> {
    client
        .query_one(CLEANUP_PUBLIC_READ_FACTS, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[derive(Default)]
struct CleanupCachedIoPhases {
    io: std::sync::atomic::AtomicUsize,
    joint: std::sync::atomic::AtomicUsize,
    segments: std::sync::atomic::AtomicUsize,
}
impl CleanupCachedIoPhases {
    fn actual_counts(&self) -> (usize, usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.io.load(Ordering::SeqCst),
            self.joint.load(Ordering::SeqCst),
            self.segments.load(Ordering::SeqCst),
        )
    }
}
struct CleanupCachedPhaseVisitor {
    io: bool,
    joint: bool,
    segment: bool,
}
impl tracing::field::Visit for CleanupCachedPhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match (field.name(), value) {
            ("artifact_read_phase", "actual_io_completed_before_joint") => self.io = true,
            ("artifact_read_phase", "joint_statement_ready") => self.joint = true,
            ("artifact_read_lifecycle_phase", "physical_segment_completed_before_more_io") => {
                self.segment = true
            }
            _ => {}
        }
    }
}
struct CleanupCachedPhaseSubscriber(Arc<CleanupCachedIoPhases>);
impl tracing::Subscriber for CleanupCachedPhaseSubscriber {
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
        use std::sync::atomic::Ordering;
        let mut visitor = CleanupCachedPhaseVisitor {
            io: false,
            joint: false,
            segment: false,
        };
        event.record(&mut visitor);
        if visitor.io {
            self.0.io.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.joint {
            self.0.joint.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.segment {
            self.0.segments.fetch_add(1, Ordering::SeqCst);
        }
    }
}

async fn arm_cached_first_cleanup_fence(
    pool: &openbot_infra::db::pool::DatabasePool,
    deployment: &str,
    tenant: &str,
    owner: &str,
    receipt: &ArtifactRegistrationReceipt,
) -> Result<serde_json::Value, String> {
    let mut controller = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let inserted: serde_json::Value = transaction.query_one(
        "INSERT INTO openbot_internal.artifact_cleanup_fences \
         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
         SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
         FROM openbot_internal.artifact_records \
         WHERE deployment_id=$1 AND tenant_id=$2 AND operation_id=$3 AND artifact_id=$4 AND owner_actor_id=$5 \
         RETURNING to_jsonb(artifact_cleanup_fences)",
        &[&deployment, &tenant, &receipt.operation_id, &receipt.artifact_id, &owner],
    ).await.map_err(|error| error.to_string())?
        .try_get(0).map_err(|error| error.to_string())?;
    require(
        inserted["operation_id"] == receipt.operation_id
            && inserted["artifact_id"] == receipt.artifact_id
            && inserted["terminal_status"] == "deleted"
            && inserted["phase"] == "armed",
        "controlled consumer fence did not retain the original pair and intent",
    )?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(inserted)
}

// Read only this Rust process's bounded f/device/inode inventory. No path fields or peer PIDs.
fn cleanup_owned_inode_fds(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<std::collections::BTreeSet<u32>, String> {
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
        let mut found = std::collections::BTreeSet::new();
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
    Ok(first)
}

fn cleanup_cached_schema_difference_paths(
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    path: &str,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    if expected == actual || out.len() >= 16 {
        return;
    }
    match (expected, actual) {
        (Value::Object(left), Value::Object(right)) => {
            for (key, value) in left {
                if out.len() >= 16 {
                    return;
                }
                let next = format!("{path}/{key}");
                match right.get(key) {
                    Some(other) => cleanup_cached_schema_difference_paths(value, other, &next, out),
                    None => out.push(next),
                }
            }
            if out.len() < 16 && right.keys().any(|key| !left.contains_key(key)) {
                out.push(format!("{path}/<unexpected-object-key>"));
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                out.push(format!("{path}/<array-length>"));
            }
            for (index, (value, other)) in left.iter().zip(right).enumerate() {
                if out.len() >= 16 {
                    return;
                }
                cleanup_cached_schema_difference_paths(
                    value,
                    other,
                    &format!("{path}/{index}"),
                    out,
                );
            }
        }
        _ => out.push(path.to_owned()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local, committed 0044 consumer fence and original retained reader"]
async fn actual_prepared_local_public_reader_cached_first_cleanup_fence_recheck_refuses_body() {
    use tracing::instrument::WithSubscriber as _;
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-cached-cleanup")
        .await
        .expect("genuine owned Prepared Local setup");
    let outcome = async {
        let prepared = fixture.prepared();
        let protocol = prepared.protocol();
        let path = fixture.root.0.join("artifacts/objects").join(&fixture.artifact.artifact_id);
        require(cleanup_owned_inode_fds(&path)?.is_empty(),
            "owned saved Local artifact unexpectedly began with a live read FD")?;
        let tracker = protocol.local_capability_authority.as_ref()
            .and_then(|source| source.artifact_read_lifecycle())
            .ok_or("same genuine Local artifact lifecycle unavailable")?;
        let phases = Arc::new(CleanupCachedIoPhases::default());
        let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
        let opened: ArtifactReadOpened = control(
            bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?)
                .with_subscriber(dispatch.clone()).await,
        )?;
        require(opened.artifact_id == fixture.artifact.artifact_id
            && opened.byte_length == PAYLOAD.len() as u64
            && opened.sha256 == format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
            "genuine Prepared Local Open did not retain original Save facts")?;
        let after_open = phases.actual_counts();
        require(after_open.0 == 1 && after_open.1 >= 2,
            "successful genuine Local Open did not complete original physical prefix and current queries")?;
        require(!cleanup_owned_inode_fds(&path)?.is_empty(),
            "successful Local Open did not retain its actual original object FD")?;
        let client = prepared.pool().get().await.map_err(|error| error.to_string())?;
        let mut expected = cleanup_public_read_facts_on(&client).await?;
        require(expected["fences"] == serde_json::json!([]),
            "owned cached-first Local fixture unexpectedly began fenced")?;
        drop(client);
        let original_auth = prepared.auth_context();
        let inserted = arm_cached_first_cleanup_fence(
            prepared.pool(), original_auth.deployment().as_str(), original_auth.tenant().as_str(),
            original_auth.actor().as_str(), &fixture.artifact,
        ).await?;
        expected["fences"] = serde_json::json!([inserted]);
        // The actual transaction's COMMIT ACK precedes this same handle's delayed seq0 request.
        let response = bridge(protocol, "main", next_request(&opened.handle_id, 0)?)
            .with_subscriber(dispatch).await;
        no_store(&response)?;
        require(response.status() == StatusCode::SERVICE_UNAVAILABLE,
            "delayed genuine Local cached first did not refuse its committed armed fence")?;
        require(["x-artifact-read-handle", "x-artifact-read-sequence",
            "x-artifact-read-length", "x-artifact-read-eof"].iter()
            .all(|name| response.headers().get(*name).is_none()),
            "Local cleanup-fence refusal retained data descriptor headers")?;
        let error: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| error.to_string())?;
        require(error == serde_json::json!({"code":"dependency_unavailable"})
            && !response.body().windows(PAYLOAD.len()).any(|part| part == PAYLOAD.as_bytes()),
            "Local cleanup refusal exposed cached payload or changed original static error")?;
        drop(response);
        let after_refusal = phases.actual_counts();
        require(after_refusal.0 == after_open.0
            && after_refusal.2 == after_open.2 && after_refusal.1 == after_open.1 + 1,
            "genuine cached first refusal repeated physical prefix work or omitted the real final query")?;
        // Prepared Local keeps per-operation Completion inside the real application's registry.
        // This existing protocol closes and awaits only this actual authority's fixture inventory;
        // its ACK requires jobs and physical resource owners to end. No replacement Completion is used.
        prepared.application().close_public_artifact_reads().map_err(|error| error.to_string())?;
        tracker.close();
        tracker.drain_before(std::time::Instant::now() + Duration::from_secs(5)).await
            .map_err(|_| "same Prepared Local read inventory did not actually drain".to_owned())?;
        require(cleanup_owned_inode_fds(&path)?.is_empty(),
            "original Local object inode retained a live FD after actual inventory drain ACK")?;
        let client = prepared.pool().get().await.map_err(|error| error.to_string())?;
        require(cleanup_public_read_facts_on(&client).await? == expected,
            "Local cached first consumer changed original source, receipt, record, charge, quota, store, fence, audit or host facts")?;
        require(std::fs::read(&path).map_err(|error| error.to_string())? == PAYLOAD.as_bytes(),
            "consumer fence changed the original owned Local artifact bytes")?;
        eprintln!("PUBLIC_ARTIFACT_LOCAL_CACHED_CLEANUP original_prepared_open=true controller_commit_ack=true seq0_refused=true no_store=true no_payload=true original_io_ack_count={} final_query_increment=1 same_authority_fixture_inventory_drain_ack=true own_inode_fd_absent=true business_facts_unchanged=true",
            after_open.0);
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("genuine Prepared Local cached first cleanup-fence refusal and physical closure");
}

async fn cleanup_arm_local_database_facts(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let tables=c.query("SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','openbot_internal') AND c.relkind='r' ORDER BY n.nspname,c.relname",&[]).await.map_err(|e|e.to_string())?;
    let mut facts = BTreeMap::new();
    for row in tables {
        let schema: String = row.get(0);
        let name: String = row.get(1);
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let sql = format!(
            "SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(t),'xmin',t.xmin::text,'ctid',t.ctid::text) ORDER BY to_jsonb(t)::text,t.ctid),'[]'::jsonb) FROM {}.{} t",
            quote(&schema),
            quote(&name)
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
fn cleanup_arm_local_only_tables_changed(
    before: &BTreeMap<String, serde_json::Value>,
    after: &BTreeMap<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), String> {
    require(
        before.keys().eq(after.keys()),
        "Local controller/arm changed ordinary table inventory",
    )?;
    for (table, value) in before {
        if !allowed.contains(&table.as_str()) && after.get(table) != Some(value) {
            return Err(format!(
                "Local arm changed unexpected ordinary/physical table: {table}"
            ));
        }
    }
    Ok(())
}
fn cleanup_arm_local_object_fact(
    path: &Path,
) -> Result<(u64, u64, u32, u32, u64, u64, String), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        m.is_file() && m.mode() & 0o7777 == 0o400 && m.nlink() == 1,
        "Local original artifact inode/type/mode changed",
    )?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.len(),
        format!("{:x}", Sha256::digest(&bytes)),
    ))
}
async fn cleanup_arm_local_waiter(
    pool: &openbot_infra::db::pool::DatabasePool,
    controller_pid: i32,
) -> Result<(i32, i32), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let observer = pool.get().await.map_err(|e| e.to_string())?;
        let observer_pid: i32 = observer
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let rows=observer.query("SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event_type='Lock' AND query LIKE '%artifact_workspace_quotas%' AND $1::integer=ANY(pg_catalog.pg_blocking_pids(pid))",&[&controller_pid]).await.map_err(|e|e.to_string())?;
        if rows.len() == 1 {
            let waiter: i32 = rows[0].get(0);
            require(
                waiter != controller_pid
                    && waiter != observer_pid
                    && controller_pid != observer_pid,
                "Local original waiter/controller/observer PIDs were not distinct",
            )?;
            return Ok((waiter, observer_pid));
        }
        require(
            Instant::now() < deadline,
            "Local arm did not reach the actual owned quota PG lock",
        )?;
        drop(observer);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires genuine Prepared Local/Window, owned PostgreSQL bundle and real Save/arm"]
async fn actual_local_original_window_arms_missing_source_and_rebound_window_is_refused() {
    use openbot_infra::artifact_administration::ArtifactCleanupArmError as ArmError;
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "cleanup-arm-original-window")
        .await
        .expect("genuine Prepared Local setup");
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let outcome=async {
        let original_auth=protocol.windows.try_read().map_err(|_|"original Window registry unavailable")?.get("main").ok_or("original actual main Window missing")?.auth.clone();
        let second=fixture.prepared().application().execute(original_auth.clone(),AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact{
            request_id:uuid::Uuid::now_v7().to_string(),source_thread_id:fixture.artifact.source_thread_id.clone(),source_run_id:fixture.artifact.source_run_id.clone(),source_message_id:fixture.artifact.source_message_id.clone(),expected_sha256:format!("{:x}",Sha256::digest(PAYLOAD.as_bytes())),
        })).await.map_err(|e|e.to_string())?;
        let second=match second {AppReply::ArtifactRegistrationReceipt(r)=>r,_=>return Err("second genuine Local Save returned another reply".to_owned())};
        require(second.artifact_id!=fixture.artifact.artifact_id&&second.operation_id!=fixture.artifact.operation_id,"Local refusal key reused the already armed original operation")?;
        let path=fixture.root.0.join("artifacts/objects").join(&fixture.artifact.artifact_id);
        let second_path=fixture.root.0.join("artifacts/objects").join(&second.artifact_id);
        let first_object=cleanup_arm_local_object_fact(&path)?;let second_object=cleanup_arm_local_object_fact(&second_path)?;
        let opened:ArtifactReadOpened=control(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await)?;
        require(opened.artifact_id==fixture.artifact.artifact_id&&cleanup_owned_inode_fds(&path)?.len()==1,"original actual Local cached reader has no real original key/FD")?;
        let before_source=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let mut controller=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let tx=controller.transaction().await.map_err(|e|e.to_string())?;
        let source_controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        require(tx.execute("DELETE FROM public.messages WHERE message_id=$1",&[&fixture.artifact.source_message_id]).await.map_err(|e|e.to_string())?==1,"Local source controller did not hard-delete the original message")?;
        tx.commit().await.map_err(|e|e.to_string())?;drop(controller);
        let after_source=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        cleanup_arm_local_only_tables_changed(&before_source,&after_source,&["public.messages"])?;
        let original_messages=before_source.get("public.messages").and_then(serde_json::Value::as_array).ok_or("original Local messages missing")?;
        let current_messages=after_source.get("public.messages").and_then(serde_json::Value::as_array).ok_or("current Local messages missing")?;
        let retained_messages:Vec<_>=original_messages.iter().filter(|v|v["row"]["message_id"].as_str()!=Some(fixture.artifact.source_message_id.as_str())).cloned().collect();
        require(retained_messages.len()+1==original_messages.len()&&retained_messages==*current_messages,"Local source controller changed undeclared messages or physical row carriers")?;
        require(before_source.get("public.messages")!=after_source.get("public.messages"),"Local source controller did not commit a real source row difference")?;
        status(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await,StatusCode::NOT_FOUND)?;
        require(matches!(fixture.prepared().application().execute(original_auth.clone(),AppCommand::GetArtifactMetadata(openbot_contracts::artifacts::GetArtifactMetadata{artifact_id:fixture.artifact.artifact_id.clone()})).await,Err(openbot_contracts::error::AppError::NotVisible)),"Local cleanup owner management reopened missing-source metadata")?;
        let before_arm=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let intent=actual.arm_explicit_saved_delete_before(&original_auth,&fixture.artifact.artifact_id,Instant::now()+Duration::from_secs(10)).await.map_err(|e|e.to_string())?;
        let armed=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        cleanup_arm_local_only_tables_changed(&before_arm,&armed,&["openbot_internal.artifact_cleanup_fences","public.audit_events","public.audit_checkpoints"])?;
        let old_audit=before_arm.get("public.audit_events").and_then(serde_json::Value::as_array).ok_or("Local original audit facts missing")?;
        let new_audit=armed.get("public.audit_events").and_then(serde_json::Value::as_array).ok_or("Local current audit facts missing")?;
        require(!old_audit.is_empty()&&new_audit.len()==old_audit.len()+1&&old_audit.iter().all(|v|new_audit.contains(v))&&before_arm.get("public.audit_checkpoints")==armed.get("public.audit_checkpoints"),"Local arm changed previous real Save audit/physical rows or checkpoint")?;
        let c=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let original_dataset:String=c.query_one("SELECT dataset_id FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND operation_id=$3 AND artifact_id=$4",&[&original_auth.deployment().as_str(),&original_auth.tenant().as_str(),&fixture.artifact.operation_id,&fixture.artifact.artifact_id]).await.map_err(|e|e.to_string())?.get(0);
        let fence=c.query("SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase FROM openbot_internal.artifact_cleanup_fences",&[]).await.map_err(|e|e.to_string())?;
        require(fence.len()==1&&fence[0].get::<_,String>(0)==original_auth.deployment().as_str()&&fence[0].get::<_,String>(1)==original_auth.tenant().as_str()&&fence[0].get::<_,String>(2)==original_dataset&&fence[0].get::<_,String>(3)==fixture.artifact.operation_id&&fence[0].get::<_,String>(4)==fixture.artifact.artifact_id&&fence[0].get::<_,String>(5)=="deleted"&&fence[0].get::<_,String>(6)=="armed","Local arm did not preserve exact original namespace/pair and fixed intent")?;
        let audit=c.query("SELECT actor_user_id,target_type,target_id,payload FROM public.audit_events WHERE event_type='artifact.cleanup_armed'",&[]).await.map_err(|e|e.to_string())?;
        require(audit.len()==1&&audit[0].get::<_,Option<String>>(0).as_deref()==Some(original_auth.actor().as_str())&&audit[0].get::<_,String>(1)=="artifact"&&audit[0].get::<_,Option<String>>(2).as_deref()==Some(fixture.artifact.artifact_id.as_str())&&audit[0].get::<_,serde_json::Value>(3)==serde_json::json!({"artifact_id":fixture.artifact.artifact_id,"artifact_operation_id":fixture.artifact.operation_id}),"Local arm audit was missing, duplicated or changed fixed typed IDs")?;drop(c);
        let barrier=actual.close_armed_artifact_reads(&intent).map_err(|e|e.to_string())?;
        let ack=barrier.drain_before(Instant::now()+Duration::from_secs(4)).await.map_err(|e|format!("{e:?}"))?;
        require(cleanup_owned_inode_fds(&path)?.is_empty()&&cleanup_arm_local_object_fact(&path)?==first_object,"Local finite armed close ACK lacked actual FD end or deleted original object")?;
        status(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await,StatusCode::NOT_FOUND)?;
        require(cleanup_arm_local_database_facts(fixture.prepared().pool()).await?==armed,"Local finite close or stopped reader wrote business rows")?;
        drop(ack);drop(barrier);drop(intent);
        // A second actual pair remains unfenced. Wait for its real original arm quota query,
        // then replace the original window before releasing the controller's actual lock.
        let mut controller=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let tx=controller.transaction().await.map_err(|e|e.to_string())?;
        let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&second.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;
        let worker_actual=actual.clone();let worker_auth=original_auth.clone();let artifact=second.artifact_id.clone();
        let worker=tokio::spawn(async move {worker_actual.arm_explicit_saved_delete_before(&worker_auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
        let (waiter_pid,observer_pid)=cleanup_arm_local_waiter(fixture.prepared().pool(),controller_pid).await?;
        protocol.unbind_window("main").map_err(|e|e.to_string())?;
        protocol.bind_window("main",fixture.prepared().auth_context().clone(),None).map_err(|e|e.to_string())?;
        let rebound=protocol.windows.try_read().map_err(|_|"new actual Window unavailable")?.get("main").ok_or("new actual Window missing")?.auth.clone();
        require(rebound==original_auth&&!rebound.request_binding().unwrap().identity().same_binding(original_auth.request_binding().unwrap().identity()),"Local same-label rebind did not replace the original epoch while retaining six Auth facts")?;
        tx.rollback().await.map_err(|e|e.to_string())?;drop(controller);
        require(matches!(worker.await.map_err(|e|e.to_string())?,Err(ArmError::Host(openbot_contracts::request_binding::HostRequestBindingError::NotCurrent))),"actual quota waiter armed using the replaced original Window")?;
        require(cleanup_arm_local_database_facts(fixture.prepared().pool()).await?==armed&&cleanup_arm_local_object_fact(&path)?==first_object&&cleanup_arm_local_object_fact(&second_path)?==second_object,"rebound-window refusal changed original pair/charge/fence/audit/bytes")?;
        eprintln!("ARTIFACT_CLEANUP_ARM_LOCAL source_controller_pid={source_controller_pid} source_hard_delete_commit_ack=true original_window_arm_ack=true exact_arm_audit=true controlled_original_fd_absent=true original_object_unchanged=true waiter_pid={waiter_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_quota_lock=true window_replaced_before_unlock=true controller_rollback_ack=true old_request_refused=true physical_delete=false");
        Ok::<_,String>(())
    }.await;
    drop(protocol);
    drop(actual);
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local original Window cleanup arm and physical owned closure");
}
