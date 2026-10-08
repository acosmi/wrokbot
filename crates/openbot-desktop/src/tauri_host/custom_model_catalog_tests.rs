//! Actual Prepared Local catalogue tests with owned PG roots and memory-only secrets.
//! Controlled inventory verification does not certify release signing or a renderer ACK.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::*;
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
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const CONNECTION: &str = "00000000-0000-7000-8000-000000000001";

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
            "openbot-custom-catalog-{label}-{}",
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
            eprintln!("CUSTOM_CATALOG_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "CUSTOM_CATALOG_LOCAL_OWNED_ROOT removed={} absent={}",
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
        let root = OwnedRoot::new("bundle")?;
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
        "/controlled/custom-catalog-local-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    prepared: Option<PreparedDesktopLocalRuntime>,
    postmaster_pid: u32,
    postmaster_file: PathBuf,
}
impl LocalFixture {
    async fn new(bundle: &OwnedBundle, label: &str) -> Result<Self, String> {
        let mut root = OwnedRoot::new(label)?;
        let assets = root.0.join("assets");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|e| e.to_string())?;
        std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e| e.to_string())?;
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|e| e.to_string())?;
        let release = DesktopLocalReleaseInput::new(
            &assets,
            "openbot",
            "main",
            bundle.open()?,
            ReviewedPostgresKeyStoreService::from_reviewed_release(
                "com.example.review.custom-catalog-scram",
            )
            .map_err(|e| e.to_string())?,
            ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
                "com.example.review.custom-catalog-vault",
            )
            .map_err(|e| e.to_string())?,
            Arc::new(MemorySecretStore::default()),
        )
        .map_err(|e| e.to_string())?;
        let application = DesktopLocalApplicationInput::new(
            DesktopOpenAiProviderInput::new(
                "https://api.example.test/v1",
                vec!["203.0.113.0/24".to_owned()],
            )
            .map_err(|e| e.to_string())?,
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // From this point an unproved shutdown keeps the owned evidence, including failures.
        root.1 = false;
        let prepared = prepare_desktop_local_runtime(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root.0)
                .map_err(|e| e.to_string())?,
            DesktopLocalRuntimeConfig::new(release, application, |authority| {
                package(authority.auth_context().tenant().as_str())
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
        let populated = async {
            prepared.protocol().bind_window("main", prepared.auth_context().clone(), None).map_err(|e| e.to_string())?;
            let auth = prepared.auth_context();
            let mut client = prepared.pool().get().await.map_err(|e| e.to_string())?;
            let tx = client.transaction().await.map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO public.model_connections(id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,revision,current_secret_id,created_at,updated_at) VALUES('00000000-0000-7000-8000-000000000001',$1,$2,$3,'Owned Local definition','openai_responses','https://model.example.test/v1/responses','owned-local-model',false,11,'00000000-0000-7000-8000-000000000002',clock_timestamp(),clock_timestamp())", &[&auth.deployment().as_str(), &auth.tenant().as_str(), &auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at) VALUES('00000000-0000-7000-8000-000000000002','00000000-0000-7000-8000-000000000001',$1,$2,$3,'owned-controlled-test-secret',clock_timestamp())", &[&auth.deployment().as_str(), &auth.tenant().as_str(), &auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            drop(client);
            let mut pids = Vec::new();
            for entry in std::fs::read_dir(&root.0).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                if path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("postgresql-17-")) && path.is_dir() {
                    let pid = std::fs::read_to_string(path.join("postmaster.pid")).map_err(|e| e.to_string())?.lines().next().ok_or("owned PID missing")?.parse::<u32>().map_err(|_| "owned PID invalid")?;
                    require(pid > 1, "owned postmaster PID invalid")?;
                    pids.push((pid, path.join("postmaster.pid")));
                }
            }
            require(pids.len() == 1, "actual Prepared did not own exactly one postmaster")?;
            pids.into_iter().next().ok_or_else(|| "owned postmaster identity missing".to_owned())
        }.await;
        match populated {
            Ok((postmaster_pid, postmaster_file)) => {
                eprintln!(
                    "CUSTOM_CATALOG_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={} original_PID_file={} data_dir={}",
                    root.0.display(),
                    postmaster_file.display(),
                    postmaster_file
                        .parent()
                        .expect("owned PID directory")
                        .display()
                );
                Ok(Self {
                    root,
                    prepared: Some(prepared),
                    postmaster_pid,
                    postmaster_file,
                })
            }
            Err(error) => {
                let cleaned = prepared.shutdown().await;
                if cleaned.is_ok() {
                    root.1 = true;
                }
                require(cleaned.is_ok(), "failed Prepared setup cleanup did not ACK")?;
                Err(error)
            }
        }
    }
    fn prepared(&self) -> &PreparedDesktopLocalRuntime {
        self.prepared
            .as_ref()
            .expect("owned Prepared already moved")
    }
    async fn finish(mut self) -> Result<(), String> {
        let closing_ok = match self.prepared.take() {
            Some(prepared) => prepared.shutdown().await.is_ok(),
            None => true,
        };
        self.root.1 = false;
        require(
            !owned_postmaster_live(self.postmaster_pid)? && !self.postmaster_file.exists(),
            "owned original postmaster or PID file survived shutdown",
        )?;
        require(closing_ok, "actual Prepared shutdown did not ACK")?;
        self.root.1 = true;
        eprintln!(
            "CUSTOM_CATALOG_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true original_PID_file_gone=true",
            self.postmaster_pid
        );
        Ok(())
    }
}
fn owned_postmaster_live(pid: u32) -> Result<bool, String> {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|_| "owned postmaster liveness observation failed".to_owned())
}
fn request(method: Method, uri: &str, body: &[u8]) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body.to_vec())
        .expect("closed test request")
}
fn no_store(response: &Response<Vec<u8>>, expected: StatusCode) -> Result<(), String> {
    require(
        response.status() == expected,
        "actual Local response status differs",
    )?;
    require(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .is_some_and(|value| value == "no-store"),
        "owned Local response missed no-store",
    )
}
fn valid_page(response: &Response<Vec<u8>>) -> Result<(), String> {
    no_store(response, StatusCode::OK)?;
    let value: serde_json::Value =
        serde_json::from_slice(response.body()).map_err(|e| e.to_string())?;
    require(
        value.as_object().is_some_and(|object| object.len() == 2),
        "actual Local page keys differ",
    )?;
    require(
        value["nextCursor"].is_null(),
        "single definition got a cursor",
    )?;
    let models = value["models"]
        .as_array()
        .ok_or("actual Local models missing")?;
    require(
        models.len() == 1,
        "actual Local catalog cardinality differs",
    )?;
    let entry = &models[0];
    require(
        entry.as_object().is_some_and(|object| object.len() == 9)
            && entry["connectionId"] == CONNECTION
            && entry["connectionRevision"] == 11
            && entry["catalogRevision"] == 1
            && entry["enabled"] == false
            && entry.get("endpoint").is_none()
            && entry.get("ownerUserId").is_none(),
        "actual Local DTO or independent revisions differ",
    )
}

#[test]
fn local_raw_cursor_and_encoded_writer_are_closed() {
    assert_eq!(parse_raw_query(Some("")).unwrap().cursor, None);
    assert_eq!(
        parse_raw_query(Some(&format!("cursor={CONNECTION}")))
            .unwrap()
            .cursor
            .as_deref(),
        Some(CONNECTION)
    );
    for raw in [
        "cursor=",
        "cursor=%30",
        "owner=x",
        "cursor=00000000-0000-7000-8000-000000000001&",
    ] {
        assert!(parse_raw_query(Some(raw)).is_err());
    }
    let mut bytes = vec![0; MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES - 1];
    assert!(BoundedWriter(&mut bytes).write_all(b"xy").is_err());
    assert_eq!(bytes.len(), MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES - 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned exact PG17.11 bundle and actual Prepared Local feature graph"]
async fn genuine_prepared_local_catalog_framing_and_window_delivery() {
    let bundle = OwnedBundle::materialize().expect("owned pinned bundle");
    let fixture = LocalFixture::new(&bundle, "framing")
        .await
        .expect("actual Prepared fixture");
    let result = async {
        let protocol = fixture.prepared().protocol();
        valid_page(
            &protocol
                .handle("main", request(Method::GET, PATH, &[]))
                .await,
        )?;
        for (label, method, uri, body, expected) in [
            (
                "main",
                Method::HEAD,
                PATH.to_owned(),
                Vec::new(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                "main",
                Method::POST,
                PATH.to_owned(),
                Vec::new(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                "main",
                Method::GET,
                format!("{PATH}?owner=other"),
                Vec::new(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "main",
                Method::GET,
                format!("{PATH}?cursor="),
                Vec::new(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "main",
                Method::GET,
                format!("{PATH}?cursor=%30{CONNECTION}"),
                Vec::new(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "main",
                Method::GET,
                PATH.to_owned(),
                b"x".to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "main",
                Method::GET,
                format!("{PATH}/unknown"),
                Vec::new(),
                StatusCode::NOT_FOUND,
            ),
            (
                "unknown",
                Method::GET,
                PATH.to_owned(),
                Vec::new(),
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            no_store(
                &protocol.handle(label, request(method, &uri, &body)).await,
                expected,
            )?;
        }
        valid_page(
            &protocol
                .handle("main", request(Method::GET, &format!("{PATH}?"), &[]))
                .await,
        )?;
        let (one, two) = tokio::join!(
            protocol.prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[])),
            protocol.prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
        );
        let (first_bytes, second_bytes) = match (&one, &two) {
            (
                PreparedCustomModelCatalogResponse::Current(first),
                PreparedCustomModelCatalogResponse::Current(second),
            ) => (&first.encoded, &second.encoded),
            _ => {
                return Err(
                    "same-body Local executions did not prepare two actual deliveries".to_owned(),
                );
            }
        };
        require(
            first_bytes == second_bytes,
            "same-body replies differed unexpectedly",
        )?;
        protocol
            .bind_window("other", fixture.prepared().auth_context().clone(), None)
            .map_err(|e| e.to_string())?;
        no_store(
            &protocol
                .finish_prepared_custom_model_catalog_response("other", one, |response| response),
            StatusCode::NOT_FOUND,
        )?;
        valid_page(&protocol.finish_prepared_custom_model_catalog_response(
            "main",
            two,
            |response| response,
        ))?;
        let abandoned = protocol
            .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
            .await;
        require(
            matches!(abandoned, PreparedCustomModelCatalogResponse::Current(_)),
            "actual pending reply missing",
        )?;
        drop(abandoned);
        valid_page(
            &protocol
                .handle("main", request(Method::GET, PATH, &[]))
                .await,
        )?;
        let old = protocol
            .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
            .await;
        protocol.unbind_window("main").map_err(|e| e.to_string())?;
        protocol
            .bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|e| e.to_string())?;
        no_store(
            &protocol
                .finish_prepared_custom_model_catalog_response("main", old, |response| response),
            StatusCode::NOT_FOUND,
        )?;
        valid_page(
            &protocol
                .handle("main", request(Method::GET, PATH, &[]))
                .await,
        )?;
        real_respond_holds_delivery_through_callback(protocol).await?;
        Ok::<(), String>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result.expect("actual Local framing/window assertions");
    cleanup.expect("owned original Local shutdown");
}

struct RespondGate {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
}
impl RespondGate {
    fn release(&self) {
        if let Ok(mut released) = self.released.lock() {
            *released = true;
            self.wake.notify_all();
        }
    }
}
struct ReleaseRespond(Arc<RespondGate>);
impl Drop for ReleaseRespond {
    fn drop(&mut self) {
        self.0.release();
    }
}
async fn real_respond_holds_delivery_through_callback(
    protocol: &Arc<DesktopTauriProtocol>,
) -> Result<(), String> {
    let mut held = Vec::new();
    for _ in 0..7 {
        let prepared = protocol
            .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
            .await;
        require(
            matches!(prepared, PreparedCustomModelCatalogResponse::Current(_)),
            "actual Local held allocation missing",
        )?;
        held.push(prepared);
    }
    let eighth = protocol
        .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
        .await;
    require(
        matches!(eighth, PreparedCustomModelCatalogResponse::Current(_)),
        "actual eighth Local allocation missing",
    )?;
    let gate = Arc::new(RespondGate {
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let release = ReleaseRespond(gate.clone());
    let worker_protocol = protocol.clone();
    let worker_gate = gate.clone();
    let worker = tokio::task::spawn_blocking(move || {
        worker_protocol.finish_prepared_custom_model_catalog_response("main", eighth, |response| {
            worker_gate.entered.notify_one();
            let released = worker_gate
                .released
                .lock()
                .map_err(|_| "owned respond gate poisoned")?;
            let (_released, timeout) = worker_gate
                .wake
                .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                .map_err(|_| "owned respond wait poisoned")?;
            require(
                !timeout.timed_out(),
                "actual respond callback hold timed out",
            )?;
            valid_page(&response)?;
            Ok::<(), String>(())
        })
    });
    let refusal = async {
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .map_err(|_| "actual respond callback did not enter")?;
        let ninth = protocol
            .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
            .await;
        match ninth {
            PreparedCustomModelCatalogResponse::Immediate(response) => {
                no_store(&response, StatusCode::CONFLICT)
            }
            PreparedCustomModelCatalogResponse::Current(_) => {
                Err("Local permit returned before actual respond completed".to_owned())
            }
        }
    }
    .await;
    drop(release);
    let joined = worker.await.map_err(|e| e.to_string());
    refusal?;
    joined??;
    let after = protocol
        .prepare_custom_model_catalog_response("main", request(Method::GET, PATH, &[]))
        .await;
    require(
        matches!(after, PreparedCustomModelCatalogResponse::Current(_)),
        "Local callback completion did not release its allocation",
    )?;
    drop(after);
    drop(held);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine same-DB verified canary and actual window/owner final tail"]
async fn genuine_prepared_local_catalog_canary_and_owner_tail_refusals() {
    let bundle = OwnedBundle::materialize().expect("owned pinned bundle");
    let fixture = LocalFixture::new(&bundle, "canary")
        .await
        .expect("actual Prepared fixture");
    let result=async {
        let protocol=fixture.prepared().protocol();
        valid_page(&protocol.handle("main",request(Method::GET,PATH,&[])).await)?;
        let auth=fixture.prepared().auth_context();
        let client=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let original:String=client.query_one("SELECT encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1", &[&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?.get(0);
        require(client.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary='controlled-canary-drift' WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",&[&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?==1,"actual owned canary mutation was not exact")?;
        no_store(&protocol.handle("main",request(Method::GET,PATH,&[])).await,StatusCode::NOT_FOUND)?;
        require(client.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1 WHERE deployment_id=$2 AND tenant_id=$3 AND key_version=1",&[&original,&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?==1,"actual canary restoration was not exact")?;
        valid_page(&protocol.handle("main",request(Method::GET,PATH,&[])).await)?;
        client.execute("UPDATE public.users SET auth_generation=auth_generation+1 WHERE id=$1", &[&auth.actor().as_str()]).await.map_err(|e|e.to_string())?;
        no_store(&protocol.handle("main",request(Method::GET,PATH,&[])).await,StatusCode::NOT_FOUND)?;
        client.execute("UPDATE public.users SET auth_generation=auth_generation-1 WHERE id=$1", &[&auth.actor().as_str()]).await.map_err(|e|e.to_string())?;
        drop(client);
        valid_page(&protocol.handle("main",request(Method::GET,PATH,&[])).await)?;
        let prepared=protocol.prepare_custom_model_catalog_response("main",request(Method::GET,PATH,&[])).await;
        require(matches!(prepared,PreparedCustomModelCatalogResponse::Current(_)),"pre-close actual delivery missing")?;
        protocol.close_request_bindings();
        let refused=protocol.finish_prepared_custom_model_catalog_response("main",prepared,|response|response);
        require(refused.status()!=StatusCode::OK,"closed original protocol delivered catalog JSON")?;
        require(!refused.body().windows(8).any(|window|window==b"\"models\""),"closed original protocol leaked a catalog frame")?;
        require(refused.headers().get(http::header::CACHE_CONTROL).is_some_and(|value|value=="no-store"),"closed protocol refusal missed no-store")?;
        Ok::<(),String>(())
    }.await;
    let cleanup = fixture.finish().await;
    result.expect("actual Local canary/owner assertions");
    cleanup.expect("owned original Local shutdown");
}
