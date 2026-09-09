//! Controller-authored regressions; every filesystem object is a newly owned test fixture.
//! No PostgreSQL, user backup, credentials, network, or external data is accessed.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::*;
use openbot_domain::vault::KeyVersion;
use openbot_infra::backup::staging::FileSink;
use openbot_infra::backup::*;

// Hooks only schedule a replacement at a public FS operation boundary, then delegate to StdFs.
// Every directory below is freshly owned by the test; no real files are used.
type FsHook = std::cell::RefCell<Option<Box<dyn FnOnce(&Path)>>>;
#[derive(Default)]
struct InterleavingFs {
    before_remove: FsHook,
    before_sync: FsHook,
    short_write: bool,
    written: Arc<AtomicUsize>,
}
struct ShortSink {
    inner: Box<dyn FileSink>,
    written: Arc<AtomicUsize>,
}
impl FileSink for ShortSink {
    fn write(&mut self, bytes: &[u8]) -> Result<u64, SinkWriteError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = self.inner.write(&bytes[..1])?;
        self.written.fetch_add(n as usize, Ordering::SeqCst);
        Err(SinkWriteError::new(StagingFault::WriteFailed, n))
    }
    fn persist(&mut self, n: u64, limit: u64) -> Result<(), StagingFault> {
        self.inner.persist(n, limit)
    }
}
impl FsPort for InterleavingFs {
    fn bind_dir(&self, p: &Path) -> Result<OwnedDir, StagingFault> {
        StdFs.bind_dir(p)
    }
    fn create_private_dir(&self, parent: &OwnedDir, name: &str) -> Result<OwnedDir, StagingFault> {
        StdFs.create_private_dir(parent, name)
    }
    fn create_file_noclobber(
        &self,
        parent: &OwnedDir,
        name: &str,
    ) -> Result<(OwnedFile, Box<dyn FileSink>), StagingFault> {
        let (owned, sink) = StdFs.create_file_noclobber(parent, name)?;
        if self.short_write {
            Ok((
                owned,
                Box::new(ShortSink {
                    inner: sink,
                    written: self.written.clone(),
                }),
            ))
        } else {
            Ok((owned, sink))
        }
    }
    fn sync_dir(&self, dir: &OwnedDir) -> Result<(), StagingFault> {
        if let Some(hook) = self.before_sync.borrow_mut().take() {
            hook(dir.as_path());
        }
        StdFs.sync_dir(dir)
    }
    fn child_exists(&self, parent: &OwnedDir, name: &str) -> Result<bool, StagingFault> {
        StdFs.child_exists(parent, name)
    }
    fn remove_file(&self, parent: &OwnedDir, file: &OwnedFile) -> Result<(), StagingFault> {
        if let Some(hook) = self.before_remove.borrow_mut().take() {
            hook(file.as_path());
        }
        StdFs.remove_file(parent, file)
    }
    fn remove_dir(&self, parent: &OwnedDir, dir: &OwnedDir) -> Result<(), StagingFault> {
        StdFs.remove_dir(parent, dir)
    }
}

#[cfg(unix)]
#[test]
fn q01_replacement_after_identity_check_must_not_delete_protected_file() {
    let f = Fixture::new();
    let temp = Temp::new();
    let protected = temp.0.join("protected");
    fs::create_dir(&protected).unwrap();
    let canary = protected.join("manifest");
    fs::write(&canary, b"OWNED_TEST_CANARY").unwrap();
    let root = temp.0.clone();
    let dest = protected.clone();
    let fs_port = InterleavingFs {
        before_remove: std::cell::RefCell::new(Some(Box::new(move |_| {
            fs::rename(root.join("stage"), root.join("moved-owned-stage")).unwrap();
            std::os::unix::fs::symlink(&dest, root.join("stage")).unwrap();
        }))),
        ..Default::default()
    };
    let mut source = f.source();
    source.insert(
        "manifest",
        vec![Ok(Chunk::try_new(0, b"z".to_vec(), true).unwrap())],
    );
    let result = stage(
        &f.plan(),
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &fs_port,
        StagingBounds::standard(),
    );
    println!("protected_exists={} result={result:?}", canary.exists());
    assert!(
        canary.exists(),
        "the check/use window still allowed cleanup to follow a substituted root and delete a protected file"
    );
}

#[cfg(unix)]
#[test]
fn q02_replaced_intermediate_directory_must_not_receive_staging_writes() {
    let mut f = Fixture::new();
    f.claim.materials[0].relative_path = "group/inner/manifest".into();
    f.claim.materials[1].relative_path = "group/inner/base".into();
    let temp = Temp::new();
    let protected = temp.0.join("protected");
    fs::create_dir_all(protected.join("inner")).unwrap();
    let root = temp.0.clone();
    let other = protected.clone();
    let escaped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = escaped.clone();
    let mut source = HookSource {
        inner: f.source(),
        opened: 0,
        hook: move |n| {
            if n == 1 {
                fs::rename(root.join("stage/group"), root.join("moved-owned-group")).unwrap();
                std::os::unix::fs::symlink(&other, root.join("stage/group")).unwrap();
            }
            if n == 2 {
                seen.store(other.join("inner/base").exists(), Ordering::SeqCst);
                return Err(StagingFault::SourceReplaced);
            }
            Ok(())
        },
    };
    let result = stage(
        &f.plan(),
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &StdFs,
        StagingBounds::standard(),
    );
    println!(
        "foreign_write_seen={} result={result:?}",
        escaped.load(Ordering::SeqCst)
    );
    assert!(
        !escaped.load(Ordering::SeqCst),
        "stable staging root and regular leaf-parent hid a replaced intermediate directory"
    );
}

#[test]
fn q03_output_changed_during_directory_sync_must_not_complete_with_integrity() {
    let f = Fixture::new();
    let temp = Temp::new();
    let root = temp.0.clone();
    let fs_port = InterleavingFs {
        before_sync: std::cell::RefCell::new(Some(Box::new(move |_| {
            fs::write(root.join("stage/manifest"), b"z").unwrap();
        }))),
        ..Default::default()
    };
    let result = stage(
        &f.plan(),
        &mut f.source(),
        &temp.0,
        &CancelFlag::new(),
        &fs_port,
        StagingBounds::standard(),
    );
    println!(
        "result={result:?} current_manifest={:?}",
        fs::read(temp.0.join("stage/manifest"))
    );
    assert!(
        !matches!(result, StagingOutcome::Completed(_)),
        "output changed after hash verification but before completion, yet digest_integrity remained true"
    );
}

struct CancelOnData {
    inner: ScriptedSource,
    cancel: Arc<CancelFlag>,
}
struct CancellingChunk {
    cancel: Arc<CancelFlag>,
    sent: bool,
}
impl EntryStream for CancellingChunk {
    fn next_chunk(&mut self) -> Result<Option<Chunk>, StagingFault> {
        if self.sent {
            return Ok(None);
        }
        self.sent = true;
        self.cancel.cancel();
        Ok(Some(Chunk::try_new(0, b"v".to_vec(), true)?))
    }
}
impl MaterialSource for CancelOnData {
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault> {
        if id == "manifest" {
            Ok(Box::new(CancellingChunk {
                cancel: self.cancel.clone(),
                sent: false,
            }))
        } else {
            self.inner.open_entry(id)
        }
    }
}
#[test]
fn q04_cancellation_during_data_read_must_prevent_next_write() {
    let f = Fixture::new();
    let temp = Temp::new();
    let meter = MeterFs::default();
    let cancel = Arc::new(CancelFlag::new());
    let mut source = CancelOnData {
        inner: f.source(),
        cancel: cancel.clone(),
    };
    let result = stage(
        &f.plan(),
        &mut source,
        &temp.0,
        &cancel,
        &meter,
        StagingBounds::standard(),
    );
    println!(
        "written_after_cancel={} result={result:?}",
        meter.bytes.load(Ordering::SeqCst)
    );
    assert_eq!(
        meter.bytes.load(Ordering::SeqCst),
        0,
        "a nonempty chunk returned after cancellation still reached the sink"
    );
}

#[test]
fn q05_short_write_failure_must_not_be_reported_as_zero_bytes() {
    let mut f = Fixture::new();
    f.claim.materials[0].declared_bytes = 2;
    f.claim.materials[0].digest = digest(b"vv");
    f.bytes.insert("manifest".into(), b"vv".to_vec());
    let temp = Temp::new();
    let fs_port = InterleavingFs {
        short_write: true,
        ..Default::default()
    };
    let result = stage(
        &f.plan(),
        &mut f.source(),
        &temp.0,
        &CancelFlag::new(),
        &fs_port,
        StagingBounds::standard(),
    );
    let StagingOutcome::Failed(failure) = result else {
        panic!("expected failed short write")
    };
    println!(
        "actual={} reported={} failure={failure:?}",
        fs_port.written.load(Ordering::SeqCst),
        failure.bytes_written()
    );
    assert_eq!(
        failure.bytes_written(),
        1,
        "a partial sink write has no progress/unknown representation and was reported as zero"
    );
}

#[test]
fn q06_file_tree_must_require_explicitly_registered_empty_directory() {
    let mut f = Fixture::new();
    let temp = Temp::new();
    let source_root = temp.0.join("source");
    f.write_source(&source_root);
    let mut extra = f.claim.materials[1].clone();
    extra.id = MaterialId::new("extra-dir");
    extra.relative_path = "missing-registered-directory".into();
    extra.directory = true;
    extra.declared_bytes = 0;
    extra.digest = digest(b"");
    f.claim.materials.push(extra);
    let RestoreOutcome::StructuralPlan(plan) = f.plan() else {
        panic!("valid explicit empty directory fixture rejected")
    };
    let result = FileTreeSource::open(&source_root, &plan, StagingBounds::standard());
    assert!(
        result.is_err(),
        "registered empty directory was absent, but the source inventory still passed"
    );
}

#[test]
fn q07_empty_directory_cannot_satisfy_required_wal_segment() {
    let mut f = Fixture::new();
    let wal = f
        .claim
        .materials
        .iter_mut()
        .find(|m| m.kind == MaterialKind::WalSegment)
        .unwrap();
    wal.directory = true;
    wal.declared_bytes = 0;
    wal.digest = digest(b"");
    let result = f.plan();
    println!("structural={}", result.is_structural_plan());
    assert!(
        !result.is_structural_plan(),
        "a directory with no WAL bytes satisfied the required WalSegment material"
    );
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wrok-primary-backup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(data: &[u8]) -> Sha256Digest {
    Sha256Digest::of(data)
}

struct Fixture {
    claim: BackupInventoryClaim,
    target: ControlledRestoreTarget,
    observations: RestoreObservations,
    bytes: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let specs = [
            ("manifest", MaterialKind::BundleManifest),
            ("base", MaterialKind::PostgresBase),
            ("wal", MaterialKind::WalSegment),
            ("config", MaterialKind::PostgresConfig),
            ("schema", MaterialKind::SchemaChecksum),
            ("migration", MaterialKind::MigrationChecksum),
            ("wrap", MaterialKind::KeyWrappingObject),
            ("profiles", MaterialKind::ProfileInventory),
            ("workspace", MaterialKind::WorkspaceInventory),
            ("compat", MaterialKind::CompatibilityRecord),
            ("audit", MaterialKind::AuditCheckpointObject),
        ];
        let materials = specs
            .iter()
            .map(|(id, kind)| MaterialClaim {
                id: MaterialId::new(*id),
                kind: *kind,
                relative_path: (*id).into(),
                directory: false,
                declared_bytes: 1,
                digest: digest(b"v"),
                bundle_id: "bundle".into(),
                dataset_id: "dataset".into(),
                barrier_id: "barrier".into(),
            })
            .collect();
        let bytes = specs
            .iter()
            .map(|(id, _)| ((*id).into(), b"v".to_vec()))
            .collect();
        let component = |name: &str| ComponentRev {
            name: name.into(),
            epoch: 5,
            digest: digest(b"build"),
        };
        let compatibility = CompatibilitySet {
            application: component("application"),
            postgres: component("postgres"),
            engine: component("engine"),
            ui: component("ui"),
        };
        let key = VaultKeyRefClaim {
            key_id: "key-one".into(),
            key_version: KeyVersion::new(1),
            canary: digest(b"canary-reference"),
        };
        let claim = BackupInventoryClaim {
            bundle: BundleIdentity {
                bundle_id: "bundle".into(),
                format_version: 1,
            },
            dataset: DatasetIdentity::new("dataset"),
            deployment: DeploymentId::new("deployment"),
            tenant: TenantId::new("tenant"),
            original_installation: InstallationIdentity::new("installation"),
            barrier: BarrierIdentity::new("barrier"),
            key_binding: KeyBindingClaim::RecoveryWrapped {
                wrapping_refs: vec![WrappingRefClaim {
                    key: key.clone(),
                    wrapping_object_id: MaterialId::new("wrap"),
                }],
            },
            scram: ScramRelationClaim {
                relation_id: "scram-relation".into(),
                bound_to_original_os_store: false,
            },
            audit: AuditCheckpointClaim {
                material_id: MaterialId::new("audit"),
                head_digest: digest(b"chain-head"),
                event_count: 1,
            },
            compatibility: compatibility.clone(),
            materials,
            empty_categories: vec![],
            receipts: ReceiptSetClaim {
                committed: vec![ReceiptClaim {
                    id: "committed-one".into(),
                    unknown: false,
                }],
                unknown: vec![ReceiptClaim {
                    id: "unknown-one".into(),
                    unknown: true,
                }],
                tool: vec![ReceiptClaim {
                    id: "tool-one".into(),
                    unknown: false,
                }],
            },
        };
        let migrations = vec![("migration-one".into(), digest(b"migration"))];
        let target = ControlledRestoreTarget {
            mode: RestoreMode::SameInstallation,
            dataset: claim.dataset.clone(),
            deployment: claim.deployment.clone(),
            tenant: claim.tenant.clone(),
            original_installation: claim.original_installation.clone(),
            schema_checksum: digest(b"schema"),
            migration_checksums: migrations.clone(),
            compatibility: compatibility.clone(),
            requires_restore_build: true,
            vault_keys: vec![key],
            profiles_empty: false,
            workspaces_empty: false,
            unknown_receipts: 1,
            capacity: CapacityPolicy {
                original_site_bytes: 100,
                margin_bytes: 100,
            },
        };
        let observations = RestoreObservations {
            schema_checksum: Some(target.schema_checksum),
            migration_checksums: Some(migrations),
            compatibility: Some(compatibility),
            restore_build_present: Some(true),
            capacity: CapacityObservation::Available { bytes: 1_000_000 },
        };
        Self {
            claim,
            target,
            observations,
            bytes,
        }
    }
    fn plan(&self) -> RestoreOutcome {
        plan_restore(RestoreRequest {
            claim: &self.claim,
            target: &self.target,
            observations: &self.observations,
            bounds: &InventoryBounds::standard(),
        })
    }
    fn source(&self) -> ScriptedSource {
        let mut source = ScriptedSource::new();
        for (id, bytes) in &self.bytes {
            source.insert(
                id.clone(),
                vec![Ok(Chunk::try_new(0, bytes.clone(), true).unwrap())],
            );
        }
        source
    }
    fn write_source(&self, root: &Path) {
        fs::create_dir(root).unwrap();
        for material in &self.claim.materials {
            let path = root.join(&material.relative_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, &self.bytes[material.id.as_str()]).unwrap();
        }
    }
}
fn stage(
    plan: &RestoreOutcome,
    source: &mut dyn MaterialSource,
    root: &Path,
    cancel: &CancelFlag,
    fs: &dyn FsPort,
    bounds: StagingBounds,
) -> StagingOutcome {
    run_staging(StagingInput {
        outcome: plan,
        source,
        request: &StagingRequest {
            parent: root.into(),
            slot: "stage".into(),
        },
        cancel,
        fs,
        bounds,
    })
}

struct HookSource<F> {
    inner: ScriptedSource,
    opened: usize,
    hook: F,
}
impl<F: FnMut(usize) -> Result<(), StagingFault>> MaterialSource for HookSource<F> {
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault> {
        (self.hook)(self.opened)?;
        self.opened += 1;
        self.inner.open_entry(id)
    }
}

#[derive(Default)]
struct MeterFs {
    bytes: Arc<AtomicUsize>,
    syncs: Mutex<Vec<PathBuf>>,
}
struct MeterSink {
    inner: Box<dyn FileSink>,
    bytes: Arc<AtomicUsize>,
}
impl FileSink for MeterSink {
    fn write(&mut self, bytes: &[u8]) -> Result<u64, SinkWriteError> {
        let n = self.inner.write(bytes)?;
        self.bytes.fetch_add(n as usize, Ordering::SeqCst);
        Ok(n)
    }
    fn persist(&mut self, len: u64, limit: u64) -> Result<(), StagingFault> {
        self.inner.persist(len, limit)
    }
}
impl FsPort for MeterFs {
    fn bind_dir(&self, p: &Path) -> Result<OwnedDir, StagingFault> {
        StdFs.bind_dir(p)
    }
    fn create_private_dir(&self, parent: &OwnedDir, name: &str) -> Result<OwnedDir, StagingFault> {
        StdFs.create_private_dir(parent, name)
    }
    fn create_file_noclobber(
        &self,
        parent: &OwnedDir,
        name: &str,
    ) -> Result<(OwnedFile, Box<dyn FileSink>), StagingFault> {
        let (owned, inner) = StdFs.create_file_noclobber(parent, name)?;
        Ok((
            owned,
            Box::new(MeterSink {
                inner,
                bytes: self.bytes.clone(),
            }),
        ))
    }
    fn sync_dir(&self, dir: &OwnedDir) -> Result<(), StagingFault> {
        self.syncs.lock().unwrap().push(dir.as_path().into());
        StdFs.sync_dir(dir)
    }
    fn child_exists(&self, parent: &OwnedDir, name: &str) -> Result<bool, StagingFault> {
        StdFs.child_exists(parent, name)
    }
    fn remove_file(&self, parent: &OwnedDir, file: &OwnedFile) -> Result<(), StagingFault> {
        StdFs.remove_file(parent, file)
    }
    fn remove_dir(&self, parent: &OwnedDir, dir: &OwnedDir) -> Result<(), StagingFault> {
        StdFs.remove_dir(parent, dir)
    }
}

#[test]
fn positive_valid_materials_stage_without_touching_original() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    assert!(plan.is_structural_plan());
    let temp = Temp::new();
    let original = temp.0.join("original");
    fs::write(&original, b"owned-test-original").unwrap();
    let mut source = fixture.source();
    let outcome = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &StdFs,
        StagingBounds::standard(),
    );
    let StagingOutcome::Completed(done) = outcome else {
        panic!("positive fixture rejected: {outcome:?}")
    };
    assert_eq!(done.files_written(), 11);
    assert_eq!(done.bytes_written(), 11);
    assert!(!done.application_ready());
    assert!(!done.grants_restore_switch());
    for m in &fixture.claim.materials {
        assert_eq!(
            fs::read(done.staging_path().join(&m.relative_path)).unwrap(),
            b"v"
        );
    }
    assert_eq!(fs::read(original).unwrap(), b"owned-test-original");
}

#[test]
fn positive_bad_digest_fails_and_preserves_original() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let temp = Temp::new();
    let original = temp.0.join("original");
    fs::write(&original, b"owned-test-original").unwrap();
    let mut source = fixture.source();
    source.insert(
        "manifest",
        vec![Ok(Chunk::try_new(0, b"z".to_vec(), true).unwrap())],
    );
    let outcome = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &StdFs,
        StagingBounds::standard(),
    );
    assert!(matches!(outcome, StagingOutcome::Failed(_)));
    assert_eq!(fs::read(original).unwrap(), b"owned-test-original");
}
