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

#[test]
fn b01_wrong_kind_wrapping_reference_is_rejected() {
    let mut f = Fixture::new();
    f.claim
        .materials
        .iter_mut()
        .find(|m| m.id.as_str() == "wrap")
        .unwrap()
        .kind = MaterialKind::PostgresConfig;
    let outcome = f.plan();
    println!("structural_plan={}", outcome.is_structural_plan());
    assert!(
        !outcome.is_structural_plan(),
        "a PG config object satisfied the recovery-wrapping reference"
    );
}

#[test]
fn b02_directory_cannot_satisfy_wrapped_key_material() {
    let mut f = Fixture::new();
    let m = f
        .claim
        .materials
        .iter_mut()
        .find(|m| m.id.as_str() == "wrap")
        .unwrap();
    m.directory = true;
    m.declared_bytes = 0;
    m.digest = digest(b"");
    assert!(
        !f.plan().is_structural_plan(),
        "an empty directory satisfied the required ciphertext object"
    );
}

#[test]
fn b03_unknown_fact_cannot_be_demoted_to_committed() {
    let mut f = Fixture::new();
    let unknown = f.claim.receipts.unknown.pop().unwrap();
    f.claim.receipts.committed.push(unknown);
    f.claim.receipts.unknown.push(ReceiptClaim {
        id: "replacement-unknown".into(),
        unknown: true,
    });
    let outcome = f.plan();
    if let RestoreOutcome::StructuralPlan(p) = &outcome {
        println!(
            "normalized_unknown={:?} committed={:?}",
            p.inventory().receipts().unknown(),
            p.inventory().receipts().committed()
        );
    }
    assert!(
        !outcome.is_structural_plan(),
        "Unknown=true was silently classified as committed; cardinality passed"
    );
}

#[test]
fn b04_metadata_collections_must_be_bounded_and_consistent() {
    let mut f = Fixture::new();
    f.claim.empty_categories = vec![
        EmptyCategoryClaim {
            kind: MaterialKind::ProfileInventory,
            reason: EmptyReason::DatasetContainsNoProfiles
        };
        4097
    ];
    assert!(
        !f.plan().is_structural_plan(),
        "4097 duplicate empty claims survived despite existing nonempty profile material"
    );
}

#[cfg(unix)]
#[test]
fn b05_cleanup_must_not_follow_replaced_root_into_protected_files() {
    let f = Fixture::new();
    let plan = f.plan();
    let temp = Temp::new();
    let protected = temp.0.join("protected");
    fs::create_dir(&protected).unwrap();
    let canary = protected.join("manifest");
    fs::write(&canary, b"OWNED_TEST_PROTECTED_CANARY").unwrap();
    let root = temp.0.clone();
    let target = protected.clone();
    let mut source = HookSource {
        inner: f.source(),
        opened: 0,
        hook: move |n| {
            if n == 1 {
                fs::rename(root.join("stage"), root.join("owned-stage-moved")).unwrap();
                std::os::unix::fs::symlink(&target, root.join("stage")).unwrap();
                return Err(StagingFault::SourceReplaced);
            }
            Ok(())
        },
    };
    let result = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &StdFs,
        StagingBounds::standard(),
    );
    println!(
        "result={result:?} protected_canary_exists={}",
        canary.exists()
    );
    assert!(
        canary.exists(),
        "cleanup followed the staging root symlink and deleted a different directory's file"
    );
}

#[test]
fn b06_previously_written_destination_change_must_not_report_integrity() {
    let f = Fixture::new();
    let plan = f.plan();
    let temp = Temp::new();
    let root = temp.0.clone();
    let mut source = HookSource {
        inner: f.source(),
        opened: 0,
        hook: move |n| {
            if n == 1 {
                fs::write(root.join("stage/manifest"), b"changed").unwrap();
            }
            Ok(())
        },
    };
    let result = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &StdFs,
        StagingBounds::standard(),
    );
    let completed = matches!(result, StagingOutcome::Completed(_));
    println!("completed={completed} result={result:?}");
    assert!(
        !completed,
        "staging completed with digest_integrity=true for already modified output"
    );
}

#[test]
fn b07_oversized_chunk_must_be_rejected_before_disk_write() {
    let f = Fixture::new();
    let plan = f.plan();
    let temp = Temp::new();
    let meter = MeterFs::default();
    let mut source = f.source();
    source.insert(
        "manifest",
        vec![Ok(Chunk::try_new(0, b"vv".to_vec(), true).unwrap())],
    );
    let bounds = StagingBounds::try_new(1024, 4096, 1_000_000, 1).unwrap();
    let result = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &meter,
        bounds,
    );
    let written = meter.bytes.load(Ordering::SeqCst);
    println!("actual_write_bytes={written} result={result:?}");
    assert_eq!(
        written, 0,
        "two bytes reached disk under a one-byte material limit"
    );
}

#[test]
fn b08_failure_receipt_must_include_partial_file_writes() {
    let f = Fixture::new();
    let plan = f.plan();
    let temp = Temp::new();
    let meter = MeterFs::default();
    let mut source = f.source();
    source.insert(
        "manifest",
        vec![
            Ok(Chunk::try_new(0, b"v".to_vec(), false).unwrap()),
            Err(StagingFault::OpenFailed),
        ],
    );
    let result = stage(
        &plan,
        &mut source,
        &temp.0,
        &CancelFlag::new(),
        &meter,
        StagingBounds::standard(),
    );
    let StagingOutcome::Failed(failure) = result else {
        panic!("fault not propagated")
    };
    println!(
        "actual_bytes={} reported_bytes={}",
        meter.bytes.load(Ordering::SeqCst),
        failure.bytes_written()
    );
    assert_eq!(
        failure.bytes_written(),
        meter.bytes.load(Ordering::SeqCst) as u64,
        "partial file writes disappeared from failure receipt"
    );
}

struct CancelAtEof {
    inner: Box<dyn EntryStream>,
    cancel: Arc<CancelFlag>,
}
impl EntryStream for CancelAtEof {
    fn next_chunk(&mut self) -> Result<Option<Chunk>, StagingFault> {
        let next = self.inner.next_chunk()?;
        if next.is_none() {
            self.cancel.cancel();
        }
        Ok(next)
    }
}
struct CancelLastSource {
    inner: ScriptedSource,
    cancel: Arc<CancelFlag>,
}
impl MaterialSource for CancelLastSource {
    fn open_entry(&mut self, id: &str) -> Result<Box<dyn EntryStream>, StagingFault> {
        let inner = self.inner.open_entry(id)?;
        if id == "audit" {
            Ok(Box::new(CancelAtEof {
                inner,
                cancel: self.cancel.clone(),
            }))
        } else {
            Ok(inner)
        }
    }
}

#[test]
fn b09_cancel_at_last_eof_must_not_persist_as_completed() {
    let f = Fixture::new();
    let plan = f.plan();
    let temp = Temp::new();
    let cancel = Arc::new(CancelFlag::new());
    let mut source = CancelLastSource {
        inner: f.source(),
        cancel: cancel.clone(),
    };
    let result = stage(
        &plan,
        &mut source,
        &temp.0,
        &cancel,
        &StdFs,
        StagingBounds::standard(),
    );
    println!(
        "cancelled={} completed={}",
        cancel.is_cancelled(),
        matches!(result, StagingOutcome::Completed(_))
    );
    assert!(
        !matches!(result, StagingOutcome::Completed(_)),
        "cancellation before final persist was ignored"
    );
}

#[test]
fn b10_all_created_directories_and_slot_parent_must_be_synced() {
    let mut f = Fixture::new();
    f.claim.materials[0].relative_path = "tree/nested/manifest".into();
    let plan = f.plan();
    assert!(plan.is_structural_plan());
    let temp = Temp::new();
    let meter = MeterFs::default();
    let result = stage(
        &plan,
        &mut f.source(),
        &temp.0,
        &CancelFlag::new(),
        &meter,
        StagingBounds::standard(),
    );
    assert!(matches!(result, StagingOutcome::Completed(_)));
    let synced = meter.syncs.lock().unwrap();
    let required = [
        temp.0.clone(),
        temp.0.join("stage"),
        temp.0.join("stage/tree"),
        temp.0.join("stage/tree/nested"),
    ];
    println!("sync_calls={synced:?}");
    assert!(
        required.iter().all(|path| synced.contains(path)),
        "directory persistence omitted nested directories or the staging slot parent"
    );
}

#[test]
fn b11_unregistered_empty_source_directory_must_be_rejected() {
    let f = Fixture::new();
    let plan = f.plan();
    let RestoreOutcome::StructuralPlan(plan) = plan else {
        panic!()
    };
    let temp = Temp::new();
    let source_root = temp.0.join("source");
    f.write_source(&source_root);
    fs::create_dir(source_root.join("undeclared")).unwrap();
    let result = FileTreeSource::open(&source_root, &plan, StagingBounds::standard());
    assert!(
        result.is_err(),
        "source tree accepted an unregistered directory"
    );
}

#[test]
fn b12_known_invalid_per_entry_bounds_must_fail_before_any_write() {
    let mut f = Fixture::new();
    f.claim.materials[1].declared_bytes = 2;
    f.claim.materials[1].digest = digest(b"vv");
    f.bytes.insert("base".into(), b"vv".to_vec());
    let plan = f.plan();
    assert!(plan.is_structural_plan());
    let temp = Temp::new();
    let meter = MeterFs::default();
    let result = stage(
        &plan,
        &mut f.source(),
        &temp.0,
        &CancelFlag::new(),
        &meter,
        StagingBounds::try_new(1024, 4096, 1_000_000, 1).unwrap(),
    );
    println!(
        "actual_bytes={} result={result:?}",
        meter.bytes.load(Ordering::SeqCst)
    );
    assert_eq!(
        meter.bytes.load(Ordering::SeqCst),
        0,
        "known invalid later entry was not preflighted before an earlier write"
    );
}

#[cfg(unix)]
#[test]
fn b13_replaced_source_root_must_not_follow_a_new_symlink() {
    let f = Fixture::new();
    let plan = f.plan();
    let RestoreOutcome::StructuralPlan(plan) = plan else {
        panic!()
    };
    let temp = Temp::new();
    let source_root = temp.0.join("source");
    let other = temp.0.join("other");
    f.write_source(&source_root);
    f.write_source(&other);
    let mut source = FileTreeSource::open(&source_root, &plan, StagingBounds::standard()).unwrap();
    fs::rename(&source_root, temp.0.join("original-source")).unwrap();
    std::os::unix::fs::symlink(&other, &source_root).unwrap();
    let result = source.open_entry("manifest");
    assert!(
        result.is_err(),
        "file source followed a replaced root into another tree after inventory validation"
    );
}
