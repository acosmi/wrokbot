//! 正反例走 [`super::run_staging`]，含真实 I/O。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::{
    AuditCheckpointClaim, BackupInventoryClaim, BarrierIdentity, BundleIdentity,
    CapacityObservation, CapacityPolicy, CompatibilitySet, ComponentRev, ControlledRestoreTarget,
    DatasetIdentity, InstallationIdentity, InventoryBounds, KeyBindingClaim, MaterialClaim,
    MaterialId, MaterialKind, ReceiptClaim, ReceiptSetClaim, RestoreMode, RestoreObservations,
    RestoreOutcome, RestoreRequest, ScramRelationClaim, VaultKeyRefClaim, WrappingRefClaim,
    plan_restore,
};
use openbot_domain::vault::KeyVersion;
use sha2::{Digest, Sha256};

use super::{
    CancelFlag, Chunk, CleanupReport, FaultInjectingFs, FileTreeSource, ScriptedSource,
    StagingBounds, StagingFault, StagingInput, StagingOutcome, StagingRequest, StdFs, run_staging,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wrok-backup-staging-{}-{}-{}",
            tag,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Spec {
    kind: MaterialKind,
    id: &'static str,
    path: &'static str,
    bytes: &'static [u8],
}

const SPECS: &[Spec] = &[
    Spec {
        kind: MaterialKind::BundleManifest,
        id: "m-bundle",
        path: "bundle/manifest",
        bytes: b"bundle-bytes",
    },
    Spec {
        kind: MaterialKind::PostgresBase,
        id: "m-base",
        path: "pg/base",
        bytes: b"base-bytes-xxxx",
    },
    Spec {
        kind: MaterialKind::WalSegment,
        id: "m-wal",
        path: "pg/wal/0001",
        bytes: b"wal-bytes",
    },
    Spec {
        kind: MaterialKind::PostgresConfig,
        id: "m-conf",
        path: "pg/postgresql.conf",
        bytes: b"",
    },
    Spec {
        kind: MaterialKind::SchemaChecksum,
        id: "m-schema",
        path: "schema/checksum",
        bytes: b"schema-digest",
    },
    Spec {
        kind: MaterialKind::MigrationChecksum,
        id: "m-mig",
        path: "schema/migration/native0031",
        bytes: b"mig-digest",
    },
    Spec {
        kind: MaterialKind::KeyWrappingObject,
        id: "m-wrap",
        path: "vault/wrap/v1",
        bytes: b"wrap-ciphertext",
    },
    Spec {
        kind: MaterialKind::ProfileInventory,
        id: "m-profile",
        path: "profiles/index",
        bytes: b"profiles",
    },
    Spec {
        kind: MaterialKind::WorkspaceInventory,
        id: "m-workspace",
        path: "workspaces/index",
        bytes: b"workspaces",
    },
    Spec {
        kind: MaterialKind::CompatibilityRecord,
        id: "m-compat",
        path: "compat/record",
        bytes: b"compat",
    },
    Spec {
        kind: MaterialKind::AuditCheckpointObject,
        id: "m-audit",
        path: "audit/checkpoint",
        bytes: b"audit-bytes",
    },
];

fn d(label: &str) -> Sha256Digest {
    Sha256Digest::of(label.as_bytes())
}

fn content_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of(bytes)
}

fn rev(name: &str) -> ComponentRev {
    ComponentRev {
        name: name.to_owned(),
        epoch: 5,
        digest: d(name),
    }
}

fn compatibility() -> CompatibilitySet {
    CompatibilitySet {
        application: rev("application"),
        postgres: rev("postgres"),
        engine: rev("engine"),
        ui: rev("ui"),
    }
}

fn vault_key() -> VaultKeyRefClaim {
    VaultKeyRefClaim {
        key_id: "vault-key-1".to_owned(),
        key_version: KeyVersion::new(1),
        canary: d("canary-1"),
    }
}

fn structural_plan() -> RestoreOutcome {
    let materials = SPECS
        .iter()
        .map(|spec| MaterialClaim {
            id: MaterialId::new(spec.id),
            kind: spec.kind,
            relative_path: spec.path.to_owned(),
            directory: false,
            declared_bytes: spec.bytes.len() as u64,
            digest: content_digest(spec.bytes),
            bundle_id: "bundle-1".to_owned(),
            dataset_id: "dataset-1".to_owned(),
            barrier_id: "barrier-1".to_owned(),
        })
        .collect();
    let key = vault_key();
    let claim = BackupInventoryClaim {
        bundle: BundleIdentity {
            bundle_id: "bundle-1".to_owned(),
            format_version: 1,
        },
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        barrier: BarrierIdentity::new("barrier-1"),
        key_binding: KeyBindingClaim::RecoveryWrapped {
            wrapping_refs: vec![WrappingRefClaim {
                key: key.clone(),
                wrapping_object_id: MaterialId::new("m-wrap"),
            }],
        },
        scram: ScramRelationClaim {
            relation_id: "scram-rel-1".to_owned(),
            bound_to_original_os_store: false,
        },
        audit: AuditCheckpointClaim {
            material_id: MaterialId::new("m-audit"),
            head_digest: d("audit-head"),
            event_count: 12,
        },
        compatibility: compatibility(),
        materials,
        empty_categories: Vec::new(),
        receipts: ReceiptSetClaim {
            committed: vec![ReceiptClaim {
                id: "committed-1".to_owned(),
                unknown: false,
            }],
            unknown: vec![ReceiptClaim {
                id: "unknown-1".to_owned(),
                unknown: true,
            }],
            tool: vec![ReceiptClaim {
                id: "tool-1".to_owned(),
                unknown: false,
            }],
        },
    };
    let target = ControlledRestoreTarget {
        mode: RestoreMode::SameInstallation,
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        schema_checksum: d("schema"),
        migration_checksums: vec![("native0031".to_owned(), d("mig"))],
        compatibility: compatibility(),
        requires_restore_build: true,
        vault_keys: vec![key],
        profiles_empty: false,
        workspaces_empty: false,
        unknown_receipts: 1,
        capacity: CapacityPolicy {
            original_site_bytes: 1_000,
            margin_bytes: 100,
        },
    };
    let observations = RestoreObservations {
        schema_checksum: Some(d("schema")),
        migration_checksums: Some(vec![("native0031".to_owned(), d("mig"))]),
        compatibility: Some(compatibility()),
        restore_build_present: Some(true),
        capacity: CapacityObservation::Available { bytes: 10_000 },
    };
    plan_restore(RestoreRequest {
        claim: &claim,
        target: &target,
        observations: &observations,
        bounds: &InventoryBounds::standard(),
    })
}

fn incomplete_plan() -> RestoreOutcome {
    let key = vault_key();
    let claim = BackupInventoryClaim {
        bundle: BundleIdentity {
            bundle_id: "bundle-1".to_owned(),
            format_version: 1,
        },
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        barrier: BarrierIdentity::new("barrier-1"),
        key_binding: KeyBindingClaim::RecoveryWrapped {
            wrapping_refs: vec![WrappingRefClaim {
                key: key.clone(),
                wrapping_object_id: MaterialId::new("m-wrap"),
            }],
        },
        scram: ScramRelationClaim {
            relation_id: "scram-rel-1".to_owned(),
            bound_to_original_os_store: false,
        },
        audit: AuditCheckpointClaim {
            material_id: MaterialId::new("m-audit"),
            head_digest: d("audit-head"),
            event_count: 12,
        },
        compatibility: compatibility(),
        materials: SPECS
            .iter()
            .filter(|spec| spec.kind != MaterialKind::WalSegment)
            .map(|spec| MaterialClaim {
                id: MaterialId::new(spec.id),
                kind: spec.kind,
                relative_path: spec.path.to_owned(),
                directory: false,
                declared_bytes: spec.bytes.len() as u64,
                digest: content_digest(spec.bytes),
                bundle_id: "bundle-1".to_owned(),
                dataset_id: "dataset-1".to_owned(),
                barrier_id: "barrier-1".to_owned(),
            })
            .collect(),
        empty_categories: Vec::new(),
        receipts: ReceiptSetClaim {
            committed: vec![ReceiptClaim {
                id: "committed-1".to_owned(),
                unknown: false,
            }],
            unknown: vec![ReceiptClaim {
                id: "unknown-1".to_owned(),
                unknown: true,
            }],
            tool: vec![ReceiptClaim {
                id: "tool-1".to_owned(),
                unknown: false,
            }],
        },
    };
    let target = ControlledRestoreTarget {
        mode: RestoreMode::SameInstallation,
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        schema_checksum: d("schema"),
        migration_checksums: vec![("native0031".to_owned(), d("mig"))],
        compatibility: compatibility(),
        requires_restore_build: true,
        vault_keys: vec![key],
        profiles_empty: false,
        workspaces_empty: false,
        unknown_receipts: 1,
        capacity: CapacityPolicy {
            original_site_bytes: 1_000,
            margin_bytes: 100,
        },
    };
    let observations = RestoreObservations {
        schema_checksum: Some(d("schema")),
        migration_checksums: Some(vec![("native0031".to_owned(), d("mig"))]),
        compatibility: Some(compatibility()),
        restore_build_present: Some(true),
        capacity: CapacityObservation::Available { bytes: 10_000 },
    };
    let outcome = plan_restore(RestoreRequest {
        claim: &claim,
        target: &target,
        observations: &observations,
        bounds: &InventoryBounds::standard(),
    });
    assert!(!matches!(outcome, RestoreOutcome::StructuralPlan(_)));
    outcome
}

fn chunks_of(bytes: &[u8], size: usize) -> Vec<Result<Chunk, StagingFault>> {
    if bytes.is_empty() {
        return vec![Chunk::try_new(0, Vec::new(), true)];
    }
    let mut out = Vec::new();
    let mut seq = 0_u32;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + size).min(bytes.len());
        let terminal = end == bytes.len();
        out.push(Chunk::try_new(seq, bytes[offset..end].to_vec(), terminal));
        offset = end;
        seq += 1;
    }
    out
}

fn scripted(size: usize) -> ScriptedSource {
    let mut source = ScriptedSource::new();
    for spec in SPECS {
        source.insert(spec.id, chunks_of(spec.bytes, size));
    }
    source
}

fn write_source_tree(root: &Path) {
    for spec in SPECS {
        let path = root.join(spec.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, spec.bytes).unwrap();
    }
}

fn site_manifest(root: &Path) -> BTreeMap<String, (u64, [u8; 32])> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for item in fs::read_dir(dir).unwrap() {
            let path = item.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                pending.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path).unwrap();
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            out.insert(rel, (bytes.len() as u64, digest));
        }
    }
    out
}

fn request(parent: &Path, slot: &str) -> StagingRequest {
    StagingRequest {
        parent: parent.to_path_buf(),
        slot: slot.to_owned(),
    }
}

fn stage(
    outcome: &RestoreOutcome,
    source: &mut dyn super::staging::MaterialSource,
    req: &StagingRequest,
    cancel: &CancelFlag,
    fs: &dyn super::staging::FsPort,
    bounds: StagingBounds,
) -> StagingOutcome {
    run_staging(StagingInput {
        outcome,
        source,
        request: req,
        cancel,
        fs,
        bounds,
    })
}

#[test]
fn illegal_precheck_writes_zero_files() {
    let temp = Temp::new("precheck");
    let original = temp.0.join("original");
    fs::create_dir(&original).unwrap();
    fs::write(original.join("keep"), b"keep-me").unwrap();
    let before = site_manifest(&original);
    let outcome = incomplete_plan();
    let mut source = scripted(8);
    let req = request(&temp.0, "staging-slot");
    let cancel = CancelFlag::new();
    let fs = StdFs;
    let result = stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    );
    match result {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::PlanNotStructural);
            assert_eq!(fail.files_written(), 0);
            assert!(fail.original_site_preserved());
            assert!(matches!(fail.cleanup(), CleanupReport::NotCreated));
        }
        other => panic!("{other:?}"),
    }
    assert!(!temp.0.join("staging-slot").exists());
    assert_eq!(site_manifest(&original), before);
}

#[test]
fn scripted_multi_file_empty_and_multi_chunk_succeeds_without_authorization() {
    let temp = Temp::new("ok");
    let outcome = structural_plan();
    let mut source = scripted(4);
    let req = request(&temp.0, "slot");
    let cancel = CancelFlag::new();
    let fs = StdFs;
    let bounds = StagingBounds::try_new(4, 64, 10_000, 10_000).unwrap();
    match stage(&outcome, &mut source, &req, &cancel, &fs, bounds) {
        StagingOutcome::Completed(done) => {
            assert_eq!(done.files_written(), SPECS.len() as u32);
            assert!(done.digest_integrity());
            assert!(!done.grants_restore_switch());
            assert!(!done.application_ready());
            assert!(!done.aead_authenticated());
            assert!(!source.reentered());
            assert!(source.pulls() >= SPECS.len() as u32);
            let staged = fs::read(temp.0.join("slot/pg/base")).unwrap();
            assert_eq!(staged, b"base-bytes-xxxx");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn oversized_chunk_truncated_extra_reorder_and_bad_digest_fail() {
    assert_eq!(
        Chunk::try_new(0, vec![0; 4 * 1024 * 1024 + 1], true).unwrap_err(),
        StagingFault::ChunkTooLarge
    );
    let outcome = structural_plan();
    let bounds = StagingBounds::try_new(4, 64, 10_000, 10_000).unwrap();
    let fs = StdFs;
    let cancel = CancelFlag::new();

    let mut too_big = ScriptedSource::new();
    for spec in SPECS {
        if spec.id == "m-bundle" {
            too_big.insert(
                spec.id,
                vec![Chunk::try_new(0, vec![0; 4 * 1024 * 1024 + 1], true)],
            );
        } else {
            too_big.insert(spec.id, chunks_of(spec.bytes, 8));
        }
    }
    let temp = Temp::new("big");
    let req = request(&temp.0, "slot");
    match stage(&outcome, &mut too_big, &req, &cancel, &fs, bounds) {
        StagingOutcome::Failed(fail) => assert_eq!(fail.fault(), StagingFault::ChunkTooLarge),
        other => panic!("big {other:?}"),
    }

    let mut truncated = scripted(8);
    truncated.insert("m-bundle", vec![Chunk::try_new(0, b"bund".to_vec(), true)]);
    let temp = Temp::new("trunc");
    let req = request(&temp.0, "slot");
    match stage(&outcome, &mut truncated, &req, &cancel, &fs, bounds) {
        StagingOutcome::Failed(fail) => assert_eq!(fail.fault(), StagingFault::ShortRead),
        other => panic!("trunc {other:?}"),
    }

    let wide = StagingBounds::standard();
    let mut extra = ScriptedSource::new();
    for spec in SPECS {
        if spec.id == "m-bundle" {
            extra.insert(
                spec.id,
                vec![
                    Chunk::try_new(0, spec.bytes.to_vec(), true),
                    Chunk::try_new(1, b"x".to_vec(), true),
                ],
            );
        } else {
            extra.insert(spec.id, chunks_of(spec.bytes, 8));
        }
    }
    let temp = Temp::new("extra");
    let req = request(&temp.0, "slot");
    match stage(&outcome, &mut extra, &req, &cancel, &fs, wide) {
        StagingOutcome::Failed(fail) => assert_eq!(fail.fault(), StagingFault::ExtraTail),
        other => panic!("extra {other:?}"),
    }

    let mut reorder = ScriptedSource::new();
    for spec in SPECS {
        if spec.id == "m-base" {
            let bytes = spec.bytes;
            reorder.insert(
                spec.id,
                vec![
                    Chunk::try_new(1, bytes[4..].to_vec(), true),
                    Chunk::try_new(0, bytes[..4].to_vec(), false),
                ],
            );
        } else {
            reorder.insert(spec.id, chunks_of(spec.bytes, 8));
        }
    }
    let temp = Temp::new("reorder");
    let req = request(&temp.0, "slot");
    match stage(&outcome, &mut reorder, &req, &cancel, &fs, wide) {
        StagingOutcome::Failed(fail) => assert_eq!(fail.fault(), StagingFault::Reordered),
        other => panic!("reorder {other:?}"),
    }

    let mut bad = scripted(8);
    bad.insert(
        "m-bundle",
        vec![Chunk::try_new(0, b"BUNDLE-bytes".to_vec(), true)],
    );
    let temp = Temp::new("digest");
    let req = request(&temp.0, "slot");
    match stage(&outcome, &mut bad, &req, &cancel, &fs, wide) {
        StagingOutcome::Failed(fail) => assert_eq!(fail.fault(), StagingFault::DigestMismatch),
        other => panic!("digest {other:?}"),
    }
}

#[test]
fn real_tree_staging_preserves_original_site_and_old_package() {
    let temp = Temp::new("tree");
    let original = temp.0.join("original-site");
    let old_pkg = temp.0.join("old-package");
    let source_root = temp.0.join("source");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&old_pkg).unwrap();
    fs::write(original.join("keep"), b"keep-me").unwrap();
    fs::write(old_pkg.join("prev"), b"previous-backup").unwrap();
    write_source_tree(&source_root);
    let before_site = site_manifest(&original);
    let before_pkg = site_manifest(&old_pkg);
    let outcome = structural_plan();
    let RestoreOutcome::StructuralPlan(plan) = &outcome else {
        panic!("plan");
    };
    let bounds = StagingBounds::try_new(8, 64, 10_000, 10_000).unwrap();
    let mut source = FileTreeSource::open(&source_root, plan, bounds).unwrap();
    let req = request(&temp.0, "slot");
    let cancel = CancelFlag::new();
    let fs = StdFs;
    match stage(&outcome, &mut source, &req, &cancel, &fs, bounds) {
        StagingOutcome::Completed(done) => {
            assert_eq!(done.files_written(), SPECS.len() as u32);
            assert_eq!(
                fs::read(temp.0.join("slot/bundle/manifest")).unwrap(),
                b"bundle-bytes"
            );
            assert!(!done.grants_restore_switch());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(site_manifest(&original), before_site);
    assert_eq!(site_manifest(&old_pkg), before_pkg);

    let mut source = FileTreeSource::open(&source_root, plan, bounds).unwrap();
    match stage(&outcome, &mut source, &req, &cancel, &fs, bounds) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::StagingExists);
            assert_eq!(fail.files_written(), 0);
        }
        other => panic!("second {other:?}"),
    }
    assert_eq!(site_manifest(&original), before_site);
}

#[cfg(unix)]
#[test]
fn links_and_absolute_source_entries_are_rejected() {
    let temp = Temp::new("links");
    let source_root = temp.0.join("source");
    write_source_tree(&source_root);
    std::os::unix::fs::symlink(source_root.join("pg/base"), source_root.join("pg/link")).unwrap();
    let outcome = structural_plan();
    let RestoreOutcome::StructuralPlan(plan) = &outcome else {
        panic!();
    };
    let bounds = StagingBounds::standard();
    assert!(matches!(
        FileTreeSource::open(&source_root, plan, bounds),
        Err(StagingFault::LinkOrSpecialFile | StagingFault::UnregisteredEntry)
    ));
}

#[test]
fn cancel_before_create_and_write_failure_keep_original() {
    let temp = Temp::new("cancel");
    let original = temp.0.join("original");
    fs::create_dir(&original).unwrap();
    fs::write(original.join("keep"), b"keep").unwrap();
    let before = site_manifest(&original);
    let outcome = structural_plan();
    let mut source = scripted(8);
    let req = request(&temp.0, "slot");
    let cancel = CancelFlag::new();
    cancel.cancel();
    let fs = StdFs;
    match stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    ) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::Cancelled);
            assert_eq!(fail.files_written(), 0);
        }
        other => panic!("{other:?}"),
    }
    assert!(!temp.0.join("slot").exists());
    assert_eq!(site_manifest(&original), before);

    let mut source = scripted(8);
    let cancel = CancelFlag::new();
    let fs = FaultInjectingFs::new().fail_write_after(1);
    match stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    ) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::WriteFailed);
            assert!(fail.original_site_preserved());
        }
        other => panic!("write {other:?}"),
    }
    assert_eq!(site_manifest(&original), before);
}

#[test]
fn sync_failure_and_residue_prevent_treating_partial_as_success() {
    let temp = Temp::new("sync");
    let outcome = structural_plan();
    let mut source = scripted(8);
    let req = request(&temp.0, "slot");
    let cancel = CancelFlag::new();
    let fs = FaultInjectingFs::new().fail_sync();
    match stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    ) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::SyncFailed);
            assert!(fail.original_site_preserved());
        }
        other => panic!("{other:?}"),
    }

    let temp = Temp::new("residue");
    let mut source = scripted(8);
    let req = request(&temp.0, "slot");
    let cancel = CancelFlag::new();
    let fs = FaultInjectingFs::new().fail_write_after(1).fail_remove();
    let cleanup = match stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    ) {
        StagingOutcome::Failed(fail) => fail.cleanup().clone(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(cleanup, CleanupReport::Residue { .. }));
    let mut source = scripted(8);
    let fs = StdFs;
    match stage(
        &outcome,
        &mut source,
        &req,
        &cancel,
        &fs,
        StagingBounds::standard(),
    ) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::StagingExists);
            assert_eq!(fail.files_written(), 0);
        }
        StagingOutcome::Completed(_) => panic!("partial staging must not count as success"),
    }
}
