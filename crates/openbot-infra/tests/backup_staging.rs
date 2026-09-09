//! GK-04 集成入口：真实 I/O 暂存，原现场不变。

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
use openbot_infra::backup::{
    CancelFlag, FileTreeSource, StagingBounds, StagingFault, StagingInput, StagingOutcome,
    StagingRequest, StdFs, run_staging,
};
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wrok-backup-staging-it-{}-{}-{}",
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

fn d(label: &str) -> Sha256Digest {
    Sha256Digest::of(label.as_bytes())
}

fn fixtures_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v5/backup-staging/source")
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let dest = to.join(item.file_name());
        if item.path().is_dir() {
            copy_dir(&item.path(), &dest);
        } else {
            fs::copy(item.path(), dest).unwrap();
        }
    }
}

fn site_manifest(root: &Path) -> BTreeMap<String, [u8; 32]> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for item in fs::read_dir(&dir).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
            out.insert(rel, digest);
        }
    }
    out
}

fn plan_for(files: &[(&str, MaterialKind, &str, Vec<u8>)]) -> RestoreOutcome {
    let key = VaultKeyRefClaim {
        key_id: "vault-key-1".to_owned(),
        key_version: KeyVersion::new(1),
        canary: d("canary-1"),
    };
    let materials = files
        .iter()
        .map(|(id, kind, path, bytes)| MaterialClaim {
            id: MaterialId::new(*id),
            kind: *kind,
            relative_path: (*path).to_owned(),
            directory: false,
            declared_bytes: bytes.len() as u64,
            digest: Sha256Digest::of(bytes),
            bundle_id: "bundle-1".to_owned(),
            dataset_id: "dataset-1".to_owned(),
            barrier_id: "barrier-1".to_owned(),
        })
        .collect();
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
            event_count: 1,
        },
        compatibility: CompatibilitySet {
            application: ComponentRev {
                name: "application".into(),
                epoch: 5,
                digest: d("application"),
            },
            postgres: ComponentRev {
                name: "postgres".into(),
                epoch: 5,
                digest: d("postgres"),
            },
            engine: ComponentRev {
                name: "engine".into(),
                epoch: 5,
                digest: d("engine"),
            },
            ui: ComponentRev {
                name: "ui".into(),
                epoch: 5,
                digest: d("ui"),
            },
        },
        materials,
        empty_categories: Vec::new(),
        receipts: ReceiptSetClaim {
            committed: vec![ReceiptClaim {
                id: "c1".into(),
                unknown: false,
            }],
            unknown: vec![ReceiptClaim {
                id: "u1".into(),
                unknown: true,
            }],
            tool: Vec::new(),
        },
    };
    let compat = claim.compatibility.clone();
    let target = ControlledRestoreTarget {
        mode: RestoreMode::SameInstallation,
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        schema_checksum: d("schema"),
        migration_checksums: vec![("native0031".into(), d("mig"))],
        compatibility: compat.clone(),
        requires_restore_build: true,
        vault_keys: vec![key],
        profiles_empty: false,
        workspaces_empty: false,
        unknown_receipts: 1,
        capacity: CapacityPolicy {
            original_site_bytes: 10,
            margin_bytes: 10,
        },
    };
    let observations = RestoreObservations {
        schema_checksum: Some(d("schema")),
        migration_checksums: Some(vec![("native0031".into(), d("mig"))]),
        compatibility: Some(compat),
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

fn required_files(root: &Path) -> Vec<(&'static str, MaterialKind, &'static str, Vec<u8>)> {
    let read = |rel: &str| fs::read(root.join(rel)).unwrap_or_default();
    vec![
        (
            "m-bundle",
            MaterialKind::BundleManifest,
            "bundle/manifest",
            read("bundle/manifest"),
        ),
        (
            "m-base",
            MaterialKind::PostgresBase,
            "pg/base",
            b"base".to_vec(),
        ),
        (
            "m-wal",
            MaterialKind::WalSegment,
            "pg/wal/0001",
            b"wal".to_vec(),
        ),
        (
            "m-conf",
            MaterialKind::PostgresConfig,
            "pg/postgresql.conf",
            Vec::new(),
        ),
        (
            "m-schema",
            MaterialKind::SchemaChecksum,
            "schema/checksum",
            b"schema".to_vec(),
        ),
        (
            "m-mig",
            MaterialKind::MigrationChecksum,
            "schema/migration/native0031",
            b"mig".to_vec(),
        ),
        (
            "m-wrap",
            MaterialKind::KeyWrappingObject,
            "vault/wrap/v1",
            b"wrap".to_vec(),
        ),
        (
            "m-profile",
            MaterialKind::ProfileInventory,
            "profiles/index",
            b"p".to_vec(),
        ),
        (
            "m-workspace",
            MaterialKind::WorkspaceInventory,
            "workspaces/index",
            b"w".to_vec(),
        ),
        (
            "m-compat",
            MaterialKind::CompatibilityRecord,
            "compat/record",
            b"c".to_vec(),
        ),
        (
            "m-audit",
            MaterialKind::AuditCheckpointObject,
            "audit/checkpoint",
            b"a".to_vec(),
        ),
    ]
}

fn materialize(root: &Path, files: &[(&str, MaterialKind, &str, Vec<u8>)]) {
    for (_, _, path, bytes) in files {
        let dest = root.join(path);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(dest, bytes).unwrap();
    }
}

#[test]
fn fixture_tree_stages_and_leaves_old_site_untouched() {
    let temp = Temp::new("it");
    let source = temp.0.join("source");
    copy_dir(&fixtures_source(), &source);
    let files = required_files(&source);
    materialize(&source, &files);
    let original = temp.0.join("original");
    let old_pkg = temp.0.join("old-pkg");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&old_pkg).unwrap();
    fs::write(original.join("live"), b"live-data").unwrap();
    fs::write(old_pkg.join("backup"), b"old-bytes").unwrap();
    let before_site = site_manifest(&original);
    let before_pkg = site_manifest(&old_pkg);

    let outcome = plan_for(&files);
    let RestoreOutcome::StructuralPlan(plan) = &outcome else {
        panic!("{outcome:?}");
    };
    let bounds = StagingBounds::try_new(8, 64, 10_000, 10_000).unwrap();
    let mut tree = FileTreeSource::open(&source, plan, bounds).unwrap();
    let req = StagingRequest {
        parent: temp.0.clone(),
        slot: "slot".into(),
    };
    let cancel = CancelFlag::new();
    let fs = StdFs;
    match run_staging(StagingInput {
        outcome: &outcome,
        source: &mut tree,
        request: &req,
        cancel: &cancel,
        fs: &fs,
        bounds,
    }) {
        StagingOutcome::Completed(done) => {
            assert_eq!(done.files_written(), files.len() as u32);
            assert!(!done.grants_restore_switch());
            assert!(!done.application_ready());
            assert_eq!(
                fs::read(temp.0.join("slot/bundle/manifest")).unwrap(),
                fs::read(source.join("bundle/manifest")).unwrap()
            );
            assert_eq!(
                fs::read(temp.0.join("slot/pg/postgresql.conf")).unwrap(),
                b""
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(site_manifest(&original), before_site);
    assert_eq!(site_manifest(&old_pkg), before_pkg);

    let mut tree = FileTreeSource::open(&source, plan, bounds).unwrap();
    match run_staging(StagingInput {
        outcome: &outcome,
        source: &mut tree,
        request: &req,
        cancel: &cancel,
        fs: &fs,
        bounds,
    }) {
        StagingOutcome::Failed(fail) => {
            assert_eq!(fail.fault(), StagingFault::StagingExists);
            assert_eq!(fail.files_written(), 0);
        }
        other => panic!("second {other:?}"),
    }
}
