//! 正反例一律走 [`super::plan_restore`]，不测同构 helper。

use openbot_contracts::ids::{DeploymentId, TenantId};

use super::{
    BackupInventoryClaim, BarrierIdentity, BlockedReason, BundleIdentity, CapacityObservation,
    CapacityPolicy, CompatibilitySet, ComponentRev, ControlledRestoreTarget, DatasetIdentity,
    EmptyCategoryClaim, EmptyReason, IncompleteReason, InstallationIdentity, InventoryBounds,
    InventoryFault, KeyBindingClaim, MaterialClaim, MaterialId, MaterialKind, ReceiptClaim,
    ReceiptSetClaim, RestoreMode, RestoreObservations, RestoreOutcome, RestoreRequest,
    ScramRelationClaim, VaultKeyRefClaim, WrappingRefClaim, plan_restore,
};
use crate::audit::hash::Sha256Digest;
use crate::vault::KeyVersion;

struct Case {
    claim: BackupInventoryClaim,
    target: ControlledRestoreTarget,
    observations: RestoreObservations,
    bounds: InventoryBounds,
}

impl Case {
    fn request(&self) -> RestoreRequest<'_> {
        RestoreRequest {
            claim: &self.claim,
            target: &self.target,
            observations: &self.observations,
            bounds: &self.bounds,
        }
    }
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of(label.as_bytes())
}

fn rev(name: &str) -> ComponentRev {
    ComponentRev {
        name: name.to_owned(),
        epoch: 5,
        digest: digest(name),
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
        canary: digest("canary-1"),
    }
}

fn entry(kind: MaterialKind, id: &str, path: &str, bytes: u64) -> MaterialClaim {
    MaterialClaim {
        id: MaterialId::new(id),
        kind,
        relative_path: path.to_owned(),
        directory: false,
        declared_bytes: bytes,
        digest: digest(id),
        bundle_id: "bundle-1".to_owned(),
        dataset_id: "dataset-1".to_owned(),
        barrier_id: "barrier-1".to_owned(),
    }
}

fn complete() -> Case {
    let materials = vec![
        entry(
            MaterialKind::BundleManifest,
            "m-bundle",
            "bundle/manifest",
            16,
        ),
        entry(MaterialKind::PostgresBase, "m-base", "pg/base", 64),
        entry(MaterialKind::WalSegment, "m-wal", "pg/wal/0001", 32),
        entry(
            MaterialKind::PostgresConfig,
            "m-conf",
            "pg/postgresql.conf",
            8,
        ),
        entry(
            MaterialKind::SchemaChecksum,
            "m-schema",
            "schema/checksum",
            32,
        ),
        entry(
            MaterialKind::MigrationChecksum,
            "m-mig",
            "schema/migration/native0031",
            32,
        ),
        entry(
            MaterialKind::KeyWrappingObject,
            "m-wrap",
            "vault/wrap/v1",
            48,
        ),
        entry(
            MaterialKind::ProfileInventory,
            "m-profile",
            "profiles/index",
            8,
        ),
        entry(
            MaterialKind::WorkspaceInventory,
            "m-workspace",
            "workspaces/index",
            8,
        ),
        entry(
            MaterialKind::CompatibilityRecord,
            "m-compat",
            "compat/record",
            16,
        ),
        entry(
            MaterialKind::AuditCheckpointObject,
            "m-audit",
            "audit/checkpoint",
            24,
        ),
    ];
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
        audit: super::AuditCheckpointClaim {
            material_id: MaterialId::new("m-audit"),
            head_digest: digest("audit-head"),
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
        schema_checksum: digest("schema"),
        migration_checksums: vec![("native0031".to_owned(), digest("mig"))],
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
        schema_checksum: Some(digest("schema")),
        migration_checksums: Some(vec![("native0031".to_owned(), digest("mig"))]),
        compatibility: Some(compatibility()),
        restore_build_present: Some(true),
        capacity: CapacityObservation::Available { bytes: 10_000 },
    };
    Case {
        claim,
        target,
        observations,
        bounds: InventoryBounds::standard(),
    }
}

fn plan(case: &Case) -> RestoreOutcome {
    plan_restore(case.request())
}

fn structural(case: &Case) -> super::StructuralRestorePlan {
    match plan(case) {
        RestoreOutcome::StructuralPlan(plan) => plan,
        other => panic!("expected structural plan, got {other:?}"),
    }
}

#[test]
fn complete_controlled_inventory_yields_structural_plan_not_ready() {
    let case = complete();
    let plan = structural(&case);
    assert!(!plan.restore_authorized());
    assert!(!plan.application_ready());
    assert!(!plan.digest_match_proves_aead());
    assert!(!plan.wal_names_prove_postgres_recovery());
    assert!(!plan.issues_recovery_epoch());
    assert!(!plan.writes_database());
    assert!(!plan.generates_keys());
    assert!(!plan.restores_dispatch());
    assert!(!plan.schedules_unknown_replay());
    assert!(!plan.directory_copy_is_complete_restore());
    assert_eq!(plan.inventory().receipts().unknown(), ["unknown-1"]);
    assert!(plan.follow_up().must_not_replay_unknown());
    assert_eq!(
        plan.pending_proofs().aead_authenticity(),
        super::ProofStatus::Pending
    );
    assert_eq!(
        plan.pending_proofs().restore_authorized(),
        super::ProofStatus::NotGranted
    );
    assert!(!plan_restore(case.request()).product_ready());
}

#[test]
fn missing_each_required_material_is_incomplete() {
    let kinds = [
        MaterialKind::BundleManifest,
        MaterialKind::PostgresBase,
        MaterialKind::PostgresConfig,
        MaterialKind::SchemaChecksum,
        MaterialKind::MigrationChecksum,
        MaterialKind::CompatibilityRecord,
        MaterialKind::AuditCheckpointObject,
        MaterialKind::ProfileInventory,
        MaterialKind::WorkspaceInventory,
    ];
    for kind in kinds {
        let mut case = complete();
        case.claim.materials.retain(|item| item.kind != kind);
        match plan(&case) {
            RestoreOutcome::Incomplete(incomplete) => match incomplete.reason() {
                IncompleteReason::MissingRequired(found) => assert_eq!(found, kind),
                other => panic!("{kind:?} got {other:?}"),
            },
            other => panic!("{kind:?} got {other:?}"),
        }
    }
}

#[test]
fn required_wal_and_base_cannot_be_empty_directories() {
    let mut wal_dir = complete();
    let wal = wal_dir
        .claim
        .materials
        .iter_mut()
        .find(|item| item.kind == MaterialKind::WalSegment)
        .unwrap();
    wal.directory = true;
    wal.declared_bytes = 0;
    wal.digest = digest("");
    match plan(&wal_dir) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingWal);
        }
        other => panic!("wal directory {other:?}"),
    }

    let mut base_dir = complete();
    let base = base_dir
        .claim
        .materials
        .iter_mut()
        .find(|item| item.kind == MaterialKind::PostgresBase)
        .unwrap();
    base.directory = true;
    base.declared_bytes = 0;
    base.digest = digest("");
    match plan(&base_dir) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(
                incomplete.reason(),
                IncompleteReason::MissingRequired(MaterialKind::PostgresBase)
            );
        }
        other => panic!("base directory {other:?}"),
    }
}

#[test]
fn missing_wal_is_incomplete() {
    let mut case = complete();
    case.claim
        .materials
        .retain(|item| item.kind != MaterialKind::WalSegment);
    match plan(&case) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingWal);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn explained_empty_profiles_and_workspaces_are_allowed() {
    let mut case = complete();
    case.claim.materials.retain(|item| {
        item.kind != MaterialKind::ProfileInventory && item.kind != MaterialKind::WorkspaceInventory
    });
    case.claim.empty_categories = vec![
        EmptyCategoryClaim {
            kind: MaterialKind::ProfileInventory,
            reason: EmptyReason::DatasetContainsNoProfiles,
        },
        EmptyCategoryClaim {
            kind: MaterialKind::WorkspaceInventory,
            reason: EmptyReason::DatasetContainsNoWorkspaces,
        },
    ];
    case.target.profiles_empty = true;
    case.target.workspaces_empty = true;
    let plan = structural(&case);
    assert_eq!(plan.inventory().explained_empty().len(), 2);
}

#[test]
fn empty_profiles_without_controlled_reason_are_incomplete() {
    let mut case = complete();
    case.claim
        .materials
        .retain(|item| item.kind != MaterialKind::ProfileInventory);
    case.target.profiles_empty = true;
    match plan(&case) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(
                incomplete.reason(),
                IncompleteReason::EmptyWithoutReason(MaterialKind::ProfileInventory)
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn duplicate_path_and_id_are_rejected() {
    let mut path_case = complete();
    let mut dup = path_case.claim.materials[1].clone();
    dup.id = MaterialId::new("m-dup-path");
    path_case.claim.materials.push(dup);
    match plan(&path_case) {
        RestoreOutcome::Rejected(InventoryFault::DuplicatePath) => {}
        other => panic!("path {other:?}"),
    }

    let mut id_case = complete();
    let mut dup = id_case.claim.materials[1].clone();
    dup.relative_path = "pg/base-copy".to_owned();
    id_case.claim.materials.push(dup);
    match plan(&id_case) {
        RestoreOutcome::Rejected(InventoryFault::DuplicateId) => {}
        other => panic!("id {other:?}"),
    }
}

#[test]
fn prefix_and_alias_conflicts_are_rejected() {
    let mut prefix = complete();
    prefix.claim.materials.push(entry(
        MaterialKind::WalSegment,
        "m-nested",
        "pg/base/extra",
        4,
    ));
    match plan(&prefix) {
        RestoreOutcome::Rejected(InventoryFault::PrefixOrAliasConflict) => {}
        other => panic!("prefix {other:?}"),
    }

    let mut alias = complete();
    alias
        .claim
        .materials
        .push(entry(MaterialKind::WalSegment, "m-alias", "PG/WAL/0002", 4));
    // fold of pg/wal/0001 vs PG/WAL/0002 is different; force same path different case
    alias.claim.materials.last_mut().unwrap().relative_path = "PG/base".to_owned();
    match plan(&alias) {
        RestoreOutcome::Rejected(InventoryFault::PrefixOrAliasConflict) => {}
        other => panic!("alias {other:?}"),
    }
}

#[test]
fn count_length_and_accumulated_overflow_are_rejected() {
    let mut count = complete();
    count.bounds = InventoryBounds::try_new(3, 255, 8, 1024, 10_000, 128, 32).unwrap();
    match plan(&count) {
        RestoreOutcome::Rejected(InventoryFault::CountOutOfBounds) => {}
        other => panic!("count {other:?}"),
    }

    let mut length = complete();
    length.claim.materials[1].declared_bytes = InventoryBounds::standard().max_entry_bytes() + 1;
    match plan(&length) {
        RestoreOutcome::Rejected(InventoryFault::LengthOutOfBounds) => {}
        other => panic!("length {other:?}"),
    }

    let mut overflow = complete();
    overflow.bounds = InventoryBounds::try_new(4_096, 255, 8, u64::MAX, u64::MAX, 128, 32).unwrap();
    overflow.claim.materials[1].declared_bytes = u64::MAX;
    overflow.claim.materials[2].declared_bytes = 1;
    match plan(&overflow) {
        RestoreOutcome::Rejected(InventoryFault::AccumulatedOverflow) => {}
        other => panic!("overflow {other:?}"),
    }
}

#[test]
fn traversal_absolute_and_secret_paths_are_rejected() {
    for path in ["../escape", "/abs/path", "C:/windows", "dir/password.txt"] {
        let mut case = complete();
        case.claim.materials[1].relative_path = path.to_owned();
        match plan(&case) {
            RestoreOutcome::Rejected(
                InventoryFault::PathInvalid | InventoryFault::SecretMaterialForbidden,
            ) => {}
            other => panic!("{path} -> {other:?}"),
        }
    }
}

#[test]
fn wrong_bundle_dataset_and_barrier_are_rejected() {
    let mut bundle = complete();
    bundle.claim.materials[2].bundle_id = "other-bundle".to_owned();
    match plan(&bundle) {
        RestoreOutcome::Rejected(InventoryFault::BundleMismatch) => {}
        other => panic!("bundle {other:?}"),
    }
    let mut dataset = complete();
    dataset.claim.materials[2].dataset_id = "other-dataset".to_owned();
    match plan(&dataset) {
        RestoreOutcome::Rejected(InventoryFault::DatasetMismatch) => {}
        other => panic!("dataset {other:?}"),
    }
    let mut barrier = complete();
    barrier.claim.materials[2].barrier_id = "other-barrier".to_owned();
    match plan(&barrier) {
        RestoreOutcome::Rejected(InventoryFault::BarrierMismatch) => {}
        other => panic!("barrier {other:?}"),
    }
}

#[test]
fn wrong_key_id_and_canary_are_blocked() {
    let mut key = complete();
    key.target.vault_keys[0].key_id = "other-key".to_owned();
    match plan(&key) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::KeyIdMismatch);
        }
        other => panic!("key {other:?}"),
    }
    let mut canary = complete();
    canary.target.vault_keys[0].canary = digest("other-canary");
    match plan(&canary) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::CanaryMismatch);
        }
        other => panic!("canary {other:?}"),
    }
}

#[test]
fn missing_wrapping_object_is_incomplete() {
    let mut case = complete();
    case.claim
        .materials
        .retain(|item| item.kind != MaterialKind::KeyWrappingObject);
    match plan(&case) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingKeyWrappingRef);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn same_installation_only_cannot_plan_new_install() {
    let mut case = complete();
    case.claim.key_binding = KeyBindingClaim::SameInstallationOsStoreOnly {
        key_refs: vec![vault_key()],
    };
    case.claim
        .materials
        .retain(|item| item.kind != MaterialKind::KeyWrappingObject);
    case.target.mode = RestoreMode::NewInstallation {
        new_installation: InstallationIdentity::new("install-2"),
    };
    match plan(&case) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::SameInstallationOnly);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn new_install_keeps_business_identity_and_does_not_use_fresh_derivation() {
    let mut case = complete();
    case.target.mode = RestoreMode::NewInstallation {
        new_installation: InstallationIdentity::new("install-2"),
    };
    let plan = structural(&case);
    match plan.identity() {
        super::IdentityBinding::NewInstallation {
            original_installation,
            new_installation,
            dataset,
            record_ids_preserved,
            ..
        } => {
            assert_eq!(original_installation.as_str(), "install-1");
            assert_eq!(new_installation.as_str(), "install-2");
            assert_eq!(dataset.as_str(), "dataset-1");
            assert!(record_ids_preserved);
        }
        other => panic!("{other:?}"),
    }
    assert!(plan.identity().preserves_business_identity());
    assert!(!plan.identity().applies_fresh_identity_derivation());
    assert!(plan.follow_up().bind_installation_to_dataset());
    assert!(plan.follow_up().mint_new_recovery_epoch());
}

#[test]
fn renaming_business_identity_or_reusing_installation_is_blocked() {
    let mut rename = complete();
    rename.target.dataset = DatasetIdentity::new("dataset-renamed");
    match plan(&rename) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::WouldRenameBusinessIdentity);
        }
        other => panic!("rename {other:?}"),
    }
    let mut reuse = complete();
    reuse.target.mode = RestoreMode::NewInstallation {
        new_installation: InstallationIdentity::new("install-1"),
    };
    match plan(&reuse) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(
                blocked.reason(),
                BlockedReason::NewInstallReusedInstallation
            );
        }
        other => panic!("reuse {other:?}"),
    }
}

#[test]
fn incompatible_release_and_missing_restore_build_do_not_guess() {
    let mut incompat = complete();
    incompat.observations.compatibility = Some(CompatibilitySet {
        application: ComponentRev {
            name: "application".to_owned(),
            epoch: 4,
            digest: digest("application"),
        },
        ..compatibility()
    });
    match plan(&incompat) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::IncompatibleRelease);
        }
        other => panic!("incompat {other:?}"),
    }

    let mut missing_build = complete();
    missing_build.observations.restore_build_present = None;
    match plan(&missing_build) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingRestoreBuild);
        }
        other => panic!("build {other:?}"),
    }

    let mut missing_mig = complete();
    missing_mig.observations.migration_checksums = None;
    match plan(&missing_mig) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(
                incomplete.reason(),
                IncompleteReason::MissingMigrationChecksum
            );
        }
        other => panic!("mig {other:?}"),
    }
}

#[test]
fn insufficient_or_missing_capacity_refuses_before_mutating_original() {
    let mut missing = complete();
    missing.observations.capacity = CapacityObservation::Missing;
    match plan(&missing) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingCapacityFacts);
        }
        other => panic!("missing {other:?}"),
    }
    let mut short = complete();
    short.observations.capacity = CapacityObservation::Available { bytes: 10 };
    match plan(&short) {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::InsufficientCapacity);
            assert!(!blocked.restore_authorized());
        }
        other => panic!("short {other:?}"),
    }
}

#[test]
fn unknown_receipts_cannot_be_omitted_or_scheduled_for_replay() {
    let mut omitted = complete();
    omitted.claim.receipts.unknown.clear();
    match plan(&omitted) {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(
                incomplete.reason(),
                IncompleteReason::MissingUnknownReceipts
            );
        }
        other => panic!("omitted {other:?}"),
    }
    let kept = structural(&complete());
    assert_eq!(kept.inventory().receipts().unknown(), ["unknown-1"]);
    assert!(!kept.schedules_unknown_replay());
}

#[test]
fn wrapping_reference_wrong_kind_or_directory_is_rejected() {
    let mut wrong_kind = complete();
    wrong_kind
        .claim
        .materials
        .iter_mut()
        .find(|item| item.id.as_str() == "m-wrap")
        .unwrap()
        .kind = MaterialKind::PostgresConfig;
    match plan(&wrong_kind) {
        RestoreOutcome::Rejected(InventoryFault::CrossReferenceMismatch) => {}
        other => panic!("kind {other:?}"),
    }

    let mut as_dir = complete();
    let wrap = as_dir
        .claim
        .materials
        .iter_mut()
        .find(|item| item.id.as_str() == "m-wrap")
        .unwrap();
    wrap.directory = true;
    wrap.declared_bytes = 0;
    match plan(&as_dir) {
        RestoreOutcome::Rejected(InventoryFault::MaterialShapeInvalid) => {}
        other => panic!("dir {other:?}"),
    }

    let mut audit_kind = complete();
    audit_kind
        .claim
        .materials
        .iter_mut()
        .find(|item| item.id.as_str() == "m-audit")
        .unwrap()
        .kind = MaterialKind::PostgresConfig;
    match plan(&audit_kind) {
        RestoreOutcome::Rejected(InventoryFault::CrossReferenceMismatch) => {}
        other => panic!("audit {other:?}"),
    }
}

#[test]
fn unknown_receipt_cannot_be_reclassified_by_bucket() {
    let mut demoted = complete();
    let unknown = demoted.claim.receipts.unknown.pop().unwrap();
    demoted.claim.receipts.committed.push(unknown);
    demoted.claim.receipts.unknown.push(ReceiptClaim {
        id: "unknown-replacement".to_owned(),
        unknown: true,
    });
    match plan(&demoted) {
        RestoreOutcome::Rejected(InventoryFault::ReceiptCategoryMismatch) => {}
        other => panic!("demoted {other:?}"),
    }
}

#[test]
fn empty_category_claims_are_bounded_deduped_and_consistent() {
    let mut overflow = complete();
    overflow.claim.empty_categories = vec![
        EmptyCategoryClaim {
            kind: MaterialKind::ProfileInventory,
            reason: EmptyReason::DatasetContainsNoProfiles,
        };
        4097
    ];
    match plan(&overflow) {
        RestoreOutcome::Rejected(InventoryFault::CountOutOfBounds) => {}
        other => panic!("overflow {other:?}"),
    }

    let mut conflict = complete();
    conflict.claim.empty_categories = vec![EmptyCategoryClaim {
        kind: MaterialKind::ProfileInventory,
        reason: EmptyReason::DatasetContainsNoProfiles,
    }];
    match plan(&conflict) {
        RestoreOutcome::Rejected(InventoryFault::EmptyCategoryInconsistent) => {}
        other => panic!("conflict {other:?}"),
    }

    let mut duplicate = complete();
    duplicate.claim.materials.retain(|item| {
        item.kind != MaterialKind::ProfileInventory && item.kind != MaterialKind::WorkspaceInventory
    });
    duplicate.target.profiles_empty = true;
    duplicate.target.workspaces_empty = true;
    duplicate.claim.empty_categories = vec![
        EmptyCategoryClaim {
            kind: MaterialKind::ProfileInventory,
            reason: EmptyReason::DatasetContainsNoProfiles,
        },
        EmptyCategoryClaim {
            kind: MaterialKind::ProfileInventory,
            reason: EmptyReason::DatasetContainsNoProfiles,
        },
    ];
    match plan(&duplicate) {
        RestoreOutcome::Rejected(InventoryFault::EmptyCategoryInconsistent) => {}
        other => panic!("dup {other:?}"),
    }
}
