//! GK-03 集成入口：从 test-only fixture 构造未核清单，只经 `plan_restore` 判定。

use std::path::PathBuf;

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::{
    BackupInventoryClaim, BarrierIdentity, BlockedReason, BundleIdentity, CapacityObservation,
    CapacityPolicy, CompatibilitySet, ComponentRev, ControlledRestoreTarget, DatasetIdentity,
    EmptyCategoryClaim, EmptyReason, IncompleteReason, InstallationIdentity, InventoryBounds,
    KeyBindingClaim, MaterialClaim, MaterialId, MaterialKind, ReceiptClaim, ReceiptSetClaim,
    RestoreMode, RestoreObservations, RestoreOutcome, RestoreRequest, ScramRelationClaim,
    VaultKeyRefClaim, WrappingRefClaim, plan_restore,
};
use openbot_domain::vault::KeyVersion;
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v5/backup-inventory")
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

fn kind_from(name: &str) -> MaterialKind {
    match name {
        "bundle_manifest" => MaterialKind::BundleManifest,
        "postgres_base" => MaterialKind::PostgresBase,
        "wal_segment" => MaterialKind::WalSegment,
        "postgres_config" => MaterialKind::PostgresConfig,
        "schema_checksum" => MaterialKind::SchemaChecksum,
        "migration_checksum" => MaterialKind::MigrationChecksum,
        "key_wrapping_object" => MaterialKind::KeyWrappingObject,
        "profile_inventory" => MaterialKind::ProfileInventory,
        "workspace_inventory" => MaterialKind::WorkspaceInventory,
        "compatibility_record" => MaterialKind::CompatibilityRecord,
        "audit_checkpoint" => MaterialKind::AuditCheckpointObject,
        other => panic!("unknown kind {other}"),
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

struct Loaded {
    claim: BackupInventoryClaim,
    target: ControlledRestoreTarget,
    observations: RestoreObservations,
    bounds: InventoryBounds,
}

fn load(name: &str) -> Loaded {
    let path = fixtures_dir().join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
    let json: Value = serde_json::from_str(&raw).expect("fixture json");
    assert_eq!(json["synthetic"], true);
    assert_eq!(json["testOnly"], true);

    let drop_kinds: Vec<MaterialKind> = json["dropKinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| kind_from(item.as_str().unwrap()))
        .collect();
    let mut materials = vec![
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
    materials.retain(|item| !drop_kinds.contains(&item.kind));

    let key = VaultKeyRefClaim {
        key_id: json["vaultKeyId"].as_str().unwrap().to_owned(),
        key_version: KeyVersion::new(
            u32::try_from(json["vaultKeyVersion"].as_u64().unwrap()).unwrap(),
        ),
        canary: digest(json["vaultCanary"].as_str().unwrap()),
    };
    let same_only = json["sameInstallationOnly"].as_bool().unwrap();
    let key_binding = if same_only {
        KeyBindingClaim::SameInstallationOsStoreOnly {
            key_refs: vec![key.clone()],
        }
    } else {
        KeyBindingClaim::RecoveryWrapped {
            wrapping_refs: vec![WrappingRefClaim {
                key: key.clone(),
                wrapping_object_id: MaterialId::new("m-wrap"),
            }],
        }
    };

    let empty_categories = json["emptyCategories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let kind = kind_from(pair[0].as_str().unwrap());
            let reason = match pair[1].as_str().unwrap() {
                "datasetContainsNoProfiles" => EmptyReason::DatasetContainsNoProfiles,
                "datasetContainsNoWorkspaces" => EmptyReason::DatasetContainsNoWorkspaces,
                other => panic!("{other}"),
            };
            EmptyCategoryClaim { kind, reason }
        })
        .collect();

    let omit_unknown = json["omitUnknown"].as_bool().unwrap_or(false);
    let unknown = if omit_unknown {
        Vec::new()
    } else {
        vec![ReceiptClaim {
            id: "unknown-1".to_owned(),
            unknown: true,
        }]
    };

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
        key_binding,
        scram: ScramRelationClaim {
            relation_id: "scram-rel-1".to_owned(),
            bound_to_original_os_store: same_only,
        },
        audit: openbot_domain::backup::AuditCheckpointClaim {
            material_id: MaterialId::new("m-audit"),
            head_digest: digest("audit-head"),
            event_count: 12,
        },
        compatibility: compatibility(),
        materials,
        empty_categories,
        receipts: ReceiptSetClaim {
            committed: vec![ReceiptClaim {
                id: "committed-1".to_owned(),
                unknown: false,
            }],
            unknown,
            tool: vec![ReceiptClaim {
                id: "tool-1".to_owned(),
                unknown: false,
            }],
        },
    };

    let mode = match json["mode"].as_str().unwrap() {
        "sameInstallation" => RestoreMode::SameInstallation,
        "newInstallation" => RestoreMode::NewInstallation {
            new_installation: InstallationIdentity::new(
                json["newInstallationId"].as_str().unwrap(),
            ),
        },
        other => panic!("{other}"),
    };

    let migrations = json["migrations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_owned(),
                digest(pair[1].as_str().unwrap()),
            )
        })
        .collect::<Vec<_>>();

    let target = ControlledRestoreTarget {
        mode,
        dataset: DatasetIdentity::new("dataset-1"),
        deployment: DeploymentId::new("deployment-1"),
        tenant: TenantId::new("tenant-1"),
        original_installation: InstallationIdentity::new("install-1"),
        schema_checksum: digest(json["schemaChecksum"].as_str().unwrap()),
        migration_checksums: migrations.clone(),
        compatibility: compatibility(),
        requires_restore_build: json["requiresRestoreBuild"].as_bool().unwrap(),
        vault_keys: vec![key],
        profiles_empty: json["profilesEmpty"].as_bool().unwrap(),
        workspaces_empty: json["workspacesEmpty"].as_bool().unwrap(),
        unknown_receipts: u32::try_from(json["unknownReceipts"].as_u64().unwrap()).unwrap(),
        capacity: CapacityPolicy {
            original_site_bytes: json["originalSiteBytes"].as_u64().unwrap(),
            margin_bytes: json["marginBytes"].as_u64().unwrap(),
        },
    };
    let observations = RestoreObservations {
        schema_checksum: Some(digest(json["schemaChecksum"].as_str().unwrap())),
        migration_checksums: Some(migrations),
        compatibility: Some(compatibility()),
        restore_build_present: Some(true),
        capacity: CapacityObservation::Available {
            bytes: json["availableBytes"].as_u64().unwrap(),
        },
    };
    Loaded {
        claim,
        target,
        observations,
        bounds: InventoryBounds::standard(),
    }
}

fn run(name: &str) -> RestoreOutcome {
    let loaded = load(name);
    plan_restore(RestoreRequest {
        claim: &loaded.claim,
        target: &loaded.target,
        observations: &loaded.observations,
        bounds: &loaded.bounds,
    })
}

#[test]
fn fixture_complete_is_structural_plan_not_authorized() {
    match run("complete.json") {
        RestoreOutcome::StructuralPlan(plan) => {
            assert!(!plan.restore_authorized());
            assert!(!plan.application_ready());
            assert!(!plan.schedules_unknown_replay());
            assert_eq!(plan.inventory().receipts().unknown(), ["unknown-1"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fixture_missing_wal_is_incomplete() {
    match run("missing-wal.json") {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(incomplete.reason(), IncompleteReason::MissingWal);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fixture_explained_empty_profiles_is_structural() {
    match run("empty-profiles.json") {
        RestoreOutcome::StructuralPlan(plan) => {
            assert_eq!(plan.inventory().explained_empty().len(), 2);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fixture_same_installation_only_new_install_is_blocked() {
    match run("same-installation-only-new-install.json") {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::SameInstallationOnly);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fixture_insufficient_capacity_is_blocked() {
    match run("insufficient-capacity.json") {
        RestoreOutcome::Blocked(blocked) => {
            assert_eq!(blocked.reason(), BlockedReason::InsufficientCapacity);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fixture_unknown_omitted_is_incomplete() {
    match run("unknown-omitted.json") {
        RestoreOutcome::Incomplete(incomplete) => {
            assert_eq!(
                incomplete.reason(),
                IncompleteReason::MissingUnknownReceipts
            );
        }
        other => panic!("{other:?}"),
    }
}
