//! GK-06：经真实 `plan_restore` 入口准备结构已核输入，再核对失效/保留计划。
//!
//! 各类预期 disposition 在本文件手写，不扫描实现内部 `CATEGORY_ORDER`。

use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::post_restore::{
    AuthMaterialKind, AuthObjectClaim, ObjectDispositionKind, PostRestoreBounds, PostRestoreFault,
    PostRestoreRequest, ReceiptClass, RecoveryEpochDerivation, plan_post_restore,
};
use openbot_domain::backup::{
    AuditCheckpointClaim, BackupInventoryClaim, BarrierIdentity, BundleIdentity,
    CapacityObservation, CapacityPolicy, CompatibilitySet, ComponentRev, ControlledRestoreTarget,
    DatasetIdentity, IdentityBinding, InstallationIdentity, InventoryBounds, KeyBindingClaim,
    MaterialClaim, MaterialId, MaterialKind, ProofStatus, ReceiptClaim, ReceiptSetClaim,
    RestoreMode, RestoreObservations, RestoreOutcome, RestoreRequest, ScramRelationClaim,
    StructuralRestorePlan, VaultKeyRefClaim, WrappingRefClaim, plan_restore,
};
use openbot_domain::vault::KeyVersion;

struct RestoreCase {
    claim: BackupInventoryClaim,
    target: ControlledRestoreTarget,
    observations: RestoreObservations,
    bounds: InventoryBounds,
}

impl RestoreCase {
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

fn complete() -> RestoreCase {
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
        audit: AuditCheckpointClaim {
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
    RestoreCase {
        claim,
        target,
        observations,
        bounds: InventoryBounds::standard(),
    }
}

fn structural_same() -> StructuralRestorePlan {
    let case = complete();
    match plan_restore(case.request()) {
        RestoreOutcome::StructuralPlan(plan) => plan,
        other => panic!("expected structural plan, got {other:?}"),
    }
}

fn structural_new() -> StructuralRestorePlan {
    let mut case = complete();
    case.target.mode = RestoreMode::NewInstallation {
        new_installation: InstallationIdentity::new("install-2"),
    };
    match plan_restore(case.request()) {
        RestoreOutcome::StructuralPlan(plan) => plan,
        other => panic!("expected new-install structural plan, got {other:?}"),
    }
}

fn obj(
    id: &str,
    kind: &str,
    actor: Option<&str>,
    installation: Option<&str>,
    snapshot_claimed_active: bool,
) -> AuthObjectClaim {
    AuthObjectClaim {
        id: id.to_owned(),
        kind: kind.to_owned(),
        actor_id: actor.map(str::to_owned),
        dataset_id: "dataset-1".to_owned(),
        deployment_id: "deployment-1".to_owned(),
        installation_id: installation.map(str::to_owned),
        snapshot_claimed_active,
    }
}

fn full_objects() -> Vec<AuthObjectClaim> {
    vec![
        obj("session-1", "auth_session", Some("actor-1"), None, false),
        obj("approval-1", "approval", Some("actor-1"), None, false),
        obj("lease-1", "lease", Some("actor-1"), Some("install-1"), true),
        obj(
            "ticket-1",
            "ticket",
            Some("actor-1"),
            Some("install-1"),
            false,
        ),
        obj("cap-1", "capability", Some("actor-1"), None, false),
        obj("oauth-1", "oauth_state", Some("actor-1"), None, false),
        obj("assert-1", "run_assertion", Some("actor-1"), None, false),
        obj(
            "device-1",
            "remote_device_registration",
            None,
            Some("install-1"),
            true,
        ),
        obj(
            "cred-1",
            "connection_credential",
            Some("actor-1"),
            None,
            true,
        ),
    ]
}

fn run<'a>(
    structural: &'a StructuralRestorePlan,
    objects: &'a [AuthObjectClaim],
    bounds: &'a PostRestoreBounds,
) -> Result<openbot_domain::backup::post_restore::PostRestorePlan, PostRestoreFault> {
    plan_post_restore(PostRestoreRequest {
        structural,
        objects,
        bounds,
    })
}

fn expected_category_defaults() -> [(&'static str, ObjectDispositionKind); 9] {
    [
        ("auth_session", ObjectDispositionKind::RetireShortLived),
        ("approval", ObjectDispositionKind::RetireShortLived),
        ("lease", ObjectDispositionKind::RetireShortLived),
        ("ticket", ObjectDispositionKind::RetireShortLived),
        ("capability", ObjectDispositionKind::RetireShortLived),
        ("oauth_state", ObjectDispositionKind::RetireShortLived),
        ("run_assertion", ObjectDispositionKind::RetireShortLived),
        (
            "remote_device_registration",
            ObjectDispositionKind::RequireReregistration,
        ),
        (
            "connection_credential",
            ObjectDispositionKind::RequireReconfirm,
        ),
    ]
}

fn assert_unfinished(plan: &openbot_domain::backup::post_restore::PostRestorePlan) {
    assert!(!plan.restore_authorized());
    assert!(!plan.application_ready());
    assert!(!plan.issues_recovery_epoch());
    assert!(!plan.writes_database());
    assert!(!plan.generates_keys());
    assert!(!plan.schedules_unknown_replay());
    assert!(!plan.restores_active_lease());
    assert!(!plan.restores_dispatch());
    assert!(!plan.snapshot_active_grants_use());
    assert!(!plan.promotes_unknown_to_success());
    assert!(!plan.resurrects_vendor_revoked_account());
    assert!(!plan.deletes_historical_decrypt_keys());
    assert!(!plan.caller_vec_proves_complete_snapshot());
    assert!(!plan.listed_dispositions_mean_already_revoked());
    assert!(!plan.applies_fresh_identity_derivation());
    assert_eq!(
        plan.pending_proofs().aead_authenticity(),
        ProofStatus::Pending
    );
    assert_eq!(
        plan.pending_proofs().restore_authorized(),
        ProofStatus::NotGranted
    );
    assert_eq!(
        plan.pending_proofs().application_ready(),
        ProofStatus::NotGranted
    );
    assert!(plan.global().epoch().required());
    assert!(!plan.global().epoch().issued());
    assert_eq!(
        plan.global().epoch().derivation(),
        RecoveryEpochDerivation::FreshRandomRequired
    );
    assert!(!plan.global().epoch().uses_old_counter_plus_one());
    assert!(!plan.global().epoch().uses_timestamp());
    assert!(!plan.global().epoch().uses_fixed_hash());
    assert!(plan.global().invalidate_old_auth_and_control());
    assert!(!plan.global().invalidate_performed());
}

#[test]
fn same_installation_preserves_business_ids_and_original_mapping() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let plan = run(&structural, &[], &bounds).expect("empty objects still plan");
    match plan.identity() {
        IdentityBinding::SameInstallation {
            installation,
            dataset,
            deployment,
            tenant,
        } => {
            assert_eq!(installation.as_str(), "install-1");
            assert_eq!(dataset.as_str(), "dataset-1");
            assert_eq!(deployment.as_str(), "deployment-1");
            assert_eq!(tenant.as_str(), "tenant-1");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(plan.identity(), structural.identity());
    assert!(plan.preserves_business_identity());
    assert!(plan.preserves_record_ids());
    assert_eq!(plan.original_installation().as_str(), "install-1");
    assert_unfinished(&plan);
}

#[test]
fn new_installation_keeps_history_and_only_uses_structural_mapping() {
    let structural = structural_new();
    let bounds = PostRestoreBounds::standard();
    let objects = full_objects();
    let plan = run(&structural, &objects, &bounds).expect("new install plan");
    match plan.identity() {
        IdentityBinding::NewInstallation {
            original_installation,
            new_installation,
            dataset,
            deployment,
            tenant,
            record_ids_preserved,
        } => {
            assert_eq!(original_installation.as_str(), "install-1");
            assert_eq!(new_installation.as_str(), "install-2");
            assert_eq!(dataset.as_str(), "dataset-1");
            assert_eq!(deployment.as_str(), "deployment-1");
            assert_eq!(tenant.as_str(), "tenant-1");
            assert!(*record_ids_preserved);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(plan.identity(), structural.identity());
    assert!(plan.preserves_business_identity());
    assert!(plan.preserves_record_ids());
    for item in plan.object_dispositions() {
        if let Some(installation) = item.installation_id() {
            assert_eq!(installation, "install-1");
            assert_ne!(installation, "install-2");
        }
    }
    assert_unfinished(&plan);
}

#[test]
fn empty_inventory_still_requires_all_category_and_epoch_obligations() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let plan = run(&structural, &[], &bounds).unwrap();
    assert_eq!(plan.input_object_count(), 0);
    assert!(plan.object_dispositions().is_empty());
    let expected = expected_category_defaults();
    assert_eq!(plan.category_rules().len(), expected.len());
    for (rule, (name, disposition)) in plan.category_rules().iter().zip(expected) {
        assert_eq!(rule.kind().as_str(), name);
        assert_eq!(rule.default_disposition(), disposition);
        assert!(rule.empty_inventory_still_requires_invalidation());
    }
    assert!(plan.global().invalidate_old_auth_and_control());
    assert!(plan.global().reconfirm_credentials());
    assert!(plan.global().keep_receipts());
    assert!(plan.global().must_not_replay_unknown());
    assert!(!plan.caller_vec_proves_complete_snapshot());
    assert_unfinished(&plan);
}

#[test]
fn full_categories_have_handwritten_object_dispositions() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let objects = full_objects();
    let plan = run(&structural, &objects, &bounds).unwrap();
    let expected = [
        (
            "session-1",
            AuthMaterialKind::AuthSession,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "approval-1",
            AuthMaterialKind::Approval,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "lease-1",
            AuthMaterialKind::Lease,
            ObjectDispositionKind::RetireShortLived,
            true,
        ),
        (
            "ticket-1",
            AuthMaterialKind::Ticket,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "cap-1",
            AuthMaterialKind::Capability,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "oauth-1",
            AuthMaterialKind::OauthState,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "assert-1",
            AuthMaterialKind::RunAssertion,
            ObjectDispositionKind::RetireShortLived,
            false,
        ),
        (
            "device-1",
            AuthMaterialKind::RemoteDeviceRegistration,
            ObjectDispositionKind::RequireReregistration,
            true,
        ),
        (
            "cred-1",
            AuthMaterialKind::ConnectionCredential,
            ObjectDispositionKind::RequireReconfirm,
            true,
        ),
    ];
    assert_eq!(plan.object_dispositions().len(), expected.len());
    for (item, (id, kind, disposition, active)) in plan.object_dispositions().iter().zip(expected) {
        assert_eq!(item.id(), id);
        assert_eq!(item.kind(), kind);
        assert_eq!(item.disposition(), disposition);
        assert_eq!(item.snapshot_claimed_active(), active);
        assert!(!item.grants_use_from_snapshot());
        assert!(!item.restores_active_lease());
        assert!(!item.rebuilds_dispatch());
        assert!(!item.resurrects_vendor_revocation());
        assert_eq!(item.dataset_id(), "dataset-1");
        assert_eq!(item.deployment_id(), "deployment-1");
    }
    let lease = &plan.object_dispositions()[2];
    assert_eq!(lease.actor_id(), Some("actor-1"));
    assert_eq!(lease.installation_id(), Some("install-1"));
    let device = &plan.object_dispositions()[7];
    assert_eq!(device.actor_id(), None);
    assert_eq!(device.installation_id(), Some("install-1"));
    assert_unfinished(&plan);
}

#[test]
fn historical_keys_are_retained_and_credentials_stay_unconfirmed() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let objects = vec![obj(
        "cred-1",
        "connection_credential",
        Some("actor-1"),
        None,
        true,
    )];
    let plan = run(&structural, &objects, &bounds).unwrap();
    assert_eq!(plan.historical_decrypt_refs().len(), 1);
    let key = &plan.historical_decrypt_refs()[0];
    assert_eq!(key.key_id(), "vault-key-1");
    assert_eq!(key.key_version(), KeyVersion::new(1));
    assert_eq!(key.canary(), digest("canary-1"));
    assert!(key.retain_decrypt_capability());
    assert!(!key.removed_by_auth_invalidation());
    let cred = &plan.object_dispositions()[0];
    assert_eq!(cred.disposition(), ObjectDispositionKind::RequireReconfirm);
    assert!(cred.snapshot_claimed_active());
    assert!(!cred.grants_use_from_snapshot());
    assert!(!plan.snapshot_active_grants_use());
    assert!(!plan.deletes_historical_decrypt_keys());
}

#[test]
fn receipts_are_kept_item_by_item_without_reclass_or_dispatch() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let plan = run(&structural, &[], &bounds).unwrap();
    let receipts = plan.receipt_retentions();
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].id(), "committed-1");
    assert_eq!(receipts[0].class(), ReceiptClass::Committed);
    assert!(receipts[0].original_class_preserved());
    assert!(!receipts[0].dispatch_scheduled());
    assert!(!receipts[0].unconfirmed_reconciliation());

    assert_eq!(receipts[1].id(), "unknown-1");
    assert_eq!(receipts[1].class(), ReceiptClass::Unknown);
    assert!(receipts[1].original_class_preserved());
    assert!(!receipts[1].unknown_promoted());
    assert!(!receipts[1].unknown_retryable());
    assert!(!receipts[1].dispatch_scheduled());
    assert!(receipts[1].unconfirmed_reconciliation());

    assert_eq!(receipts[2].id(), "tool-1");
    assert_eq!(receipts[2].class(), ReceiptClass::Tool);
    assert!(receipts[2].original_class_preserved());
    assert!(!receipts[2].dispatch_scheduled());
    assert!(!plan.schedules_unknown_replay());
    assert!(!plan.promotes_unknown_to_success());
    assert!(!plan.restores_dispatch());
}

#[test]
fn same_input_is_stable() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let objects = full_objects();
    let first = run(&structural, &objects, &bounds).unwrap();
    let second = run(&structural, &objects, &bounds).unwrap();
    assert_eq!(first, second);
}

#[test]
fn binding_duplicate_unknown_and_limit_failures_have_no_partial_plan() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();

    let wrong_dataset = vec![AuthObjectClaim {
        dataset_id: "dataset-2".to_owned(),
        ..obj("session-1", "auth_session", Some("actor-1"), None, false)
    }];
    assert_eq!(
        run(&structural, &wrong_dataset, &bounds),
        Err(PostRestoreFault::BindingMismatch)
    );

    let wide = vec![obj("session-1", "auth_session", Some("all"), None, false)];
    assert_eq!(
        run(&structural, &wide, &bounds),
        Err(PostRestoreFault::BindingMismatch)
    );

    let missing_actor = vec![obj("session-1", "auth_session", None, None, false)];
    assert_eq!(
        run(&structural, &missing_actor, &bounds),
        Err(PostRestoreFault::BindingMismatch)
    );

    let missing_install = vec![obj("lease-1", "lease", Some("actor-1"), None, false)];
    assert_eq!(
        run(&structural, &missing_install, &bounds),
        Err(PostRestoreFault::BindingMismatch)
    );

    let new_install_binding = vec![obj(
        "lease-1",
        "lease",
        Some("actor-1"),
        Some("install-2"),
        false,
    )];
    assert_eq!(
        run(&structural, &new_install_binding, &bounds),
        Err(PostRestoreFault::BindingMismatch)
    );

    let duplicate = vec![
        obj("session-1", "auth_session", Some("actor-1"), None, false),
        obj("session-1", "approval", Some("actor-1"), None, false),
    ];
    assert_eq!(
        run(&structural, &duplicate, &bounds),
        Err(PostRestoreFault::DuplicateTarget)
    );

    let unknown = vec![obj(
        "legacy-tab-1",
        "legacy_tab_state",
        Some("actor-1"),
        None,
        false,
    )];
    assert_eq!(
        run(&structural, &unknown, &bounds),
        Err(PostRestoreFault::UnknownCategory)
    );

    let tight = PostRestoreBounds::try_new(1, 128, 1_048_576, 2_097_152).unwrap();
    let two = vec![
        obj("session-1", "auth_session", Some("actor-1"), None, false),
        obj("approval-1", "approval", Some("actor-1"), None, false),
    ];
    assert_eq!(
        run(&structural, &two, &tight),
        Err(PostRestoreFault::CountOutOfBounds)
    );
}

#[test]
fn secret_prose_identity_and_budget_failures_do_not_succeed() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();

    let secret = vec![obj(
        "api-token-1",
        "auth_session",
        Some("actor-1"),
        None,
        false,
    )];
    assert_eq!(
        run(&structural, &secret, &bounds),
        Err(PostRestoreFault::SecretMaterialForbidden)
    );

    let prose = vec![obj(
        "vendor refused the account.",
        "auth_session",
        Some("actor-1"),
        None,
        false,
    )];
    assert_eq!(
        run(&structural, &prose, &bounds),
        Err(PostRestoreFault::ProseRejected)
    );

    let empty_id = vec![obj("", "auth_session", Some("actor-1"), None, false)];
    assert_eq!(
        run(&structural, &empty_id, &bounds),
        Err(PostRestoreFault::IdentityInvalid)
    );

    let path_id = vec![obj(
        "actor/session",
        "auth_session",
        Some("actor-1"),
        None,
        false,
    )];
    assert_eq!(
        run(&structural, &path_id, &bounds),
        Err(PostRestoreFault::IdentityInvalid)
    );

    let tiny_output = PostRestoreBounds::try_new(8_192, 128, 1_048_576, 1).unwrap();
    assert_eq!(
        run(&structural, &[], &tiny_output),
        Err(PostRestoreFault::LengthOutOfBounds)
    );

    let tiny_ids = PostRestoreBounds::try_new(8_192, 128, 4, 2_097_152).unwrap();
    let one = vec![obj(
        "session-1",
        "auth_session",
        Some("actor-1"),
        None,
        false,
    )];
    assert_eq!(
        run(&structural, &one, &tiny_ids),
        Err(PostRestoreFault::LengthOutOfBounds)
    );
}

#[test]
fn pending_proofs_remain_associated_and_unauthorized() {
    let structural = structural_same();
    let bounds = PostRestoreBounds::standard();
    let plan = run(&structural, &full_objects(), &bounds).unwrap();
    assert_eq!(plan.pending_proofs(), structural.pending_proofs());
    assert_eq!(plan.follow_up(), structural.follow_up());
    assert!(plan.follow_up().mint_new_recovery_epoch());
    assert!(plan.follow_up().invalidate_old_auth_and_control());
    assert!(plan.follow_up().reconfirm_credentials());
    assert!(plan.follow_up().keep_committed_unknown_and_tool_receipts());
    assert!(plan.follow_up().must_not_replay_unknown());
    assert!(!structural.restore_authorized());
    assert!(!plan.restore_authorized());
    assert!(plan.identifier_bytes() > 0);
    assert!(plan.output_bytes() > 0);
    assert_eq!(plan.input_object_count(), 9);
}

#[test]
fn controller_bounds_cannot_expand_named_caps() {
    assert!(PostRestoreBounds::try_new(u32::MAX, u16::MAX, u64::MAX, u64::MAX).is_err());
}
#[test]
fn controller_wildcard_object_id_is_not_an_invalidation_target() {
    let structural = structural_same();
    let objects = [obj("*", "auth_session", Some("actor-1"), None, true)];
    assert!(run(&structural, &objects, &PostRestoreBounds::standard()).is_err());
}
#[test]
fn controller_output_budget_includes_owned_structures() {
    let structural = structural_same();
    let objects = full_objects();
    let p = run(&structural, &objects, &PostRestoreBounds::standard()).unwrap();
    let minimum = std::mem::size_of_val(&p)
        + std::mem::size_of_val(p.object_dispositions())
        + std::mem::size_of_val(p.receipt_retentions())
        + std::mem::size_of_val(p.historical_decrypt_refs());
    assert!(p.output_bytes() >= minimum as u64);
}

#[test]
fn controller_exact_budget_edges_and_source_binding() {
    let structural = structural_same();
    let objects = full_objects();
    let plan = run(&structural, &objects, &PostRestoreBounds::standard()).unwrap();
    assert_eq!(plan.source_bundle(), structural.inventory().bundle());
    assert_eq!(plan.source_barrier(), structural.inventory().barrier());
    assert_eq!(plan.source_manifest(), digest("m-bundle"));
    let exact =
        PostRestoreBounds::try_new(9, 128, plan.identifier_bytes(), plan.output_bytes()).unwrap();
    assert!(run(&structural, &objects, &exact).is_ok());
    for (ids, out) in [
        (plan.identifier_bytes() - 1, plan.output_bytes()),
        (plan.identifier_bytes(), plan.output_bytes() - 1),
    ] {
        assert!(
            run(
                &structural,
                &objects,
                &PostRestoreBounds::try_new(9, 128, ids, out).unwrap()
            )
            .is_err()
        );
    }
}
#[test]
fn controller_object_count_upper_boundary_is_bounded() {
    let structural = structural_same();
    let mut objects: Vec<_> = (0..8192)
        .map(|i| obj(&format!("s{i}"), "auth_session", Some("a"), None, false))
        .collect();
    let plan = run(&structural, &objects, &PostRestoreBounds::standard()).unwrap();
    assert_eq!(plan.object_dispositions().len(), 8192);
    objects.push(obj("extra", "auth_session", Some("a"), None, false));
    assert_eq!(
        run(&structural, &objects, &PostRestoreBounds::standard()),
        Err(PostRestoreFault::CountOutOfBounds)
    );
}
