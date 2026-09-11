//! GK-07 公开入口：结构兼容性预检。期望从规范手写，不用实现自身规则生成 oracle。

use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::backup::{CompatibilitySet, ComponentRev, ProofStatus};
use openbot_domain::upgrade_preflight::{
    CompatiblePreviousClaim, ComponentSetClaim, MAX_COMPONENTS, MAX_ID_BYTES, MAX_MIGRATIONS,
    MigrationClaim, OperationIntent, PendingAction, PreflightFault, PreflightRequest, ProofClaims,
    ReleaseMajors, ReleaseSnapshot, RestoreBuildClaim, RestoreFormatClaim, SchemaChangeKind,
    SchemaInventoryClaim, StartupFacts, WriterKind, plan_upgrade_preflight,
};

const REQUIRED_NAMES: [&str; 4] = ["application", "postgres", "engine", "ui"];
const EXPAND_KINDS: [SchemaChangeKind; 5] = [
    SchemaChangeKind::NewTable,
    SchemaChangeKind::NullableColumn,
    SchemaChangeKind::Backfill,
    SchemaChangeKind::Index,
    SchemaChangeKind::NonDestructiveConstraint,
];
const FORBIDDEN_KINDS: [SchemaChangeKind; 5] = [
    SchemaChangeKind::Drop,
    SchemaChangeKind::Rename,
    SchemaChangeKind::TypeTightening,
    SchemaChangeKind::PrimaryKeyRewrite,
    SchemaChangeKind::Unknown,
];

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of(label.as_bytes())
}

fn rev(name: &str, epoch: u32) -> ComponentRev {
    ComponentRev {
        name: name.to_owned(),
        epoch,
        digest: digest(name),
    }
}

fn named(epoch: u32) -> ComponentSetClaim {
    ComponentSetClaim::from_set(CompatibilitySet {
        application: rev("application", epoch),
        postgres: rev("postgres", epoch),
        engine: rev("engine", epoch),
        ui: rev("ui", epoch),
    })
}

fn majors() -> ReleaseMajors {
    ReleaseMajors {
        rust_core: 1,
        tauri: 2,
        electron: 43,
        postgres: 17,
    }
}

fn startup(epoch: u32, protocol: u32) -> StartupFacts {
    StartupFacts {
        protocol,
        sidecar_protocol: protocol,
        release_epoch: epoch,
        core_identity: 10,
        minimum_compatible_core: 8,
        compatibility_range: openbot_domain::upgrade_preflight::CompatibilityRange::Inclusive {
            min_core: 8,
            max_core: 12,
        },
    }
}

fn schema_v1() -> SchemaInventoryClaim {
    SchemaInventoryClaim {
        scope: "public".to_owned(),
        checksum: Some(digest("schema-v1")),
        migrations: vec![MigrationClaim {
            name: "native_0031_model_snapshot".to_owned(),
            checksum: Some(digest("m31")),
            change: SchemaChangeKind::NewTable,
        }],
    }
}

fn restore_v1() -> RestoreFormatClaim {
    RestoreFormatClaim {
        format_id: "restore-v1".to_owned(),
        compatible_previous: CompatiblePreviousClaim::Identified {
            format_id: "restore-v0".to_owned(),
        },
    }
}

fn snapshot(epoch: u32) -> ReleaseSnapshot {
    ReleaseSnapshot {
        components: named(epoch),
        majors: majors(),
        startup: startup(epoch, 4),
        schema: schema_v1(),
        restore_format: restore_v1(),
        restore_build: None,
        writer: WriterKind::RustNative,
    }
}

fn claims() -> ProofClaims {
    ProofClaims {
        signature_described_valid: true,
        notarization_described_valid: true,
        rollback_authorization_described: true,
    }
}

fn run_preflight(
    intent: OperationIntent,
    running: &ReleaseSnapshot,
    candidate: &ReleaseSnapshot,
) -> Result<openbot_domain::upgrade_preflight::PreflightPlan, PreflightFault> {
    plan_upgrade_preflight(PreflightRequest {
        intent,
        previous_build: if intent == OperationIntent::EmergencyRollback {
            Some(candidate)
        } else {
            None
        },
        rollback_schema: if intent == OperationIntent::EmergencyRollback {
            running.schema.checksum
        } else {
            None
        },
        running,
        candidate,
        proof_claims: &claims(),
    })
}

fn assert_unauthorized(plan: &openbot_domain::upgrade_preflight::PreflightPlan) {
    let proofs = plan.pending_proofs();
    assert_eq!(proofs.install_authorized(), ProofStatus::NotGranted);
    assert_eq!(proofs.rollback_authorized(), ProofStatus::NotGranted);
    assert_eq!(proofs.restore_authorized(), ProofStatus::NotGranted);
    assert_eq!(proofs.signature_verification(), ProofStatus::Pending);
    assert_eq!(proofs.notarization(), ProofStatus::Pending);
    assert_eq!(proofs.resource_integrity(), ProofStatus::Pending);
    assert_eq!(proofs.atomic_switch(), ProofStatus::Pending);
    assert!(
        !plan
            .pending_actions()
            .iter()
            .any(|action| action.as_str().contains("SQL")
                || action.as_str().contains("DROP")
                || action.as_str().contains("ALTER"))
    );
}

fn security_expand_candidate(running: &ReleaseSnapshot) -> ReleaseSnapshot {
    let mut candidate = running.clone();
    candidate.components = ComponentSetClaim::from_set(CompatibilitySet {
        application: ComponentRev {
            name: "application".to_owned(),
            epoch: 5,
            digest: digest("application-security"),
        },
        postgres: rev("postgres", 5),
        engine: rev("engine", 5),
        ui: rev("ui", 5),
    });
    candidate
}

#[test]
fn closed_component_names_match_handwritten_literals() {
    assert_eq!(REQUIRED_NAMES, ["application", "postgres", "engine", "ui"]);
}

#[test]
fn rust_security_expand_upgrade_yields_plan() {
    let running = snapshot(5);
    let candidate = security_expand_candidate(&running);
    let plan =
        run_preflight(OperationIntent::Upgrade, &running, &candidate).expect("security expand");
    assert_eq!(plan.intent(), OperationIntent::Upgrade);
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::VerifySignatures)
    );
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::AtomicSwitch)
    );
    assert!(
        !plan
            .pending_actions()
            .contains(&PendingAction::PostgresMajorUpgrade)
    );
    assert_unauthorized(&plan);
}

#[test]
fn postgres_major_only_upgrade_yields_plan() {
    let running = snapshot(5);
    let mut candidate = snapshot(6);
    candidate.majors.postgres = 18;
    candidate.startup.protocol = 4;
    candidate.startup.sidecar_protocol = 4;
    let plan =
        run_preflight(OperationIntent::Upgrade, &running, &candidate).expect("pg major only");
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::PostgresMajorUpgrade)
    );
    assert_unauthorized(&plan);
}

#[test]
fn electron_major_only_upgrade_yields_plan() {
    let running = snapshot(5);
    let mut candidate = snapshot(6);
    candidate.majors.electron = 44;
    candidate.startup.protocol = 5;
    candidate.startup.sidecar_protocol = 5;
    let plan =
        run_preflight(OperationIntent::Upgrade, &running, &candidate).expect("electron major only");
    assert!(
        !plan
            .pending_actions()
            .contains(&PendingAction::PostgresMajorUpgrade)
    );
    assert_unauthorized(&plan);
}

#[test]
fn pg_and_tauri_major_same_release_is_refused() {
    let running = snapshot(5);
    let mut candidate = snapshot(6);
    candidate.majors.postgres = 18;
    candidate.majors.tauri = 3;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &candidate)
            .expect_err("pg+tauri")
            .as_str(),
        "upgrade_preflight_pg_major_with_tauri_major"
    );
}

#[test]
fn pg_and_electron_major_same_release_is_refused() {
    let running = snapshot(5);
    let mut candidate = snapshot(6);
    candidate.majors.postgres = 18;
    candidate.majors.electron = 44;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &candidate)
            .expect_err("pg+electron")
            .as_str(),
        "upgrade_preflight_pg_major_with_electron_major"
    );
}

#[test]
fn same_epoch_consistent_set_yields_plan() {
    let running = snapshot(5);
    let candidate = security_expand_candidate(&running);
    let plan = run_preflight(OperationIntent::Upgrade, &running, &candidate).expect("same epoch");
    assert_eq!(plan.intent(), OperationIntent::Upgrade);
    assert_unauthorized(&plan);
}

#[test]
fn missing_duplicate_mixed_epoch_digest_and_protocol_contradictions_are_refused() {
    let running = snapshot(5);

    let mut missing = snapshot(5);
    missing.components = ComponentSetClaim {
        entries: vec![rev("application", 5), rev("postgres", 5), rev("engine", 5)],
    };
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &missing)
            .expect_err("missing")
            .as_str(),
        "upgrade_preflight_missing_component"
    );

    let mut duplicate = snapshot(5);
    duplicate.components = ComponentSetClaim {
        entries: vec![
            rev("application", 5),
            rev("postgres", 5),
            rev("engine", 5),
            rev("ui", 5),
            rev("application", 5),
        ],
    };
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &duplicate)
            .expect_err("duplicate")
            .as_str(),
        "upgrade_preflight_duplicate_component"
    );

    let mut mixed = snapshot(5);
    mixed.components = ComponentSetClaim {
        entries: vec![
            rev("application", 5),
            rev("postgres", 5),
            rev("engine", 6),
            rev("ui", 5),
        ],
    };
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &mixed)
            .expect_err("mixed epoch")
            .as_str(),
        "upgrade_preflight_mixed_release_epoch"
    );

    let mut same_digest = snapshot(5);
    same_digest.components = ComponentSetClaim {
        entries: vec![
            ComponentRev {
                name: "application".to_owned(),
                epoch: 5,
                digest: digest("shared"),
            },
            ComponentRev {
                name: "postgres".to_owned(),
                epoch: 5,
                digest: digest("shared"),
            },
            rev("engine", 5),
            rev("ui", 5),
        ],
    };
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &same_digest)
            .expect_err("digest")
            .as_str(),
        "upgrade_preflight_digest_contradiction"
    );

    let mut protocol = snapshot(5);
    protocol.startup.sidecar_protocol = 9;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &protocol)
            .expect_err("protocol")
            .as_str(),
        "upgrade_preflight_protocol_contradiction"
    );
}

#[test]
fn minimum_core_outside_range_is_refused() {
    let running = snapshot(5);
    let mut candidate = security_expand_candidate(&running);
    candidate.startup.minimum_compatible_core = 11;
    candidate.startup.core_identity = 10;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &candidate)
            .expect_err("min core")
            .as_str(),
        "upgrade_preflight_minimum_core_incompatible"
    );
}

#[test]
fn expand_kinds_are_allowed_and_forbidden_kinds_are_refused() {
    assert_eq!(
        EXPAND_KINDS,
        [
            SchemaChangeKind::NewTable,
            SchemaChangeKind::NullableColumn,
            SchemaChangeKind::Backfill,
            SchemaChangeKind::Index,
            SchemaChangeKind::NonDestructiveConstraint,
        ]
    );
    let running = snapshot(5);
    let mut candidate = security_expand_candidate(&running);
    candidate.schema.checksum = Some(digest("schema-v2"));
    candidate.schema.migrations = vec![
        MigrationClaim {
            name: "native_0031_model_snapshot".to_owned(),
            checksum: Some(digest("m31")),
            change: SchemaChangeKind::NewTable,
        },
        MigrationClaim {
            name: "native_0032_new_table".to_owned(),
            checksum: Some(digest("m32")),
            change: SchemaChangeKind::NewTable,
        },
        MigrationClaim {
            name: "native_0033_nullable".to_owned(),
            checksum: Some(digest("m33")),
            change: SchemaChangeKind::NullableColumn,
        },
        MigrationClaim {
            name: "native_0034_backfill".to_owned(),
            checksum: Some(digest("m34")),
            change: SchemaChangeKind::Backfill,
        },
        MigrationClaim {
            name: "native_0035_index".to_owned(),
            checksum: Some(digest("m35")),
            change: SchemaChangeKind::Index,
        },
        MigrationClaim {
            name: "native_0036_constraint".to_owned(),
            checksum: Some(digest("m36")),
            change: SchemaChangeKind::NonDestructiveConstraint,
        },
    ];
    let plan = run_preflight(OperationIntent::Upgrade, &running, &candidate).expect("expand");
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::ApplyExpandMigrations)
    );
    assert_unauthorized(&plan);

    for kind in FORBIDDEN_KINDS {
        let mut forbidden = security_expand_candidate(&running);
        forbidden.schema.checksum = Some(digest("schema-bad"));
        forbidden.schema.migrations = vec![
            MigrationClaim {
                name: "native_0031_model_snapshot".to_owned(),
                checksum: Some(digest("m31")),
                change: SchemaChangeKind::NewTable,
            },
            MigrationClaim {
                name: "native_0032_forbidden".to_owned(),
                checksum: Some(digest("m-bad")),
                change: kind,
            },
        ];
        assert_eq!(
            run_preflight(OperationIntent::Upgrade, &running, &forbidden)
                .expect_err("forbidden kind")
                .as_str(),
            "upgrade_preflight_schema_change_not_expand"
        );
    }
}

#[test]
fn migration_name_checksum_missing_and_drift_are_refused() {
    let running = snapshot(5);
    let mut name_drift = security_expand_candidate(&running);
    name_drift.schema.checksum = Some(digest("schema-renamed"));
    name_drift.schema.migrations[0].name = "native_0031_renamed".to_owned();
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &name_drift)
            .expect_err("name")
            .as_str(),
        "upgrade_preflight_migration_name_drift"
    );

    let mut checksum_drift = security_expand_candidate(&running);
    checksum_drift.schema.migrations[0].checksum = Some(digest("m31-other"));
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &checksum_drift)
            .expect_err("checksum drift")
            .as_str(),
        "upgrade_preflight_migration_checksum_drift"
    );

    let mut missing = security_expand_candidate(&running);
    missing.schema.migrations[0].checksum = None;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &missing)
            .expect_err("missing checksum")
            .as_str(),
        "upgrade_preflight_migration_checksum_missing"
    );

    let mut scope = security_expand_candidate(&running);
    scope.schema.scope = "other".to_owned();
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &scope)
            .expect_err("scope")
            .as_str(),
        "upgrade_preflight_schema_scope_drift"
    );
}

#[test]
fn ordinary_downgrade_is_refused() {
    let running = snapshot(6);
    let candidate = snapshot(5);
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &candidate)
            .expect_err("downgrade")
            .as_str(),
        "upgrade_preflight_ordinary_downgrade"
    );
}

#[test]
fn emergency_rollback_to_previous_rust_build_keeps_authorization_pending() {
    let mut running = snapshot(6);
    running.schema.checksum = Some(digest("schema-v2"));
    running.schema.migrations.push(MigrationClaim {
        name: "native_0032_nullable".to_owned(),
        checksum: Some(digest("m32")),
        change: SchemaChangeKind::NullableColumn,
    });
    let candidate = snapshot(5);
    let plan = run_preflight(OperationIntent::EmergencyRollback, &running, &candidate)
        .expect("rollback structure");
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::VerifyRollbackAuthorization)
    );
    assert_eq!(
        plan.pending_proofs().rollback_authorization(),
        ProofStatus::Pending
    );
    assert_eq!(
        plan.pending_proofs().rollback_authorized(),
        ProofStatus::NotGranted
    );
    assert_unauthorized(&plan);
}

#[test]
fn emergency_rollback_without_independent_authorization_claim_is_refused() {
    let mut running = snapshot(6);
    running.schema.checksum = Some(digest("schema-v2"));
    running.schema.migrations.push(MigrationClaim {
        name: "native_0032_nullable".to_owned(),
        checksum: Some(digest("m32")),
        change: SchemaChangeKind::NullableColumn,
    });
    let candidate = snapshot(5);
    let claims = ProofClaims {
        signature_described_valid: true,
        notarization_described_valid: true,
        rollback_authorization_described: false,
    };
    assert_eq!(
        plan_upgrade_preflight(PreflightRequest {
            previous_build: None,
            rollback_schema: None,
            intent: OperationIntent::EmergencyRollback,
            running: &running,
            candidate: &candidate,
            proof_claims: &claims,
        })
        .expect_err("missing auth")
        .as_str(),
        "upgrade_preflight_missing_rollback_authorization"
    );
}

#[test]
fn intelligence_typescript_writer_rollback_is_refused() {
    let running = snapshot(6);
    let mut candidate = snapshot(5);
    candidate.writer = WriterKind::IntelligenceTypeScript;
    assert_eq!(
        run_preflight(OperationIntent::EmergencyRollback, &running, &candidate)
            .expect_err("ts writer")
            .as_str(),
        "upgrade_preflight_forbidden_writer"
    );
}

#[test]
fn incompatible_schema_rollback_is_refused() {
    let running = snapshot(6);
    let mut candidate = snapshot(5);
    candidate.schema.migrations[0].name = "native_0001_unrelated".to_owned();
    candidate.schema.checksum = Some(digest("schema-other"));
    assert_eq!(
        run_preflight(OperationIntent::EmergencyRollback, &running, &candidate)
            .expect_err("incompatible")
            .as_str(),
        "upgrade_preflight_migration_name_drift"
    );
}

#[test]
fn new_restore_format_with_matching_build_yields_pending_plan() {
    let running = snapshot(5);
    let mut candidate = snapshot(5);
    candidate.components = ComponentSetClaim::from_set(CompatibilitySet {
        application: ComponentRev {
            name: "application".to_owned(),
            epoch: 5,
            digest: digest("application-restore"),
        },
        postgres: rev("postgres", 5),
        engine: rev("engine", 5),
        ui: rev("ui", 5),
    });
    candidate.restore_format = RestoreFormatClaim {
        format_id: "restore-v2".to_owned(),
        compatible_previous: CompatiblePreviousClaim::None,
    };
    candidate.restore_build = Some(RestoreBuildClaim {
        format_id: "restore-v2".to_owned(),
        digest: digest("restore-build-v2"),
        described_runnable: true,
    });
    let plan = run_preflight(OperationIntent::RestoreFormatSwitch, &running, &candidate)
        .expect("restore format");
    assert!(
        plan.pending_actions()
            .contains(&PendingAction::VerifyRestoreBuild)
    );
    assert_eq!(plan.pending_proofs().restore_build(), ProofStatus::Pending);
    assert_eq!(
        plan.pending_proofs().restore_authorized(),
        ProofStatus::NotGranted
    );
    assert_unauthorized(&plan);
}

#[test]
fn restore_format_missing_mismatch_and_not_runnable_are_refused() {
    let running = snapshot(5);
    let mut base = snapshot(5);
    base.components = ComponentSetClaim::from_set(CompatibilitySet {
        application: ComponentRev {
            name: "application".to_owned(),
            epoch: 5,
            digest: digest("application-restore"),
        },
        postgres: rev("postgres", 5),
        engine: rev("engine", 5),
        ui: rev("ui", 5),
    });
    base.restore_format = RestoreFormatClaim {
        format_id: "restore-v2".to_owned(),
        compatible_previous: CompatiblePreviousClaim::None,
    };

    assert_eq!(
        run_preflight(OperationIntent::RestoreFormatSwitch, &running, &base)
            .expect_err("missing build")
            .as_str(),
        "upgrade_preflight_restore_build_missing"
    );

    let mut mismatch = base.clone();
    mismatch.restore_build = Some(RestoreBuildClaim {
        format_id: "restore-v9".to_owned(),
        digest: digest("wrong"),
        described_runnable: true,
    });
    assert_eq!(
        run_preflight(OperationIntent::RestoreFormatSwitch, &running, &mismatch)
            .expect_err("mismatch")
            .as_str(),
        "upgrade_preflight_restore_build_format_mismatch"
    );

    let mut not_runnable = base;
    not_runnable.restore_build = Some(RestoreBuildClaim {
        format_id: "restore-v2".to_owned(),
        digest: digest("restore-build-v2"),
        described_runnable: false,
    });
    assert_eq!(
        run_preflight(
            OperationIntent::RestoreFormatSwitch,
            &running,
            &not_runnable
        )
        .expect_err("not runnable")
        .as_str(),
        "upgrade_preflight_restore_build_missing"
    );
}

#[test]
fn all_true_signature_claims_still_do_not_authorize() {
    let running = snapshot(5);
    let candidate = security_expand_candidate(&running);
    let claims = ProofClaims {
        signature_described_valid: true,
        notarization_described_valid: true,
        rollback_authorization_described: true,
    };
    let plan = plan_upgrade_preflight(PreflightRequest {
        previous_build: None,
        rollback_schema: None,
        intent: OperationIntent::Upgrade,
        running: &running,
        candidate: &candidate,
        proof_claims: &claims,
    })
    .expect("claims cannot authorize");
    assert_unauthorized(&plan);
}

#[test]
fn empty_too_long_duplicate_unbounded_unknown_and_overflow_do_not_succeed() {
    let running = snapshot(5);

    let mut empty = security_expand_candidate(&running);
    empty.schema.scope = String::new();
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &empty)
            .expect_err("empty")
            .as_str(),
        "upgrade_preflight_schema_scope_missing"
    );

    let mut too_long = security_expand_candidate(&running);
    too_long.schema.scope = "a".repeat(MAX_ID_BYTES + 1);
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &too_long)
            .expect_err("too long")
            .as_str(),
        "upgrade_preflight_input_too_long"
    );

    let mut duplicate = security_expand_candidate(&running);
    duplicate.schema.checksum = Some(digest("schema-dup"));
    duplicate.schema.migrations.push(MigrationClaim {
        name: "native_0031_model_snapshot".to_owned(),
        checksum: Some(digest("m31-dup")),
        change: SchemaChangeKind::Index,
    });
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &duplicate)
            .expect_err("duplicate")
            .as_str(),
        "upgrade_preflight_input_duplicate"
    );

    let mut unbounded = security_expand_candidate(&running);
    unbounded.startup.compatibility_range =
        openbot_domain::upgrade_preflight::CompatibilityRange::Unbounded;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &unbounded)
            .expect_err("unbounded")
            .as_str(),
        "upgrade_preflight_unbounded_compatibility_range"
    );

    let mut unknown = security_expand_candidate(&running);
    unknown.startup.compatibility_range =
        openbot_domain::upgrade_preflight::CompatibilityRange::Unknown;
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &unknown)
            .expect_err("unknown")
            .as_str(),
        "upgrade_preflight_unknown_compatibility_range"
    );

    let mut overflow = security_expand_candidate(&running);
    overflow.components = ComponentSetClaim {
        entries: (0..=MAX_COMPONENTS)
            .map(|i| ComponentRev {
                name: format!("component-{i}"),
                epoch: 5,
                digest: digest(&format!("component-{i}")),
            })
            .collect(),
    };
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &overflow)
            .expect_err("overflow")
            .as_str(),
        "upgrade_preflight_count_out_of_bounds"
    );

    let mut too_many_migrations = security_expand_candidate(&running);
    too_many_migrations.schema.checksum = Some(digest("schema-overflow"));
    too_many_migrations.schema.migrations = (0..=MAX_MIGRATIONS)
        .map(|i| MigrationClaim {
            name: format!("native_{i:04}_extra"),
            checksum: Some(digest(&format!("m{i}"))),
            change: SchemaChangeKind::Index,
        })
        .collect();
    assert_eq!(
        run_preflight(OperationIntent::Upgrade, &running, &too_many_migrations)
            .expect_err("migration overflow")
            .as_str(),
        "upgrade_preflight_count_out_of_bounds"
    );
}

#[test]
fn current_protocol_four_and_epoch_five_are_not_a_permanent_ceiling() {
    let running = snapshot(5);
    let mut candidate = snapshot(7);
    candidate.startup.protocol = 6;
    candidate.startup.sidecar_protocol = 6;
    let plan = run_preflight(OperationIntent::Upgrade, &running, &candidate)
        .expect("protocol 4 / epoch 5 must not freeze upgrades");
    assert_unauthorized(&plan);
}

#[test]
fn controller_core_build_downgrade_is_refused_even_with_same_major_epoch() {
    let running = snapshot(5);
    let mut candidate = security_expand_candidate(&running);
    candidate.startup.core_identity = 9;
    assert!(run_preflight(OperationIntent::Upgrade, &running, &candidate).is_err());
}
#[test]
fn controller_invalid_supplied_restore_build_is_not_ignored() {
    let running = snapshot(5);
    let mut candidate = snapshot(6);
    candidate.restore_build = Some(RestoreBuildClaim {
        format_id: "other-format".to_owned(),
        digest: digest("wrong-build"),
        described_runnable: false,
    });
    assert!(run_preflight(OperationIntent::Upgrade, &running, &candidate).is_err());
}
#[test]
fn controller_empty_migration_ledger_does_not_prove_compatibility() {
    let mut running = snapshot(5);
    running.schema.migrations.clear();
    let mut candidate = snapshot(6);
    candidate.schema.migrations.clear();
    assert!(run_preflight(OperationIntent::Upgrade, &running, &candidate).is_err());
}

#[test]
fn controller_rollback_requires_exact_previous_build_and_expanded_schema() {
    let running = snapshot(6);
    let candidate = snapshot(5);
    let mut other = candidate.clone();
    other.components.entries[0].digest = digest("other-old-build");
    for (previous, schema) in [
        (None, running.schema.checksum),
        (Some(&other), running.schema.checksum),
        (Some(&candidate), Some(digest("stale-schema"))),
    ] {
        assert!(
            plan_upgrade_preflight(PreflightRequest {
                intent: OperationIntent::EmergencyRollback,
                running: &running,
                candidate: &candidate,
                previous_build: previous,
                rollback_schema: schema,
                proof_claims: &claims(),
            })
            .is_err()
        );
    }
    let plan = run_preflight(OperationIntent::EmergencyRollback, &running, &candidate).unwrap();
    assert_eq!(plan.candidate(), &candidate);
    assert_eq!(plan.running(), &running);
    assert_unauthorized(&plan);
}
#[test]
fn controller_plan_identity_changes_when_package_or_restore_build_changes() {
    let running = snapshot(5);
    let a = snapshot(6);
    let mut b = a.clone();
    b.components.entries[0].digest = digest("different-package");
    assert_ne!(
        run_preflight(OperationIntent::Upgrade, &running, &a).unwrap(),
        run_preflight(OperationIntent::Upgrade, &running, &b).unwrap()
    );
}
