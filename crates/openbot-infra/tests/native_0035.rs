//! R401/R402: additive schema, append-only typed rows and Desktop canary registration.

mod harness;

use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{NATIVE_0035_TABLES, remember_effect_receipts};
use openbot_infra::db::{baseline, desktop_vault_canary, fresh, pool, schema_facts};
use time::OffsetDateTime;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

fn expected() -> SchemaFacts {
    serde_json::from_str(include_str!("../../../fixtures/db/schema-0035.json")).unwrap()
}

fn assert_additive(before: &SchemaFacts, after: &SchemaFacts) {
    assert_eq!(after.enums, before.enums);
    assert_eq!(after.extensions, before.extensions);
    assert_eq!(after.functions, before.functions);
    assert_eq!(after.tables.len(), before.tables.len() + 1);
    for old in &before.tables {
        assert_eq!(after.table(&old.name), Some(old), "{}", old.name);
    }
    assert_eq!(NATIVE_0035_TABLES.len(), 1);
    let spec = &NATIVE_0035_TABLES[0];
    assert_eq!(spec.name, "remember_effect_receipts");
    let table = after.table(spec.name).unwrap();
    assert_eq!(table.columns.len(), 23);
    assert_eq!(table.constraints.len(), 16);
    assert_eq!(table.indexes.len(), 3);
    assert_eq!(table.triggers.len(), 2);
    assert!(
        table
            .constraints
            .iter()
            .all(|constraint| constraint.kind != "f")
    );
    assert_eq!(
        table
            .triggers
            .iter()
            .map(|trigger| trigger.name.as_str())
            .collect::<Vec<_>>(),
        [
            "remember_effect_receipts_append_only",
            "remember_effect_receipts_no_truncate",
        ]
    );
    for (index, (actual, declared)) in table.columns.iter().zip(spec.column_specs).enumerate() {
        assert_eq!(actual.name, declared.name);
        assert_eq!(actual.sql_type, declared.sql_type);
        assert_eq!(actual.notnull, declared.not_null);
        assert_eq!(actual.default, None);
        assert_eq!(usize::try_from(actual.ordinal).unwrap(), index + 1);
    }
}

async fn assert_ledger(client: &tokio_postgres::Client) {
    let row = client
        .query_one(
            "SELECT count(*)::bigint,max(version) FROM openbot_internal.schema_migrations",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 23);
    assert_eq!(row.get::<_, i32>(1), 35);
    let row = client
        .query_one(
            "SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=35",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), native::NATIVE_0035_NAME);
    assert_eq!(row.get::<_, String>(1), native::native_0035_checksum());
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn upgrade_is_additive_once_and_fresh_matches_owned_0035_fixture() {
    let admin = harness::admin_config("native0035_schema");
    harness::with_temp_database(&admin, "receipt35upgrade", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&client).await.unwrap();
        native::apply_through(&mut client, native::NATIVE_0034_VERSION)
            .await
            .unwrap();
        let before = schema_facts::fetch(&client).await.unwrap();
        let old: SchemaFacts =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0034.json")).unwrap();
        assert_eq!(before, old);
        assert_eq!(
            native::apply_through(&mut client, native::NATIVE_0035_VERSION)
                .await
                .unwrap(),
            ApplyOutcome::Applied
        );
        let after = schema_facts::fetch(&client).await.unwrap();
        assert_additive(&before, &after);
        assert_eq!(after, expected());
        assert_ledger(&client).await;
        assert_eq!(
            native::apply_through(&mut client, native::NATIVE_0035_VERSION)
                .await
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert_eq!(schema_facts::fetch(&client).await.unwrap(), after);
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
    harness::with_temp_database(&admin, "receipt35fresh", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        assert_eq!(
            fresh::apply(&mut client).await.unwrap(),
            fresh::FreshApplyOutcome::Applied(ApplyOutcome::Applied)
        );
        assert_eq!(schema_facts::fetch(&client).await.unwrap(), expected());
        assert_ledger(&client).await;
        assert_eq!(
            fresh::apply(&mut client).await.unwrap(),
            fresh::FreshApplyOutcome::AlreadyInitialized
        );
        drop(client);
        desktop_vault_canary::verify_current_layout(&pool)
            .await
            .unwrap();
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn concurrent_upgrade_records_0035_exactly_once() {
    let admin = harness::admin_config("native0035_concurrent");
    harness::with_temp_database(&admin, "receipt35race", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut first = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&first).await.unwrap();
        native::apply_through(&mut first, native::NATIVE_0034_VERSION)
            .await
            .unwrap();
        let mut second = pool.get().await.map_err(|error| error.to_string())?;
        let (left, right) = tokio::join!(
            native::apply_through(&mut first, native::NATIVE_0035_VERSION),
            native::apply_through(&mut second, native::NATIVE_0035_VERSION),
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ApplyOutcome::Applied)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ApplyOutcome::AlreadyApplied)
                .count(),
            1
        );
        assert_ledger(&first).await;
        assert_eq!(schema_facts::fetch(&first).await.unwrap(), expected());
        drop(first);
        drop(second);
        pool.close();
        Ok(())
    })
    .await;
}

fn receipt(index: u128) -> remember_effect_receipts::Row {
    remember_effect_receipts::Row {
        receipt_id: Uuid::from_u128(index).to_string(),
        deployment_id: "deployment".into(),
        tenant_id: "tenant".into(),
        thread_id: "original-thread".into(),
        run_id: "original-run".into(),
        actor_id: "original-owner".into(),
        bot_id: "original-bot".into(),
        auth_generation: 0,
        tool_call_id: format!("call-{index}"),
        call_seq: i64::try_from(index).unwrap(),
        attempt_id: format!("attempt-{index}"),
        attempt_seq: 0,
        decision_id: format!("decision-{index}"),
        capability_id: format!("capability-{index}"),
        args_hash: "a".repeat(64),
        schema_hash: "b".repeat(64),
        catalog_generation: 0,
        target_kind: "memory_user".into(),
        target_id: "original-owner".into(),
        memory_id: Uuid::from_u128(index + 1000).to_string(),
        memory_event_seq: 0,
        audit_event_id: Uuid::from_u128(index + 2000).to_string(),
        recorded_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn insert_sql() -> String {
    let placeholders = (1..=remember_effect_receipts::COLUMNS.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "INSERT INTO public.remember_effect_receipts ({}) VALUES ({placeholders})",
        remember_effect_receipts::COLUMNS.join(",")
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn typed_receipts_are_immutable_and_binding_constraints_are_enforced() {
    let admin = harness::admin_config("native0035_rows");
    harness::with_temp_database(&admin, "receipt35rows", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        fresh::apply(&mut client).await.unwrap();
        let sql = insert_sql();
        let original = receipt(1);
        // No business rows exist: history deliberately has no business foreign keys.
        client
            .execute(&sql, &original.as_sql_params())
            .await
            .unwrap();
        let read = client
            .query_one("SELECT * FROM public.remember_effect_receipts", &[])
            .await
            .unwrap();
        assert_eq!(
            remember_effect_receipts::Row::try_from(&read).unwrap(),
            original
        );
        for statement in [
            "UPDATE public.remember_effect_receipts SET target_id=target_id",
            "DELETE FROM public.remember_effect_receipts",
            "TRUNCATE public.remember_effect_receipts",
        ] {
            assert_eq!(
                client.batch_execute(statement).await.unwrap_err().code(),
                Some(&SqlState::RAISE_EXCEPTION),
                "{statement}"
            );
            let read = client
                .query_one("SELECT * FROM public.remember_effect_receipts", &[])
                .await
                .unwrap();
            assert_eq!(
                remember_effect_receipts::Row::try_from(&read).unwrap(),
                original
            );
        }
        for duplicate in [
            original.clone(),
            remember_effect_receipts::Row {
                attempt_id: original.attempt_id.clone(),
                ..receipt(2)
            },
            remember_effect_receipts::Row {
                call_seq: original.call_seq,
                attempt_seq: original.attempt_seq,
                ..receipt(3)
            },
        ] {
            assert_eq!(
                client
                    .execute(&sql, &duplicate.as_sql_params())
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::UNIQUE_VIOLATION)
            );
        }
        for field in [
            "deployment_id",
            "tenant_id",
            "thread_id",
            "run_id",
            "actor_id",
            "bot_id",
            "tool_call_id",
            "attempt_id",
            "decision_id",
            "capability_id",
            "target_id",
        ] {
            for value in [
                String::new(),
                "x".repeat(513),
                "界".repeat(171),
                "line\nbreak".into(),
                "c1\u{85}control".into(),
            ] {
                let mut invalid = receipt(10);
                match field {
                    "deployment_id" => invalid.deployment_id = value,
                    "tenant_id" => invalid.tenant_id = value,
                    "thread_id" => invalid.thread_id = value,
                    "run_id" => invalid.run_id = value,
                    "actor_id" | "target_id" => {
                        invalid.actor_id = value.clone();
                        invalid.target_id = value;
                    }
                    "bot_id" => invalid.bot_id = value,
                    "tool_call_id" => invalid.tool_call_id = value,
                    "attempt_id" => invalid.attempt_id = value,
                    "decision_id" => invalid.decision_id = value,
                    "capability_id" => invalid.capability_id = value,
                    _ => unreachable!("closed identity fields"),
                }
                assert_eq!(
                    client
                        .execute(&sql, &invalid.as_sql_params())
                        .await
                        .unwrap_err()
                        .code(),
                    Some(&SqlState::CHECK_VIOLATION),
                    "{field}"
                );
            }
        }
        for field in [
            "auth_generation",
            "call_seq",
            "attempt_seq",
            "catalog_generation",
            "memory_event_seq",
        ] {
            let mut invalid = receipt(10);
            match field {
                "auth_generation" => invalid.auth_generation = -1,
                "call_seq" => invalid.call_seq = -1,
                "attempt_seq" => invalid.attempt_seq = -1,
                "catalog_generation" => invalid.catalog_generation = -1,
                "memory_event_seq" => invalid.memory_event_seq = 1,
                _ => unreachable!("closed sequence fields"),
            }
            assert_eq!(
                client
                    .execute(&sql, &invalid.as_sql_params())
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::CHECK_VIOLATION),
                "{field}"
            );
        }
        for field in ["args_hash", "schema_hash"] {
            for value in [
                "a".repeat(63),
                "a".repeat(65),
                "A".repeat(64),
                "g".repeat(64),
            ] {
                let mut invalid = receipt(10);
                if field == "args_hash" {
                    invalid.args_hash = value;
                } else {
                    invalid.schema_hash = value;
                }
                assert_eq!(
                    client
                        .execute(&sql, &invalid.as_sql_params())
                        .await
                        .unwrap_err()
                        .code(),
                    Some(&SqlState::CHECK_VIOLATION),
                    "{field}"
                );
            }
        }
        for field in ["receipt_id", "memory_id", "audit_event_id"] {
            for value in ["invalid-uuid", "550E8400-E29B-41D4-A716-446655440000"] {
                let mut invalid = receipt(10);
                match field {
                    "receipt_id" => invalid.receipt_id = value.into(),
                    "memory_id" => invalid.memory_id = value.into(),
                    "audit_event_id" => invalid.audit_event_id = value.into(),
                    _ => unreachable!("closed UUID fields"),
                }
                assert_eq!(
                    client
                        .execute(&sql, &invalid.as_sql_params())
                        .await
                        .unwrap_err()
                        .code(),
                    Some(&SqlState::CHECK_VIOLATION),
                    "{field}"
                );
            }
        }
        for (kind, target) in [
            ("other", "original-owner"),
            ("memory_user", "wrong"),
            ("memory_bot", "wrong"),
            ("memory_thread", "wrong"),
        ] {
            let invalid = remember_effect_receipts::Row {
                target_kind: kind.into(),
                target_id: target.into(),
                ..receipt(10)
            };
            assert_eq!(
                client
                    .execute(&sql, &invalid.as_sql_params())
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::CHECK_VIOLATION)
            );
        }
        for (index, kind, target) in [
            (20, "memory_bot", "original-bot"),
            (21, "memory_thread", "original-thread"),
        ] {
            let valid = remember_effect_receipts::Row {
                target_kind: kind.into(),
                target_id: target.into(),
                ..receipt(index)
            };
            client.execute(&sql, &valid.as_sql_params()).await.unwrap();
        }
        let boundary = remember_effect_receipts::Row {
            deployment_id: "x".repeat(512),
            tenant_id: format!("{}xy", "界".repeat(170)),
            auth_generation: i64::MAX,
            call_seq: i64::MAX,
            attempt_seq: i64::MAX,
            catalog_generation: i64::MAX,
            ..receipt(22)
        };
        client
            .execute(&sql, &boundary.as_sql_params())
            .await
            .unwrap();
        let count: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM public.remember_effect_receipts",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 4);
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn desktop_canary_accepts_registered_34_and_35_but_rejects_public_drift() {
    let admin = harness::admin_config("native0035_canary");
    harness::with_temp_database(&admin, "receipt35canary", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&client).await.unwrap();
        native::apply_through(&mut client, native::NATIVE_0034_VERSION).await.unwrap();
        assert_eq!(desktop_vault_canary::verify_pre_upgrade_layout(&pool).await.unwrap().native_version(), 34);
        assert!(desktop_vault_canary::verify_current_layout(&pool).await.is_err());
        native::apply_through(&mut client, native::NATIVE_0035_VERSION).await.unwrap();
        assert_eq!(desktop_vault_canary::verify_pre_upgrade_layout(&pool).await.unwrap().native_version(), 35);
        desktop_vault_canary::verify_current_layout(&pool).await.unwrap();
        client.batch_execute("DROP TRIGGER remember_effect_receipts_no_truncate ON public.remember_effect_receipts").await.unwrap();
        assert!(desktop_vault_canary::verify_pre_upgrade_layout(&pool).await.is_err());
        assert!(desktop_vault_canary::verify_current_layout(&pool).await.is_err());
        drop(client);
        pool.close();
        Ok(())
    }).await;
}
