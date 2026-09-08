//! Native 0030 schema, typed-row and composite-reference PostgreSQL 17 evidence.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{
    NATIVE_0030_TABLES, TableRow, model_connection_secrets, model_connections,
};
use openbot_infra::db::{baseline, pool, schema_facts};
use time::OffsetDateTime;
use tokio_postgres::{Client, Transaction, error::SqlState};
use uuid::Uuid;

const POST_0029: &str = include_str!("../../../fixtures/db/schema-0029.json");

fn post_0030_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0030.json")
}

async fn initialize(client: &mut Client) -> Result<(), String> {
    baseline::apply(client).await.map_err(|e| e.to_string())?;
    native::apply_through(client, native::NATIVE_0030_VERSION)
        .await
        .map_err(|e| e.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email) VALUES
               ('schema-alice','schema-alice@example.test'),
               ('schema-bob','schema-bob@example.test');
             INSERT INTO public.user_roles(user_id,role) VALUES
               ('schema-alice','user'),('schema-bob','admin');",
        )
        .await
        .map_err(|e| e.to_string())
}

fn pair(
    number: u128,
    deployment: &str,
    tenant: &str,
    owner: &str,
    deleted: bool,
) -> (model_connections::Row, model_connection_secrets::Row) {
    let created = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(42);
    let updated = created + time::Duration::seconds(17);
    let deleted_at = deleted.then_some(updated);
    let connection = model_connections::Row {
        id: Uuid::from_u128(number),
        deployment_id: deployment.to_owned(),
        tenant_id: tenant.to_owned(),
        owner_user_id: owner.to_owned(),
        name: format!("模型连接-{number}"),
        protocol: "openai_chat_completions".to_owned(),
        endpoint: "https://provider.example.test/v1/chat/completions".to_owned(),
        model: "model-中文".to_owned(),
        enabled: !deleted,
        revision: 7,
        current_secret_id: Uuid::from_u128(number + 1000),
        created_at: created,
        updated_at: updated,
        deleted_at,
    };
    let secret = model_connection_secrets::Row {
        id: connection.current_secret_id,
        connection_id: connection.id,
        deployment_id: deployment.to_owned(),
        tenant_id: tenant.to_owned(),
        owner_user_id: owner.to_owned(),
        encrypted_value: format!("MODEL-CIPHERTEXT-{number}-CANARY"),
        created_at: created,
        retired_at: deleted_at,
    };
    (connection, secret)
}

async fn insert_row<R: TableRow>(transaction: &Transaction<'_>, row: &R) -> Result<(), String> {
    let placeholders = (1..=R::COLUMNS.len())
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "INSERT INTO public.{} ({}) VALUES ({placeholders})",
        R::TABLE_NAME,
        R::COLUMNS.join(","),
    );
    transaction
        .execute(&sql, &row.as_sql_params())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn insert_pair(
    client: &mut Client,
    connection: &model_connections::Row,
    secret: &model_connection_secrets::Row,
) -> Result<(), String> {
    let transaction = client.transaction().await.map_err(|e| e.to_string())?;
    // The reciprocal references are intentionally deferred until both rows exist.
    insert_row(&transaction, connection).await?;
    insert_row(&transaction, secret).await?;
    transaction.commit().await.map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0030_preserves_all_old_schema_facts_and_registers_two_exact_tables() {
    let admin = admin_config("native0030_schema");
    with_temp_database(&admin, "native0030facts", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply_through(&mut client, native::NATIVE_0029_VERSION)
                .await
                .map_err(|e| e.to_string())?;
            let before = schema_facts::fetch(&client)
                .await
                .map_err(|e| e.to_string())?;
            let expected_before: SchemaFacts =
                serde_json::from_str(POST_0029).map_err(|e| e.to_string())?;
            assert_eq!(before, expected_before);
            assert_eq!(
                native::apply_through(&mut client, native::NATIVE_0030_VERSION)
                    .await
                    .map_err(|e| e.to_string())?,
                ApplyOutcome::Applied
            );
            let after = schema_facts::fetch(&client)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(after.enums, before.enums);
            assert_eq!(after.extensions, before.extensions);
            assert_eq!(after.functions, before.functions);
            assert_eq!(after.tables.len(), before.tables.len() + 2);
            for old in &before.tables {
                // Compare columns/defaults/ordinals, constraints, indexes and triggers together.
                assert_eq!(after.table(&old.name), Some(old), "{}", old.name);
            }
            assert_eq!(NATIVE_0030_TABLES.len(), 2);
            for spec in NATIVE_0030_TABLES {
                let table = after.table(spec.name).expect("new table exists");
                assert_eq!(table.columns.len(), spec.columns.len());
                assert_eq!(table.columns.len(), spec.column_specs.len());
                for (position, (actual, declared)) in table
                    .columns
                    .iter()
                    .zip(spec.column_specs.iter())
                    .enumerate()
                {
                    assert_eq!(actual.name, spec.columns[position]);
                    assert_eq!(actual.name, declared.name);
                    assert_eq!(actual.sql_type, declared.sql_type);
                    assert_eq!(actual.notnull, declared.not_null);
                    assert_eq!(usize::try_from(actual.ordinal).unwrap(), position + 1);
                }
            }
            if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0030").is_some() {
                let mut encoded =
                    serde_json::to_string_pretty(&after).map_err(|e| e.to_string())?;
                encoded.push('\n');
                std::fs::write(post_0030_path(), encoded).map_err(|e| e.to_string())?;
            } else {
                let expected = std::fs::read_to_string(post_0030_path())
                    .map_err(|e| format!("schema-0030 fixture missing: {e}"))?;
                let expected: SchemaFacts =
                    serde_json::from_str(&expected).map_err(|e| e.to_string())?;
                assert_eq!(after, expected);
            }
            let ledger: i64 = client
                .query_one(
                    "SELECT count(*) FROM openbot_internal.schema_migrations",
                    &[],
                )
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            assert_eq!(ledger, 18);
            assert_eq!(
                native::apply_through(&mut client, native::NATIVE_0030_VERSION)
                    .await
                    .map_err(|e| e.to_string())?,
                ApplyOutcome::AlreadyApplied
            );
            println!(
                "native0030 old_tables={} unchanged; added_tables=2; ledger=18",
                before.tables.len()
            );
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0030_typed_rows_round_trip_all_fields_and_redact_ciphertext() {
    let admin = admin_config("native0030_rows");
    with_temp_database(&admin, "native0030rows", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            initialize(&mut client).await?;
            for (number, deleted) in [(1, false), (2, true)] {
                let (connection, secret) =
                    pair(number, "dep-a", "tenant-a", "schema-alice", deleted);
                insert_pair(&mut client, &connection, &secret).await?;
                let raw = client
                    .query_one(
                        "SELECT * FROM public.model_connections WHERE id=$1",
                        &[&connection.id],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                let decoded = model_connections::Row::try_from(&raw).map_err(|e| e.to_string())?;
                assert_eq!(decoded, connection);
                assert_eq!(decoded.as_sql_params().len(), 14);
                assert!(format!("{decoded:?}").contains(&connection.current_secret_id.to_string()));
                let raw = client
                    .query_one(
                        "SELECT * FROM public.model_connection_secrets WHERE id=$1",
                        &[&secret.id],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                let decoded =
                    model_connection_secrets::Row::try_from(&raw).map_err(|e| e.to_string())?;
                assert_eq!(decoded, secret);
                assert_eq!(decoded.as_sql_params().len(), 8);
                let debug = format!("{decoded:?}");
                assert!(!debug.contains(&secret.encrypted_value));
                assert!(debug.contains("schema-alice"));
                assert_eq!(debug.matches("<redacted>").count(), 1);
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn post_0030_composite_references_reject_rebinding_and_user_delete_cascades() {
    let admin = admin_config("native0030_scope");
    with_temp_database(&admin, "native0030scope", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            initialize(&mut client).await?;
            let pairs = [
                pair(1, "dep-a", "tenant-a", "schema-alice", false),
                pair(2, "dep-a", "tenant-a", "schema-alice", false),
                pair(3, "dep-a", "tenant-a", "schema-bob", false),
                pair(4, "dep-a", "tenant-b", "schema-alice", false),
                pair(5, "dep-b", "tenant-a", "schema-alice", false),
            ];
            for (connection, secret) in &pairs {
                insert_pair(&mut client, connection, secret).await?;
            }
            for (_, foreign_secret) in &pairs[1..] {
                let tx = client.transaction().await.map_err(|e| e.to_string())?;
                tx.execute(
                    "UPDATE public.model_connections SET current_secret_id=$2 WHERE id=$1",
                    &[&pairs[0].0.id, &foreign_secret.id],
                ).await.map_err(|e| e.to_string())?;
                let error = tx.commit().await.expect_err("foreign current secret must fail at commit");
                assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
                assert_eq!(error.as_db_error().and_then(|e| e.constraint()), Some("model_connections_current_secret_scope"));
            }
            for (column, foreign_value) in [
                ("deployment_id", "dep-b"),
                ("tenant_id", "tenant-b"),
                ("owner_user_id", "schema-bob"),
            ] {
                let mut mismatched = pairs[0].1.clone();
                mismatched.id = Uuid::from_u128(2000);
                match column {
                    "deployment_id" => mismatched.deployment_id = foreign_value.to_owned(),
                    "tenant_id" => mismatched.tenant_id = foreign_value.to_owned(),
                    "owner_user_id" => mismatched.owner_user_id = foreign_value.to_owned(),
                    _ => unreachable!(),
                }
                let tx = client.transaction().await.map_err(|e| e.to_string())?;
                insert_row(&tx, &mismatched).await?;
                let error = tx.commit().await.expect_err("secret scope mismatch must fail at commit");
                assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION), "{column}");
            }
            let tx = client.transaction().await.map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE public.model_connection_secrets SET connection_id=$2 WHERE id=$1",
                &[&pairs[0].1.id, &pairs[1].0.id],
            ).await.map_err(|e| e.to_string())?;
            let error = tx.commit().await.expect_err("current secret cannot move to another connection");
            assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));

            let mut historical = pairs[0].1.clone();
            historical.id = Uuid::from_u128(3000);
            historical.retired_at = Some(OffsetDateTime::UNIX_EPOCH);
            let tx = client.transaction().await.map_err(|e| e.to_string())?;
            insert_row(&tx, &historical).await?;
            tx.commit().await.map_err(|e| e.to_string())?;
            client.execute("DELETE FROM public.user_roles WHERE user_id='schema-alice'", &[])
                .await.map_err(|e| e.to_string())?;
            let count = client.query_one(
                "SELECT (SELECT count(*) FROM public.model_connections),
                        (SELECT count(*) FROM public.model_connection_secrets)", &[])
                .await.map_err(|e| e.to_string())?;
            assert_eq!((count.get::<_, i64>(0), count.get::<_, i64>(1)), (5, 6));
            client.execute("DELETE FROM public.users WHERE id='schema-alice'", &[])
                .await.map_err(|e| e.to_string())?;
            let count = client.query_one(
                "SELECT (SELECT count(*) FROM public.model_connections),
                        (SELECT count(*) FROM public.model_connection_secrets)", &[])
                .await.map_err(|e| e.to_string())?;
            assert_eq!((count.get::<_, i64>(0), count.get::<_, i64>(1)), (1, 1));
            let owner: String = client.query_one("SELECT owner_user_id FROM public.model_connections", &[])
                .await.map_err(|e| e.to_string())?.get(0);
            assert_eq!(owner, "schema-bob");
            println!("native0030 deferred_fk_negatives=8; role_delete_preserves=5/6; user_cascade_survivors=1/1");
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
