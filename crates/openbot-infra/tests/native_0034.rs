//! R395 durable OAuth send ownership: additive schema, typed rows and unresolved tombstones.

mod harness;

use openbot_infra::db::native::{self, ApplyOutcome};
use openbot_infra::db::schema_facts::SchemaFacts;
use openbot_infra::db::tables::{NATIVE_0034_TABLES, oauth_refresh_operations};
use openbot_infra::db::{baseline, fresh, pool, schema_facts};
use time::OffsetDateTime;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/db/schema-0034.json")
}

fn expected() -> SchemaFacts {
    serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn upgrade_is_additive_once_and_fresh_matches_owned_fixture() {
    let admin = harness::admin_config("native0034_schema");
    harness::with_temp_database(&admin, "oauth34upgrade", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        baseline::apply(&client).await.unwrap();
        native::apply_through(&mut client, native::NATIVE_0033_VERSION)
            .await
            .unwrap();
        let before = schema_facts::fetch(&client).await.unwrap();
        let old: SchemaFacts =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0033.json")).unwrap();
        assert_eq!(before, old);
        assert_eq!(
            native::apply(&mut client).await.unwrap(),
            ApplyOutcome::Applied
        );
        let after = schema_facts::fetch(&client).await.unwrap();
        assert_eq!(after.enums, before.enums);
        assert_eq!(after.extensions, before.extensions);
        assert_eq!(after.functions, before.functions);
        assert_eq!(after.tables.len(), before.tables.len() + 1);
        for old in &before.tables {
            assert_eq!(after.table(&old.name), Some(old));
        }
        assert_eq!(NATIVE_0034_TABLES.len(), 1);
        let spec = &NATIVE_0034_TABLES[0];
        let table = after.table(spec.name).unwrap();
        assert_eq!(table.columns.len(), 18);
        assert_eq!(table.constraints.len(), 12);
        assert_eq!(table.indexes.len(), 3);
        assert!(table.triggers.is_empty());
        for (index, (actual, declared)) in table.columns.iter().zip(spec.column_specs).enumerate() {
            assert_eq!(actual.name, declared.name);
            assert_eq!(actual.sql_type, declared.sql_type);
            assert_eq!(actual.notnull, declared.not_null);
            assert_eq!(actual.default, None);
            assert_eq!(usize::try_from(actual.ordinal).unwrap(), index + 1);
        }
        if std::env::var_os("OPENBOT_REGENERATE_SCHEMA_0034").is_some() {
            std::fs::write(
                fixture_path(),
                format!("{}\n", serde_json::to_string_pretty(&after).unwrap()),
            )
            .unwrap();
        } else {
            assert_eq!(after, expected());
        }
        let row = client
            .query_one(
                "SELECT count(*)::bigint, max(version) FROM openbot_internal.schema_migrations",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 22);
        assert_eq!(row.get::<_, i32>(1), 34);
        assert_eq!(
            client
                .query_one(
                    "SELECT checksum FROM openbot_internal.schema_migrations WHERE version=34",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            native::native_0034_checksum()
        );
        assert_eq!(
            native::apply(&mut client).await.unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
    harness::with_temp_database(&admin, "oauth34fresh", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut client).await.unwrap();
        assert_eq!(schema_facts::fetch(&client).await.unwrap(), expected());
        drop(client);
        openbot_infra::db::desktop_vault_canary::verify_current_layout(&pool)
            .await
            .unwrap();
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn typed_rows_allow_sequential_commit_but_keep_unresolved_exclusive() {
    let admin = harness::admin_config("native0034_rows");
    harness::with_temp_database(&admin, "oauth34rows", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut client).await.unwrap();
        let now = OffsetDateTime::UNIX_EPOCH;
        // No authority FK: removal/reconnect must not erase an already consumed token's receipt.
        let row = oauth_refresh_operations::Row {
            operation_id: Uuid::from_u128(1), credential_id: Uuid::from_u128(2), generation: 1,
            actor_id: "removed-owner".to_owned(), auth_generation: 0,
            server_id: "removed-server".to_owned(), client_credential_id: Uuid::from_u128(3),
            server_generation: 0, server_updated_at: now, client_updated_at: now,
            resource: "https://resource.example.test/mcp".to_owned(), transport: "mcp".to_owned(),
            egress_allow_cidrs: vec![Some("192.0.2.0/24".to_owned()), None], granted_scope: "files.read".to_owned(),
            state: "pending".to_owned(), admitted_at: None, created_at: now, completed_at: None,
        };
        let placeholders = (1..=oauth_refresh_operations::COLUMNS.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
        let sql = format!("INSERT INTO public.oauth_refresh_operations ({}) VALUES ({placeholders})", oauth_refresh_operations::COLUMNS.join(","));
        client.execute(&sql, &row.as_sql_params()).await.unwrap();
        assert_eq!(oauth_refresh_operations::Row::try_from(&client.query_one("SELECT * FROM public.oauth_refresh_operations", &[]).await.unwrap()).unwrap(), row);
        let next = oauth_refresh_operations::Row { operation_id: Uuid::from_u128(4), generation: 2, ..row.clone() };
        assert_eq!(client.execute(&sql, &next.as_sql_params()).await.unwrap_err().code(), Some(&SqlState::UNIQUE_VIOLATION));
        for statement in [
            "UPDATE public.oauth_refresh_operations SET generation=0",
            "UPDATE public.oauth_refresh_operations SET auth_generation=-1",
            "UPDATE public.oauth_refresh_operations SET server_generation=-1",
            "UPDATE public.oauth_refresh_operations SET state='retryable'",
            "UPDATE public.oauth_refresh_operations SET state='committed'",
            "UPDATE public.oauth_refresh_operations SET completed_at=clock_timestamp()",
            "UPDATE public.oauth_refresh_operations SET transport='unchecked'",
            "UPDATE public.oauth_refresh_operations SET resource=''",
        ] {
            assert_eq!(client.batch_execute(statement).await.unwrap_err().code(), Some(&SqlState::CHECK_VIOLATION));
        }
        client.batch_execute("UPDATE public.oauth_refresh_operations SET admitted_at=clock_timestamp(),completed_at=clock_timestamp(),state='unknown'").await.unwrap();
        assert_eq!(client.execute(&sql, &next.as_sql_params()).await.unwrap_err().code(), Some(&SqlState::UNIQUE_VIOLATION));
        client.batch_execute("UPDATE public.oauth_refresh_operations SET state='committed'").await.unwrap();
        client.execute(&sql, &next.as_sql_params()).await.unwrap();
        drop(client);
        pool.close();
        Ok(())
    }).await;
}
