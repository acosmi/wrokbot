//! Native 0032 internal Desktop Vault canary schema.
mod harness;

use openbot_infra::db::{desktop_vault_canary, fresh, native, pool, schema_facts};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn native_0032_is_internal_expand_only_and_fresh_matches_upgrade() {
    let admin = harness::admin_config("native0032_schema");
    harness::with_temp_database(&admin, "vault32upgrade", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut client).await.map_err(|e| e.to_string())?;
        let public = schema_facts::fetch(&client).await.unwrap();
        let expected = serde_json::from_str(include_str!(
            "../../../fixtures/db/schema-0031.json"
        ))
        .unwrap();
        assert_eq!(public, expected);
        let columns: Vec<(String, String, bool)> = client
            .query(
                "SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull FROM pg_attribute a WHERE a.attrelid='openbot_internal.desktop_vault_canaries'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect();
        assert_eq!(columns.len(), 8);
        assert_eq!(columns[0], ("dataset_id".into(), "text".into(), true));
        assert_eq!(columns[7], ("created_at".into(), "timestamp with time zone".into(), true));
        let ledger: i64 = client
            .query_one("SELECT count(*) FROM openbot_internal.schema_migrations", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(ledger, 20);
        let checksum: String = client
            .query_one(
                "SELECT checksum FROM openbot_internal.schema_migrations WHERE version=32",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(checksum, native::native_0032_checksum());
        native::validate_current(&client).await.unwrap();
        desktop_vault_canary::verify_current_layout(&pool)
            .await
            .unwrap();
        client
            .batch_execute(
                "ALTER TABLE openbot_internal.desktop_vault_canaries DROP CONSTRAINT desktop_vault_canaries_pkey",
            )
            .await
            .unwrap();
        native::validate_current(&client).await.unwrap();
        assert!(desktop_vault_canary::verify_current_layout(&pool).await.is_err());
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}
