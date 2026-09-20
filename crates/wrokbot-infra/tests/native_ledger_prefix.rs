//! Read-only known-prefix validation for the Rust-owned migration ledger.

mod harness;

use wrokbot_infra::db::{baseline, native, pool};
use tokio_postgres::Client;

type LedgerRow = (i32, String, String, String);

async fn ledger_rows(client: &Client) -> Vec<LedgerRow> {
    client
        .query(
            "SELECT version,name,checksum,applied_at::text \
             FROM openbot_internal.schema_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

async fn prefix_refusal_is_read_only(client: &Client, required_through: i32) {
    let before = ledger_rows(client).await;
    assert!(
        native::validate_known_prefix(client, required_through)
            .await
            .is_err()
    );
    assert_eq!(ledger_rows(client).await, before);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn known_prefix_accepts_0031_and_rejects_every_ledger_drift_without_writing() {
    let admin = harness::admin_config("native_ledger_prefix");
    harness::with_temp_database(&admin, "knownprefix", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&client).await.map_err(|error| error.to_string())?;
        native::apply_through(&mut client, native::NATIVE_0031_VERSION)
            .await
            .map_err(|error| error.to_string())?;

        let valid = native::validate_known_prefix(&client, native::NATIVE_0031_VERSION)
            .await
            .unwrap();
        assert_eq!(valid.latest_version(), native::NATIVE_0031_VERSION);
        let before_current = ledger_rows(&client).await;
        assert!(native::validate_current(&client).await.is_err());
        assert_eq!(ledger_rows(&client).await, before_current);
        prefix_refusal_is_read_only(&client, native::NATIVE_0032_VERSION).await;
        prefix_refusal_is_read_only(&client, 12).await;
        prefix_refusal_is_read_only(&client, 33).await;
        prefix_refusal_is_read_only(&client, 34).await;

        let original = client
            .query_one(
                "SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=20",
                &[],
            )
            .await
            .unwrap();
        let original_name: String = original.get(0);
        let original_checksum: String = original.get(1);
        client
            .execute(
                "UPDATE openbot_internal.schema_migrations SET name='drifted-name' WHERE version=20",
                &[],
            )
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;
        client
            .execute(
                "UPDATE openbot_internal.schema_migrations SET name=$1 WHERE version=20",
                &[&original_name],
            )
            .await
            .unwrap();

        client
            .execute(
                "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=20",
                &[],
            )
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;
        client
            .execute(
                "UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=20",
                &[&original_checksum],
            )
            .await
            .unwrap();

        let removed = client
            .query_one(
                "DELETE FROM openbot_internal.schema_migrations WHERE version=20 \
                 RETURNING name,checksum,applied_at",
                &[],
            )
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;
        let removed_name: String = removed.get(0);
        let removed_checksum: String = removed.get(1);
        let removed_applied_at: time::OffsetDateTime = removed.get(2);
        client
            .execute(
                "INSERT INTO openbot_internal.schema_migrations(version,name,checksum,applied_at) \
                 VALUES(20,$1,$2,$3)",
                &[&removed_name, &removed_checksum, &removed_applied_at],
            )
            .await
            .unwrap();

        client
            .execute(
                "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) \
                 VALUES(34,'future-0034',repeat('3',64))",
                &[],
            )
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;
        client
            .execute(
                "DELETE FROM openbot_internal.schema_migrations WHERE version=34",
                &[],
            )
            .await
            .unwrap();

        client
            .execute(
                "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) \
                 VALUES(12,'unknown-extra',repeat('1',64))",
                &[],
            )
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;
        client
            .execute(
                "DELETE FROM openbot_internal.schema_migrations WHERE version=12",
                &[],
            )
            .await
            .unwrap();

        client
            .execute("TRUNCATE openbot_internal.schema_migrations", &[])
            .await
            .unwrap();
        prefix_refusal_is_read_only(&client, native::NATIVE_0031_VERSION).await;

        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}
