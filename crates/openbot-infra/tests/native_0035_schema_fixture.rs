//! Explicit, isolated PostgreSQL export for the native 0035 public schema fixture.
//! This target has no compile-time dependency on the fixture it creates.

mod harness;

use openbot_infra::db::{baseline, native, pool, schema_facts};

#[tokio::test]
#[ignore = "fixture generation only: requires owned PostgreSQL and OPENBOT_REGENERATE_SCHEMA_0035=1"]
async fn generate_schema_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_SCHEMA_0035").as_deref(),
        Ok("1"),
        "fixture writes require the explicit regeneration switch"
    );
    let admin = harness::admin_config("native0035_fixture");
    harness::with_temp_database(&admin, "receipt35fixture", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let mut client = pool.get().await.map_err(|error| error.to_string())?;
        baseline::apply(&client)
            .await
            .map_err(|error| error.to_string())?;
        native::apply_through(&mut client, native::NATIVE_0035_VERSION)
            .await
            .map_err(|error| error.to_string())?;
        let facts = schema_facts::fetch(&client)
            .await
            .map_err(|error| error.to_string())?;
        let receipts = facts
            .table("remember_effect_receipts")
            .expect("0035 must exist");
        assert_eq!(receipts.columns.len(), 23);
        assert_eq!(receipts.triggers.len(), 2);
        let destination = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/db/schema-0035.json");
        let encoded = format!("{}\n", serde_json::to_string_pretty(&facts).unwrap());
        std::fs::write(destination, encoded).map_err(|error| error.to_string())?;
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}
