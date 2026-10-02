//! Generates the 0036 oracle only from a fresh, owned PostgreSQL instance.
mod harness;

use openbot_infra::db::{fresh, native, pool, schema_facts};

#[tokio::test]
#[ignore = "fixture generation only: owned PostgreSQL and OPENBOT_REGENERATE_SCHEMA_0036=1"]
async fn generate_schema_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_SCHEMA_0036").as_deref(),
        Ok("1")
    );
    harness::with_temp_database(
        &harness::admin_config("native0036fixture"),
        "occupancy36fixture",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            assert_eq!(native::NATIVE_LATEST_VERSION, 36);
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            let facts = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            let table = facts.table("thread_run_occupancy").expect("0036 table");
            assert_eq!(table.columns.len(), 2);
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/db/schema-0036.json");
            std::fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&facts).unwrap()),
            )
            .map_err(|e| e.to_string())?;
            drop(c);
            p.close();
            Ok(())
        },
    )
    .await;
}
