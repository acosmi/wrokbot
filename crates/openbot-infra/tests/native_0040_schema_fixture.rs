//! Generate the schema40 oracle from a fresh owned PostgreSQL database.
mod harness;
use openbot_infra::db::{fresh, native, pool, schema_facts};

#[tokio::test]
#[ignore = "generation only: owned PostgreSQL and OPENBOT_REGENERATE_SCHEMA_0040=1"]
async fn generate_schema_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_SCHEMA_0040").as_deref(),
        Ok("1")
    );
    harness::with_temp_database(
        &harness::admin_config("prefs40fixture"),
        "prefs40fixture",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            assert_eq!(native::NATIVE_LATEST_VERSION, 40);
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            let facts = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            let column = facts
                .table("user_ui_preferences")
                .unwrap()
                .column("revision")
                .unwrap();
            assert!(!column.notnull);
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/db/schema-0040.json");
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
