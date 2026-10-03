//! Generate this oracle from a fresh owned PG, never from an earlier fixture.
mod harness;
use openbot_infra::db::{baseline, native, pool, schema_facts};

#[tokio::test]
#[ignore = "generation only: owned PostgreSQL and OPENBOT_REGENERATE_SCHEMA_0039=1"]
async fn generate_schema_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_SCHEMA_0039").as_deref(),
        Ok("1")
    );
    harness::with_temp_database(
        &harness::admin_config("skill39fixture"),
        "skill39fixture",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply_through(&mut c, 39)
                .await
                .map_err(|e| e.to_string())?;
            let facts = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
            assert!(
                facts
                    .table("skills")
                    .unwrap()
                    .columns
                    .iter()
                    .any(|c| c.name == "revision")
            );
            assert!(facts.table("skill_retired_slugs").is_some());
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/db/schema-0039.json");
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
