//! 用测试自建临时 PostgreSQL 捕获 artifact registry 的独立内部 schema oracle。
mod harness;

use openbot_infra::artifact_registry::capture_artifact_registry_schema;
use openbot_infra::db::{fresh, native, pool};

#[tokio::test]
#[ignore = "generation only: owned PostgreSQL and OPENBOT_REGENERATE_ARTIFACT_DATASET_0041=1"]
async fn generate_artifact_dataset_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_ARTIFACT_DATASET_0041").as_deref(),
        Ok("1"),
        "没有显式生成授权时不得写 schema oracle"
    );
    harness::with_temp_database(
        &harness::admin_config("artifact41fixture"),
        "artifact41fixture",
        |config| async move {
            let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut c = p.get().await.map_err(|e| e.to_string())?;
            assert_eq!(native::NATIVE_LATEST_VERSION, 41);
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            drop(c);
            let facts = capture_artifact_registry_schema(&p)
                .await
                .map_err(|e| e.to_string())?;
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/db/artifact-dataset-bindings-0041.json");
            std::fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&facts).unwrap()),
            )
            .map_err(|e| e.to_string())?;
            p.close();
            Ok(())
        },
    )
    .await;
}
