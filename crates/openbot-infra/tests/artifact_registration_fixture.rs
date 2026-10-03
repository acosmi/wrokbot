//! Independent actual native0042 internal-schema generation in an owned disposable PG database.
#![cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]

mod harness;

use openbot_infra::artifact_administration::capture_artifact_registration_schema;
use openbot_infra::db::{fresh, native, pool};

#[tokio::test]
#[ignore = "owned PostgreSQL plus OPENBOT_REGENERATE_ARTIFACT_REGISTRATION_0042=1 required"]
async fn generate_artifact_registration_fixture_from_owned_pg() {
    assert_eq!(
        std::env::var("OPENBOT_REGENERATE_ARTIFACT_REGISTRATION_0042").as_deref(),
        Ok("1"),
        "explicit generation authorization required"
    );
    harness::with_temp_database(
        &harness::admin_config("artifact42fixture"),
        "artifact42fixture",
        |config| async move {
            let pool = pool::connect(&config)
                .await
                .map_err(|error| error.to_string())?;
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            assert_eq!(native::NATIVE_LATEST_VERSION, 42);
            fresh::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let facts = capture_artifact_registration_schema(&pool)
                .await
                .map_err(|error| error.to_string())?;
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/db/artifact-registration-0042.json");
            std::fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&facts).unwrap()),
            )
            .map_err(|error| error.to_string())?;
            pool.close();
            Ok(())
        },
    )
    .await;
}
