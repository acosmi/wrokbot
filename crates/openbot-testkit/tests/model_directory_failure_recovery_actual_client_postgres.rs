//! Owned PostgreSQL/HTTP carrier for finite actual-client directory fault evidence.
//! Carrier readiness is not a runtime verdict or a model capability claim.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/model_directory_failure_recovery_actual_client_host.rs"]
mod host;
#[path = "../../openbot-infra/tests/support/provider_target_fixture.rs"]
mod provider_target_fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_model_directory_failure_recovery_client_host() {
    harness::with_temp_database(
        &harness::admin_config("modeldirclient"),
        "modeldirclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
