//! Owned PostgreSQL/HTTP/TLS carrier for finite actual-client model-save evidence.
//! Readiness of this carrier does not establish any browser or runtime case verdict.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/runtime_capabilities_actual_client_host.rs"]
mod host;
#[path = "../../openbot-infra/tests/support/provider_target_fixture.rs"]
mod provider_target_fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_models_save_capability_client_host() {
    harness::with_temp_database(
        &harness::admin_config("capactualclient"),
        "capactualclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
