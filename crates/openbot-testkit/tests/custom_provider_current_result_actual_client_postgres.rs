//! Owned PostgreSQL/HTTP/TLS carrier for finite actual-client Custom401 evidence.
//! Host readiness is not a browser or run verdict.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/custom_provider_current_result_tls_fixture.rs"]
mod custom_provider_current_result_tls_fixture;
#[path = "support/custom_provider_current_result_actual_client_host.rs"]
mod host;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_custom_401_current_result_client_host() {
    harness::with_temp_database(
        &harness::admin_config("custom401client"),
        "custom401client",
        |config| async move { host::run(config).await },
    )
    .await;
}
