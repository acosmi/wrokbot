//! Owned PostgreSQL/HTTP/TLS carrier for seven finite current-run client observations.
//! Host readiness is not a browser, provider, journal or product verdict.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/current_run_results_owned_tls_fixture.rs"]
mod current_run_results_owned_tls_fixture;
#[path = "support/current_run_results_actual_client_host.rs"]
mod host;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_current_run_results_client_host() {
    harness::with_temp_database(
        &harness::admin_config("currentrunclient"),
        "currentrunclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
