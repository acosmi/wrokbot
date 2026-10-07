//! Ordinary Models and Workspace/Computer consumers on an owned PostgreSQL/HTTP/TLS host.
//! This ignored host is an infrastructure entry, not a verdict for either compiled-client case.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/delivered_capability_actual_client_host.rs"]
mod host;
#[path = "../../openbot-infra/tests/support/provider_target_fixture.rs"]
mod provider_target_fixture;

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; actual ciphertext-column mutation observer"]
async fn actual_ciphertext_only_change_alters_snapshot_without_exposing_ciphertext() {
    harness::with_temp_database(
        &harness::admin_config("cipherobserver"),
        "cipherobserver",
        |config| async move { host::verify_ciphertext_snapshot_mutation(config).await },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_delivered_capability_client_host() {
    harness::with_temp_database(
        &harness::admin_config("capclient"),
        "capclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
