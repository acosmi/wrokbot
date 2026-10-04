//! Ignored carrier for eight finite normal unsaved Agents Test browser cases.
//! Readiness and fixture acknowledgements are not evidence of a product verdict.
mod harness {
    include!("../../../test-support/postgres_harness.rs");
}
#[path = "support/agent_connection_probe_owned_tls_fixture.rs"]
mod agent_connection_probe_owned_tls_fixture;
#[path = "support/agent_connection_probe_actual_client_host.rs"]
mod host;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, immutable WASM dist and piped actual-client driver"]
async fn actual_agent_connection_probe_client_host() {
    harness::with_temp_database(
        &harness::admin_config("agentprobeclient"),
        "agentprobeclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
