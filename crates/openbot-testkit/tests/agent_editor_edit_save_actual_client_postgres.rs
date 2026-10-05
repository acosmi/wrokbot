//! Ignored actual normal Agents editor edit/Save carrier; IPC is observation and owned cleanup only.
mod harness {
    include!("../../../test-support/postgres_harness.rs");
}
#[path = "support/agent_editor_edit_save_owned_tls_fixture.rs"]
mod agent_editor_edit_save_owned_tls_fixture;
#[path = "support/agent_editor_edit_save_actual_client_host.rs"]
mod host;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned isolated PostgreSQL, fresh immutable WASM and actual ordinary editor driver"]
async fn actual_agent_editor_edit_save_client_host() {
    harness::with_temp_database(
        &harness::admin_config("agenteditsaveclient"),
        "agenteditsaveclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
