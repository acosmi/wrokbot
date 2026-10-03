//! Owned real PostgreSQL/HTTP host for the finite R415 current-WASM journeys.
//! The external private driver owns the libtest child's pipes and all browser operations.
//! This carrier itself claims no browser case, presentation, or native OS acceptance.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

#[path = "support/r415_actual_client_host/mod.rs"]
mod host;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires ROOT-owned isolated PostgreSQL, immutable WASM dist and piped IPC driver"]
async fn actual_four_object_client_host() {
    harness::with_temp_database(
        &harness::admin_config("r415actualclient"),
        "r415actualclient",
        |config| async move { host::run(config).await },
    )
    .await;
}
