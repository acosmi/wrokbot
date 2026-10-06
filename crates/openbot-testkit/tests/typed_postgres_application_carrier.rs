//! Existing typed Desktop commands over an owned, real PostgreSQL shared Application.

#[path = "support/typed_postgres_application_carrier.rs"]
mod carrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP023 PostgreSQL fixture and source metadata"]
async fn typed_shared_application_current_user() {
    carrier::run(carrier::Case::CurrentUser).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP023 PostgreSQL fixture and source metadata"]
async fn typed_model_storage_http_window_roundtrip() {
    carrier::run(carrier::Case::ModelStorage).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP023 PostgreSQL fixture and source metadata"]
async fn typed_principal_isolation() {
    carrier::run(carrier::Case::PrincipalIsolation).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP023 PostgreSQL fixture and source metadata"]
async fn window_unbind_generation_current_authority() {
    carrier::run(carrier::Case::WindowGeneration).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP023 PostgreSQL fixture and source metadata"]
async fn session_revoke_capability_source_denial() {
    carrier::run(carrier::Case::SessionCapabilities).await;
}
