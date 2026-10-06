//! Original 074/075 producers through one real PostgreSQL Application and both host carriers.

#[path = "support/reconciliation_producer_application_carrier.rs"]
mod carrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP024 PostgreSQL fixture and exact source metadata"]
async fn producer_journal_074_http_desktop_facts() {
    carrier::run(carrier::Case::JournalFacts).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP024 PostgreSQL fixture and exact source metadata"]
async fn producer_remember_075_http_desktop_receipt() {
    carrier::run(carrier::Case::RememberReceipt).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP024 PostgreSQL fixture and exact source metadata"]
async fn producer_receipt_pagination_readonly() {
    carrier::run(carrier::Case::Pagination).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Root-owned COMP024 PostgreSQL fixture and exact source metadata"]
async fn producer_current_authority_owner_isolation() {
    carrier::run(carrier::Case::CurrentAuthority).await;
}
