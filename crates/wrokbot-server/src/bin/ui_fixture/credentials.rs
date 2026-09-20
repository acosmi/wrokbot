//! The credential UI fixture uses the production PostgreSQL/Vault port when the explicit isolated
//! PG fixture mode is enabled. Memory mode remains unavailable instead of pretending to save keys.

use wrokbot_application::credential_admin::{CredentialAdministration, NoCredentialAdministration};
use wrokbot_contracts::ids::{DeploymentId, TenantId};
use wrokbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use wrokbot_infra::credential_admin::PostgresCredentialAdministration;
use wrokbot_infra::mcp::SafeRmcpClient;
use wrokbot_infra::mcp_catalog::PostgresMcpCatalog;
use wrokbot_infra::mcp_connections::PostgresMcpConnections;
use wrokbot_infra::mcp_oauth::McpOAuthClient;
use wrokbot_infra::net::safe_http::{EgressPolicy, SafeDialer, SchemePolicy};
use wrokbot_infra::vault::CredentialRecordVault;
use std::sync::Arc;

pub(super) fn assemble(
    probe: Option<&super::PostgresApprovalProbe>,
) -> Result<Arc<dyn CredentialAdministration>, Box<dyn std::error::Error>> {
    let Some(probe) = probe else {
        return Ok(Arc::new(NoCredentialAdministration));
    };
    let pool = probe.pool.clone();
    let vault = CredentialRecordVault::single_key(
        TenantId::new(super::FIXTURE_TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x65; 32])?,
    );
    let catalog = Arc::new(PostgresMcpCatalog::new(
        pool.clone(),
        SafeRmcpClient::new(
            SafeDialer::new(EgressPolicy::default()),
            SchemePolicy::HttpsOnly,
            None,
        ),
        super::FIXTURE_APPROVAL_AUDIT_KEY.to_vec(),
    )?);
    let mcp = Arc::new(PostgresMcpConnections::new(
        pool.clone(),
        vault.clone(),
        McpOAuthClient::new(
            SafeDialer::new(EgressPolicy::default()),
            SchemePolicy::HttpsOnly,
        ),
        catalog,
        DeploymentId::new(super::FIXTURE_DEPLOYMENT),
        TenantId::new(super::FIXTURE_TENANT),
        vec![0x67; 32],
        super::FIXTURE_APPROVAL_AUDIT_KEY.to_vec(),
        None,
        None,
        SchemePolicy::HttpsOnly,
    )?);
    Ok(Arc::new(
        PostgresCredentialAdministration::new(
            pool,
            vault,
            DeploymentId::new(super::FIXTURE_DEPLOYMENT),
            TenantId::new(super::FIXTURE_TENANT),
            SecretBytes::new(super::FIXTURE_APPROVAL_AUDIT_KEY.to_vec()),
            mcp,
        )?
        .with_model_reference("openai".to_owned(), "fixture-default-model".to_owned())?,
    ))
}
