use std::sync::Arc;

use async_trait::async_trait;
use wrokbot_contracts::auth::AuthContext;
use wrokbot_contracts::ids::{DeploymentId, TenantId};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::gateway_transport::{
    GatewayFenceError, GatewayHttpAuthority, GatewayHttpPermit, GatewayRequestDescriptor,
    GatewayRequestKind,
};

use super::GatewayAuthorityError;
use super::store::{self, DetachedSession};
use super::strict::AuthorityInner;

pub(super) struct EnrollmentFence {
    pool: deadpool_postgres::Pool,
    auth: AuthContext,
    deployment: DeploymentId,
    tenant: TenantId,
    deadline: Instant,
}

impl EnrollmentFence {
    pub(super) fn new(
        pool: deadpool_postgres::Pool,
        auth: AuthContext,
        deployment: DeploymentId,
        tenant: TenantId,
        deadline: Instant,
    ) -> Self {
        Self {
            pool,
            auth,
            deployment,
            tenant,
            deadline,
        }
    }
}

struct Permit {
    session: Arc<DetachedSession>,
    cancel: CancellationToken,
    deadline: Instant,
    close: bool,
    released: bool,
}

#[async_trait]
impl GatewayHttpPermit for Permit {
    async fn release_after_headers(mut self: Box<Self>) -> Result<(), GatewayFenceError> {
        let result = self.session.rollback(&self.cancel, self.deadline).await;
        if self.close || result.is_err() {
            self.session.schedule_close();
        }
        self.released = true;
        result.map_err(|_| GatewayFenceError::CleanupUnknown)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if !self.released {
            self.session.schedule_close();
        }
    }
}

fn map(error: GatewayAuthorityError) -> GatewayFenceError {
    match error {
        GatewayAuthorityError::NotVisible
        | GatewayAuthorityError::Conflict
        | GatewayAuthorityError::InvalidInput => GatewayFenceError::Refused,
        GatewayAuthorityError::ReconciliationRequired
        | GatewayAuthorityError::CommitUnknown
        | GatewayAuthorityError::Corrupt => GatewayFenceError::CleanupUnknown,
        _ => GatewayFenceError::Unavailable,
    }
}

#[async_trait]
impl GatewayHttpAuthority for EnrollmentFence {
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        cancel: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        if !matches!(
            request.kind(),
            GatewayRequestKind::OAuthDiscovery | GatewayRequestKind::AccountProfile
        ) || request.streaming()
            || self.auth.deployment() != &self.deployment
            || self.auth.tenant() != &self.tenant
        {
            return Err(GatewayFenceError::Refused);
        }
        let session = DetachedSession::acquire(&self.pool, &cancel, self.deadline)
            .await
            .map_err(map)?;
        session.begin(&cancel, self.deadline).await.map_err(map)?;
        session
            .verify_actor(&self.auth, &cancel, self.deadline, true)
            .await
            .map_err(map)?;
        Ok(Box::new(Permit {
            session,
            cancel,
            deadline: self.deadline,
            close: true,
            released: false,
        }))
    }
}

#[async_trait]
impl GatewayHttpAuthority for AuthorityInner {
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        cancel: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        if request.streaming() || request.kind() == GatewayRequestKind::Model {
            return Err(GatewayFenceError::Refused);
        }
        if matches!(
            request.kind(),
            GatewayRequestKind::OAuthRegistration | GatewayRequestKind::OAuthRevocation
        ) {
            return Err(GatewayFenceError::Refused);
        }

        let (session, operation_id, close) = match self.active_session() {
            Some(active) => (active.session, active.operation_id, false),
            None if request.kind() == GatewayRequestKind::Catalogue => (
                DetachedSession::acquire(&self.pool, &cancel, self.scope.deadline)
                    .await
                    .map_err(map)?,
                None,
                true,
            ),
            None => return Err(GatewayFenceError::Refused),
        };

        if request.kind() == GatewayRequestKind::OAuthToken {
            let operation_id = operation_id.ok_or(GatewayFenceError::Refused)?;
            store::admit_token_send(&session, &self.scope, operation_id, self.audit_key.expose())
                .await
                .map_err(map)?;
            self.mark_token_admitted(operation_id).map_err(map)?;
        } else if request.kind() == GatewayRequestKind::AccountProfile && operation_id.is_none() {
            return Err(GatewayFenceError::Refused);
        }

        session
            .begin(&cancel, self.scope.deadline)
            .await
            .map_err(map)?;
        let connection = store::load_connection(&session, &self.scope, false)
            .await
            .map_err(map)?;
        match request.kind() {
            GatewayRequestKind::Catalogue if connection.state != "ready" => {
                return Err(GatewayFenceError::Refused);
            }
            GatewayRequestKind::Catalogue => {
                let secret = connection
                    .current_secret_id
                    .ok_or(GatewayFenceError::CleanupUnknown)?;
                store::load_secret(
                    &session,
                    &self.scope,
                    secret,
                    connection.credential_generation,
                )
                .await
                .map_err(map)?;
            }
            GatewayRequestKind::OAuthToken
            | GatewayRequestKind::OAuthDiscovery
            | GatewayRequestKind::AccountProfile => {
                let operation_id = operation_id.ok_or(GatewayFenceError::Refused)?;
                let operation = store::load_operation(&session, &self.scope, operation_id, false)
                    .await
                    .map_err(map)?;
                if !matches!(operation.state.as_str(), "pending" | "staged") {
                    return Err(GatewayFenceError::Refused);
                }
                if request.kind() == GatewayRequestKind::AccountProfile
                    && operation.token_admitted_at.is_none()
                {
                    return Err(GatewayFenceError::Refused);
                }
            }
            _ => return Err(GatewayFenceError::Refused),
        }
        Ok(Box::new(Permit {
            session,
            cancel,
            deadline: self.scope.deadline,
            close,
            released: false,
        }))
    }
}
