//! Original-pool dataset provenance for current-database custom model V2 operations.
//!
//! This binding reuses storage identity, never artifact or user authorization. Its
//! transaction can only come from the once-enrolled registry's original pool.

use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

use openbot_application::RunModelDatasetInitialOrigin;
use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::ids::{DeploymentId, TenantId};

use crate::artifact_registry::{ArtifactDatasetRegistry, ArtifactRegistryError};
use crate::db::pool::{DatabasePool, GuardedClient, GuardedTransaction, TransactionOwnerError};

/// Closed dataset failures. Transaction completion keeps its original owner type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModelDatasetError {
    /// The original pool, scope, schema, tuple or trusted producer does not match.
    #[error("model_dataset_invalid_binding")]
    InvalidBinding,
    /// The bounded actual observation could not complete.
    #[error("model_dataset_unavailable")]
    Unavailable,
}

struct OriginalRegistryEnrollment {
    registry: Weak<ArtifactDatasetRegistry>,
    owner: Weak<()>,
}

/// Once-enrolled current-database identity. It has no free dataset/transaction constructor.
pub struct PostgresModelDatasetBinding {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    enrollment: OnceLock<Result<OriginalRegistryEnrollment, ModelDatasetError>>,
}

impl core::fmt::Debug for PostgresModelDatasetBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgresModelDatasetBinding(<original-registry>)")
    }
}

impl PostgresModelDatasetBinding {
    pub(crate) fn unbound(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, ModelDatasetError> {
        if pool.is_closed()
            || !is_valid_artifact_identity(deployment.as_str())
            || !is_valid_artifact_identity(tenant.as_str())
        {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            enrollment: OnceLock::new(),
        })
    }

    /// Enroll the original trusted startup producer exactly once, including a failed first call.
    /// A failed or duplicate call must terminate the capability's host assembly.
    pub fn enroll_original_registry(
        &self,
        registry: &Arc<ArtifactDatasetRegistry>,
    ) -> Result<(), ModelDatasetError> {
        let result = if self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
            && registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            Ok(OriginalRegistryEnrollment {
                registry: Arc::downgrade(registry),
                owner: Arc::downgrade(&registry.owner()),
            })
        } else {
            Err(ModelDatasetError::InvalidBinding)
        };
        self.enrollment
            .set(result)
            .map_err(|_| ModelDatasetError::InvalidBinding)?;
        self.original_registry().map(|_| ())
    }

    /// Compare actual manager identity and both configured scopes, without granting authority.
    /// The original unbound Arc may be connected to consumers before host enrollment.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        self.matches_original_pool(pool) && &self.deployment == deployment && &self.tenant == tenant
    }

    pub(crate) fn matches_original_pool(&self, pool: &DatabasePool) -> bool {
        !self.pool.is_closed()
            && !pool.is_closed()
            && std::ptr::eq(self.pool.manager(), pool.manager())
    }

    fn original_registry(&self) -> Result<Arc<ArtifactDatasetRegistry>, ModelDatasetError> {
        let enrollment = self
            .enrollment
            .get()
            .ok_or(ModelDatasetError::InvalidBinding)?
            .as_ref()
            .map_err(|error| *error)?;
        let registry = enrollment
            .registry
            .upgrade()
            .ok_or(ModelDatasetError::InvalidBinding)?;
        let owner = enrollment
            .owner
            .upgrade()
            .ok_or(ModelDatasetError::InvalidBinding)?;
        if !registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
            || !self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
            || !Arc::ptr_eq(&owner, &registry.owner())
        {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(registry)
    }

    pub(crate) async fn checkout(
        &self,
        deadline: Instant,
    ) -> Result<ModelDatasetCheckout<'_>, ModelDatasetError> {
        let registry = self.original_registry()?;
        if Instant::now() >= deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        let client = registry
            .pool()
            .get_guarded(deadline)
            .await
            .map_err(|_| ModelDatasetError::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        // Recheck after the only checkout await; an ended/closed producer cannot grant a Tx.
        let current = self.original_registry()?;
        if !Arc::ptr_eq(&current, &registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(ModelDatasetCheckout {
            binding: self,
            registry,
            client,
            deadline,
        })
    }
}

pub(crate) struct ModelDatasetCheckout<'a> {
    binding: &'a PostgresModelDatasetBinding,
    registry: Arc<ArtifactDatasetRegistry>,
    client: GuardedClient,
    deadline: Instant,
}

impl core::fmt::Debug for ModelDatasetCheckout<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetCheckout(<original-owner>)")
    }
}

impl ModelDatasetCheckout<'_> {
    pub(crate) async fn begin_read_committed(
        &mut self,
    ) -> Result<ModelDatasetTransaction<'_>, TransactionOwnerError> {
        let transaction = self.client.begin_read_committed().await?;
        Ok(ModelDatasetTransaction {
            transaction,
            binding: self.binding,
            registry: &self.registry,
            deadline: self.deadline,
        })
    }
}

pub(crate) struct ModelDatasetTransaction<'a> {
    transaction: GuardedTransaction<'a>,
    binding: &'a PostgresModelDatasetBinding,
    registry: &'a ArtifactDatasetRegistry,
    deadline: Instant,
}

impl core::fmt::Debug for ModelDatasetTransaction<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetTransaction(<original-owner>)")
    }
}

impl<'a> ModelDatasetTransaction<'a> {
    pub(crate) fn as_transaction(&self) -> &tokio_postgres::Transaction<'a> {
        self.transaction.as_transaction()
    }

    pub(crate) async fn verify_current_dataset(
        &self,
    ) -> Result<ModelDatasetFacts, ModelDatasetError> {
        let current = self.binding.original_registry()?;
        if !std::ptr::eq(Arc::as_ptr(&current), self.registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        if Instant::now() >= self.deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.registry
                .verify_model_dataset_in_transaction(self.as_transaction()),
        )
        .await
        .map_err(|_| ModelDatasetError::Unavailable)?
        .map_err(|error| match error {
            ArtifactRegistryError::Unavailable => ModelDatasetError::Unavailable,
            _ => ModelDatasetError::InvalidBinding,
        })?;
        if Instant::now() >= self.deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        let current = self.binding.original_registry()?;
        if !std::ptr::eq(Arc::as_ptr(&current), self.registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        let binding = self.registry.binding();
        let initial_origin = match binding.initial_origin() {
            "desktop_canary" => RunModelDatasetInitialOrigin::DesktopCanary,
            "server_first_adoption" => RunModelDatasetInitialOrigin::ServerFirstAdoption,
            _ => return Err(ModelDatasetError::InvalidBinding),
        };
        Ok(ModelDatasetFacts {
            deployment: self.binding.deployment.clone(),
            tenant: self.binding.tenant.clone(),
            dataset_id: binding.dataset_id().to_owned(),
            binding_schema: binding.binding_schema(),
            initial_origin,
            created_at: binding.created_at(),
        })
    }

    pub(crate) async fn commit(self) -> Result<(), TransactionOwnerError> {
        self.transaction.commit().await
    }

    pub(crate) async fn rollback(self) -> Result<(), TransactionOwnerError> {
        self.transaction.rollback().await
    }
}

pub(crate) struct ModelDatasetFacts {
    deployment: DeploymentId,
    tenant: TenantId,
    dataset_id: String,
    binding_schema: i16,
    initial_origin: RunModelDatasetInitialOrigin,
    created_at: time::OffsetDateTime,
}

impl core::fmt::Debug for ModelDatasetFacts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetFacts(<verified-original-tuple>)")
    }
}

impl ModelDatasetFacts {
    pub(crate) fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }
    pub(crate) fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub(crate) fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub(crate) fn binding_schema(&self) -> i16 {
        self.binding_schema
    }
    pub(crate) fn initial_origin(&self) -> RunModelDatasetInitialOrigin {
        self.initial_origin
    }
    pub(crate) fn created_at(&self) -> time::OffsetDateTime {
        self.created_at
    }
}
