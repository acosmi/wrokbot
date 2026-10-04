//! Rust-only original-host operation; each accepted block has its own current observation.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use openbot_contracts::artifact_read::{
    ArtifactReadAllocationLease, LeasedArtifactReadBlock, PendingArtifactReadBuffer,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    ArtifactReadCurrentTarget, ArtifactReadTailWitness, HostRequestBindingKind,
    VerifiedHostRequestBinding,
};

#[async_trait]
pub trait ArtifactReadOperation: Send {
    async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError>;
    fn close(&mut self);
}

pub struct CurrentArtifactReadOperation {
    auth: AuthContext,
    original: VerifiedHostRequestBinding,
    port: Box<dyn ArtifactReadOperation>,
    closed: bool,
}
impl CurrentArtifactReadOperation {
    #[doc(hidden)]
    pub fn from_trusted_operation(
        auth: AuthContext,
        mut port: Box<dyn ArtifactReadOperation>,
    ) -> Result<Self, AppError> {
        let original = match auth.request_binding().cloned() {
            Some(binding)
                if matches!(
                    binding.kind(),
                    HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
                ) =>
            {
                binding
            }
            _ => {
                port.close();
                return Err(host_unavailable());
            }
        };
        Ok(Self {
            auth,
            original,
            port,
            closed: false,
        })
    }
    pub async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError> {
        if self.closed {
            return Err(artifacts_unavailable());
        }
        if auth != &self.auth
            || !auth
                .request_binding()
                .is_some_and(|current| self.original.identity().same_binding(current.identity()))
        {
            self.close();
            return Err(AppError::Unauthenticated);
        }
        // An admission refusal while an original lease is held is not an accepted IO failure.
        // The actual producer controls terminal failures; cancellation always closes this port.
        let mut attempt = Attempt {
            port: self.port.as_mut(),
            completed: false,
        };
        let result = attempt.port.next_block(auth).await;
        attempt.completed = true;
        result
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.port.close();
    }
}
impl Drop for CurrentArtifactReadOperation {
    fn drop(&mut self) {
        self.close();
    }
}
struct Attempt<'a> {
    port: &'a mut dyn ArtifactReadOperation,
    completed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.port.close();
        }
    }
}

pub struct CurrentArtifactReadBlock {
    pending: Option<PendingArtifactReadBuffer>,
    lease: Option<Box<dyn ArtifactReadAllocationLease>>,
    original: Option<VerifiedHostRequestBinding>,
    auth: AuthContext,
    target: Arc<dyn ArtifactReadCurrentTarget>,
    witness: Box<dyn ArtifactReadTailWitness>,
    deadline: Instant,
}
impl CurrentArtifactReadBlock {
    #[doc(hidden)]
    pub fn from_trusted_observation(
        pending: PendingArtifactReadBuffer,
        auth: AuthContext,
        target: Arc<dyn ArtifactReadCurrentTarget>,
        witness: Box<dyn ArtifactReadTailWitness>,
        deadline: Instant,
        lease: Box<dyn ArtifactReadAllocationLease>,
    ) -> Result<Self, AppError> {
        // Coupled ownership precedes every fallible validation, including missing binding.
        let mut block = Self {
            pending: Some(pending),
            lease: Some(lease),
            original: None,
            auth,
            target,
            witness,
            deadline,
        };
        block.original = Some(
            block
                .auth
                .request_binding()
                .cloned()
                .ok_or_else(host_unavailable)?,
        );
        if block
            .pending
            .as_ref()
            .and_then(PendingArtifactReadBuffer::actual_length)
            .is_none()
        {
            return Err(artifacts_unavailable());
        }
        block.verify_current(&block.auth)?;
        Ok(block)
    }
    fn verify_current(&self, auth: &AuthContext) -> Result<(), AppError> {
        if auth != &self.auth {
            return Err(AppError::Unauthenticated);
        }
        self.original
            .as_ref()
            .ok_or_else(host_unavailable)?
            .verify_artifact_read_tail(
                auth,
                self.target.as_ref(),
                self.witness.as_ref(),
                self.deadline,
            )
            .map_err(AppError::from)
    }
    pub fn handoff(
        mut self,
        auth: &AuthContext,
    ) -> Result<Option<LeasedArtifactReadBlock>, AppError> {
        self.verify_current(auth)?;
        let original = self.original.as_ref().ok_or_else(host_unavailable)?;
        let pending = self.pending.take().ok_or_else(artifacts_unavailable)?;
        let lease = self.lease.take().ok_or_else(artifacts_unavailable)?;
        let block = pending.handoff_leased(
            auth,
            original,
            self.target.as_ref(),
            self.witness.as_ref(),
            self.deadline,
            lease,
        )?;
        if block.is_empty() {
            drop(block);
            Ok(None)
        } else {
            Ok(Some(block))
        }
    }
}
impl Drop for CurrentArtifactReadBlock {
    fn drop(&mut self) {
        if let Some(pending) = &mut self.pending {
            pending.wipe();
        }
        drop(self.pending.take());
        drop(self.lease.take());
    }
}
const fn host_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "host_request_binding",
    }
}
const fn artifacts_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifacts",
    }
}

#[cfg(test)]
#[path = "artifact_read_lifecycle_tests.rs"]
mod tests;
