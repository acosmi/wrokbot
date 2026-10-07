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

/// Producer port for sequential blocks bound to one original authenticated host operation.
#[async_trait]
pub trait ArtifactReadOperation: Send {
    /// Admit and observe the next original block; its pending owner retains the in-flight slot.
    async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError>;
    /// Permanently stop this original operation; actual resource disposal remains producer-owned.
    fn close(&mut self);
}

/// Application-owned operation enforcing the original six auth facts and exact host binding.
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
                    HostRequestBindingKind::ServerSession
                        | HostRequestBindingKind::ServerSingleUserOwner
                        | HostRequestBindingKind::DesktopWindow
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
    /// Check the original binding and request the next block; cancelling this waiter closes the port.
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
    /// Permanently close this application operation and signal its actual producer to stop.
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

/// Pending original allocation and lease retained through current observation and synchronous handoff.
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
    /// Actual already-read prefix length; it grants no access to the pending bytes.
    pub fn prefix_length(&self) -> Result<usize, AppError> {
        self.pending
            .as_ref()
            .and_then(PendingArtifactReadBuffer::actual_length)
            .ok_or_else(artifacts_unavailable)
    }
    pub(crate) fn current_target(&self) -> Arc<dyn ArtifactReadCurrentTarget> {
        Arc::clone(&self.target)
    }
    /// Refresh the original current joint while retaining this exact pending allocation.
    /// A delayed client never renews the immutable reader lifetime.
    pub async fn refresh_current_before(
        &mut self,
        auth: &AuthContext,
        original_handle_deadline: Instant,
    ) -> Result<(), AppError> {
        if auth != &self.auth {
            return Err(AppError::Unauthenticated);
        }
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or_else(artifacts_unavailable)?
            .min(original_handle_deadline);
        let witness = self
            .original
            .as_ref()
            .ok_or_else(host_unavailable)?
            .verify_artifact_read_current_before(auth, self.target.as_ref(), deadline)
            .await?;
        self.witness = witness;
        self.deadline = deadline;
        self.verify_current(auth)
    }
    /// Transfer the same full allocation while keeping its actual current-tail context.
    /// Empty actual EOF retains the context until its real operation has closed.
    pub fn handoff_frame(
        mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadFrame, AppError> {
        self.verify_current(auth)?;
        let original = self.original.as_ref().ok_or_else(host_unavailable)?;
        let pending = self.pending.take().ok_or_else(artifacts_unavailable)?;
        let lease = self.lease.take().ok_or_else(artifacts_unavailable)?;
        let bytes = pending.handoff_leased(
            auth,
            original,
            self.target.as_ref(),
            self.witness.as_ref(),
            self.deadline,
            lease,
        )?;
        Ok(CurrentArtifactReadFrame {
            bytes,
            current: self,
        })
    }
    /// Recheck the current tail and transfer the original leased prefix; verified empty EOF returns None.
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

/// Non-Clone original allocation plus the real retained FD/host/clock tail.
/// Transport ownership never turns the serialized block descriptor into a grant.
pub struct CurrentArtifactReadFrame {
    bytes: LeasedArtifactReadBlock,
    current: CurrentArtifactReadBlock,
}
impl CurrentArtifactReadFrame {
    /// Borrow only the already-observed prefix; the full initialized allocation stays owned.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
    /// Report the actual prefix length without changing ownership.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Report a real zero prefix; a short nonzero block is not EOF.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Last synchronous original binding, physical FD, window and clock check.
    pub fn verify_current_tail(&self, auth: &AuthContext) -> Result<(), AppError> {
        self.current.verify_current(auth)
    }
    /// Actually release/wipe the original allocation before retaining a no-byte control tail.
    pub fn into_control_tail(self) -> CurrentArtifactReadControlTail {
        let Self { bytes, current } = self;
        drop(bytes);
        CurrentArtifactReadControlTail { current }
    }
}

/// Actual retained host witness for control after resources close; no physical byte authority.
pub struct CurrentArtifactReadControlTail {
    current: CurrentArtifactReadBlock,
}
impl CurrentArtifactReadControlTail {
    /// Observe the actual original joint before releasing the physical reader.
    /// The caller's immutable control budget is never extended by this observation.
    pub async fn observe_current_before(
        auth: &AuthContext,
        target: Arc<dyn ArtifactReadCurrentTarget>,
        original_deadline: Instant,
    ) -> Result<Self, AppError> {
        let original = auth
            .request_binding()
            .cloned()
            .ok_or_else(host_unavailable)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or_else(artifacts_unavailable)?
            .min(original_deadline);
        let witness = original
            .verify_artifact_read_current_before(auth, target.as_ref(), deadline)
            .await?;
        let control = Self {
            current: CurrentArtifactReadBlock {
                pending: None,
                lease: None,
                original: Some(original),
                auth: auth.clone(),
                target,
                witness,
                deadline,
            },
        };
        control.verify_current_tail(auth)?;
        Ok(control)
    }
    /// Recheck the same genuine host/window/clock after a true per-reader close await.
    /// The original FD can already be closed; this method grants no bytes.
    pub fn verify_current_tail(&self, auth: &AuthContext) -> Result<(), AppError> {
        if auth != &self.current.auth {
            return Err(AppError::Unauthenticated);
        }
        self.current
            .original
            .as_ref()
            .ok_or_else(host_unavailable)?
            .verify_artifact_read_control_tail(
                auth,
                self.current.witness.as_ref(),
                self.current.deadline,
            )
            .map_err(AppError::from)
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
