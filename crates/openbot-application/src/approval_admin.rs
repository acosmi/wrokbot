//! Application-owned human tool-approval administration.

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::tool::{PendingToolApprovals, ToolApprovalDecision, ToolApprovalResolved};

use crate::service::AppEventStream;

/// Stable approval administration failure without argument summaries or database text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolApprovalAdministrationError {
    /// Approval is absent, resolved, expired or belongs to another actor/scope.
    #[error("tool_approval_not_visible")]
    NotVisible,
    /// Closed input failed validation.
    #[error("tool_approval_invalid_input field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// A concurrent decision or expiry won.
    #[error("tool_approval_conflict")]
    Conflict,
    /// PostgreSQL/runtime dependency unavailable.
    #[error("tool_approval_unavailable")]
    Unavailable,
    /// Stored row violates the closed schema.
    #[error("tool_approval_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Decision commit may have succeeded; caller must refresh pending state.
    #[error("tool_approval_commit_unknown")]
    CommitUnknown,
}

impl ToolApprovalAdministrationError {
    /// Stable application mapping.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::NotVisible => AppError::NotVisible,
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Conflict => AppError::RequestConflict {
                resource: "tool_approval",
            },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "tool_approval",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Typed production port shared by Axum, Desktop in-process and future Leptos actions.
#[async_trait]
pub trait ToolApprovalAdministration: Send + Sync {
    /// List current actor's unexpired pending requests, oldest first.
    async fn list_pending(
        &self,
        auth: &AuthContext,
    ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError>;

    /// Resolve exactly one current actor-owned pending request.
    async fn decide(
        &self,
        auth: &AuthContext,
        approval_id: &str,
        decision: ToolApprovalDecision,
    ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError>;

    /// Subscribe to actor-scoped refresh hints. Implementations must derive every hint from the
    /// same durable list projection and terminate on revocation/dependency failure.
    async fn subscribe_activity(
        &self,
        _auth: &AuthContext,
    ) -> Result<AppEventStream, ToolApprovalAdministrationError> {
        Err(ToolApprovalAdministrationError::Unavailable)
    }
}

/// Fail-closed default when no production coordinator is assembled.
#[derive(Debug, Default)]
pub struct NoToolApprovalAdministration;

#[async_trait]
impl ToolApprovalAdministration for NoToolApprovalAdministration {
    async fn list_pending(
        &self,
        _auth: &AuthContext,
    ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError> {
        Err(ToolApprovalAdministrationError::Unavailable)
    }

    async fn decide(
        &self,
        _auth: &AuthContext,
        _approval_id: &str,
        _decision: ToolApprovalDecision,
    ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError> {
        Err(ToolApprovalAdministrationError::Unavailable)
    }
}

/// Application use case: list actor-owned pending approvals.
pub async fn list_pending_tool_approvals(
    port: &dyn ToolApprovalAdministration,
    auth: &AuthContext,
) -> Result<PendingToolApprovals, AppError> {
    port.list_pending(auth)
        .await
        .map_err(ToolApprovalAdministrationError::into_app_error)
}

/// Application use case: grant/deny one exact stored binding.
pub async fn decide_tool_approval(
    port: &dyn ToolApprovalAdministration,
    auth: &AuthContext,
    approval_id: &str,
    decision: ToolApprovalDecision,
) -> Result<ToolApprovalResolved, AppError> {
    if approval_id.is_empty() || approval_id.len() > 128 || approval_id.as_bytes().contains(&0) {
        return Err(AppError::MalformedPayload {
            field: "approvalId",
        });
    }
    port.decide(auth, approval_id, decision)
        .await
        .map_err(ToolApprovalAdministrationError::into_app_error)
}

/// Application use case: subscribe to actor-owned approval refresh hints.
pub async fn subscribe_tool_approval_activity(
    port: &dyn ToolApprovalAdministration,
    auth: &AuthContext,
) -> Result<AppEventStream, AppError> {
    port.subscribe_activity(auth)
        .await
        .map_err(ToolApprovalAdministrationError::into_app_error)
}
