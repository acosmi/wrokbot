//! Authenticated ScreenSession ticket issuance through the single ApplicationService boundary.

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::screen::{ScreenSessionRequest, ScreenSessionTicket};

/// Stable Computer-port failures without ticket, origin, actor, or stream values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScreenSessionAdministrationError {
    /// Closed request/binding validation failed.
    #[error("screen_session_invalid field={field}")]
    InvalidInput {
        /// Static field name only.
        field: &'static str,
    },
    /// The exact target is absent or invisible under current authority.
    #[error("screen_session_not_visible")]
    NotVisible,
    /// Active viewers plus pending tickets reached the configured cap.
    #[error("screen_session_viewer_limit")]
    ViewerLimit,
    /// CSPRNG, clock, or ScreenHub authority is unavailable.
    #[error("screen_session_unavailable")]
    Unavailable,
}

impl ScreenSessionAdministrationError {
    /// Stable public application mapping.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::ViewerLimit => AppError::RequestConflict {
                resource: "screen_viewers",
            },
            Self::Unavailable => AppError::DependencyUnavailable {
                dependency: "screen_sessions",
            },
        }
    }
}

/// Screen ticket authority implemented by `openbot-computer` and shared by Server/Desktop.
#[async_trait]
pub trait ScreenSessionAdministration: Send + Sync {
    /// Resolve the exact target under current auth and issue one host-bound ticket.
    async fn issue(
        &self,
        auth: &AuthContext,
        request: ScreenSessionRequest,
    ) -> Result<ScreenSessionTicket, ScreenSessionAdministrationError>;
}

/// Fail-closed default until a Computer authority is explicitly injected.
#[derive(Debug, Default)]
pub struct NoScreenSessionAdministration;

#[async_trait]
impl ScreenSessionAdministration for NoScreenSessionAdministration {
    async fn issue(
        &self,
        _auth: &AuthContext,
        _request: ScreenSessionRequest,
    ) -> Result<ScreenSessionTicket, ScreenSessionAdministrationError> {
        Err(ScreenSessionAdministrationError::Unavailable)
    }
}

/// Issue an actor-scoped ScreenSession ticket without moving authority into transport.
pub async fn issue_screen_session(
    port: &dyn ScreenSessionAdministration,
    auth: &AuthContext,
    request: ScreenSessionRequest,
) -> Result<ScreenSessionTicket, AppError> {
    port.issue(auth, request)
        .await
        .map_err(ScreenSessionAdministrationError::into_app_error)
}
