//! Remote Agent callback-token administration use case and outbound port.

use async_trait::async_trait;
use openbot_contracts::agent::{CallbackTokenIssued, CallbackTokenRevoked};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;
use openbot_contracts::ids::{RunId, ThreadId};
use serde_json::Value;

/// Durable callback-token administration failure with no database or secret text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentCallbackTokenError {
    /// Database, CSPRNG, or audit chain unavailable.
    #[error("agent_callback_token_unavailable")]
    Unavailable,
    /// Stored Agent/profile state is corrupt.
    #[error("agent_callback_token_corrupt field={field}")]
    Corrupt {
        /// Static field name only.
        field: &'static str,
    },
    /// Missing, deleted, wrong-type, cross-tenant, or unmanageable Agent; unified as 404.
    #[error("agent_callback_token_not_visible")]
    NotVisible,
    /// Commit result is unknown; retrying issue safely rotates again, but this response has no token.
    #[error("agent_callback_token_commit_unknown")]
    CommitUnknown,
}

impl AgentCallbackTokenError {
    /// Stable public error projection.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "agent_callback_tokens",
            },
            Self::NotVisible => AppError::NotVisible,
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Application-owned administration port; implementation must update hash and append audit in one
/// PostgreSQL transaction. Cleartext may leave it only in the issue return value.
#[async_trait]
pub trait AgentCallbackTokenAdministration: Send + Sync {
    /// Issue or rotate one remote Agent token.
    async fn issue(
        &self,
        auth: &AuthContext,
        agent: &BotId,
    ) -> Result<CallbackTokenIssued, AgentCallbackTokenError>;

    /// Revoke one remote Agent token.
    async fn revoke(
        &self,
        auth: &AuthContext,
        agent: &BotId,
    ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError>;
}

/// Explicit fail-closed placeholder until a production adapter is injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAgentCallbackTokenAdministration;

#[async_trait]
impl AgentCallbackTokenAdministration for NoAgentCallbackTokenAdministration {
    async fn issue(
        &self,
        _auth: &AuthContext,
        _agent: &BotId,
    ) -> Result<CallbackTokenIssued, AgentCallbackTokenError> {
        Err(AgentCallbackTokenError::Unavailable)
    }

    async fn revoke(
        &self,
        _auth: &AuthContext,
        _agent: &BotId,
    ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError> {
        Err(AgentCallbackTokenError::Unavailable)
    }
}

/// Issue/rotate via the unique typed application boundary.
pub async fn issue_agent_callback_token<A: AgentCallbackTokenAdministration>(
    administration: &A,
    auth: &AuthContext,
    agent: &BotId,
) -> Result<CallbackTokenIssued, AppError> {
    administration
        .issue(auth, agent)
        .await
        .map_err(AgentCallbackTokenError::into_app_error)
}

/// Revoke via the unique typed application boundary.
pub async fn revoke_agent_callback_token<A: AgentCallbackTokenAdministration>(
    administration: &A,
    auth: &AuthContext,
    agent: &BotId,
) -> Result<CallbackTokenRevoked, AppError> {
    administration
        .revoke(auth, agent)
        .await
        .map_err(AgentCallbackTokenError::into_app_error)
}

/// Verified remote callback identity. It cannot be deserialized and carries no presented secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteCallbackAuthorization {
    auth: AuthContext,
    run: RunId,
    thread: ThreadId,
    bot: BotId,
}

impl RemoteCallbackAuthorization {
    /// Construct only in an authenticator after token/assertion/run/tool verification.
    #[must_use]
    pub fn new(auth: AuthContext, run: RunId, thread: ThreadId, bot: BotId) -> Self {
        Self {
            auth,
            run,
            thread,
            bot,
        }
    }

    /// Fresh authority reconstructed from PostgreSQL.
    #[must_use]
    pub const fn auth(&self) -> &AuthContext {
        &self.auth
    }

    /// Verified active run.
    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// Verified active thread.
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Token owner and assertion Bot, proven equal.
    #[must_use]
    pub const fn bot(&self) -> &BotId {
        &self.bot
    }
}

/// Remote callback credential/grant decision failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteCallbackAuthError {
    /// Token or assertion invalid; both halves deliberately share one answer.
    #[error("remote_callback_unauthenticated")]
    Unauthenticated,
    /// A valid token belongs to a different Bot than the signed assertion.
    #[error("remote_callback_bot_mismatch")]
    BotMismatch,
    /// Requested tool was not in the signed current grant set.
    #[error("remote_callback_tool_not_visible")]
    ToolNotVisible,
    /// Credential pair is valid but the callback tool name/arguments shape is malformed.
    #[error("remote_callback_input_invalid field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// PostgreSQL/audit/signing dependency unavailable.
    #[error("remote_callback_unavailable")]
    Unavailable,
    /// Stored state violates the closed schema.
    #[error("remote_callback_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
}

impl RemoteCallbackAuthError {
    /// Stable public mapping. Bot mismatch preserves the upstream 403 without inventing a role.
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        match self {
            Self::Unauthenticated => AppError::Unauthenticated,
            Self::BotMismatch => AppError::PolicyRefused {
                rule: "callback_token_bot_mismatch".to_owned(),
                decision: None,
            },
            Self::ToolNotVisible => AppError::NotVisible,
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "remote_callback_auth",
            },
        }
    }
}

/// Machine-to-machine auth port, analogous to HTTP session `AuthResolver` but bound to a run/tool.
#[async_trait]
pub trait RemoteCallbackAuthenticator: Send + Sync {
    /// Verify both credentials, active DB scope, and exact current tool set. `run` remains an
    /// untrusted JSON value so missing/null/non-string assertions all receive the same 401.
    async fn authorize(
        &self,
        presented_token: &str,
        run: &Value,
        requested_tool: &str,
    ) -> Result<RemoteCallbackAuthorization, RemoteCallbackAuthError>;
}
