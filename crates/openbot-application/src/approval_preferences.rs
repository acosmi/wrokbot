//! Internal remember approval-preference persistence port.
//!
//! A preference is additional policy input. Reading or saving it does not authorize a remember
//! effect, supply an original operation receipt, or enable a public command or host route.

use async_trait::async_trait;
use openbot_contracts::approval_preferences::{
    RememberPreference, RememberPreferenceState, RememberPreferenceTarget, StoredRememberPreference,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::{AppError, StaleGenerationSubject};
use openbot_contracts::ids::BotId;
use openbot_contracts::revision::RevisionSnapshot;

/// Closed internal persistence failures without database text, target text or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RememberPreferenceRepositoryError {
    /// A trusted typed input failed its closed identity or positive-revision validation.
    #[error("remember_preference_invalid_input field={field}")]
    InvalidInput {
        /// Static field identifier, never the supplied value.
        field: &'static str,
    },
    /// The current original actor/host/target is unavailable to this caller, or the row is absent.
    #[error("remember_preference_not_visible")]
    NotVisible,
    /// The original expected revision lost; this is the real current committed row snapshot.
    #[error("remember_preference_revision_conflict")]
    Conflict {
        /// Existing closed three-field revision snapshot, without a preference or target payload.
        snapshot: RevisionSnapshot,
    },
    /// A dependency, lock, deadline, retirement or stored revision cannot support this request.
    #[error("remember_preference_unavailable")]
    Unavailable,
    /// A stored row violates the closed schema and must not be represented as absent.
    #[error("remember_preference_corrupt field={field}")]
    Corrupt {
        /// Static column identifier only.
        field: &'static str,
    },
    /// The original COMMIT was entered without a definite acknowledgement; never retry the write.
    #[error("remember_preference_commit_unknown")]
    CommitUnknown,
    /// The original COMMIT acknowledged after the absolute deadline; the write is definite.
    #[error("remember_preference_commit_acknowledged_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    /// The original ROLLBACK acknowledged after the absolute deadline; no timely result is valid.
    #[error("remember_preference_rollback_acknowledged_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

impl RememberPreferenceRepositoryError {
    /// Preserve the existing closed transport errors without exposing stored target details.
    ///
    /// A conflict uses the current authorized three-field revision snapshot. Commit uncertainty
    /// remains a dependency failure; the internal caller still retains `CommitUnknown` and must
    /// never replay the original write on the strength of a later row observation.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::Conflict { snapshot } => AppError::StaleGeneration {
                subject: StaleGenerationSubject::Configuration { snapshot },
            },
            Self::Unavailable
            | Self::Corrupt { .. }
            | Self::CommitUnknown
            | Self::CommitAcknowledgedAfterDeadline
            | Self::RollbackAcknowledgedAfterDeadline => AppError::DependencyUnavailable {
                dependency: "remember_preference",
            },
        }
    }
}

/// Internal non-Serde port for the same-Pool current-authority preference transaction.
///
/// Each entry starts one absolute five-second budget. Implementations acquire their own original
/// connection and transaction, verify the actual attached host and full actor/Bot/Thread scope,
/// and close through the original COMMIT or ROLLBACK acknowledgement. Callers cannot supply a
/// transaction or derive authorization from a stored preference.
#[async_trait]
pub trait RememberPreferenceRepository: Send + Sync {
    /// Observe current state; absent means Ask with no inserted row, ID, revision or audit event.
    async fn read(
        &self,
        auth: &AuthContext,
        bot: &BotId,
        target: RememberPreferenceTarget,
    ) -> Result<RememberPreferenceState, RememberPreferenceRepositoryError>;

    /// Create revision one only for `None`, or match a positive existing revision and advance it.
    ///
    /// Saving the same preference still advances the revision. `None` on an existing row and a
    /// stale positive revision return the current snapshot; a positive revision on an absent row
    /// returns NotVisible. Nonpositive expected values fail before any write. Business mutation
    /// and its typed configuration audit event share the original transaction.
    async fn write(
        &self,
        auth: &AuthContext,
        bot: &BotId,
        target: RememberPreferenceTarget,
        preference: RememberPreference,
        expected_revision: Option<i64>,
    ) -> Result<StoredRememberPreference, RememberPreferenceRepositoryError>;
}
