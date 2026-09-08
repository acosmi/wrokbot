//! Application-owned authenticated UI preference use cases.

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::ui::{UiPreferences, UpdateUiPreferences};

/// Stable storage failure without database text or actor identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UiPreferenceAdministrationError {
    /// Closed input failed validation.
    #[error("ui_preferences_invalid_input field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// PostgreSQL/local settings dependency is unavailable.
    #[error("ui_preferences_unavailable")]
    Unavailable,
    /// Stored data violates the closed theme/locale domain.
    #[error("ui_preferences_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// The commit result is unknown and the caller must re-read.
    #[error("ui_preferences_commit_unknown")]
    CommitUnknown,
}

impl UiPreferenceAdministrationError {
    /// Stable application error mapping.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "ui_preferences",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Shared Server/Desktop preference storage port.
#[async_trait]
pub trait UiPreferenceAdministration: Send + Sync {
    /// Read the exact actor/deployment/tenant row, returning both fields absent when unset.
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError>;

    /// Atomically merge one or both fields into the exact actor/deployment/tenant row.
    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError>;
}

/// Fail-closed default until a host injects PostgreSQL or Desktop-local storage.
#[derive(Debug, Default)]
pub struct NoUiPreferenceAdministration;

#[async_trait]
impl UiPreferenceAdministration for NoUiPreferenceAdministration {
    async fn get(
        &self,
        _auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        Err(UiPreferenceAdministrationError::Unavailable)
    }

    async fn update(
        &self,
        _auth: &AuthContext,
        _update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        Err(UiPreferenceAdministrationError::Unavailable)
    }
}

/// Read authenticated stored preferences without inventing host fallback values.
pub async fn get_ui_preferences(
    port: &dyn UiPreferenceAdministration,
    auth: &AuthContext,
) -> Result<UiPreferences, AppError> {
    port.get(auth)
        .await
        .map_err(UiPreferenceAdministrationError::into_app_error)
}

/// Validate and merge an authenticated partial update.
pub async fn update_ui_preferences(
    port: &dyn UiPreferenceAdministration,
    auth: &AuthContext,
    update: UpdateUiPreferences,
) -> Result<UiPreferences, AppError> {
    if update.is_empty() {
        return Err(AppError::MalformedPayload { field: "body" });
    }
    port.update(auth, update)
        .await
        .map_err(UiPreferenceAdministrationError::into_app_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::ui::UiTheme;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakePort {
        updates: Mutex<Vec<UpdateUiPreferences>>,
    }

    #[async_trait]
    impl UiPreferenceAdministration for FakePort {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            Ok(UiPreferences::default())
        }

        async fn update(
            &self,
            _auth: &AuthContext,
            update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.updates.lock().unwrap().push(update);
            Ok(UiPreferences {
                theme: update.theme,
                locale: update.locale,
            })
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn empty_updates_are_rejected_before_the_port() {
        let port = FakePort::default();
        assert_eq!(
            update_ui_preferences(&port, &auth(), UpdateUiPreferences::default()).await,
            Err(AppError::MalformedPayload { field: "body" })
        );
        assert!(port.updates.lock().unwrap().is_empty());

        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
        };
        assert_eq!(
            update_ui_preferences(&port, &auth(), update).await.unwrap(),
            UiPreferences {
                theme: Some(UiTheme::Dark),
                locale: None,
            }
        );
        assert_eq!(port.updates.lock().unwrap().as_slice(), &[update]);
    }
}
