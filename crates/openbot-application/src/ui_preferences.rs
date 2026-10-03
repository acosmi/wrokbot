//! Application-owned authenticated UI preference use cases.

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::ui::{UiPreferences, UpdateUiPreferences};

/// Stable storage failure without database text or actor identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UiPreferenceAdministrationError {
    /// The actor or requested existing preference row is no longer visible.
    #[error("ui_preferences_not_visible")]
    NotVisible,
    /// Current authorized editing metadata differs from the submitted version.
    #[error("ui_preferences_stale_snapshot")]
    StaleSnapshot(openbot_contracts::revision::RevisionSnapshot),
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
            Self::NotVisible => AppError::NotVisible,
            Self::StaleSnapshot(snapshot) => AppError::StaleGeneration {
                subject: openbot_contracts::error::StaleGenerationSubject::Configuration {
                    snapshot,
                },
            },
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

/// Fail-closed default until a host injects the authoritative preference store.
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
    let preferences = port
        .get(auth)
        .await
        .map_err(UiPreferenceAdministrationError::into_app_error)?;
    validate_preferences(preferences)?;
    Ok(preferences)
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
    if update
        .expected_revision
        .is_some_and(|revision| revision <= 0)
    {
        return Err(AppError::MalformedPayload {
            field: "expectedRevision",
        });
    }
    let preferences = port
        .update(auth, update)
        .await
        .map_err(UiPreferenceAdministrationError::into_app_error)?;
    validate_preferences(preferences)?;
    let expected_revision = update
        .expected_revision
        .map_or(Some(1), |r| r.checked_add(1));
    if expected_revision.is_none()
        || preferences.revision != expected_revision
        || update.theme.is_some() && preferences.theme != update.theme
        || update.locale.is_some() && preferences.locale != update.locale
    {
        return Err(UiPreferenceAdministrationError::Corrupt {
            field: "preferences",
        }
        .into_app_error());
    }
    Ok(preferences)
}

fn validate_preferences(preferences: UiPreferences) -> Result<(), AppError> {
    let valid = match (preferences.revision, preferences.updated_at) {
        (None, None) => preferences.theme.is_none() && preferences.locale.is_none(),
        (Some(_), Some(_)) => preferences.revision_snapshot().is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(UiPreferenceAdministrationError::Corrupt {
            field: "preferences",
        }
        .into_app_error())
    }
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
        reply: Mutex<Option<Result<UiPreferences, UiPreferenceAdministrationError>>>,
    }

    #[async_trait]
    impl UiPreferenceAdministration for FakePort {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.reply
                .lock()
                .unwrap()
                .unwrap_or(Ok(UiPreferences::default()))
        }

        async fn update(
            &self,
            _auth: &AuthContext,
            update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.updates.lock().unwrap().push(update);
            if let Some(reply) = *self.reply.lock().unwrap() {
                return reply;
            }
            Ok(UiPreferences {
                theme: update.theme,
                locale: update.locale,
                revision: update
                    .expected_revision
                    .map_or(Some(1), |r| r.checked_add(1)),
                updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
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
            expected_revision: None,
        };
        assert_eq!(
            update_ui_preferences(&port, &auth(), update).await.unwrap(),
            UiPreferences {
                theme: Some(UiTheme::Dark),
                locale: None,
                revision: Some(1),
                updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            }
        );
        assert_eq!(port.updates.lock().unwrap().as_slice(), &[update]);
    }

    #[tokio::test]
    async fn preferences_validate_current_pair_and_successful_cas_receipt() {
        let port = FakePort::default();
        let valid = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(3),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            expected_revision: Some(2),
        };
        *port.reply.lock().unwrap() = Some(Ok(valid));
        assert_eq!(
            update_ui_preferences(&port, &auth(), update).await.unwrap(),
            valid
        );
        for invalid in [
            UiPreferences {
                revision: None,
                ..valid
            },
            UiPreferences {
                updated_at: None,
                ..valid
            },
            UiPreferences {
                revision: Some(0),
                ..valid
            },
            UiPreferences {
                theme: None,
                ..valid
            },
        ] {
            *port.reply.lock().unwrap() = Some(Ok(invalid));
            assert!(matches!(
                get_ui_preferences(&port, &auth()).await,
                Err(AppError::DependencyUnavailable {
                    dependency: "ui_preferences"
                })
            ));
        }
        for invalid in [
            UiPreferences::default(),
            UiPreferences {
                revision: Some(2),
                ..valid
            },
            UiPreferences {
                theme: Some(UiTheme::Light),
                ..valid
            },
        ] {
            *port.reply.lock().unwrap() = Some(Ok(invalid));
            assert!(matches!(
                update_ui_preferences(&port, &auth(), update).await,
                Err(AppError::DependencyUnavailable {
                    dependency: "ui_preferences"
                })
            ));
        }
    }

    #[tokio::test]
    async fn preferences_reject_nonpositive_versions_but_maximum_defers_to_current_authority() {
        let port = FakePort::default();
        let mut update = UpdateUiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            expected_revision: Some(0),
        };
        for revision in [0, -1, i64::MIN] {
            update.expected_revision = Some(revision);
            assert_eq!(
                update_ui_preferences(&port, &auth(), update).await,
                Err(AppError::MalformedPayload {
                    field: "expectedRevision"
                })
            );
        }
        assert!(port.updates.lock().unwrap().is_empty());
        let current = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(2),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        let snapshot = current.revision_snapshot().unwrap();
        update.expected_revision = Some(i64::MAX);
        for error in [
            UiPreferenceAdministrationError::NotVisible,
            UiPreferenceAdministrationError::StaleSnapshot(snapshot),
        ] {
            *port.reply.lock().unwrap() = Some(Err(error));
            assert_eq!(
                update_ui_preferences(&port, &auth(), update).await,
                Err(error.into_app_error())
            );
        }
        assert_eq!(port.updates.lock().unwrap().len(), 2);
    }
}
