//! Closed Server/Desktop UI preference contracts shared with the WASM bundle.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Whether this authenticated browser request is backed by one revocable database session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionStatus {
    /// `true` only for a concrete multi-user session row; single-user loopback is `false`.
    pub revocable: bool,
}

/// First-release theme preference. Absence in [`UiPreferences`] means “use host fallback”.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTheme {
    /// Follow the operating-system color scheme.
    #[default]
    System,
    /// Force light tokens.
    Light,
    /// Force dark tokens.
    Dark,
}

impl UiTheme {
    /// Stable cookie/database value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// First-release locale preference. The wire/database values are BCP 47 language tags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiLocale {
    /// English source locale.
    #[default]
    #[serde(rename = "en")]
    En,
    /// Simplified Chinese.
    #[serde(rename = "zh-CN")]
    ZhCn,
}

impl UiLocale {
    /// Stable BCP 47 cookie/HTML/database value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }
}

/// Authenticated actor's stored preferences. `None` preserves the host fallback independently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiPreferences {
    /// Explicit theme, or host/system fallback when absent.
    pub theme: Option<UiTheme>,
    /// Explicit locale, or Accept-Language/OS fallback when absent.
    pub locale: Option<UiLocale>,
    /// Committed editing revision, or `None` while no preference row exists.
    pub revision: Option<i64>,
    /// Database time of the committed revision; absent exactly when revision is absent.
    #[serde(with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
}

impl UiPreferences {
    /// Hash the current persisted configuration; unset preferences have no invented snapshot.
    pub fn revision_snapshot(
        &self,
    ) -> Result<crate::revision::RevisionSnapshot, serde_json::Error> {
        use serde::ser::Error as _;
        let (Some(revision), Some(updated_at)) = (self.revision, self.updated_at) else {
            return Err(serde_json::Error::custom("invalid_ui_preference_revision"));
        };
        if self.theme.is_none() && self.locale.is_none() {
            return Err(serde_json::Error::custom("invalid_ui_preference_revision"));
        }
        crate::revision::RevisionSnapshot::from_public(revision, updated_at, self)
    }
}

/// Atomic partial update. At least one field must be present at the application boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUiPreferences {
    /// New explicit theme; absent means leave the stored theme unchanged.
    pub theme: Option<UiTheme>,
    /// New explicit locale; absent means leave the stored locale unchanged.
    pub locale: Option<UiLocale>,
    /// Absent creates only; present updates the exact known committed revision.
    #[serde(default)]
    pub expected_revision: Option<i64>,
}

impl UpdateUiPreferences {
    /// Whether the update carries no mutation at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.theme.is_none() && self.locale.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_wire_values_are_closed_and_bcp47_exact() {
        let preferences = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: Some(UiLocale::ZhCn),
            revision: Some(1),
            updated_at: Some(OffsetDateTime::UNIX_EPOCH),
        };
        assert_eq!(
            serde_json::to_string(&preferences).unwrap(),
            r#"{"theme":"dark","locale":"zh-CN","revision":1,"updatedAt":"1970-01-01T00:00:00Z"}"#
        );
        assert!(
            serde_json::from_str::<UpdateUiPreferences>(
                r#"{"theme":"dark","locale":"zh-CN","actor":"admin"}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<UiTheme>(r#""sepia""#).is_err());
        assert!(serde_json::from_str::<UiLocale>(r#""zh""#).is_err());
        assert_eq!(
            serde_json::to_string(&SessionStatus { revocable: true }).unwrap(),
            r#"{"revocable":true}"#
        );
        assert!(
            serde_json::from_str::<SessionStatus>(r#"{"revocable":true,"sessionId":"x"}"#).is_err()
        );
    }

    #[test]
    fn preference_revision_metadata_distinguishes_unset_and_committed_configuration() {
        let unset = UiPreferences::default();
        assert_eq!(
            serde_json::to_value(unset).unwrap(),
            serde_json::json!({"theme":null,"locale":null,"revision":null,"updatedAt":null})
        );
        assert!(unset.revision_snapshot().is_err());
        let valid = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(2),
            updated_at: Some(OffsetDateTime::UNIX_EPOCH),
        };
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
            assert!(invalid.revision_snapshot().is_err());
        }
        let snapshot = valid.revision_snapshot().unwrap();
        let independent = crate::revision::RevisionSnapshot::from_public(2, OffsetDateTime::UNIX_EPOCH, &serde_json::json!({"theme":"dark","locale":null,"revision":2,"updatedAt":"1970-01-01T00:00:00Z"})).unwrap();
        assert_eq!(snapshot, independent);
        assert_ne!(
            UiPreferences {
                locale: Some(UiLocale::ZhCn),
                ..valid
            }
            .revision_snapshot()
            .unwrap(),
            snapshot
        );
    }

    #[test]
    fn preference_update_expected_version_is_closed_and_does_not_count_as_content() {
        for wire in [
            r#"{"theme":"dark","expectedRevision":"1"}"#,
            r#"{"theme":"dark","expectedRevision":1.2}"#,
            r#"{"theme":"dark","expectedRevision":9223372036854775808}"#,
            r#"{"theme":"dark","expectedRevision":1,"updatedAt":"forged"}"#,
            r#"{"theme":"dark","expectedRevision":1,"expectedRevision":2}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateUiPreferences>(wire).is_err(),
                "{wire}"
            );
        }
        let create: UpdateUiPreferences = serde_json::from_str(r#"{"theme":"dark"}"#).unwrap();
        assert_eq!(create.expected_revision, None);
        let empty: UpdateUiPreferences = serde_json::from_str(r#"{"expectedRevision":2}"#).unwrap();
        assert!(empty.is_empty());
    }
}
