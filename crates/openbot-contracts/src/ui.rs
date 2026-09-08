//! Closed Server/Desktop UI preference contracts shared with the WASM bundle.

use serde::{Deserialize, Serialize};

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
}

/// Atomic partial update. At least one field must be present at the application boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUiPreferences {
    /// New explicit theme; absent means leave the stored theme unchanged.
    pub theme: Option<UiTheme>,
    /// New explicit locale; absent means leave the stored locale unchanged.
    pub locale: Option<UiLocale>,
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
        };
        assert_eq!(
            serde_json::to_string(&preferences).unwrap(),
            r#"{"theme":"dark","locale":"zh-CN"}"#
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
}
