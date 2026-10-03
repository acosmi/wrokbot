//! Exact authenticated preference projections and CAS receipts, including real row absence.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use super::ApiError;
use openbot_contracts::{
    revision::RevisionSnapshot,
    ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences},
};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CasError {
    InvalidInput,
    Rejected(ApiError),
    Conflict(RevisionSnapshot),
    Unknown,
}

struct Projection {
    theme: Option<UiTheme>,
    locale: Option<UiLocale>,
    revision: Option<i64>,
    updated_at: Option<String>,
}

impl<'de> Deserialize<'de> for Projection {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct ProjectionVisitor;
        impl<'de> serde::de::Visitor<'de> for ProjectionVisitor {
            type Value = Projection;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("four explicit preference fields")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Projection, M::Error> {
                use serde::de::Error;
                let (mut theme, mut locale, mut revision, mut updated_at) =
                    (None, None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "theme" => {
                            if theme.is_some() {
                                return Err(M::Error::duplicate_field("theme"));
                            }
                            theme = Some(map.next_value::<Option<UiTheme>>()?);
                        }
                        "locale" => {
                            if locale.is_some() {
                                return Err(M::Error::duplicate_field("locale"));
                            }
                            locale = Some(map.next_value::<Option<UiLocale>>()?);
                        }
                        "revision" => {
                            if revision.is_some() {
                                return Err(M::Error::duplicate_field("revision"));
                            }
                            revision = Some(map.next_value::<Option<i64>>()?);
                        }
                        "updatedAt" => {
                            if updated_at.is_some() {
                                return Err(M::Error::duplicate_field("updatedAt"));
                            }
                            updated_at = Some(map.next_value::<Option<String>>()?);
                        }
                        _ => {
                            return Err(M::Error::unknown_field(
                                &key,
                                &["theme", "locale", "revision", "updatedAt"],
                            ));
                        }
                    }
                }
                Ok(Projection {
                    theme: theme.ok_or_else(|| M::Error::missing_field("theme"))?,
                    locale: locale.ok_or_else(|| M::Error::missing_field("locale"))?,
                    revision: revision.ok_or_else(|| M::Error::missing_field("revision"))?,
                    updated_at: updated_at.ok_or_else(|| M::Error::missing_field("updatedAt"))?,
                })
            }
        }
        decoder.deserialize_map(ProjectionVisitor)
    }
}

fn projection(text: &str) -> Result<UiPreferences, ApiError> {
    if text.len() > 16 * 1024 {
        return Err(ApiError::InvalidResponse);
    }
    let wire: Projection = serde_json::from_str(text).map_err(|_| ApiError::InvalidResponse)?;
    let updated_at = wire
        .updated_at
        .map(|value| {
            time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
        })
        .transpose()
        .map_err(|_| ApiError::InvalidResponse)?;
    let stored = UiPreferences {
        theme: wire.theme,
        locale: wire.locale,
        revision: wire.revision,
        updated_at,
    };
    match (stored.revision, stored.updated_at) {
        (None, None) if stored.theme.is_none() && stored.locale.is_none() => Ok(stored),
        (Some(_), Some(_)) if stored.revision_snapshot().is_ok() => Ok(stored),
        _ => Err(ApiError::InvalidResponse),
    }
}

pub(crate) async fn read() -> Result<UiPreferences, ApiError> {
    #[cfg(target_arch = "wasm32")]
    {
        let response =
            super::request::Request::send(super::request::Request::get("/api/me/preferences"))
                .await?;
        if response.status() != 200 {
            return Err(super::status_error(response.status()));
        }
        let text = zeroize::Zeroizing::new(
            response
                .text()
                .await
                .map_err(|_| ApiError::InvalidResponse)?,
        );
        projection(&text)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(ApiError::Unavailable)
    }
}

fn exact_receipt(base: UiPreferences, update: UpdateUiPreferences, stored: UiPreferences) -> bool {
    let next = update
        .expected_revision
        .map_or(Some(1), |revision| revision.checked_add(1));
    next.is_some()
        && update.expected_revision == base.revision
        && stored.revision == next
        && stored.updated_at.is_some()
        && stored.theme == update.theme.or(base.theme)
        && stored.locale == update.locale.or(base.locale)
}

pub(crate) async fn save(
    base: UiPreferences,
    update: UpdateUiPreferences,
) -> Result<UiPreferences, CasError> {
    if update.is_empty()
        || update.expected_revision != base.revision
        || update
            .expected_revision
            .is_some_and(|revision| revision <= 0 || revision.checked_add(1).is_none())
    {
        return Err(CasError::InvalidInput);
    }
    #[cfg(target_arch = "wasm32")]
    {
        let request = super::request::Request::put("/api/me/preferences")
            .json(&update)
            .map_err(|_| CasError::InvalidInput)?;
        let response = super::request::Request::send(request)
            .await
            .map_err(|_| CasError::Unknown)?;
        let status = response.status();
        if status != 200 && status != 409 {
            return Err(match status {
                400 | 422 => CasError::InvalidInput,
                401 => CasError::Rejected(ApiError::Unauthorized),
                403 => CasError::Rejected(ApiError::Forbidden),
                404 => CasError::Rejected(ApiError::NotFound),
                _ => CasError::Unknown,
            });
        }
        // This is a caller post-read cap; browser response allocation is not claimed bounded.
        let text = zeroize::Zeroizing::new(response.text().await.map_err(|_| CasError::Unknown)?);
        if text.len() > 16 * 1024 {
            return Err(CasError::Unknown);
        }
        if status == 409 {
            let snapshot: RevisionSnapshot =
                serde_json::from_str(&text).map_err(|_| CasError::Unknown)?;
            if base
                .revision
                .is_some_and(|revision| snapshot.current_revision() <= revision)
            {
                return Err(CasError::Unknown);
            }
            return Err(CasError::Conflict(snapshot));
        }
        let stored = projection(&text).map_err(|_| CasError::Unknown)?;
        if !exact_receipt(base, update, stored) {
            return Err(CasError::Unknown);
        }
        Ok(stored)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(CasError::Rejected(ApiError::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_requires_all_four_nulls_and_rejects_omitted_duplicate_or_extra_keys() {
        assert_eq!(
            projection(r#"{"theme":null,"locale":null,"revision":null,"updatedAt":null}"#).unwrap(),
            UiPreferences::default()
        );
        for bad in [
            r#"{}"#,
            r#"{"theme":null,"locale":null,"revision":null}"#,
            r#"{"theme":null,"theme":"dark","locale":null,"revision":null,"updatedAt":null}"#,
            r#"{"theme":null,"locale":null,"revision":null,"updatedAt":null,"actor":"admin"}"#,
            r#"{"theme":"dark","locale":null,"revision":null,"updatedAt":null}"#,
        ] {
            assert!(projection(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn receipt_keeps_unedited_fields_and_never_accepts_revision_skips_or_absent_ack() {
        let base = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: Some(UiLocale::En),
            revision: Some(2),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Light),
            locale: None,
            expected_revision: Some(2),
        };
        let good = UiPreferences {
            theme: Some(UiTheme::Light),
            revision: Some(3),
            ..base
        };
        assert!(exact_receipt(base, update, good));
        for bad in [
            UiPreferences {
                revision: Some(4),
                ..good
            },
            UiPreferences {
                locale: Some(UiLocale::ZhCn),
                ..good
            },
            UiPreferences::default(),
        ] {
            assert!(!exact_receipt(base, update, bad));
        }
        let create = UpdateUiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            expected_revision: None,
        };
        assert!(exact_receipt(
            UiPreferences::default(),
            create,
            UiPreferences {
                theme: Some(UiTheme::Dark),
                locale: None,
                revision: Some(1),
                updated_at: base.updated_at
            }
        ));
    }
}
