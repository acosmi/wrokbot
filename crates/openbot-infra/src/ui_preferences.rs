//! PostgreSQL implementation of actor-scoped Server UI preferences.

use async_trait::async_trait;
use openbot_application::{UiPreferenceAdministration, UiPreferenceAdministrationError};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};
use tokio_postgres::Row;

/// Production cross-device UI preference store.
#[derive(Clone)]
pub struct PostgresUiPreferenceAdministration {
    pool: deadpool_postgres::Pool,
}

impl PostgresUiPreferenceAdministration {
    /// Construct from the Server/Desktop shared PostgreSQL pool.
    #[must_use]
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UiPreferenceAdministration for PostgresUiPreferenceAdministration {
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT theme,locale FROM public.user_ui_preferences \
                 WHERE deployment_id=$1 AND tenant_id=$2 AND actor_user_id=$3",
                &[
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &auth.actor().as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("读取 UI preferences 失败", error))?;
        row.as_ref().map_or(Ok(UiPreferences::default()), decode)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        if update.is_empty() {
            return Err(UiPreferenceAdministrationError::InvalidInput { field: "body" });
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let theme = update.theme.map(UiTheme::as_str);
        let locale = update.locale.map(UiLocale::as_str);
        let row = transaction
            .query_one(
                "INSERT INTO public.user_ui_preferences \
                    (deployment_id,tenant_id,actor_user_id,theme,locale,updated_at) \
                 VALUES ($1,$2,$3,$4,$5,statement_timestamp()) \
                 ON CONFLICT (deployment_id,tenant_id,actor_user_id) DO UPDATE SET \
                    theme=coalesce(EXCLUDED.theme,user_ui_preferences.theme), \
                    locale=coalesce(EXCLUDED.locale,user_ui_preferences.locale), \
                    updated_at=statement_timestamp() \
                 RETURNING theme,locale",
                &[
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &auth.actor().as_str(),
                    &theme,
                    &locale,
                ],
            )
            .await
            .map_err(|error| unavailable("保存 UI preferences 失败", error))?;
        let preferences = decode(&row)?;
        transaction
            .commit()
            .await
            .map_err(|_| UiPreferenceAdministrationError::CommitUnknown)?;
        Ok(preferences)
    }
}

fn decode(row: &Row) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let theme = row
        .try_get::<_, Option<String>>("theme")
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "theme" })?
        .map(|value| match value.as_str() {
            "system" => Ok(UiTheme::System),
            "light" => Ok(UiTheme::Light),
            "dark" => Ok(UiTheme::Dark),
            _ => Err(UiPreferenceAdministrationError::Corrupt { field: "theme" }),
        })
        .transpose()?;
    let locale = row
        .try_get::<_, Option<String>>("locale")
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "locale" })?
        .map(|value| match value.as_str() {
            "en" => Ok(UiLocale::En),
            "zh-CN" => Ok(UiLocale::ZhCn),
            _ => Err(UiPreferenceAdministrationError::Corrupt { field: "locale" }),
        })
        .transpose()?;
    if theme.is_none() && locale.is_none() {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "row" });
    }
    Ok(UiPreferences { theme, locale })
}

fn unavailable(
    context: &'static str,
    error: tokio_postgres::Error,
) -> UiPreferenceAdministrationError {
    tracing::warn!(error = %error, "{context}");
    UiPreferenceAdministrationError::Unavailable
}
