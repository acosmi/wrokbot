//! Desktop-local, bounded and atomically replaced UI preference file.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openbot_application::{UiPreferenceAdministration, UiPreferenceAdministrationError};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences};

const FILE_HEADER: &str = "openbot-ui-preferences-v1";
const FILE_MAX_BYTES: u64 = 256;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Host-owned local preference storage used only by Desktop Local mode.
#[derive(Clone)]
pub struct DesktopUiPreferenceStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    path: PathBuf,
    mutation: Mutex<()>,
}

impl DesktopUiPreferenceStore {
    /// Bind to the exact host-selected settings file.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                path: path.into(),
                mutation: Mutex::new(()),
            }),
        }
    }

    fn read(&self) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        read_file(&self.inner.path)
    }

    fn update_sync(
        &self,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let mut preferences = self.read()?;
        preferences.theme = update.theme.or(preferences.theme);
        preferences.locale = update.locale.or(preferences.locale);
        write_atomic(&self.inner.path, preferences)?;
        Ok(preferences)
    }
}

#[async_trait]
impl UiPreferenceAdministration for DesktopUiPreferenceStore {
    async fn get(
        &self,
        _auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.read())
            .await
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?
    }

    async fn update(
        &self,
        _auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        if update.is_empty() {
            return Err(UiPreferenceAdministrationError::InvalidInput { field: "body" });
        }
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.update_sync(update))
            .await
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?
    }
}

fn read_file(path: &Path) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(UiPreferences::default());
        }
        Err(_) => return Err(UiPreferenceAdministrationError::Unavailable),
    };
    if !metadata.is_file() || metadata.len() > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    let raw = fs::read_to_string(path)
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    parse(&raw)
}

fn parse(raw: &str) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let mut lines = raw.lines();
    if lines.next() != Some(FILE_HEADER) {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "version" });
    }
    let theme = match lines.next() {
        Some("theme=-") => None,
        Some("theme=system") => Some(UiTheme::System),
        Some("theme=light") => Some(UiTheme::Light),
        Some("theme=dark") => Some(UiTheme::Dark),
        _ => return Err(UiPreferenceAdministrationError::Corrupt { field: "theme" }),
    };
    let locale = match lines.next() {
        Some("locale=-") => None,
        Some("locale=en") => Some(UiLocale::En),
        Some("locale=zh-CN") => Some(UiLocale::ZhCn),
        _ => return Err(UiPreferenceAdministrationError::Corrupt { field: "locale" }),
    };
    if lines.next().is_some() {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    Ok(UiPreferences { theme, locale })
}

fn render(preferences: UiPreferences) -> String {
    let theme = preferences.theme.map_or("-", UiTheme::as_str);
    let locale = preferences.locale.map_or("-", UiLocale::as_str);
    format!("{FILE_HEADER}\ntheme={theme}\nlocale={locale}\n")
}

fn write_atomic(
    path: &Path,
    preferences: UiPreferences,
) -> Result<(), UiPreferenceAdministrationError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(UiPreferenceAdministrationError::InvalidInput { field: "path" })?;
    fs::create_dir_all(parent).map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(UiPreferenceAdministrationError::InvalidInput { field: "path" })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let encoded = render(preferences);
        file.write_all(encoded.as_bytes())
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        file.sync_all()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("local"),
            TenantId::new("local"),
            ActorId::new("local"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[test]
    fn parser_is_closed_and_round_trips_independent_fields() {
        let preferences = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
        };
        assert_eq!(parse(&render(preferences)).unwrap(), preferences);
        assert!(parse("openbot-ui-preferences-v1\ntheme=sepia\nlocale=en\n").is_err());
        assert!(parse("openbot-ui-preferences-v1\ntheme=dark\nlocale=en\nextra=x\n").is_err());
    }

    #[tokio::test]
    async fn local_store_merges_and_replaces_without_leaving_temp_files() {
        let root = std::env::temp_dir().join(format!(
            "openbot-desktop-ui-preferences-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(store.get(&auth()).await.unwrap(), UiPreferences::default());
        store
            .update(
                &auth(),
                UpdateUiPreferences {
                    theme: Some(UiTheme::Light),
                    locale: None,
                },
            )
            .await
            .unwrap();
        let stored = store
            .update(
                &auth(),
                UpdateUiPreferences {
                    theme: None,
                    locale: Some(UiLocale::ZhCn),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            stored,
            UiPreferences {
                theme: Some(UiTheme::Light),
                locale: Some(UiLocale::ZhCn),
            }
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
