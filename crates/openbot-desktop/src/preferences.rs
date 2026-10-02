//! Desktop-local, bounded and atomically replaced UI preference file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
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
    let file =
        File::open(path).map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    let opened = file
        .metadata()
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    if !opened.is_file() || opened.len() > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    read_preferences(file)
}

fn read_preferences(
    reader: impl io::Read,
) -> Result<UiPreferences, UiPreferenceAdministrationError> {
    let mut bytes = Vec::new();
    reader
        .take(FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    if bytes.len() as u64 > FILE_MAX_BYTES {
        return Err(UiPreferenceAdministrationError::Corrupt { field: "file" });
    }
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| UiPreferenceAdministrationError::Corrupt { field: "file" })?;
    parse(raw)
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

    struct GrowingInput {
        initial: Vec<u8>,
        supplied: usize,
        available: usize,
    }

    impl io::Read for GrowingInput {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let remaining = self.available - self.supplied;
            let count = if self.supplied < self.initial.len() {
                output.len().min(self.initial.len() - self.supplied)
            } else {
                output.len().min(remaining)
            };
            for (index, byte) in output[..count].iter_mut().enumerate() {
                *byte = self
                    .initial
                    .get(self.supplied + index)
                    .copied()
                    .unwrap_or(b'x');
            }
            self.supplied += count;
            Ok(count)
        }
    }

    #[test]
    fn read_budget_stops_a_growing_source_after_one_excess_byte() {
        let initial = render(UiPreferences::default()).into_bytes();
        assert!(initial.len() < FILE_MAX_BYTES as usize);
        let mut growing = GrowingInput {
            initial,
            supplied: 0,
            available: 1024 * 1024,
        };
        assert_eq!(
            read_preferences(&mut growing),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(growing.supplied, FILE_MAX_BYTES as usize + 1);
        assert!(growing.available > growing.supplied);
    }

    #[test]
    fn read_boundary_checks_length_before_decoding_and_preserves_parser_errors() {
        assert_eq!(
            read_preferences(&b"x".repeat(256)[..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "version" })
        );
        assert_eq!(
            read_preferences(&b"x".repeat(257)[..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(
            read_preferences(&[0xff][..]),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        for (input, field) in [
            ("bad-version\ntheme=dark\nlocale=en\n", "version"),
            (
                "openbot-ui-preferences-v1\ntheme=sepia\nlocale=en\n",
                "theme",
            ),
            (
                "openbot-ui-preferences-v1\ntheme=dark\nlocale=bad\n",
                "locale",
            ),
            (
                "openbot-ui-preferences-v1\ntheme=dark\nlocale=en\nextra=x\n",
                "file",
            ),
        ] {
            assert_eq!(
                read_preferences(input.as_bytes()),
                Err(UiPreferenceAdministrationError::Corrupt { field })
            );
        }
        let preferences = UiPreferences {
            theme: Some(UiTheme::System),
            locale: Some(UiLocale::En),
        };
        assert_eq!(
            read_preferences(render(preferences).as_bytes()),
            Ok(preferences)
        );
    }

    #[test]
    fn read_failure_keeps_the_file_corruption_class() {
        struct BrokenInput;
        impl io::Read for BrokenInput {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("owned test input failure"))
            }
        }
        assert_eq!(
            read_preferences(BrokenInput),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_reads_keep_missing_directory_and_link_semantics() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "openbot-desktop-ui-preferences-reading-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        assert_eq!(read_file(&path), Ok(UiPreferences::default()));
        assert_eq!(
            read_file(&root),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        let preferences = UiPreferences {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
        };
        fs::write(&path, render(preferences)).unwrap();
        assert_eq!(read_file(&path), Ok(preferences));
        symlink("ui-preferences-v1", root.join("soft-link")).unwrap();
        fs::hard_link(&path, root.join("hard-link")).unwrap();
        assert_eq!(read_file(&root.join("soft-link")), Ok(preferences));
        assert_eq!(read_file(&root.join("hard-link")), Ok(preferences));
        fs::write(&path, [0xff]).unwrap();
        assert_eq!(
            read_file(&path),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        fs::write(&path, b"x".repeat(257)).unwrap();
        assert_eq!(
            read_file(&path),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rejected_file_update_preserves_original_bytes_and_no_temporary_output() {
        let root = std::env::temp_dir().join(format!(
            "openbot-desktop-ui-preferences-rejected-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let original = b"x".repeat(257);
        fs::write(&path, &original).unwrap();
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(
            store.get(&auth()).await,
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(
            store
                .update(
                    &auth(),
                    UpdateUiPreferences {
                        theme: Some(UiTheme::Dark),
                        locale: None,
                    },
                )
                .await,
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
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
