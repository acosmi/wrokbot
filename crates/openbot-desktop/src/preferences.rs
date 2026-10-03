//! Bounded Desktop first-frame projection; PostgreSQL owns every editing reply.

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

/// Host-owned first-frame cache. It never implements the authoritative editing port.
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

    /// Read bounded host-selected values for first paint only, never for an editing reply.
    /// Returned revision/time are absent; callers must not infer that a PG row is absent.
    pub fn read_first_frame_projection(
        &self,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        self.read()
    }

    fn read(&self) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        read_file(&self.inner.path)
    }

    fn project_sync(
        &self,
        preferences: UiPreferences,
    ) -> Result<(), UiPreferenceAdministrationError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        // Reject a malformed existing projection rather than replacing unrelated bytes.
        self.read()?;
        write_atomic(&self.inner.path, preferences)
    }
}

/// Desktop editing delegates to the same PostgreSQL CAS and audit port as Server.
#[derive(Clone)]
pub struct DesktopUiPreferenceAdministration {
    authority: Arc<dyn UiPreferenceAdministration>,
    projection: DesktopUiPreferenceStore,
}

impl DesktopUiPreferenceAdministration {
    /// A host-selected cache path carries values for first paint, never a revision or authority.
    pub fn new(authority: Arc<dyn UiPreferenceAdministration>, path: impl Into<PathBuf>) -> Self {
        Self {
            authority,
            projection: DesktopUiPreferenceStore::new(path),
        }
    }

    async fn project(&self, preferences: UiPreferences) {
        // An absent PG row must not erase the old first-frame projection or create a row.
        if preferences.revision.is_none() {
            return;
        }
        let store = self.projection.clone();
        let result = tokio::task::spawn_blocking(move || store.project_sync(preferences)).await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::warn!(
                "Committed UI preferences remain authoritative; first-frame cache unavailable"
            );
        }
    }
}

#[async_trait]
impl UiPreferenceAdministration for DesktopUiPreferenceAdministration {
    async fn get(
        &self,
        auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        let preferences = self.authority.get(auth).await?;
        self.project(preferences).await;
        Ok(preferences)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        // A failed/unknown/409 PG result never becomes a file fallback or a second PG request.
        let preferences = self.authority.update(auth, update).await?;
        self.project(preferences).await;
        Ok(preferences)
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
    Ok(UiPreferences {
        theme,
        locale,
        ..UiPreferences::default()
    })
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
            ..UiPreferences::default()
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
            ..UiPreferences::default()
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
            ..UiPreferences::default()
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

    #[test]
    fn rejected_projection_preserves_original_bytes_and_no_temporary_output() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-projection-rejected-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let original = b"x".repeat(257);
        fs::write(&path, &original).unwrap();
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(
            store.read(),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(
            store.project_sync(committed(1)),
            Err(UiPreferenceAdministrationError::Corrupt { field: "file" })
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    fn committed(revision: i64) -> UiPreferences {
        UiPreferences {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
            revision: Some(revision),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn projection_replaces_without_revision_or_temporary_files() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-projection-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let store = DesktopUiPreferenceStore::new(&path);
        assert_eq!(store.read().unwrap(), UiPreferences::default());
        store.project_sync(committed(1)).unwrap();
        store.project_sync(committed(2)).unwrap();
        let cache = store.read().unwrap();
        assert_eq!(cache.theme, Some(UiTheme::Light));
        assert_eq!(cache.locale, Some(UiLocale::ZhCn));
        assert_eq!(cache.revision, None);
        assert_eq!(cache.updated_at, None);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    struct Authority {
        result: Mutex<Result<UiPreferences, UiPreferenceAdministrationError>>,
        updates: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl UiPreferenceAdministration for Authority {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            *self.result.lock().unwrap()
        }
        async fn update(
            &self,
            _auth: &AuthContext,
            _update: UpdateUiPreferences,
        ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
            self.updates.fetch_add(1, Ordering::Relaxed);
            *self.result.lock().unwrap()
        }
    }

    #[tokio::test]
    async fn pg_reply_is_authoritative_and_cache_failure_never_replays() {
        let root = std::env::temp_dir().join(format!(
            "openbot-ui-authority-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("ui-preferences-v1");
        let prior = render(UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            ..Default::default()
        });
        fs::write(&path, &prior).unwrap();
        let authority = Arc::new(Authority {
            result: Mutex::new(Ok(UiPreferences::default())),
            updates: std::sync::atomic::AtomicUsize::new(0),
        });
        let store = DesktopUiPreferenceAdministration::new(authority.clone(), &path);
        assert_eq!(store.get(&auth()).await.unwrap(), UiPreferences::default());
        assert_eq!(fs::read_to_string(&path).unwrap(), prior);
        *authority.result.lock().unwrap() = Err(UiPreferenceAdministrationError::StaleSnapshot(
            committed(2).revision_snapshot().unwrap(),
        ));
        let update = UpdateUiPreferences {
            theme: Some(UiTheme::Light),
            locale: None,
            expected_revision: Some(1),
        };
        assert!(matches!(
            store.update(&auth(), update).await,
            Err(UiPreferenceAdministrationError::StaleSnapshot(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), prior);
        let corrupt = b"x".repeat(257);
        fs::write(&path, &corrupt).unwrap();
        *authority.result.lock().unwrap() = Ok(committed(3));
        assert_eq!(store.update(&auth(), update).await.unwrap(), committed(3));
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        assert_eq!(authority.updates.load(Ordering::Relaxed), 2);
        fs::remove_file(&path).unwrap();
        assert_eq!(store.get(&auth()).await.unwrap(), committed(3));
        assert_eq!(read_file(&path).unwrap().revision, None);
        assert_eq!(read_file(&path).unwrap().theme, Some(UiTheme::Light));
        assert_eq!(authority.updates.load(Ordering::Relaxed), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
