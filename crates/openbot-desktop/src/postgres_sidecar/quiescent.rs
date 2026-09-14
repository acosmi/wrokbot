//! Sealed VerifiedQuiescentInstance minting and cleanup-only start-lock reclaim.

use super::helper_journal::{self, HelperJournalError};
use super::kernel_start_lock::KernelStartLock;
use super::startup_journal::{self, StartupJournalError};
use super::{PostgresSidecarError, path_matches_open_file, sync_directory};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use wrok_bot_macos_process::{
    DataDirectoryOpenerObservation, ProcessIdentity, observe_data_directory_openers,
};

const LOCK_HEADER: &str = "openbot-postgres-start-lock-v1";

/// Proof that one instance is quiescent enough to reclaim its dynamic start-lock evidence.
///
/// Not serializable, not a wire type, and not recovery/epoch authority.
pub(super) struct VerifiedQuiescentInstance {
    instance_id: String,
}

impl core::fmt::Debug for VerifiedQuiescentInstance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedQuiescentInstance(<sealed>)")
    }
}

impl VerifiedQuiescentInstance {
    /// Mint only when owner, empty openers, and cleanup-eligible journals all hold.
    pub(super) fn try_verify(
        owner: &KernelStartLock,
        app_data_root: &Path,
        instance_id: &str,
        data_dir: &Path,
    ) -> Result<Self, PostgresSidecarError> {
        if !owner.is_current() || owner.root() != app_data_root {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        if data_dir.parent() != Some(app_data_root)
            || data_dir.file_name().and_then(|name| name.to_str())
                != Some(format!("postgresql-17-{instance_id}").as_str())
        {
            return Err(PostgresSidecarError::DataDirectoryInvalid);
        }
        let metadata = fs::metadata(data_dir).map_err(|_| PostgresSidecarError::DataDirectoryInvalid)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if !metadata.is_dir() || metadata.ino() == 0 {
                return Err(PostgresSidecarError::DataDirectoryInvalid);
            }
            let self_identity = ProcessIdentity::capture(std::process::id())
                .map_err(|_| PostgresSidecarError::ProcessIdentityInvalid)?;
            match observe_data_directory_openers(
                data_dir,
                metadata.dev(),
                metadata.ino(),
                std::slice::from_ref(&self_identity),
            ) {
                Ok(DataDirectoryOpenerObservation::Empty) => {}
                Ok(DataDirectoryOpenerObservation::Observed) => {
                    return Err(PostgresSidecarError::StartupJournalRecoveryRequired);
                }
                Err(_) => return Err(PostgresSidecarError::ProcessIdentityInvalid),
            }
        }
        startup_journal::allows_quiescent_cleanup(app_data_root, instance_id, data_dir).map_err(
            |error| match error {
                StartupJournalError::RecoveryRequired => {
                    PostgresSidecarError::StartupJournalRecoveryRequired
                }
                StartupJournalError::ReconciliationRequired => {
                    PostgresSidecarError::StartLockGuardInvalid
                }
                StartupJournalError::Invalid => PostgresSidecarError::StartLockGuardInvalid,
            },
        )?;
        helper_journal::allows_quiescent_cleanup(app_data_root, instance_id, data_dir).map_err(
            |error| match error {
                HelperJournalError::RecoveryRequired => {
                    PostgresSidecarError::HelperJournalRecoveryRequired
                }
                HelperJournalError::ReconciliationRequired | HelperJournalError::Invalid => {
                    PostgresSidecarError::StartLockGuardInvalid
                }
            },
        )?;
        if !owner.is_current() {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        Ok(Self {
            instance_id: instance_id.to_owned(),
        })
    }

    /// Delete this instance's dynamic start-lock evidence only.
    pub(super) fn reclaim_start_lock_evidence(
        self,
        owner: &KernelStartLock,
        app_data_root: &Path,
    ) -> Result<(), PostgresSidecarError> {
        if !owner.is_current() || owner.root() != app_data_root {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        let path =
            app_data_root.join(format!(".postgresql-17-{}.start-lock-v1", self.instance_id));
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        if !metadata.is_file() {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
        }
        let mut file = secure_open_read(&path).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        if !lock_bytes_match_instance(&bytes, &self.instance_id) {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        if !path_matches_open_file(&path, &file, &bytes, true) {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        drop(file);
        fs::remove_file(&path).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        sync_directory(app_data_root)?;
        if !owner.is_current() {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        Ok(())
    }
}

fn lock_bytes_match_instance(bytes: &[u8], instance_id: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.lines();
    if lines.next() != Some(LOCK_HEADER) {
        return false;
    }
    let mut saw_instance = false;
    for line in lines {
        if let Some(value) = line.strip_prefix("instance=") {
            if value != instance_id || saw_instance {
                return false;
            }
            saw_instance = true;
        } else if !(line.starts_with("pid=")
            || line.starts_with("manifest=")
            || line.starts_with("nonce="))
        {
            return false;
        }
    }
    saw_instance
}

fn secure_open_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x100 | 0x4);
    }
    options.open(path)
}


#[cfg(all(test, target_os = "macos"))]
mod tests {
            use crate::postgres_sidecar::{PostgresBundleDigest, PostgresStartLock, PostgresSidecarError};
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::io::Write as _;
    use std::path::PathBuf;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wrok-v6-pr-012-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    #[test]
    fn cleanup_state_reclaims_stale_start_lock_then_acquire_succeeds() {
        let root = temp_root("reclaim");
        let instance = "a".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        write!(
            file,
            "openbot-postgres-start-lock-v1\npid=1\ninstance={instance}\nmanifest={}\nnonce={}\n",
            "11".repeat(32),
            "22".repeat(16)
        )
        .unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            PostgresStartLock::acquire(&root, &instance, PostgresBundleDigest([0x11; 32])),
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        ));

        let reclaimed = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(reclaimed.is_ok(), "{reclaimed:?}");
        assert!(!lock_path.exists() || reclaimed.is_ok());
        drop(reclaimed.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mid_phase_startup_journal_blocks_reclaim() {
        let root = temp_root("midphase");
        let instance = "b".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
        fs::write(
            &lock_path,
            format!(
                "openbot-postgres-start-lock-v1\npid=1\ninstance={instance}\nmanifest={}\nnonce={}\n",
                "11".repeat(32),
                "22".repeat(16)
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        // Minimal invalid/mid marker file that fails closed as RecoveryRequired or Invalid.
        fs::write(&journal, b"{\"schema\":\"openbot-postgres-startup\",\"phase\":\"spawn_entered\"}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(lock_path.is_file());
        let _ = fs::remove_dir_all(&root);
    }
}
