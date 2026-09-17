//! Sealed VerifiedQuiescentInstance minting and cleanup-only start-lock reclaim.

use super::helper_journal::{self, HelperJournalError};
use super::kernel_start_lock::KernelStartLock;
use super::startup_journal::{self, StartupJournalError};
use super::{path_matches_open_file, sync_directory, PostgresSidecarError};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use wrok_bot_macos_process::{
    observe_data_directory_openers, DataDirectoryOpenerObservation, ProcessIdentity,
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
        let metadata =
            fs::metadata(data_dir).map_err(|_| PostgresSidecarError::DataDirectoryInvalid)?;
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
        let path = app_data_root.join(format!(".postgresql-17-{}.start-lock-v1", self.instance_id));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
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
        let mut file =
            secure_open_read(&path).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
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

/// One-shot mid-phase journal retirement under a held kernel owner and Empty openers.
pub(super) fn recover_mid_phase_journals(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
) -> Result<(), PostgresSidecarError> {
    if !owner.is_current() || owner.root() != app_data_root {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if data_dir.parent() != Some(app_data_root)
        || data_dir.file_name().and_then(|name| name.to_str())
            != Some(format!("postgresql-17-{instance_id}").as_str())
    {
        return Err(PostgresSidecarError::DataDirectoryInvalid);
    }
    let metadata =
        fs::metadata(data_dir).map_err(|_| PostgresSidecarError::DataDirectoryInvalid)?;
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
    startup_journal::recover_mid_phase(owner, app_data_root, instance_id, data_dir).map_err(
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
    helper_journal::recover_mid_phase(owner, app_data_root, instance_id, data_dir).map_err(
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
    Ok(())
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
    use crate::postgres_sidecar::kernel_start_lock::KernelStartLock;
    use crate::postgres_sidecar::{PostgresBundleDigest, PostgresSidecarError, PostgresStartLock};
    use std::fs::{self, File, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;
    use wrok_bot_macos_process::ProcessIdentity;

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }

    fn owner_observation_hex() -> String {
        let identity = ProcessIdentity::capture(std::process::id()).expect("self");
        encode_hex(&identity.evidence_bytes().expect("evidence"))
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let parent = path.parent().unwrap();
        File::open(parent).unwrap().sync_all().unwrap();
    }

    fn plant_stale_lock(root: &Path, instance: &str) -> PathBuf {
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
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        lock_path
    }

    fn data_dir_ids(data_dir: &Path) -> (u64, u64) {
        let metadata = fs::metadata(data_dir).unwrap();
        (metadata.dev(), metadata.ino())
    }

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
        fs::write(
            &journal,
            b"{\"schema\":\"openbot-postgres-startup\",\"phase\":\"spawn_entered\"}",
        )
        .unwrap();
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

    #[test]
    fn spawn_entered_null_child_deletes_and_reclaims_start_lock() {
        let root = temp_root("013-spawn-delete");
        let instance = "c".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "34".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": null,
            "phase": "spawn_entered"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(!journal.exists(), "spawn_entered journal should be deleted");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn child_observed_absent_child_advances_to_exit_confirmed_and_reclaims() {
        let root = temp_root("013-child-exit");
        let instance = "d".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "56".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let bytes = fs::read(&journal).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["phase"], "exit_confirmed");
        assert_eq!(value["childObservation"], child_hex);
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn crash_after_mid_phase_durable_write_restarts_from_files() {
        let root = temp_root("036-crash-during-recovery");
        let instance = "f".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "56".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let kernel = KernelStartLock::acquire(&root, &instance).unwrap();
        super::recover_mid_phase_journals(&kernel, &root, &instance, &data_dir).unwrap();
        let after_crash_point: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after_crash_point["phase"], "exit_confirmed");
        assert!(
            lock_path.is_file(),
            "start-lock must remain when recovery crashes before reclaim"
        );
        drop(kernel);
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let after_restart: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after_restart["phase"], "exit_confirmed");
        assert_eq!(after_restart["childObservation"], child_hex);
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn live_child_observed_refuses_write_and_keeps_start_lock() {
        let root = temp_root("013-live-child");
        let instance = "e".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let before = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "78".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        let before_bytes = serde_json::to_vec(&before).unwrap();
        write_private(&journal, &before_bytes);
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(matches!(
            rejected,
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        ));
        assert_eq!(fs::read(&journal).unwrap(), before_bytes);
        assert!(lock_path.is_file());
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn helper_spawn_entered_null_child_deletes_and_reclaims() {
        let root = temp_root("013-helper-delete");
        let instance = "f".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "9a".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_postgres",
            "childObservation": null,
            "phase": "spawn_entered"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(!journal.exists());
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn existing_version_pg_ctl_exit_confirmed_completes_helpers_and_reclaims() {
        let root = temp_root("015-pgctl-complete");
        let instance = "17".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data_dir.join("PG_VERSION"), b"17\n").unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "ab".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_pg_ctl",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(value["phase"], "helpers_complete");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn version_postgres_exit_confirmed_does_not_complete_or_reclaim() {
        let root = temp_root("015-version-incomplete");
        let instance = "18".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data_dir.join("PG_VERSION"), b"17\n").unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let before = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "cd".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_postgres",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        let before_bytes = serde_json::to_vec(&before).unwrap();
        write_private(&journal, &before_bytes);
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(lock_path.is_file());
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after["phase"], "exit_confirmed");
        assert_eq!(after["helperKind"], "version_postgres");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn fresh_initdb_exit_confirmed_completes_helpers_and_reclaims() {
        let root = temp_root("015-initdb-complete");
        let instance = "19".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        // Fresh: empty data dir, no PG_VERSION
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "ef".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "initdb",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(value["phase"], "helpers_complete");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }
}
