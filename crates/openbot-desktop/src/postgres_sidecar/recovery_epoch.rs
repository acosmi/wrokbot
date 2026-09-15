//! Installation-local recovery epoch evidence for controlled start-lock reclaim (V6-PR-014).
//!
//! Minting happens only on the verified Quiescent reclaim path. V6-PR-016 compares a consumed
//! epoch file so unreclaimed epochs block new secret writes; V6-PR-017/018 may write that consumed
//! witness on secret reconcile. V6-PR-019 plants `.auth-invalidation-required-v1` on the same
//! consume path as a durable obligation for a later auth_generation bump. This module does not
//! itself bump auth_generation, open Application, or claim backup RestoreAuthorized.

use super::kernel_start_lock::KernelStartLock;
use super::{
    encode_hex, path_matches_open_file, sync_directory, valid_instance_id, PostgresSidecarError,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const EPOCH_HEADER: &str = "openbot-postgres-recovery-epoch-v1";
const CONSUMED_HEADER: &str = "openbot-postgres-consumed-recovery-epoch-v1";
const AUTH_INVALIDATION_HEADER: &str = "openbot-postgres-auth-invalidation-required-v1";
const EPOCH_BYTES: usize = 32;
const EPOCH_HEX_BYTES: usize = EPOCH_BYTES * 2;
const MAX_FILE_BYTES: usize = 512;
const MAX_CANDIDATE_ATTEMPTS: usize = 8;
const CANDIDATE_NONCE_BYTES: usize = 16;

/// Sealed local recovery epoch bound to one instance file.
pub(super) struct RecoveryEpoch {
    path: PathBuf,
    bytes: Vec<u8>,
    file: File,
    epoch_hex: String,
}

impl core::fmt::Debug for RecoveryEpoch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveryEpoch(<sealed>)")
    }
}

impl RecoveryEpoch {
    pub(super) fn epoch_hex(&self) -> &str {
        &self.epoch_hex
    }

    pub(super) fn is_current(&self) -> bool {
        path_matches_open_file(&self.path, &self.file, &self.bytes, true)
    }
}

/// Load an existing epoch file, or `Ok(None)` when absent.
pub(super) fn load_optional(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
) -> Result<Option<RecoveryEpoch>, PostgresSidecarError> {
    if !owner.is_current() || owner.root() != app_data_root || !valid_instance_id(instance_id) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let path = epoch_path(app_data_root, instance_id);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(metadata) => {
            if !valid_epoch_metadata(&metadata, None) {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            let mut file =
                secure_open_read(&path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            let epoch_hex = parse_epoch_bytes(&bytes, instance_id)?;
            if !path_matches_open_file(&path, &file, &bytes, true) || !owner.is_current() {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            Ok(Some(RecoveryEpoch {
                path,
                bytes,
                file,
                epoch_hex,
            }))
        }
        Err(_) => Err(PostgresSidecarError::StartLockGuardInvalid),
    }
}

/// Mint a fresh random epoch, or replace an existing same-instance file, before start-lock reclaim.
pub(super) fn mint_or_replace_for_reclaim(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
) -> Result<RecoveryEpoch, PostgresSidecarError> {
    if !owner.is_current() || owner.root() != app_data_root || !valid_instance_id(instance_id) {
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    let path = epoch_path(app_data_root, instance_id);
    let mut random = [0_u8; EPOCH_BYTES];
    getrandom::fill(&mut random).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
    let epoch_hex = encode_hex(&random);
    let bytes = format!("{EPOCH_HEADER}\ninstance={instance_id}\nepoch={epoch_hex}\n").into_bytes();
    if bytes.len() > MAX_FILE_BYTES {
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }

    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            publish_new(owner, app_data_root, instance_id, &path, bytes, epoch_hex)
        }
        Ok(metadata) => {
            if !valid_epoch_metadata(&metadata, None) {
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
            let mut old_file = secure_open_read(&path)
                .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
            let mut old_bytes = Vec::new();
            old_file
                .read_to_end(&mut old_bytes)
                .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
            let old_hex = parse_epoch_bytes(&old_bytes, instance_id)
                .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
            if !path_matches_open_file(&path, &old_file, &old_bytes, true) {
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
            if old_hex == epoch_hex {
                // Astronomically unlikely; refuse reuse rather than publish a collision.
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
            replace_exact(
                owner,
                app_data_root,
                instance_id,
                &path,
                &old_file,
                &old_bytes,
                bytes,
                epoch_hex,
            )
        }
        Err(_) => Err(PostgresSidecarError::StartLockRecoveryRequired),
    }
}

fn publish_new(
    owner: &KernelStartLock,
    root: &Path,
    instance_id: &str,
    path: &Path,
    bytes: Vec<u8>,
    epoch_hex: String,
) -> Result<RecoveryEpoch, PostgresSidecarError> {
    let (candidate_path, mut candidate) = create_candidate(root, instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    if !path_matches_open_file(&candidate_path, &candidate, &bytes, true) || !owner.is_current() {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    match fs::hard_link(&candidate_path, path) {
        Ok(()) => {
            if sync_directory(root).is_err()
                || !path_matches_open_file(path, &candidate, &bytes, false)
                || fs::remove_file(&candidate_path).is_err()
                || sync_directory(root).is_err()
                || !path_matches_open_file(path, &candidate, &bytes, true)
                || !owner.is_current()
            {
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
            Ok(RecoveryEpoch {
                path: path.to_owned(),
                bytes,
                file: candidate,
                epoch_hex,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&candidate_path);
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        }
        Err(_) => {
            let _ = fs::remove_file(&candidate_path);
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        }
    }
}

fn replace_exact(
    owner: &KernelStartLock,
    root: &Path,
    instance_id: &str,
    path: &Path,
    old_file: &File,
    old_bytes: &[u8],
    bytes: Vec<u8>,
    epoch_hex: String,
) -> Result<RecoveryEpoch, PostgresSidecarError> {
    let (candidate_path, mut candidate) = create_candidate(root, instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    if !path_matches_open_file(path, old_file, old_bytes, true)
        || !path_matches_open_file(&candidate_path, &candidate, &bytes, true)
        || !owner.is_current()
    {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    if fs::rename(&candidate_path, path).is_err()
        || sync_directory(root).is_err()
        || !path_matches_open_file(path, &candidate, &bytes, true)
        || !owner.is_current()
    {
        return Err(PostgresSidecarError::StartLockRecoveryRequired);
    }
    Ok(RecoveryEpoch {
        path: path.to_owned(),
        bytes,
        file: candidate,
        epoch_hex,
    })
}

/// Write consumed epoch equal to `current`, creating or replacing the witness file.
/// Never invents a different epoch value.
pub(super) fn write_consumed_matching(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
) -> Result<(), PostgresSidecarError> {
    write_labeled_epoch_witness(
        owner,
        app_data_root,
        instance_id,
        current,
        CONSUMED_HEADER,
        &consumed_path(app_data_root, instance_id),
    )
}

/// Plant auth-invalidation-required equal to `current` (V6-PR-019). Idempotent when matching.
pub(super) fn write_auth_invalidation_required(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
) -> Result<(), PostgresSidecarError> {
    write_labeled_epoch_witness(
        owner,
        app_data_root,
        instance_id,
        current,
        AUTH_INVALIDATION_HEADER,
        &auth_invalidation_path(app_data_root, instance_id),
    )
}

/// True when auth-invalidation-required exists and matches `current` epoch.
pub(super) fn auth_invalidation_required(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
) -> Result<bool, PostgresSidecarError> {
    if !owner.is_current()
        || owner.root() != app_data_root
        || !valid_instance_id(instance_id)
        || !current.is_current()
    {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    match load_labeled_epoch_hex(
        owner,
        app_data_root,
        instance_id,
        AUTH_INVALIDATION_HEADER,
        &auth_invalidation_path(app_data_root, instance_id),
    )? {
        None => Ok(false),
        Some(hex) => Ok(hex == current.epoch_hex()),
    }
}

fn write_labeled_epoch_witness(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
    header: &str,
    path: &Path,
) -> Result<(), PostgresSidecarError> {
    if !owner.is_current()
        || owner.root() != app_data_root
        || !valid_instance_id(instance_id)
        || !current.is_current()
    {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let epoch_hex = current.epoch_hex().to_owned();
    let bytes = format!("{header}\ninstance={instance_id}\nepoch={epoch_hex}\n").into_bytes();
    if bytes.len() > MAX_FILE_BYTES {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (candidate_path, mut candidate) = create_candidate(app_data_root, instance_id)
                .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            if candidate
                .write_all(&bytes)
                .and_then(|()| candidate.sync_all())
                .is_err()
            {
                let _ = fs::remove_file(&candidate_path);
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            if !path_matches_open_file(&candidate_path, &candidate, &bytes, true)
                || !owner.is_current()
            {
                let _ = fs::remove_file(&candidate_path);
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            match fs::hard_link(&candidate_path, path) {
                Ok(()) => {
                    if sync_directory(app_data_root).is_err()
                        || !path_matches_open_file(path, &candidate, &bytes, false)
                        || fs::remove_file(&candidate_path).is_err()
                        || sync_directory(app_data_root).is_err()
                        || !path_matches_open_file(path, &candidate, &bytes, true)
                        || !owner.is_current()
                        || !current.is_current()
                    {
                        return Err(PostgresSidecarError::StartLockGuardInvalid);
                    }
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(&candidate_path);
                    write_labeled_epoch_replace(
                        owner,
                        app_data_root,
                        instance_id,
                        current,
                        header,
                        path,
                        bytes,
                    )
                }
                Err(_) => {
                    let _ = fs::remove_file(&candidate_path);
                    Err(PostgresSidecarError::StartLockGuardInvalid)
                }
            }
        }
        Ok(_) => write_labeled_epoch_replace(
            owner,
            app_data_root,
            instance_id,
            current,
            header,
            path,
            bytes,
        ),
        Err(_) => Err(PostgresSidecarError::StartLockGuardInvalid),
    }
}

fn write_labeled_epoch_replace(
    owner: &KernelStartLock,
    root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
    header: &str,
    path: &Path,
    bytes: Vec<u8>,
) -> Result<(), PostgresSidecarError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    if !valid_epoch_metadata(&metadata, None) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let mut old_file =
        secure_open_read(path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    let mut old_bytes = Vec::new();
    old_file
        .read_to_end(&mut old_bytes)
        .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    let old_hex = parse_epoch_bytes_with_header(&old_bytes, instance_id, header)?;
    if !path_matches_open_file(path, &old_file, &old_bytes, true) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if old_hex == current.epoch_hex() {
        return Ok(());
    }
    let (candidate_path, mut candidate) = create_candidate(root, instance_id)
        .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if !path_matches_open_file(&candidate_path, &candidate, &bytes, true) || !owner.is_current() {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if !path_matches_open_file(path, &old_file, &old_bytes, true) {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if fs::rename(&candidate_path, path).is_err()
        || sync_directory(root).is_err()
        || !owner.is_current()
        || !current.is_current()
    {
        let _ = fs::remove_file(&candidate_path);
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    Ok(())
}

fn auth_invalidation_path(root: &Path, instance_id: &str) -> PathBuf {
    root.join(format!(
        ".postgresql-17-{instance_id}.auth-invalidation-required-v1"
    ))
}

fn load_labeled_epoch_hex(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    header: &str,
    path: &Path,
) -> Result<Option<String>, PostgresSidecarError> {
    if !owner.is_current() || owner.root() != app_data_root || !valid_instance_id(instance_id) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(metadata) => {
            if !valid_epoch_metadata(&metadata, None) {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            let mut file =
                secure_open_read(path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            let epoch_hex = parse_epoch_bytes_with_header(&bytes, instance_id, header)?;
            if !path_matches_open_file(path, &file, &bytes, true) || !owner.is_current() {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            Ok(Some(epoch_hex))
        }
        Err(_) => Err(PostgresSidecarError::StartLockGuardInvalid),
    }
}


fn consumed_path(root: &Path, instance_id: &str) -> PathBuf {
    root.join(format!(
        ".postgresql-17-{instance_id}.consumed-recovery-epoch-v1"
    ))
}

/// Fail closed on a malformed consumed file; absence is allowed (pending).
pub(super) fn ensure_consumed_readable(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
) -> Result<(), PostgresSidecarError> {
    let _ = load_consumed_hex(owner, app_data_root, instance_id)?;
    Ok(())
}

/// True when a current recovery epoch exists and has not been consumed at the same value.
pub(super) fn invalidation_pending(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: Option<&RecoveryEpoch>,
) -> Result<bool, PostgresSidecarError> {
    let Some(current) = current else {
        return Ok(false);
    };
    match load_consumed_hex(owner, app_data_root, instance_id)? {
        None => Ok(true),
        Some(consumed) => Ok(consumed != current.epoch_hex()),
    }
}

fn load_consumed_hex(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
) -> Result<Option<String>, PostgresSidecarError> {
    load_labeled_epoch_hex(
        owner,
        app_data_root,
        instance_id,
        CONSUMED_HEADER,
        &consumed_path(app_data_root, instance_id),
    )
}

fn epoch_path(root: &Path, instance_id: &str) -> PathBuf {
    root.join(format!(".postgresql-17-{instance_id}.recovery-epoch-v1"))
}

fn parse_epoch_bytes(bytes: &[u8], instance_id: &str) -> Result<String, PostgresSidecarError> {
    parse_epoch_bytes_with_header(bytes, instance_id, EPOCH_HEADER)
}

fn parse_epoch_bytes_with_header(
    bytes: &[u8],
    instance_id: &str,
    header: &str,
) -> Result<String, PostgresSidecarError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    let mut lines = text.lines();
    if lines.next() != Some(header) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let mut saw_instance = false;
    let mut epoch_hex = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("instance=") {
            if value != instance_id || saw_instance || !valid_instance_id(value) {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            saw_instance = true;
        } else if let Some(value) = line.strip_prefix("epoch=") {
            if epoch_hex.is_some() || !valid_lower_hex(value, EPOCH_HEX_BYTES) {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            epoch_hex = Some(value.to_owned());
        } else if !line.is_empty() {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
    }
    if !saw_instance {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    epoch_hex.ok_or(PostgresSidecarError::StartLockGuardInvalid)
}

fn valid_epoch_metadata(metadata: &fs::Metadata, expected_len: Option<usize>) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() >= 1
            && metadata.len() <= MAX_FILE_BYTES as u64
            && expected_len.is_none_or(|length| metadata.len() == length as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, expected_len);
        false
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_candidate(
    root: &Path,
    instance_id: &str,
) -> Result<(PathBuf, File), PostgresSidecarError> {
    for _ in 0..MAX_CANDIDATE_ATTEMPTS {
        let mut nonce = [0_u8; CANDIDATE_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        let path = root.join(format!(
            ".postgresql-17-{instance_id}.recovery-epoch-v1.candidate-{}",
            encode_hex(&nonce)
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
            options.custom_flags(0x100 | 0x4);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(PostgresSidecarError::StartLockRecoveryRequired),
        }
    }
    Err(PostgresSidecarError::StartLockRecoveryRequired)
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
    use super::*;
    use crate::postgres_sidecar::{PostgresBundleDigest, PostgresStartLock};
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wrok-v6-pr-014-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
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

    fn epoch_path_for(root: &Path, instance: &str) -> PathBuf {
        root.join(format!(".postgresql-17-{instance}.recovery-epoch-v1"))
    }

    fn read_epoch_hex(path: &Path) -> String {
        let text = fs::read_to_string(path).unwrap();
        text.lines()
            .find_map(|line| line.strip_prefix("epoch=").map(str::to_owned))
            .expect("epoch line")
    }

    #[test]
    fn reclaim_path_mints_new_epoch_and_second_reclaim_rotates() {
        let root = temp_root("mint");
        let instance = "a".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let epoch_path = epoch_path_for(&root, &instance);
        assert!(!epoch_path.exists());

        let first = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(first.is_ok(), "{first:?}");
        assert!(epoch_path.is_file());
        let first_hex = read_epoch_hex(&epoch_path);
        assert_eq!(first_hex.len(), 64);
        drop(first.unwrap());

        // Leave a stale lock again while keeping the minted epoch.
        let _ = plant_stale_lock(&root, &instance);
        assert!(lock_path.is_file());
        let second = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(second.is_ok(), "{second:?}");
        let second_hex = read_epoch_hex(&epoch_path);
        assert_ne!(first_hex, second_hex);
        drop(second.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normal_acquire_without_stale_lock_does_not_change_existing_epoch() {
        let root = temp_root("keep");
        let instance = "b".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = plant_stale_lock(&root, &instance);
        let epoch_path = epoch_path_for(&root, &instance);
        let first = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        let hex = read_epoch_hex(&epoch_path);
        drop(first);

        let second = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(second.is_ok(), "{second:?}");
        assert_eq!(read_epoch_hex(&epoch_path), hex);
        drop(second.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_epoch_file_blocks_acquire_without_deleting_start_lock_on_reclaim_failure() {
        let root = temp_root("bad");
        let instance = "c".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let epoch_path = epoch_path_for(&root, &instance);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&epoch_path).unwrap();
        std::io::Write::write_all(&mut file, b"not-an-epoch\n").unwrap();
        file.sync_all().unwrap();

        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(
            lock_path.is_file(),
            "start-lock must remain when epoch mint/replace fails"
        );
        assert_eq!(fs::read(&epoch_path).unwrap(), b"not-an-epoch\n");
        let _ = fs::remove_dir_all(&root);
    }

    fn consumed_path_for(root: &Path, instance: &str) -> PathBuf {
        root.join(format!(
            ".postgresql-17-{instance}.consumed-recovery-epoch-v1"
        ))
    }

    fn write_consumed(root: &Path, instance: &str, epoch_hex: &str) {
        let path = consumed_path_for(root, instance);
        let body = format!(
            "openbot-postgres-consumed-recovery-epoch-v1\ninstance={instance}\nepoch={epoch_hex}\n"
        );
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&path).unwrap();
        std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }


    fn auth_invalidation_path_for(root: &Path, instance: &str) -> PathBuf {
        root.join(format!(
            ".postgresql-17-{instance}.auth-invalidation-required-v1"
        ))
    }

    fn plant_data_dir(root: &Path, instance: &str) -> PathBuf {
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        data_dir
    }

    #[test]
    fn reclaim_without_consumed_marks_invalidation_pending() {
        let root = temp_root("016-pending");
        let instance = "d".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let lock = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        assert!(lock.control_invalidation_pending());
        assert!(!consumed_path_for(&root, &instance).exists());
        assert!(!auth_invalidation_path_for(&root, &instance).exists());
        drop(lock);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn matching_consumed_clears_invalidation_pending() {
        let root = temp_root("016-match");
        let instance = "e".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let first = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        let hex = read_epoch_hex(&epoch_path_for(&root, &instance));
        drop(first);
        write_consumed(&root, &instance, &hex);
        let second = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        assert!(!second.control_invalidation_pending());
        assert!(!auth_invalidation_path_for(&root, &instance).exists());
        drop(second);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_consumed_blocks_reclaim_and_keeps_stale_start_lock() {
        let root = temp_root("016-bad-consumed");
        let instance = "f".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let lock_path = plant_stale_lock(&root, &instance);
        let consumed = consumed_path_for(&root, &instance);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&consumed).unwrap();
        std::io::Write::write_all(&mut file, b"not-consumed\n").unwrap();
        file.sync_all().unwrap();
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(lock_path.is_file(), "stale start-lock must remain");
        assert_eq!(fs::read(&consumed).unwrap(), b"not-consumed\n");
        let _ = fs::remove_dir_all(&root);
    }
}
