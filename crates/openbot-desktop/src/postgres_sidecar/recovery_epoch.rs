//! Installation-local recovery epoch evidence for controlled start-lock reclaim (V6-PR-014).
//!
//! Minting happens only on the verified Quiescent reclaim path. V6-PR-016 compares a consumed
//! epoch file so unreclaimed epochs block new secret writes; V6-PR-017/018 may write that consumed
//! witness on secret reconcile. V6-PR-019 plants `.auth-invalidation-required-v1` on the same
//! consume path as a durable obligation. V6-PR-020 may clear that file after a successful
//! desktop-local auth_generation bump. V6-PR-024 plants `.auth-invalidation-applied-v1` after
//! that bump so a failed clear cannot cause a second bump for the same epoch. This module does
//! not itself bump auth_generation, open Application, or claim backup RestoreAuthorized.

use super::kernel_start_lock::KernelStartLock;
use super::{
    PostgresSidecarError, encode_hex, path_matches_open_file, sync_directory, valid_instance_id,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const EPOCH_HEADER: &str = "openbot-postgres-recovery-epoch-v1";
const CONSUMED_HEADER: &str = "openbot-postgres-consumed-recovery-epoch-v1";
const AUTH_INVALIDATION_HEADER: &str = "openbot-postgres-auth-invalidation-required-v1";
const AUTH_INVALIDATION_APPLIED_HEADER: &str = "openbot-postgres-auth-invalidation-applied-v1";
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
                EpochFileObservation {
                    path: &path,
                    file: &old_file,
                    bytes: &old_bytes,
                },
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

/// Exact prior epoch file, borrowed without granting replacement authority.
struct EpochFileObservation<'a> {
    path: &'a Path,
    file: &'a File,
    bytes: &'a [u8],
}

fn replace_exact(
    owner: &KernelStartLock,
    root: &Path,
    instance_id: &str,
    previous: EpochFileObservation<'_>,
    bytes: Vec<u8>,
    epoch_hex: String,
) -> Result<RecoveryEpoch, PostgresSidecarError> {
    let EpochFileObservation {
        path,
        file: old_file,
        bytes: old_bytes,
    } = previous;
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

/// Remove a matching auth-invalidation-required witness after generation was advanced (V6-PR-020).
/// Absence is success. Mismatch or corrupt file fails closed.
pub(super) fn clear_auth_invalidation_required(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    current: &RecoveryEpoch,
) -> Result<(), PostgresSidecarError> {
    if !owner.is_current()
        || owner.root() != app_data_root
        || !valid_instance_id(instance_id)
        || !current.is_current()
    {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let path = auth_invalidation_path(app_data_root, instance_id);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
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
            let hex = parse_epoch_bytes_with_header(&bytes, instance_id, AUTH_INVALIDATION_HEADER)?;
            if hex != current.epoch_hex()
                || !path_matches_open_file(&path, &file, &bytes, true)
                || !owner.is_current()
            {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            drop(file);
            fs::remove_file(&path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            sync_directory(app_data_root)
                .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
            if !owner.is_current() || !current.is_current() {
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
            Ok(())
        }
        Err(_) => Err(PostgresSidecarError::StartLockGuardInvalid),
    }
}

/// Plant auth-invalidation-applied equal to `current` (V6-PR-024). Idempotent when matching.
pub(super) fn write_auth_invalidation_applied(
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
        AUTH_INVALIDATION_APPLIED_HEADER,
        &auth_invalidation_applied_path(app_data_root, instance_id),
    )
}

/// True when auth-invalidation-applied exists and matches `current` epoch.
pub(super) fn auth_invalidation_applied(
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
        AUTH_INVALIDATION_APPLIED_HEADER,
        &auth_invalidation_applied_path(app_data_root, instance_id),
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

fn auth_invalidation_applied_path(root: &Path, instance_id: &str) -> PathBuf {
    root.join(format!(
        ".postgresql-17-{instance_id}.auth-invalidation-applied-v1"
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
    let mut lines = text.split('\n');
    if lines.next() != Some(header) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let instance = lines
        .next()
        .and_then(|line| line.strip_prefix("instance="))
        .ok_or(PostgresSidecarError::StartLockGuardInvalid)?;
    let epoch_hex = lines
        .next()
        .and_then(|line| line.strip_prefix("epoch="))
        .ok_or(PostgresSidecarError::StartLockGuardInvalid)?;
    if instance != instance_id
        || !valid_instance_id(instance)
        || !valid_lower_hex(epoch_hex, EPOCH_HEX_BYTES)
        || lines.next() != Some("")
        || lines.next().is_some()
    {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    Ok(epoch_hex.to_owned())
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
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
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

    fn read_epoch_hex(path: &Path, instance: &str) -> String {
        parse_epoch_bytes(&fs::read(path).unwrap(), instance).unwrap()
    }

    fn record_bytes(header: &str, instance: &str, epoch: &str) -> Vec<u8> {
        format!("{header}\ninstance={instance}\nepoch={epoch}\n").into_bytes()
    }

    fn malformed_records(
        header: &str,
        instance: &str,
        epoch: &str,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let canonical = String::from_utf8(record_bytes(header, instance, epoch)).unwrap();
        vec![
            (
                "reversed",
                format!("{header}\nepoch={epoch}\ninstance={instance}\n").into_bytes(),
            ),
            (
                "blank-middle",
                canonical.replacen("\n", "\n\n", 1).into_bytes(),
            ),
            ("blank-end", format!("{canonical}\n").into_bytes()),
            ("crlf", canonical.replace('\n', "\r\n").into_bytes()),
            (
                "missing-final-lf",
                canonical.trim_end_matches('\n').as_bytes().to_vec(),
            ),
            ("unknown", format!("{canonical}other=value\n").into_bytes()),
            (
                "duplicate-instance",
                format!("{canonical}instance={instance}\n").into_bytes(),
            ),
            (
                "duplicate-epoch",
                format!("{canonical}epoch={epoch}\n").into_bytes(),
            ),
            (
                "missing-instance",
                format!("{header}\nepoch={epoch}\n").into_bytes(),
            ),
            (
                "missing-epoch",
                format!("{header}\ninstance={instance}\n").into_bytes(),
            ),
            (
                "wrong-instance",
                record_bytes(header, &"f".repeat(64), epoch),
            ),
            (
                "uppercase-instance",
                record_bytes(header, &instance.to_uppercase(), epoch),
            ),
            (
                "uppercase-epoch",
                record_bytes(header, instance, &epoch.to_uppercase()),
            ),
            ("short-epoch", record_bytes(header, instance, &epoch[..63])),
            (
                "long-epoch",
                record_bytes(header, instance, &format!("{epoch}0")),
            ),
            (
                "nonhex-epoch",
                record_bytes(header, instance, &"g".repeat(64)),
            ),
            (
                "wrong-header",
                record_bytes("unknown-epoch-v1", instance, epoch),
            ),
            ("invalid-utf8", vec![0xff]),
        ]
    }

    #[test]
    fn canonical_epoch_records_accept_all_four_headers() {
        let instance = "ab".repeat(32);
        let epoch = "cd".repeat(32);
        for header in [
            EPOCH_HEADER,
            CONSUMED_HEADER,
            AUTH_INVALIDATION_HEADER,
            AUTH_INVALIDATION_APPLIED_HEADER,
        ] {
            assert_eq!(
                parse_epoch_bytes_with_header(
                    &record_bytes(header, &instance, &epoch),
                    &instance,
                    header
                )
                .unwrap(),
                epoch
            );
        }
    }

    #[test]
    fn malformed_epoch_records_reject_all_four_headers() {
        let instance = "ab".repeat(32);
        let epoch = "cd".repeat(32);
        let mut accepted = Vec::new();
        for header in [
            EPOCH_HEADER,
            CONSUMED_HEADER,
            AUTH_INVALIDATION_HEADER,
            AUTH_INVALIDATION_APPLIED_HEADER,
        ] {
            for (name, bytes) in malformed_records(header, &instance, &epoch) {
                let result = parse_epoch_bytes_with_header(&bytes, &instance, header);
                eprintln!(
                    "epoch-record case={name} header={header} accepted={}",
                    result.is_ok()
                );
                match result {
                    Err(PostgresSidecarError::StartLockGuardInvalid) => {}
                    other => accepted.push(format!("{header}/{name}: {other:?}")),
                }
            }
        }
        assert!(
            accepted.is_empty(),
            "malformed records accepted: {accepted:?}"
        );
    }

    fn plant_record(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RecordSnapshot {
        path: PathBuf,
        bytes: Vec<u8>,
        mode: u32,
        device: u64,
        inode: u64,
        links: u64,
    }

    fn snapshot_records(root: &Path) -> Vec<RecordSnapshot> {
        assert_eq!(fs::metadata(root).unwrap().mode() & 0o777, 0o700);
        let mut records = Vec::new();
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_file() {
                assert_eq!(metadata.mode() & 0o777, 0o600);
                records.push(RecordSnapshot {
                    bytes: fs::read(&path).unwrap(),
                    path,
                    mode: metadata.mode(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    links: metadata.nlink(),
                });
            }
        }
        records.sort_by(|left, right| left.path.cmp(&right.path));
        records
    }

    #[test]
    fn malformed_epoch_reclaim_preserves_all_prior_records() {
        let instance = "ab".repeat(32);
        let epoch = "cd".repeat(32);
        for (name, bytes) in malformed_records(EPOCH_HEADER, &instance, &epoch) {
            let root = temp_root(name);
            let data_dir = plant_data_dir(&root, &instance);
            plant_stale_lock(&root, &instance);
            plant_record(&epoch_path(&root, &instance), &bytes);
            for (header, path) in [
                (CONSUMED_HEADER, consumed_path(&root, &instance)),
                (
                    AUTH_INVALIDATION_HEADER,
                    auth_invalidation_path(&root, &instance),
                ),
                (
                    AUTH_INVALIDATION_APPLIED_HEADER,
                    auth_invalidation_applied_path(&root, &instance),
                ),
            ] {
                plant_record(&path, &record_bytes(header, &instance, &epoch));
            }
            drop(KernelStartLock::acquire(&root, &instance).unwrap());
            let before = snapshot_records(&root);
            let rejected = PostgresStartLock::acquire_with_data_dir(
                &root,
                &instance,
                PostgresBundleDigest([0x11; 32]),
                &data_dir,
            );
            assert!(
                matches!(
                    rejected,
                    Err(PostgresSidecarError::StartLockRecoveryRequired)
                ),
                "{name}: {rejected:?}"
            );
            assert_eq!(snapshot_records(&root), before, "{name}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn malformed_consumed_reclaim_preserves_prior_epoch() {
        let root = temp_root("065-consumed-reclaim");
        let instance = "ab".repeat(32);
        let epoch = "cd".repeat(32);
        let data_dir = plant_data_dir(&root, &instance);
        plant_stale_lock(&root, &instance);
        plant_record(
            &epoch_path(&root, &instance),
            &record_bytes(EPOCH_HEADER, &instance, &epoch),
        );
        let malformed = String::from_utf8(record_bytes(CONSUMED_HEADER, &instance, &epoch))
            .unwrap()
            .replace('\n', "\r\n");
        plant_record(&consumed_path(&root, &instance), malformed.as_bytes());
        drop(KernelStartLock::acquire(&root, &instance).unwrap());
        let before = snapshot_records(&root);
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        let after = snapshot_records(&root);
        assert!(
            matches!(
                rejected,
                Err(PostgresSidecarError::StartLockRecoveryRequired)
            ),
            "{rejected:?}"
        );
        assert_eq!(
            after, before,
            "rejection must preserve the prior epoch and consumed evidence"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_labeled_records_never_grant_consumption_or_secret_writes() {
        use crate::postgres_sidecar::{
            PostgresSecretStoreError, ReviewedPostgresKeyStoreService, tests::MemorySecretStore,
        };
        for header in [
            CONSUMED_HEADER,
            AUTH_INVALIDATION_HEADER,
            AUTH_INVALIDATION_APPLIED_HEADER,
        ] {
            for (name, _) in malformed_records(header, &"ab".repeat(32), &"cd".repeat(32)) {
                let root = temp_root(name);
                let instance = "ab".repeat(32);
                let data_dir = plant_data_dir(&root, &instance);
                plant_stale_lock(&root, &instance);
                let lock = PostgresStartLock::acquire_with_data_dir(
                    &root,
                    &instance,
                    PostgresBundleDigest([0x11; 32]),
                    &data_dir,
                )
                .unwrap();
                let current = lock.recovery_epoch.as_ref().unwrap();
                let epoch = current.epoch_hex();
                let bytes = malformed_records(header, &instance, epoch)
                    .into_iter()
                    .find(|(case, _)| *case == name)
                    .unwrap()
                    .1;
                for (label, path) in [
                    (CONSUMED_HEADER, consumed_path(&root, &instance)),
                    (
                        AUTH_INVALIDATION_HEADER,
                        auth_invalidation_path(&root, &instance),
                    ),
                    (
                        AUTH_INVALIDATION_APPLIED_HEADER,
                        auth_invalidation_applied_path(&root, &instance),
                    ),
                ] {
                    let body = if label == header {
                        bytes.clone()
                    } else {
                        record_bytes(label, &instance, epoch)
                    };
                    plant_record(&path, &body);
                }
                let before = snapshot_records(&root);
                let owner = &lock.kernel_guard;
                let rejected = match header {
                    CONSUMED_HEADER => {
                        assert!(matches!(
                            invalidation_pending(owner, &root, &instance, Some(current)),
                            Err(PostgresSidecarError::StartLockGuardInvalid)
                        ));
                        write_consumed_matching(owner, &root, &instance, current)
                    }
                    AUTH_INVALIDATION_HEADER => {
                        assert!(matches!(
                            lock.auth_invalidation_outstanding(),
                            Err(PostgresSidecarError::StartLockGuardInvalid)
                        ));
                        assert!(matches!(
                            lock.clear_auth_invalidation_after_advance(),
                            Err(PostgresSidecarError::StartLockGuardInvalid)
                        ));
                        write_auth_invalidation_required(owner, &root, &instance, current)
                    }
                    AUTH_INVALIDATION_APPLIED_HEADER => {
                        assert!(matches!(
                            lock.auth_invalidation_applied(),
                            Err(PostgresSidecarError::StartLockGuardInvalid)
                        ));
                        write_auth_invalidation_applied(owner, &root, &instance, current)
                    }
                    _ => unreachable!(),
                };
                assert!(
                    matches!(rejected, Err(PostgresSidecarError::StartLockGuardInvalid)),
                    "{header}/{name}: {rejected:?}"
                );
                if header != AUTH_INVALIDATION_APPLIED_HEADER {
                    let store = MemorySecretStore::empty();
                    let service = ReviewedPostgresKeyStoreService::from_reviewed_release(
                        "com.example.065.private-test",
                    )
                    .unwrap();
                    let fresh = lock.inspect_data_directory(&data_dir).unwrap();
                    assert!(
                        matches!(
                            lock.load_or_create_scram_secret(&store, &service, &fresh),
                            Err(PostgresSecretStoreError::ReconciliationRequired)
                        ),
                        "{header}/{name}"
                    );
                    assert_eq!(store.write_count(), 0, "{header}/{name}");
                    assert!(lock.control_invalidation_pending());
                }
                assert_eq!(snapshot_records(&root), before, "{header}/{name}");
                drop(lock);
                fs::remove_dir_all(root).unwrap();
            }
        }
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
        let first_hex = read_epoch_hex(&epoch_path, &instance);
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
        let second_hex = read_epoch_hex(&epoch_path, &instance);
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
        let hex = read_epoch_hex(&epoch_path, &instance);
        drop(first);

        let second = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(second.is_ok(), "{second:?}");
        assert_eq!(read_epoch_hex(&epoch_path, &instance), hex);
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

    fn auth_invalidation_applied_path_for(root: &Path, instance: &str) -> PathBuf {
        root.join(format!(
            ".postgresql-17-{instance}.auth-invalidation-applied-v1"
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
        let hex = read_epoch_hex(&epoch_path_for(&root, &instance), &instance);
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
    fn clear_auth_invalidation_required_removes_matching_file() {
        let root = temp_root("020-clear-auth");
        let instance = "a".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let lock = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        let hex = read_epoch_hex(&epoch_path_for(&root, &instance), &instance);
        let auth_path = auth_invalidation_path_for(&root, &instance);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&auth_path).unwrap();
        let body = format!(
            "openbot-postgres-auth-invalidation-required-v1\ninstance={instance}\nepoch={hex}\n"
        );
        std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
        file.sync_all().unwrap();
        assert!(lock.auth_invalidation_outstanding().unwrap());
        lock.clear_auth_invalidation_after_advance().unwrap();
        assert!(!auth_path.exists());
        assert!(!lock.auth_invalidation_outstanding().unwrap());
        lock.clear_auth_invalidation_after_advance().unwrap();
        drop(lock);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn write_auth_invalidation_applied_is_idempotent_when_matching() {
        let root = temp_root("024-applied-idem");
        let instance = "b".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let lock = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        assert!(!lock.auth_invalidation_applied().unwrap());
        lock.mark_auth_invalidation_applied().unwrap();
        assert!(lock.auth_invalidation_applied().unwrap());
        let path = auth_invalidation_applied_path_for(&root, &instance);
        let before = fs::read(&path).unwrap();
        lock.mark_auth_invalidation_applied().unwrap();
        assert_eq!(before, fs::read(&path).unwrap());
        drop(lock);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn applied_match_allows_clear_required_without_replant() {
        let root = temp_root("024-clear-only");
        let instance = "c".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let lock = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        let hex = read_epoch_hex(&epoch_path_for(&root, &instance), &instance);
        let auth_path = auth_invalidation_path_for(&root, &instance);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&auth_path).unwrap();
        let body = format!(
            "openbot-postgres-auth-invalidation-required-v1\ninstance={instance}\nepoch={hex}\n"
        );
        std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
        file.sync_all().unwrap();
        assert!(lock.auth_invalidation_outstanding().unwrap());
        lock.mark_auth_invalidation_applied().unwrap();
        assert!(lock.auth_invalidation_applied().unwrap());
        lock.clear_auth_invalidation_after_advance().unwrap();
        assert!(!auth_path.exists());
        assert!(!lock.auth_invalidation_outstanding().unwrap());
        assert!(lock.auth_invalidation_applied().unwrap());
        drop(lock);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_applied_fails_closed() {
        let root = temp_root("024-bad-applied");
        let instance = "1".repeat(64);
        let data_dir = plant_data_dir(&root, &instance);
        let _ = plant_stale_lock(&root, &instance);
        let lock = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        )
        .unwrap();
        let path = auth_invalidation_applied_path_for(&root, &instance);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&path).unwrap();
        std::io::Write::write_all(&mut file, b"not-an-applied-witness\n").unwrap();
        file.sync_all().unwrap();
        assert!(lock.auth_invalidation_applied().is_err());
        drop(lock);
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
