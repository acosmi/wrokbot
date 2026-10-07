//! Actual owned-FS observations. These are byte-adapter facts, not PG registration, authority,
//! production cleanup, hostile same-UID/ACL isolation, or other-platform acceptance.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{
    ArtifactBlob, ArtifactByteError, ArtifactByteProbe, ArtifactByteStorageLocation,
    ArtifactByteStore, ArtifactProbePhase,
};

struct OwnedFiles {
    container: PathBuf,
    root: PathBuf,
}

impl OwnedFiles {
    fn new() -> Self {
        let container =
            std::env::temp_dir().join(format!("openbot-artifact-probe-{}", Uuid::now_v7()));
        DirBuilder::new().mode(0o700).create(&container).unwrap();
        let container = fs::canonicalize(container).unwrap();
        let root = container.join("root");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { container, root }
    }

    fn bind(&self, maximum: u64) -> ArtifactByteStore {
        ArtifactByteStore::bind_private_root(File::open(&self.root).unwrap(), maximum).unwrap()
    }

    fn path(&self, location: ArtifactByteStorageLocation, id: Uuid) -> PathBuf {
        self.root
            .join(match location {
                ArtifactByteStorageLocation::Staging => "staging",
                ArtifactByteStorageLocation::Object => "objects",
            })
            .join(id.to_string())
    }
}

impl Drop for OwnedFiles {
    fn drop(&mut self) {
        let outcome = fs::remove_dir_all(&self.container);
        let absent = !self.container.exists();
        eprintln!(
            "ARTIFACT_PROBE_UNIT_CLEANUP removed={} absent={absent}",
            outcome.is_ok()
        );
        if !std::thread::panicking() {
            assert!(
                outcome.is_ok() && absent,
                "owned byte observation cleanup failed"
            );
        }
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn actual_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    file.sync_all().unwrap();
}

fn expect_retained(
    store: &ArtifactByteStore,
    id: Uuid,
    expected_location: ArtifactByteStorageLocation,
    actual: &[u8],
) {
    match store.probe_actual(id) {
        ArtifactByteProbe::Retained {
            location,
            byte_length,
            sha256,
        } => {
            assert_eq!(location, expected_location);
            assert_eq!(byte_length, actual.len() as u64);
            assert_eq!(sha256, hash(actual));
        }
        ArtifactByteProbe::Absent => panic!("real retained bytes were reported absent"),
        ArtifactByteProbe::Indeterminate => panic!("stable owned actual bytes were not observed"),
    }
}

#[test]
fn absent_requires_both_real_locations_to_be_missing() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    assert!(matches!(store.probe_actual(id), ArtifactByteProbe::Absent));
    assert!(
        !files
            .path(ArtifactByteStorageLocation::Staging, id)
            .exists()
    );
    assert!(!files.path(ArtifactByteStorageLocation::Object, id).exists());
}

#[test]
fn actual_zero_length_staging_is_retained_and_has_the_empty_full_hash() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    actual_file(
        &files.path(ArtifactByteStorageLocation::Staging, id),
        b"",
        0o600,
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Staging, b"");
}

#[test]
fn actual_zero_length_object_is_retained_and_has_the_empty_full_hash() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    actual_file(
        &files.path(ArtifactByteStorageLocation::Object, id),
        b"",
        0o400,
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Object, b"");
}

#[test]
fn partial_staging_uses_actual_length_and_full_hash_separate_from_expected() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    let expected = b"expected complete message";
    let actual = &expected[..5];
    let blob = ArtifactBlob::from_record(id, expected.len() as u64, hash(expected)).unwrap();
    actual_file(
        &files.path(ArtifactByteStorageLocation::Staging, id),
        actual,
        0o600,
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Staging, actual);
    assert_ne!(blob.byte_length(), actual.len() as u64);
    assert_ne!(*blob.sha256(), hash(actual));
    assert_eq!(blob.byte_length(), expected.len() as u64);
}

#[test]
fn sealed_actual_object_is_read_fully_without_accepting_a_record_digest() {
    let files = OwnedFiles::new();
    let store = files.bind(256 * 1024);
    let id = Uuid::now_v7();
    let mut actual = vec![b'a'; 128 * 1024];
    actual[64 * 1024] = b'b';
    actual_file(
        &files.path(ArtifactByteStorageLocation::Object, id),
        &actual,
        0o400,
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Object, &actual);
    assert_ne!(hash(&actual), hash(&vec![b'a'; actual.len()]));
}

#[test]
fn both_actual_locations_are_indeterminate_even_if_content_matches() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    actual_file(
        &files.path(ArtifactByteStorageLocation::Staging, id),
        b"same",
        0o600,
    );
    actual_file(
        &files.path(ArtifactByteStorageLocation::Object, id),
        b"same",
        0o400,
    );
    assert!(matches!(
        store.probe_actual(id),
        ArtifactByteProbe::Indeterminate
    ));
}

#[test]
fn symlink_at_either_location_is_indeterminate_without_following_it() {
    for location in [
        ArtifactByteStorageLocation::Staging,
        ArtifactByteStorageLocation::Object,
    ] {
        let files = OwnedFiles::new();
        let store = files.bind(4096);
        let id = Uuid::now_v7();
        let target = files.container.join("owned-target");
        actual_file(&target, b"must not be followed", 0o400);
        symlink(&target, files.path(location, id)).unwrap();
        assert!(matches!(
            store.probe_actual(id),
            ArtifactByteProbe::Indeterminate
        ));
        assert_eq!(fs::read(&target).unwrap(), b"must not be followed");
    }
}

#[test]
fn hard_link_with_two_actual_names_is_indeterminate() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    let path = files.path(ArtifactByteStorageLocation::Object, id);
    actual_file(&path, b"linked", 0o400);
    fs::hard_link(&path, files.container.join("owned-other-name")).unwrap();
    assert!(matches!(
        store.probe_actual(id),
        ArtifactByteProbe::Indeterminate
    ));
}

#[test]
fn unsafe_mode_and_directory_objects_are_indeterminate() {
    for mode in [0o000, 0o444, 0o640, 0o700] {
        let files = OwnedFiles::new();
        let store = files.bind(4096);
        let id = Uuid::now_v7();
        actual_file(
            &files.path(ArtifactByteStorageLocation::Object, id),
            b"private",
            mode,
        );
        assert!(matches!(
            store.probe_actual(id),
            ArtifactByteProbe::Indeterminate
        ));
    }
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    DirBuilder::new()
        .mode(0o700)
        .create(files.path(ArtifactByteStorageLocation::Object, id))
        .unwrap();
    assert!(matches!(
        store.probe_actual(id),
        ArtifactByteProbe::Indeterminate
    ));
}

#[test]
fn actual_file_over_tightened_store_limit_is_indeterminate() {
    let files = OwnedFiles::new();
    let store = files.bind(4);
    let id = Uuid::now_v7();
    actual_file(
        &files.path(ArtifactByteStorageLocation::Object, id),
        b"12345",
        0o400,
    );
    assert!(matches!(
        store.probe_actual(id),
        ArtifactByteProbe::Indeterminate
    ));
}

struct FailWithBlockedCleanup {
    staging: PathBuf,
    prefix: Vec<u8>,
    emitted: bool,
}

impl io::Read for FailWithBlockedCleanup {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.emitted {
            return Err(io::Error::other("owned input fault"));
        }
        self.emitted = true;
        fs::set_permissions(&self.staging, Permissions::from_mode(0o500))?;
        if self.prefix.is_empty() {
            return Err(io::Error::other("owned input fault before first byte"));
        }
        assert!(self.prefix.len() <= output.len());
        output[..self.prefix.len()].copy_from_slice(&self.prefix);
        Ok(self.prefix.len())
    }
}

fn actual_failed_stage(prefix: &[u8]) {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "actual EACCES fixture needs a non-root Unix uid"
    );
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let id = Uuid::now_v7();
    let expected = b"expected complete logical message";
    let blob = ArtifactBlob::from_record(id, expected.len() as u64, hash(expected)).unwrap();
    let staging = files.root.join("staging");
    let mut input = FailWithBlockedCleanup {
        staging: staging.clone(),
        prefix: prefix.to_vec(),
        emitted: false,
    };
    let outcome = store.stage_for(&mut input, &blob);
    // Restore this owned directory before observing or cleaning the genuinely retained file.
    fs::set_permissions(staging, Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(outcome, Err(ArtifactByteError::CleanupFailed)));
    assert_eq!(
        fs::read(files.path(ArtifactByteStorageLocation::Staging, id)).unwrap(),
        prefix
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Staging, prefix);
    assert_ne!(blob.byte_length(), prefix.len() as u64);
    assert_ne!(*blob.sha256(), hash(prefix));
}

#[test]
fn real_zero_byte_input_failure_and_cleanup_eacces_leave_accurate_retained_zero() {
    actual_failed_stage(b"");
}

#[test]
fn real_partial_input_failure_and_cleanup_eacces_leave_accurate_retained_prefix() {
    actual_failed_stage(b"prefix");
}

#[test]
fn real_install_renames_before_digest_error_and_probe_retains_actual_object() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    let expected = b"aaaaaaaa";
    let actual = b"bbbbbbbb";
    let id = Uuid::now_v7();
    let blob = ArtifactBlob::from_record(id, expected.len() as u64, hash(expected)).unwrap();
    let stage = store.stage_for(&mut Cursor::new(expected), &blob).unwrap();
    let path = files.path(ArtifactByteStorageLocation::Staging, id);
    // Controlled fault on this fixture's original inode and length, after successful stage
    // verification. No race/callback is required and this does not certify hostile-writer safety.
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let mut changed = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    changed.write_all(actual).unwrap();
    changed.sync_all().unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
    changed.sync_all().unwrap();
    assert!(matches!(
        store.install(stage),
        Err(ArtifactByteError::ContentMismatch)
    ));
    assert!(
        !path.exists(),
        "actual NOREPLACE rename did not happen before the error"
    );
    assert_eq!(
        fs::read(files.path(ArtifactByteStorageLocation::Object, id)).unwrap(),
        actual
    );
    expect_retained(&store, id, ArtifactByteStorageLocation::Object, actual);
    assert_ne!(*blob.sha256(), hash(actual));
}

#[test]
fn invalid_uuid_and_nonprivate_directory_never_prove_absence() {
    let files = OwnedFiles::new();
    let store = files.bind(4096);
    assert!(matches!(
        store.probe_actual(Uuid::nil()),
        ArtifactByteProbe::Indeterminate
    ));
    fs::set_permissions(files.root.join("staging"), Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store.probe_actual(Uuid::now_v7()),
        ArtifactByteProbe::Indeterminate
    ));
    fs::set_permissions(files.root.join("staging"), Permissions::from_mode(0o700)).unwrap();
}

// This oracle observes only this process and previously observed owned inode tuples. It never
// follows a user path or treats a reusable descriptor number as proof of an original File.
fn guarded_owned_inode_fds(identities: &[(u64, u64)]) -> BTreeSet<(u64, u64, u32)> {
    let sample = || {
        #[cfg(target_os = "linux")]
        {
            let mut found = BTreeSet::new();
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                let entry = entry.unwrap();
                let Ok(fd) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if identities.contains(&(metadata.dev(), metadata.ino())) {
                    found.insert((metadata.dev(), metadata.ino(), fd));
                }
            }
            found
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Read as _;
            use std::process::{Command, Stdio};
            let pid = std::process::id();
            let mut child = Command::new("/usr/sbin/lsof")
                .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("own-PID FD observation unavailable (Unproven)");
            let child_pid = child.id();
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let output = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
            });
            let errors = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            // Join both original pipe owners before interpreting either result or panicking.
            let output = output.join();
            let errors = errors.join();
            let output = output.unwrap().unwrap();
            let errors = errors.unwrap().unwrap();
            assert!(
                status
                    .as_ref()
                    .is_some_and(std::process::ExitStatus::success)
            );
            assert!(output.len() <= 65_536 && output.ends_with(b"\n"));
            assert!(
                errors.is_empty(),
                "own-PID FD observation stderr (Unproven)"
            );
            let text = std::str::from_utf8(&output).unwrap();
            let mut own_pid = false;
            let (mut fd, mut device, mut inode) = (None, None, None);
            let mut found = BTreeSet::new();
            for line in text.lines().chain(std::iter::once("f")) {
                let (kind, value) = line.split_at_checked(1).unwrap();
                match kind {
                    "p" => {
                        assert_eq!(value.parse::<u32>().unwrap(), pid);
                        own_pid = true;
                    }
                    "f" => {
                        if let Some(&(original_device, original_inode)) =
                            identities
                                .iter()
                                .find(|&&(original_device, original_inode)| {
                                    device == Some(original_device & u64::from(u32::MAX))
                                        && inode == Some(original_inode)
                                })
                        {
                            found.insert((original_device, original_inode, fd.unwrap()));
                        }
                        fd = value.parse::<u32>().ok();
                        device = None;
                        inode = None;
                    }
                    "D" => {
                        device = Some(if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16).unwrap()
                        } else {
                            value.parse::<u64>().unwrap()
                        });
                    }
                    "i" => inode = Some(value.parse::<u64>().unwrap()),
                    _ => panic!("own-PID FD observation unknown field (Unproven)"),
                }
            }
            assert!(own_pid, "own-PID FD observation missing PID (Unproven)");
            eprintln!(
                "ARTIFACT_GUARDED_FD_ORACLE child_pid={child_pid} natural_zero=true reaped=true pipe_workers_joined=true matching_fds={}",
                found.len()
            );
            found
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            panic!("actual owned FD oracle unsupported (Unproven)")
        }
    };
    let first = sample();
    let second = sample();
    assert_eq!(first, second, "owned original inode FD inventory unstable");
    first
}

struct GuardedOwnedFiles {
    // On a failed assertion automatic field drop closes the Store before owned scratch removal.
    store: Option<ArtifactByteStore>,
    files: OwnedFiles,
    original_directories: BTreeSet<(u64, u64, u32)>,
    observed_inodes: RefCell<Vec<(u64, u64)>>,
}

impl GuardedOwnedFiles {
    fn new(maximum: u64) -> Self {
        let files = OwnedFiles::new();
        let store = files.bind(maximum);
        let directories = &store.directories;
        let original_directories = [
            &directories.root,
            &directories.staging,
            &directories.objects,
        ]
        .into_iter()
        .map(|file| {
            let metadata = file.metadata().unwrap();
            (
                metadata.dev(),
                metadata.ino(),
                u32::try_from(file.as_raw_fd()).unwrap(),
            )
        })
        .collect::<BTreeSet<_>>();
        let observed_inodes = RefCell::new(
            original_directories
                .iter()
                .map(|&(dev, ino, _)| (dev, ino))
                .collect(),
        );
        let owned = Self {
            store: Some(store),
            files,
            original_directories,
            observed_inodes,
        };
        owned.assert_original_directories_live();
        owned
    }

    fn store(&self) -> &ArtifactByteStore {
        self.store.as_ref().unwrap()
    }

    fn remember(&self, path: &Path) -> (u64, u64) {
        assert!(path.starts_with(&self.files.container));
        let metadata = fs::symlink_metadata(path).unwrap();
        let identity = (metadata.dev(), metadata.ino());
        let mut observed = self.observed_inodes.borrow_mut();
        if !observed.contains(&identity) {
            observed.push(identity);
        }
        identity
    }

    fn assert_original_directories_live(&self) {
        let identities = self
            .original_directories
            .iter()
            .map(|&(d, i, _)| (d, i))
            .collect::<Vec<_>>();
        assert_eq!(
            guarded_owned_inode_fds(&identities),
            self.original_directories
        );
    }

    fn assert_leaf_live(&self, path: &Path) {
        let identity = self.remember(path);
        let fds = guarded_owned_inode_fds(&[identity]);
        assert_eq!(
            fds.len(),
            1,
            "original probe did not hold its actual leaf FD"
        );
    }

    fn finish(mut self, leg: &str) {
        let identities = self.observed_inodes.borrow().clone();
        assert_eq!(
            guarded_owned_inode_fds(&identities),
            self.original_directories,
            "returned probe retained an original leaf or temporary directory FD"
        );
        drop(self.store.take());
        assert!(
            guarded_owned_inode_fds(&identities).is_empty(),
            "original Store owned inode still has an actual FD after drop"
        );
        let container = self.files.container.clone();
        drop(self.files);
        assert!(
            matches!(fs::symlink_metadata(container), Err(error) if error.kind() == io::ErrorKind::NotFound)
        );
        eprintln!(
            "ARTIFACT_GUARDED_FS_TAIL leg={leg} original_directory_fds=3 original_leaf_fds_absent=true store_fds_absent=true scratch_removed=true"
        );
    }
}

fn guarded_expect_retained(
    probe: ArtifactByteProbe,
    location: ArtifactByteStorageLocation,
    bytes: &[u8],
) {
    match probe {
        ArtifactByteProbe::Retained {
            location: actual_location,
            byte_length,
            sha256,
        } => {
            assert_eq!(actual_location, location);
            assert_eq!(byte_length, bytes.len() as u64);
            assert_eq!(sha256, hash(bytes));
        }
        ArtifactByteProbe::Absent | ArtifactByteProbe::Indeterminate => {
            panic!("actual stable owned bytes were not retained")
        }
    }
}

fn guarded_multi_segment_bytes() -> Vec<u8> {
    let mut bytes = vec![b'a'; 128 * 1024 + 17];
    bytes[64 * 1024] = b'b';
    bytes[128 * 1024] = b'c';
    bytes
}

#[test]
fn guarded_probe_refuses_expired_entry_and_trusted_stop_without_changing_retained_bytes() {
    let owned = GuardedOwnedFiles::new(4096);
    let id = Uuid::now_v7();
    let path = owned.files.path(ArtifactByteStorageLocation::Object, id);
    actual_file(&path, b"actual retained", 0o400);
    owned.remember(&path);
    let expired = Instant::now();
    let mut callbacks = Vec::new();
    assert!(matches!(
        owned
            .store()
            .probe_actual_guarded_before(id, expired, &mut |phase| {
                callbacks.push(phase);
                false
            }),
        ArtifactByteProbe::Indeterminate
    ));
    // An expired result/callback list makes no assertion about a zero-syscall implementation.
    let mut stopped = false;
    assert!(matches!(
        owned.store().probe_actual_guarded_before(
            id,
            Instant::now() + Duration::from_secs(30),
            &mut |phase| {
                if phase == ArtifactProbePhase::Entry {
                    stopped = true;
                    true
                } else {
                    false
                }
            }
        ),
        ArtifactByteProbe::Indeterminate
    ));
    assert!(stopped);
    assert_eq!(fs::read(&path).unwrap(), b"actual retained");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o400);
    expect_retained(
        owned.store(),
        id,
        ArtifactByteStorageLocation::Object,
        b"actual retained",
    );
    owned.finish("FS01");
}

#[test]
fn guarded_probe_absent_requires_all_original_directory_syncs_and_current_names() {
    let owned = GuardedOwnedFiles::new(4096);
    let id = Uuid::now_v7();
    let mut phases = Vec::new();
    let result = owned.store().probe_actual_guarded_before(
        id,
        Instant::now() + Duration::from_secs(30),
        &mut |phase| {
            phases.push(phase);
            false
        },
    );
    assert!(matches!(result, ArtifactByteProbe::Absent));
    assert_eq!(
        phases,
        vec![
            ArtifactProbePhase::Entry,
            ArtifactProbePhase::BeforeStagingSync,
            ArtifactProbePhase::AfterStagingSync,
            ArtifactProbePhase::BeforeObjectsSync,
            ArtifactProbePhase::AfterObjectsSync,
            ArtifactProbePhase::BeforeRootSync,
            ArtifactProbePhase::AfterRootSync,
            ArtifactProbePhase::FinalObservation
        ]
    );
    for location in [
        ArtifactByteStorageLocation::Object,
        ArtifactByteStorageLocation::Staging,
    ] {
        assert!(
            matches!(fs::symlink_metadata(owned.files.path(location, id)),
            Err(error) if error.kind() == io::ErrorKind::NotFound)
        );
    }
    // These AFTER callbacks are bound by reviewed Source to successful actual syncs. A counter
    // alone is not a syscall oracle, nor is ordinary Absent a deletion/cleanup authorization.
    owned.finish("FS02-absent");
    for location in [
        ArtifactByteStorageLocation::Staging,
        ArtifactByteStorageLocation::Object,
    ] {
        let owned = GuardedOwnedFiles::new(4096);
        let id = Uuid::now_v7();
        let path = owned.files.path(location, id);
        let mut inserted = false;
        let result = owned.store().probe_actual_guarded_before(
            id,
            Instant::now() + Duration::from_secs(30),
            &mut |phase| {
                if phase == ArtifactProbePhase::FinalObservation {
                    actual_file(&path, b"late actual name", 0o600);
                    owned.remember(&path);
                    inserted = true;
                }
                false
            },
        );
        assert!(inserted && matches!(result, ArtifactByteProbe::Indeterminate));
        assert_eq!(fs::read(path).unwrap(), b"late actual name");
        owned.finish("FS02-late-name");
    }
}

#[test]
fn guarded_probe_returns_actual_full_hash_for_multisegment_object_staging_and_empty_bytes() {
    for location in [
        ArtifactByteStorageLocation::Object,
        ArtifactByteStorageLocation::Staging,
    ] {
        for actual in [guarded_multi_segment_bytes(), Vec::new()] {
            let owned = GuardedOwnedFiles::new(256 * 1024);
            let id = Uuid::now_v7();
            let path = owned.files.path(location, id);
            let mode = if location == ArtifactByteStorageLocation::Object {
                0o400
            } else {
                0o600
            };
            actual_file(&path, &actual, mode);
            owned.remember(&path);
            let mut phases = Vec::new();
            let mut leaf_seen = false;
            let result = owned.store().probe_actual_guarded_before(
                id,
                Instant::now() + Duration::from_secs(30),
                &mut |phase| {
                    phases.push(phase);
                    if !leaf_seen
                        && matches!(
                            phase,
                            ArtifactProbePhase::AfterHashSegment
                                | ArtifactProbePhase::BeforeEofRead
                        )
                    {
                        owned.assert_leaf_live(&path);
                        leaf_seen = true;
                    }
                    false
                },
            );
            guarded_expect_retained(result, location, &actual);
            assert!(leaf_seen);
            let segments = if actual.is_empty() { 0 } else { 3 };
            for phase in [
                ArtifactProbePhase::BeforeHashSegment,
                ArtifactProbePhase::AfterHashSegment,
            ] {
                assert_eq!(
                    phases.iter().filter(|&&actual| actual == phase).count(),
                    segments
                );
            }
            for phase in [
                ArtifactProbePhase::Entry,
                ArtifactProbePhase::BeforeEofRead,
                ArtifactProbePhase::AfterEofRead,
                ArtifactProbePhase::BeforeFileSync,
                ArtifactProbePhase::AfterFileSync,
                ArtifactProbePhase::BeforeStagingSync,
                ArtifactProbePhase::AfterStagingSync,
                ArtifactProbePhase::BeforeObjectsSync,
                ArtifactProbePhase::AfterObjectsSync,
                ArtifactProbePhase::BeforeRootSync,
                ArtifactProbePhase::AfterRootSync,
                ArtifactProbePhase::FinalObservation,
            ] {
                assert_eq!(phases.iter().filter(|&&actual| actual == phase).count(), 1);
            }
            assert_eq!(fs::read(&path).unwrap(), actual);
            expect_retained(owned.store(), id, location, &actual);
            owned.finish("FS03");
        }
    }
}

#[test]
fn guarded_probe_uses_original_deadline_and_refuses_stop_at_hash_and_sync_cutpoints() {
    for target in [
        ArtifactProbePhase::BeforeHashSegment,
        ArtifactProbePhase::AfterHashSegment,
        ArtifactProbePhase::BeforeEofRead,
        ArtifactProbePhase::AfterEofRead,
        ArtifactProbePhase::BeforeFileSync,
        ArtifactProbePhase::AfterFileSync,
        ArtifactProbePhase::BeforeStagingSync,
        ArtifactProbePhase::AfterStagingSync,
        ArtifactProbePhase::BeforeObjectsSync,
        ArtifactProbePhase::AfterObjectsSync,
        ArtifactProbePhase::BeforeRootSync,
        ArtifactProbePhase::AfterRootSync,
        ArtifactProbePhase::FinalObservation,
    ] {
        let owned = GuardedOwnedFiles::new(256 * 1024);
        let id = Uuid::now_v7();
        let actual = guarded_multi_segment_bytes();
        let path = owned.files.path(ArtifactByteStorageLocation::Object, id);
        actual_file(&path, &actual, 0o400);
        owned.remember(&path);
        let mut reached = false;
        let result = owned.store().probe_actual_guarded_before(
            id,
            Instant::now() + Duration::from_secs(30),
            &mut |phase| {
                if phase == target {
                    reached = true;
                    true
                } else {
                    false
                }
            },
        );
        assert!(reached && matches!(result, ArtifactByteProbe::Indeterminate));
        assert_eq!(fs::read(&path).unwrap(), actual);
        eprintln!("ARTIFACT_GUARDED_STOP target={target:?} retained_unchanged=true");
        owned.finish("FS04-stop");
    }
    for target in [
        ArtifactProbePhase::AfterHashSegment,
        ArtifactProbePhase::AfterRootSync,
    ] {
        let owned = GuardedOwnedFiles::new(256 * 1024);
        let id = Uuid::now_v7();
        let actual = guarded_multi_segment_bytes();
        let path = owned.files.path(ArtifactByteStorageLocation::Object, id);
        actual_file(&path, &actual, 0o400);
        owned.remember(&path);
        let original_deadline = Instant::now() + Duration::from_secs(2);
        let mut reached = false;
        let result =
            owned
                .store()
                .probe_actual_guarded_before(id, original_deadline, &mut |phase| {
                    if phase == target && !reached {
                        reached = true;
                        std::thread::sleep(
                            original_deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(10),
                        );
                    }
                    false
                });
        assert!(reached && Instant::now() >= original_deadline);
        assert!(matches!(result, ArtifactByteProbe::Indeterminate));
        assert_eq!(fs::read(path).unwrap(), actual);
        eprintln!(
            "ARTIFACT_GUARDED_DEADLINE target={target:?} original_absolute_expired=true result_indeterminate=true"
        );
        owned.finish("FS04-original-deadline");
    }
}

#[test]
fn guarded_probe_refuses_current_child_directory_replacement_and_symlinks_with_original_fds_alive()
{
    for child_name in ["objects", "staging"] {
        for use_symlink in [false, true] {
            for target_phase in [
                ArtifactProbePhase::BeforeFileSync,
                ArtifactProbePhase::FinalObservation,
            ] {
                let owned = GuardedOwnedFiles::new(4096);
                let id = Uuid::now_v7();
                let original_path = owned.files.path(ArtifactByteStorageLocation::Object, id);
                actual_file(&original_path, b"original actual bytes", 0o400);
                owned.remember(&original_path);
                let child = owned.files.root.join(child_name);
                let retired = owned.files.root.join(format!("retired-{child_name}"));
                let replacement = owned.files.container.join("owned-child-target");
                DirBuilder::new().mode(0o700).create(&replacement).unwrap();
                actual_file(&replacement.join("keep"), b"replacement keeper", 0o600);
                owned.remember(&replacement);
                owned.remember(&replacement.join("keep"));
                let original_child = fs::metadata(&child).unwrap();
                let mut changed = false;
                let result = owned.store().probe_actual_guarded_before(
                    id,
                    Instant::now() + Duration::from_secs(30),
                    &mut |phase| {
                        if phase == target_phase && !changed {
                            fs::rename(&child, &retired).unwrap();
                            if use_symlink {
                                symlink(&replacement, &child).unwrap();
                            } else {
                                DirBuilder::new().mode(0o700).create(&child).unwrap();
                                owned.remember(&child);
                            }
                            let held = if child_name == "objects" {
                                &owned.store().directories.objects
                            } else {
                                &owned.store().directories.staging
                            };
                            let still_live = held.metadata().unwrap();
                            assert_eq!(
                                (still_live.dev(), still_live.ino()),
                                (original_child.dev(), original_child.ino())
                            );
                            owned.assert_original_directories_live();
                            changed = true;
                        }
                        false
                    },
                );
                assert!(changed && matches!(result, ArtifactByteProbe::Indeterminate));
                let retained = if child_name == "objects" {
                    retired.join(id.to_string())
                } else {
                    original_path
                };
                assert_eq!(fs::read(retained).unwrap(), b"original actual bytes");
                assert_eq!(
                    fs::read(replacement.join("keep")).unwrap(),
                    b"replacement keeper"
                );
                assert_eq!(
                    fs::symlink_metadata(&child)
                        .unwrap()
                        .file_type()
                        .is_symlink(),
                    use_symlink
                );
                eprintln!(
                    "ARTIFACT_GUARDED_CHILD_DRIFT child={child_name} symlink={use_symlink} phase={target_phase:?} original_fds_live=true refused=true"
                );
                owned.finish("FS05");
            }
        }
    }
}

#[test]
fn guarded_probe_refuses_leaf_identity_mode_link_and_dual_location_drift() {
    for drift in ["replacement", "mode", "hardlink", "dual-location"] {
        for target_phase in [
            ArtifactProbePhase::AfterHashSegment,
            ArtifactProbePhase::FinalObservation,
        ] {
            let owned = GuardedOwnedFiles::new(256 * 1024);
            let id = Uuid::now_v7();
            let actual = guarded_multi_segment_bytes();
            let path = owned.files.path(ArtifactByteStorageLocation::Object, id);
            let other = owned.files.path(ArtifactByteStorageLocation::Staging, id);
            let backup = owned.files.container.join("owned-original-leaf");
            actual_file(&path, &actual, 0o400);
            owned.remember(&path);
            let original = fs::metadata(&path).unwrap();
            let mut leaf_seen = false;
            let mut changed = false;
            let result = owned.store().probe_actual_guarded_before(
                id,
                Instant::now() + Duration::from_secs(30),
                &mut |phase| {
                    if phase == ArtifactProbePhase::AfterHashSegment && !leaf_seen {
                        owned.assert_leaf_live(&path);
                        leaf_seen = true;
                    }
                    if phase == target_phase && !changed {
                        match drift {
                            "replacement" => {
                                fs::rename(&path, &backup).unwrap();
                                actual_file(&path, &actual, 0o400);
                                owned.remember(&path);
                                let current = fs::metadata(&path).unwrap();
                                assert_ne!(
                                    (current.dev(), current.ino()),
                                    (original.dev(), original.ino())
                                );
                            }
                            "mode" => {
                                fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap()
                            }
                            "hardlink" => {
                                fs::hard_link(&path, &backup).unwrap();
                                assert_eq!(fs::metadata(&path).unwrap().nlink(), 2);
                            }
                            "dual-location" => {
                                actual_file(&other, &actual, 0o600);
                                owned.remember(&other);
                            }
                            _ => unreachable!(),
                        }
                        changed = true;
                    }
                    false
                },
            );
            assert!(leaf_seen && changed && matches!(result, ArtifactByteProbe::Indeterminate));
            let preserved = if drift == "replacement" {
                &backup
            } else {
                &path
            };
            assert_eq!(fs::read(preserved).unwrap(), actual);
            if drift == "replacement" {
                assert_eq!(fs::read(&path).unwrap(), actual);
            }
            if drift == "dual-location" {
                assert_eq!(fs::read(&other).unwrap(), actual);
            }
            eprintln!(
                "ARTIFACT_GUARDED_LEAF_DRIFT drift={drift} phase={target_phase:?} original_leaf_fd_seen=true preserved_actual_bytes=true refused=true"
            );
            owned.finish("FS06");
        }
    }
}
