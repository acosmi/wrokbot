//! Actual owned-FS observations. These are byte-adapter facts, not PG registration, authority,
//! production cleanup, hostile same-UID/ACL isolation, or other-platform acceptance.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{
    ArtifactBlob, ArtifactByteError, ArtifactByteProbe, ArtifactByteStorageLocation,
    ArtifactByteStore,
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
