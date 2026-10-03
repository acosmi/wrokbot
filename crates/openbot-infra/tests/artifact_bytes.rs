//! Actual private-file I/O for the internal R414 byte foundation only.
//! No database, application authorization, public read route or ready state is exercised.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use openbot_infra::artifact_bytes::{
    ArtifactBlob, ArtifactByteError, ArtifactByteStore, MAX_ARTIFACT_BYTES,
    MAX_ARTIFACT_READ_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

struct PrivateTemp {
    container: PathBuf,
}

impl PrivateTemp {
    fn new() -> Self {
        let container =
            std::env::temp_dir().join(format!("wrok-artifact-bytes-{}", Uuid::now_v7()));
        private_directory(&container);
        private_directory(&container.join("root"));
        Self { container }
    }

    fn root(&self) -> PathBuf {
        self.container.join("root")
    }

    fn bind(&self, max: u64) -> ArtifactByteStore {
        ArtifactByteStore::bind_private_root(File::open(self.root()).unwrap(), max).unwrap()
    }

    fn object(&self, blob: &ArtifactBlob) -> PathBuf {
        self.root().join("objects").join(blob.id().to_string())
    }

    fn stage(&self, blob: &ArtifactBlob) -> PathBuf {
        self.root().join("staging").join(blob.id().to_string())
    }

    fn assert_staging_empty(&self) {
        assert_eq!(
            fs::read_dir(self.root().join("staging")).unwrap().count(),
            0
        );
    }
}

impl Drop for PrivateTemp {
    fn drop(&mut self) {
        // This UUID directory and everything inside it was created by this test.
        let _ = fs::remove_dir_all(&self.container);
    }
}

fn private_directory(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn private_object(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
}

fn installed(store: &ArtifactByteStore, bytes: &[u8]) -> ArtifactBlob {
    let stage = store
        .stage(&mut Cursor::new(bytes), bytes.len() as u64, digest(bytes))
        .unwrap();
    store.install(stage).unwrap()
}

fn read_all(store: &ArtifactByteStore, blob: &ArtifactBlob, chunk: usize) -> Vec<u8> {
    let mut reader = store.open_verified(blob).unwrap();
    let mut output = Vec::new();
    let mut buffer = vec![0; chunk];
    loop {
        let read = reader.read_chunk(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read]);
    }
    assert_eq!(reader.read_chunk(&mut buffer).unwrap(), 0);
    output
}

struct RepeatedInput {
    remaining: u64,
    byte: u8,
}

impl Read for RepeatedInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.remaining.min(output.len() as u64) as usize;
        output[..count].fill(self.byte);
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn repeated_digest(length: u64, byte: u8) -> [u8; 32] {
    let buffer = [byte; 64 * 1024];
    let mut hash = Sha256::new();
    let mut remaining = length;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    hash.finalize().into()
}

fn repeated_roundtrip(length: u64) {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let expected = repeated_digest(length, 0x5a);
    let mut input = RepeatedInput {
        remaining: length,
        byte: 0x5a,
    };
    let stage = store.stage(&mut input, length, expected).unwrap();
    assert_eq!(input.remaining, 0);
    assert_eq!(stage.blob().byte_length(), length);
    assert_eq!(*stage.blob().sha256(), expected);
    assert_eq!(
        fs::metadata(temp.stage(stage.blob())).unwrap().mode() & 0o7777,
        0o400
    );
    let blob = store.install(stage).unwrap();
    temp.assert_staging_empty();
    let mut reader = store.open_verified(&blob).unwrap();
    let mut buffer = vec![0; MAX_ARTIFACT_READ_CHUNK_BYTES];
    let mut read_length = 0;
    let mut hash = Sha256::new();
    loop {
        let read = reader.read_chunk(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        assert!(buffer[..read].iter().all(|&byte| byte == 0x5a));
        hash.update(&buffer[..read]);
        read_length += read as u64;
    }
    assert_eq!(read_length, length);
    assert_eq!(<[u8; 32]>::from(hash.finalize()), expected);
}

#[test]
fn empty_and_binary_bytes_roundtrip_with_uuid_v7_binding() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    for bytes in [b"".as_slice(), b"a\0b\xff\r\n\xe4\xb8\xad".as_slice()] {
        let blob = installed(&store, bytes);
        assert_eq!(blob.id().get_version_num(), 7);
        assert_eq!(blob.id().get_variant(), Variant::RFC4122);
        assert_eq!(blob.byte_length(), bytes.len() as u64);
        assert_eq!(*blob.sha256(), digest(bytes));
        let recovered =
            ArtifactBlob::from_record(blob.id(), blob.byte_length(), *blob.sha256()).unwrap();
        assert_eq!(recovered, blob);
        assert_eq!(read_all(&store, &recovered, 3), bytes);
        let metadata = fs::metadata(temp.object(&blob)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert_eq!(metadata.nlink(), 1);
    }
    temp.assert_staging_empty();
}

#[test]
fn exact_four_mib_roundtrip_uses_the_maximum_read_chunk() {
    repeated_roundtrip(MAX_ARTIFACT_READ_CHUNK_BYTES as u64);
}

#[test]
fn larger_than_one_chunk_roundtrip_preserves_the_last_partial_chunk() {
    repeated_roundtrip(MAX_ARTIFACT_READ_CHUNK_BYTES as u64 + 17);
}

#[test]
fn exact_sixty_four_mib_roundtrip_is_streamed_without_a_full_size_allocation() {
    repeated_roundtrip(MAX_ARTIFACT_BYTES);
}

#[test]
fn record_binding_rejects_non_v7_identity_and_global_limit_overflow() {
    assert_eq!(
        ArtifactBlob::from_record(Uuid::nil(), 0, digest(b"")).err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    let mut bytes = [0x11; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    assert_eq!(
        ArtifactBlob::from_record(Uuid::from_bytes(bytes), 0, digest(b"")).err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    bytes[6] = 0x70;
    bytes[8] = 0xc0;
    assert_eq!(
        ArtifactBlob::from_record(Uuid::from_bytes(bytes), 0, digest(b"")).err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    assert_eq!(
        ArtifactBlob::from_record(Uuid::now_v7(), MAX_ARTIFACT_BYTES + 1, [0; 32]).err(),
        Some(ArtifactByteError::TooLarge)
    );
}

struct NeverRead {
    reads: usize,
}

impl Read for NeverRead {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        Err(io::Error::other("input must not be consumed"))
    }
}

#[test]
fn global_limit_plus_one_is_rejected_before_consuming_input() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let mut input = NeverRead { reads: 0 };
    assert_eq!(
        store
            .stage(&mut input, MAX_ARTIFACT_BYTES + 1, [0; 32])
            .err(),
        Some(ArtifactByteError::TooLarge)
    );
    assert_eq!(input.reads, 0);
    temp.assert_staging_empty();
}

#[test]
fn host_policy_cannot_widen_and_can_restrict_write_and_read_lengths() {
    let temp = PrivateTemp::new();
    assert_eq!(
        ArtifactByteStore::bind_private_root(
            File::open(temp.root()).unwrap(),
            MAX_ARTIFACT_BYTES + 1
        )
        .err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"three");
    let tighter = temp.bind(4);
    let mut input = NeverRead { reads: 0 };
    assert_eq!(
        tighter.stage(&mut input, 5, [0; 32]).err(),
        Some(ArtifactByteError::TooLarge)
    );
    assert_eq!(input.reads, 0);
    assert_eq!(
        tighter.open_verified(&blob).err(),
        Some(ArtifactByteError::TooLarge)
    );
    let zero = temp.bind(0);
    assert!(installed(&zero, b"").byte_length() == 0);
    temp.assert_staging_empty();
}

#[test]
fn short_long_and_wrong_hash_inputs_leave_no_stage_or_object() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    for (bytes, declared, expected, error) in [
        (
            b"ab".as_slice(),
            3,
            digest(b"abc"),
            ArtifactByteError::LengthMismatch,
        ),
        (
            b"abcd".as_slice(),
            3,
            digest(b"abc"),
            ArtifactByteError::LengthMismatch,
        ),
        (
            b"abc".as_slice(),
            3,
            digest(b"abd"),
            ArtifactByteError::ContentMismatch,
        ),
        (
            b"x".as_slice(),
            0,
            digest(b""),
            ArtifactByteError::LengthMismatch,
        ),
    ] {
        assert_eq!(
            store
                .stage(&mut Cursor::new(bytes), declared, expected)
                .err(),
            Some(error)
        );
        temp.assert_staging_empty();
        assert_eq!(
            fs::read_dir(temp.root().join("objects")).unwrap().count(),
            0
        );
    }
}

struct FailsAfterPrefix {
    supplied: bool,
}

impl Read for FailsAfterPrefix {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.supplied {
            return Err(io::Error::other("synthetic input failure"));
        }
        self.supplied = true;
        output[0] = b'a';
        Ok(1)
    }
}

#[test]
fn input_io_failure_cleans_partially_written_stage() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let mut input = FailsAfterPrefix { supplied: false };
    assert_eq!(
        store.stage(&mut input, 3, digest(b"abc")).err(),
        Some(ArtifactByteError::Io)
    );
    temp.assert_staging_empty();
    assert_eq!(
        fs::read_dir(temp.root().join("objects")).unwrap().count(),
        0
    );
}

struct InterruptedInput {
    input: Cursor<Vec<u8>>,
    interruptions: usize,
}

impl Read for InterruptedInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.interruptions > 0 {
            self.interruptions -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.input.read(output)
    }
}

#[test]
fn interrupted_input_read_is_retried_and_still_verified() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let mut input = InterruptedInput {
        input: Cursor::new(b"abc".to_vec()),
        interruptions: 2,
    };
    let stage = store.stage(&mut input, 3, digest(b"abc")).unwrap();
    let blob = store.install(stage).unwrap();
    assert_eq!(read_all(&store, &blob, 2), b"abc");
}

#[test]
fn drop_and_explicit_discard_remove_uninstalled_stages() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    assert!(temp.stage(stage.blob()).exists());
    drop(stage);
    temp.assert_staging_empty();
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    stage.discard().unwrap();
    temp.assert_staging_empty();
    assert_eq!(
        fs::read_dir(temp.root().join("objects")).unwrap().count(),
        0
    );
}

#[test]
fn install_cannot_replace_an_existing_same_id_object() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    let target = temp.object(stage.blob());
    private_object(&target, b"keep this object");
    assert_eq!(
        store.install(stage).err(),
        Some(ArtifactByteError::AlreadyExists)
    );
    assert_eq!(fs::read(target).unwrap(), b"keep this object");
    temp.assert_staging_empty();
}

#[test]
fn install_cannot_replace_an_existing_same_id_symlink() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    let destination = temp.container.join("sentinel");
    private_object(&destination, b"sentinel");
    let target = temp.object(stage.blob());
    symlink(&destination, &target).unwrap();
    assert_eq!(
        store.install(stage).err(),
        Some(ArtifactByteError::AlreadyExists)
    );
    assert_eq!(fs::read_link(target).unwrap(), destination);
    assert_eq!(fs::read(destination).unwrap(), b"sentinel");
    temp.assert_staging_empty();
}

#[test]
fn stage_cannot_be_installed_by_another_store_and_is_cleaned() {
    let first = PrivateTemp::new();
    let second = PrivateTemp::new();
    let source = first.bind(MAX_ARTIFACT_BYTES);
    let destination = second.bind(MAX_ARTIFACT_BYTES);
    let stage = source
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    assert_eq!(
        destination.install(stage).err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    first.assert_staging_empty();
    second.assert_staging_empty();
    assert_eq!(
        fs::read_dir(second.root().join("objects")).unwrap().count(),
        0
    );
    // Independently bound handles to the same root are distinct stores too.
    let rebound = first.bind(MAX_ARTIFACT_BYTES);
    let stage = source
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    assert_eq!(
        rebound.install(stage).err(),
        Some(ArtifactByteError::InvalidBinding)
    );
    first.assert_staging_empty();
}

#[test]
fn root_requires_a_private_directory_descriptor() {
    let temp = PrivateTemp::new();
    for mode in [0o755, 0o770, 0o1700] {
        fs::set_permissions(temp.root(), Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            ArtifactByteStore::bind_private_root(
                File::open(temp.root()).unwrap(),
                MAX_ARTIFACT_BYTES
            )
            .err(),
            Some(ArtifactByteError::UnsafeObject)
        );
    }
    fs::set_permissions(temp.root(), Permissions::from_mode(0o700)).unwrap();
    let regular = temp.container.join("regular-root");
    private_object(&regular, b"");
    assert_eq!(
        ArtifactByteStore::bind_private_root(File::open(regular).unwrap(), MAX_ARTIFACT_BYTES)
            .err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    assert_eq!(
        fs::metadata(temp.root().join("staging")).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(temp.root().join("objects")).unwrap().mode() & 0o7777,
        0o700
    );
    drop(store);
}

#[test]
fn existing_child_directories_require_exact_private_permissions() {
    for name in ["staging", "objects"] {
        for mode in [0o755, 0o770, 0o1700] {
            let temp = PrivateTemp::new();
            let child = temp.root().join(name);
            private_directory(&child);
            fs::set_permissions(child, Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                ArtifactByteStore::bind_private_root(
                    File::open(temp.root()).unwrap(),
                    MAX_ARTIFACT_BYTES
                )
                .err(),
                Some(ArtifactByteError::UnsafeObject)
            );
        }
    }
}

#[test]
fn child_symlinks_and_regular_files_are_rejected_during_binding() {
    for name in ["staging", "objects"] {
        let temp = PrivateTemp::new();
        let target = temp.container.join("other-private-directory");
        private_directory(&target);
        symlink(&target, temp.root().join(name)).unwrap();
        assert_eq!(
            ArtifactByteStore::bind_private_root(
                File::open(temp.root()).unwrap(),
                MAX_ARTIFACT_BYTES
            )
            .err(),
            Some(ArtifactByteError::UnsafeObject)
        );
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
        let temp = PrivateTemp::new();
        private_object(&temp.root().join(name), b"");
        assert_eq!(
            ArtifactByteStore::bind_private_root(
                File::open(temp.root()).unwrap(),
                MAX_ARTIFACT_BYTES
            )
            .err(),
            Some(ArtifactByteError::UnsafeObject)
        );
    }
}

#[test]
fn record_hash_or_length_mismatch_is_rejected_against_actual_object() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abc");
    for length in [2, 4] {
        let wrong = ArtifactBlob::from_record(blob.id(), length, *blob.sha256()).unwrap();
        assert_eq!(
            store.open_verified(&wrong).err(),
            Some(ArtifactByteError::LengthMismatch)
        );
    }
    let wrong = ArtifactBlob::from_record(blob.id(), 3, digest(b"abd")).unwrap();
    assert_eq!(
        store.open_verified(&wrong).err(),
        Some(ArtifactByteError::ContentMismatch)
    );
}

#[test]
fn modified_object_hash_and_length_are_rejected_on_reopening() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abc");
    let path = temp.object(&blob);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"abd").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        store.open_verified(&blob).err(),
        Some(ArtifactByteError::ContentMismatch)
    );
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"ab").unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        store.open_verified(&blob).err(),
        Some(ArtifactByteError::LengthMismatch)
    );
}

#[test]
fn object_symlink_hardlink_directory_and_fifo_are_rejected() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let target = temp.container.join("sentinel");
    private_object(&target, b"abc");
    let linked = ArtifactBlob::from_record(Uuid::now_v7(), 3, digest(b"abc")).unwrap();
    symlink(&target, temp.object(&linked)).unwrap();
    assert_eq!(
        store.open_verified(&linked).err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    let hardlinked = installed(&store, b"abc");
    fs::hard_link(temp.object(&hardlinked), temp.container.join("extra-link")).unwrap();
    assert_eq!(
        store.open_verified(&hardlinked).err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    let directory = ArtifactBlob::from_record(Uuid::now_v7(), 0, digest(b"")).unwrap();
    private_directory(&temp.object(&directory));
    assert_eq!(
        store.open_verified(&directory).err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    let fifo = ArtifactBlob::from_record(Uuid::now_v7(), 0, digest(b"")).unwrap();
    // Darwin's locked rustix has no mkfifoat; the standard system utility only receives
    // a path inside this test's freshly created private directory.
    let status = std::process::Command::new("mkfifo")
        .arg(temp.object(&fifo))
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(temp.object(&fifo), Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        store.open_verified(&fifo).err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    assert_eq!(fs::read(target).unwrap(), b"abc");
}

#[test]
fn existing_object_requires_exact_read_only_private_mode() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abc");
    for mode in [0o600, 0o440, 0o444, 0o1400] {
        fs::set_permissions(temp.object(&blob), Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            store.open_verified(&blob).err(),
            Some(ArtifactByteError::UnsafeObject)
        );
    }
    fs::set_permissions(temp.object(&blob), Permissions::from_mode(0o400)).unwrap();
    assert_eq!(read_all(&store, &blob, 2), b"abc");
}

#[test]
fn invalid_chunk_does_not_consume_reader_bytes() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abcdef");
    let mut reader = store.open_verified(&blob).unwrap();
    assert_eq!(
        reader.read_chunk(&mut []),
        Err(ArtifactByteError::InvalidChunk)
    );
    let mut oversized = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES + 1];
    assert_eq!(
        reader.read_chunk(&mut oversized),
        Err(ArtifactByteError::InvalidChunk)
    );
    assert!(oversized.iter().all(|&byte| byte == 0xa5));
    let mut output = [0; 3];
    assert_eq!(reader.read_chunk(&mut output).unwrap(), 3);
    assert_eq!(&output, b"abc");
    assert_eq!(reader.read_chunk(&mut output).unwrap(), 3);
    assert_eq!(&output, b"def");
    assert_eq!(reader.read_chunk(&mut output).unwrap(), 0);
}

#[test]
fn open_reader_rejects_later_metadata_change_and_repeat_reads() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abcdef");
    let mut reader = store.open_verified(&blob).unwrap();
    let mut output = [0; 3];
    assert_eq!(reader.read_chunk(&mut output).unwrap(), 3);
    assert_eq!(&output, b"abc");
    fs::set_permissions(temp.object(&blob), Permissions::from_mode(0o600)).unwrap();
    output.fill(0xa5);
    assert_eq!(
        reader.read_chunk(&mut output),
        Err(ArtifactByteError::UnsafeObject)
    );
    assert_eq!(output, [0xa5; 3]);
    fs::set_permissions(temp.object(&blob), Permissions::from_mode(0o400)).unwrap();
    assert_eq!(reader.read_chunk(&mut output), Err(ArtifactByteError::Io));
    assert_eq!(output, [0xa5; 3]);
}

#[test]
fn open_reader_rejects_later_content_change_even_when_length_and_mode_match() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abcdef");
    let path = temp.object(&blob);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
    let mut reader = store.open_verified(&blob).unwrap();
    let mut output = [0; 3];
    assert_eq!(reader.read_chunk(&mut output).unwrap(), 3);
    assert_eq!(&output, b"abc");
    writer.seek(SeekFrom::Start(3)).unwrap();
    writer.write_all(b"xyz").unwrap();
    writer
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(7))
        .unwrap();
    writer.sync_all().unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 6);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o400);
    output.fill(0xa5);
    assert_eq!(
        reader.read_chunk(&mut output),
        Err(ArtifactByteError::UnsafeObject)
    );
    assert_eq!(output, [0xa5; 3]);
    writer.seek(SeekFrom::Start(3)).unwrap();
    writer.write_all(b"def").unwrap();
    writer.sync_all().unwrap();
    assert_eq!(reader.read_chunk(&mut output), Err(ArtifactByteError::Io));
    assert_eq!(output, [0xa5; 3]);
}

#[test]
fn open_reader_rejects_truncation_and_does_not_return_a_short_success() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = installed(&store, b"abcdef");
    let mut reader = store.open_verified(&blob).unwrap();
    let path = temp.object(&blob);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let writer = OpenOptions::new().write(true).open(&path).unwrap();
    writer.set_len(2).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
    let mut output = [0xa5; 6];
    assert_eq!(
        reader.read_chunk(&mut output),
        Err(ArtifactByteError::UnsafeObject)
    );
    assert_eq!(output, [0xa5; 6]);
    assert_eq!(reader.read_chunk(&mut output), Err(ArtifactByteError::Io));
}

#[test]
fn stable_identity_staging_is_exclusive_between_concurrent_stores() {
    let temp = PrivateTemp::new();
    let first = temp.bind(MAX_ARTIFACT_BYTES);
    let second = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = ArtifactBlob::from_record(Uuid::now_v7(), 3, digest(b"abc")).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            first.stage_for(&mut Cursor::new(b"abc"), &blob)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            second.stage_for(&mut Cursor::new(b"abc"), &blob)
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let installed = match (left, right) {
        (Ok(stage), Err(ArtifactByteError::AlreadyExists)) => first.install(stage).unwrap(),
        (Err(ArtifactByteError::AlreadyExists), Ok(stage)) => second.install(stage).unwrap(),
        _ => panic!("exactly one same-id staging operation must succeed"),
    };
    assert_eq!(installed, blob);
    assert_eq!(read_all(&first, &installed, 2), b"abc");
    temp.assert_staging_empty();
    assert_eq!(
        fs::read_dir(temp.root().join("objects")).unwrap().count(),
        1
    );
}

#[test]
fn repeated_stable_identity_install_preserves_the_original_object() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let blob = ArtifactBlob::from_record(Uuid::now_v7(), 3, digest(b"abc")).unwrap();
    let stage = store.stage_for(&mut Cursor::new(b"abc"), &blob).unwrap();
    let installed = store.install(stage).unwrap();
    let original_inode = fs::metadata(temp.object(&installed)).unwrap().ino();
    let changed = ArtifactBlob::from_record(blob.id(), 3, digest(b"xyz")).unwrap();
    let stage = store.stage_for(&mut Cursor::new(b"xyz"), &changed).unwrap();
    assert_eq!(
        store.install(stage).err(),
        Some(ArtifactByteError::AlreadyExists)
    );
    assert_eq!(
        fs::metadata(temp.object(&installed)).unwrap().ino(),
        original_inode
    );
    assert_eq!(read_all(&store, &installed, 2), b"abc");
    temp.assert_staging_empty();
}

#[test]
fn private_directory_permissions_are_rechecked_after_binding() {
    for child in ["", "staging", "objects"] {
        let temp = PrivateTemp::new();
        let store = temp.bind(MAX_ARTIFACT_BYTES);
        let blob = installed(&store, b"abc");
        let stage = store
            .stage(&mut Cursor::new(b"xyz"), 3, digest(b"xyz"))
            .unwrap();
        let path = temp.root().join(child);
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        let mut input = NeverRead { reads: 0 };
        assert_eq!(
            store.stage(&mut input, 3, digest(b"abc")).err(),
            Some(ArtifactByteError::UnsafeObject)
        );
        assert_eq!(input.reads, 0);
        assert_eq!(
            store.open_verified(&blob).err(),
            Some(ArtifactByteError::UnsafeObject)
        );
        assert_eq!(
            store.install(stage).err(),
            Some(ArtifactByteError::UnsafeObject)
        );
        fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
        assert_eq!(read_all(&store, &blob, 2), b"abc");
    }
}

#[test]
fn replaced_root_path_cannot_redirect_the_bound_store() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let original_root = temp.container.join("bound-root");
    fs::rename(temp.root(), &original_root).unwrap();
    let decoy = temp.container.join("decoy-root");
    private_directory(&decoy);
    private_directory(&decoy.join("staging"));
    private_directory(&decoy.join("objects"));
    symlink(&decoy, temp.root()).unwrap();
    let blob = installed(&store, b"original directory");
    assert_eq!(read_all(&store, &blob, 5), b"original directory");
    assert!(
        original_root
            .join("objects")
            .join(blob.id().to_string())
            .is_file()
    );
    assert_eq!(fs::read_dir(decoy.join("staging")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(decoy.join("objects")).unwrap().count(), 0);
}

#[test]
fn replaced_child_paths_cannot_redirect_staging_install_or_reading() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"before"), 6, digest(b"before"))
        .unwrap();
    let retained_staging = temp.root().join("bound-staging");
    let retained_objects = temp.root().join("bound-objects");
    for (name, retained) in [
        ("staging", &retained_staging),
        ("objects", &retained_objects),
    ] {
        fs::rename(temp.root().join(name), retained).unwrap();
        let decoy = temp.container.join(format!("decoy-{name}"));
        private_directory(&decoy);
        symlink(&decoy, temp.root().join(name)).unwrap();
    }
    let first = store.install(stage).unwrap();
    let second = installed(&store, b"after");
    assert_eq!(read_all(&store, &first, 3), b"before");
    assert_eq!(read_all(&store, &second, 3), b"after");
    assert_eq!(fs::read_dir(retained_staging).unwrap().count(), 0);
    assert_eq!(fs::read_dir(retained_objects).unwrap().count(), 2);
    for name in ["staging", "objects"] {
        assert_eq!(
            fs::read_dir(temp.container.join(format!("decoy-{name}")))
                .unwrap()
                .count(),
            0
        );
    }
}

fn replace_stage_leaf(temp: &PrivateTemp, blob: &ArtifactBlob) -> PathBuf {
    let path = temp.stage(blob);
    let retained = temp.container.join(format!("retained-{}", blob.id()));
    fs::rename(&path, retained).unwrap();
    private_object(&path, b"replacement must survive");
    path
}

#[test]
fn drop_cannot_remove_a_replacement_staging_inode() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    let replacement = replace_stage_leaf(&temp, stage.blob());
    drop(stage);
    assert_eq!(fs::read(replacement).unwrap(), b"replacement must survive");
}

#[test]
fn discard_reports_cleanup_failure_and_preserves_replacement_staging_inode() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    let replacement = replace_stage_leaf(&temp, stage.blob());
    assert_eq!(stage.discard(), Err(ArtifactByteError::CleanupFailed));
    assert_eq!(fs::read(replacement).unwrap(), b"replacement must survive");
}

#[test]
fn install_rejects_replacement_staging_inode_without_deleting_it() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let stage = store
        .stage(&mut Cursor::new(b"abc"), 3, digest(b"abc"))
        .unwrap();
    let object = temp.object(stage.blob());
    let replacement = replace_stage_leaf(&temp, stage.blob());
    assert_eq!(
        store.install(stage).err(),
        Some(ArtifactByteError::UnsafeObject)
    );
    assert_eq!(fs::read(replacement).unwrap(), b"replacement must survive");
    assert!(!object.exists());
}

struct ReplaceStageThenFail {
    staging: PathBuf,
    retained: PathBuf,
    replacement: Option<PathBuf>,
}

impl Read for ReplaceStageThenFail {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        let path = fs::read_dir(&self.staging)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::rename(&path, &self.retained).unwrap();
        private_object(&path, b"replacement after input failure");
        self.replacement = Some(path);
        Err(io::Error::other(
            "synthetic input failure after leaf replacement",
        ))
    }
}

#[test]
fn input_failure_cleanup_preserves_a_replaced_staging_leaf() {
    let temp = PrivateTemp::new();
    let store = temp.bind(MAX_ARTIFACT_BYTES);
    let mut input = ReplaceStageThenFail {
        staging: temp.root().join("staging"),
        retained: temp.container.join("original-stage"),
        replacement: None,
    };
    assert_eq!(
        store.stage(&mut input, 3, digest(b"abc")).err(),
        Some(ArtifactByteError::CleanupFailed)
    );
    assert_eq!(
        fs::read(input.replacement.unwrap()).unwrap(),
        b"replacement after input failure"
    );
    assert_eq!(
        fs::read_dir(temp.root().join("objects")).unwrap().count(),
        0
    );
}
