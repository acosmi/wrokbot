//! Real temporary-directory checks of descriptor-bound IO; no product data or restore switch.
#![cfg(unix)]
use openbot_infra::backup::{FsPort, StagingFault, StdFs};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "wrok-owned-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn f01_bound_directory_replacement_never_creates_in_another_directory() {
    let t = Temp::new();
    let parent = StdFs.bind_dir(&t.0).unwrap();
    let owned = StdFs.create_private_dir(&parent, "owned").unwrap();
    fs::create_dir(t.0.join("protected")).unwrap();
    fs::write(t.0.join("protected/canary"), b"preserve").unwrap();
    fs::rename(t.0.join("owned"), t.0.join("moved")).unwrap();
    symlink(t.0.join("protected"), t.0.join("owned")).unwrap();
    assert!(StdFs.create_file_noclobber(&owned, "unexpected").is_err());
    assert!(!t.0.join("protected/unexpected").exists());
    assert_eq!(fs::read(t.0.join("protected/canary")).unwrap(), b"preserve");
}
#[test]
fn f02_open_sink_keeps_original_file_when_path_is_replaced() {
    let t = Temp::new();
    let parent = StdFs.bind_dir(&t.0).unwrap();
    let root = StdFs.create_private_dir(&parent, "stage").unwrap();
    let (file, mut sink) = StdFs.create_file_noclobber(&root, "payload").unwrap();
    fs::write(t.0.join("canary"), b"preserve").unwrap();
    fs::rename(file.as_path(), root.as_path().join("moved")).unwrap();
    symlink(t.0.join("canary"), file.as_path()).unwrap();
    assert_eq!(sink.write(b"new").unwrap(), 3);
    sink.persist(3, 16).unwrap();
    assert_eq!(fs::read(t.0.join("canary")).unwrap(), b"preserve");
    assert_eq!(fs::read(root.as_path().join("moved")).unwrap(), b"new");
}
#[test]
fn f03_cleanup_without_atomic_leaf_ownership_preserves_every_object() {
    let t = Temp::new();
    let parent = StdFs.bind_dir(&t.0).unwrap();
    let root = StdFs.create_private_dir(&parent, "stage").unwrap();
    let (file, mut sink) = StdFs.create_file_noclobber(&root, "payload").unwrap();
    sink.write(b"new").unwrap();
    assert_eq!(
        StdFs.remove_file(&root, &file),
        Err(StagingFault::OsBindingUnprovable)
    );
    assert!(file.as_path().exists());
    fs::rename(file.as_path(), root.as_path().join("moved")).unwrap();
    fs::write(file.as_path(), b"preserve").unwrap();
    assert_eq!(
        StdFs.remove_file(&root, &file),
        Err(StagingFault::OsBindingUnprovable)
    );
    assert_eq!(fs::read(file.as_path()).unwrap(), b"preserve");
    assert_eq!(
        StdFs.remove_dir(&parent, &root),
        Err(StagingFault::OsBindingUnprovable)
    );
}
#[test]
fn f04_creation_is_private_and_never_replaces_existing_leaf() {
    let t = Temp::new();
    let parent = StdFs.bind_dir(&t.0).unwrap();
    let root = StdFs.create_private_dir(&parent, "stage").unwrap();
    let (file, mut sink) = StdFs.create_file_noclobber(&root, "payload").unwrap();
    assert_eq!(
        fs::metadata(root.as_path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(file.as_path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    sink.write(b"new").unwrap();
    sink.persist(3, 3).unwrap();
    assert!(StdFs.create_file_noclobber(&root, "payload").is_err());
    assert_eq!(fs::read(file.as_path()).unwrap(), b"new");
}
