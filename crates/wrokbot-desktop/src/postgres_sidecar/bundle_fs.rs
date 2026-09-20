//! Bounded bundle reads. Validation refers to the opened handle, not only a prior path stat.
//! This module does not make a mutable directory immutable or provide atomic path-to-exec binding.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{
    BUNDLE_MAX_BYTES, BUNDLE_MAX_FILES, MANIFEST_FILE, PostgresSidecarError, normalized_relative,
};

pub(super) const BUNDLE_MAX_ENTRIES: usize = 16_384;

fn shape() -> PostgresSidecarError {
    PostgresSidecarError::BundleShape
}

fn check_file(metadata: &Metadata, limit: u64) -> Result<(), PostgresSidecarError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(shape());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(shape());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Link count is not exposed by stable Rust 1.98 on Windows. Do not claim Unix's nlink
        // guarantee here; Windows release still requires its separately audited native boundary.
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(shape());
        }
    }
    Ok(())
}

pub(super) fn open_regular(
    path: &Path,
    limit: u64,
) -> Result<(File, Metadata), PostgresSidecarError> {
    check_file(&fs::symlink_metadata(path)?, limit)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Darwin O_NOFOLLOW | O_NONBLOCK: a raced FIFO must not block before handle validation.
        options.custom_flags(0x100 | 0x4);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000 | 0x800);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // OPEN_REPARSE_POINT; keep other write/delete opens out while this read handle lives.
        options.custom_flags(0x0020_0000).share_mode(0x1);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    check_file(&metadata, limit)?;
    Ok((file, metadata))
}

fn consume_opened(
    mut file: File,
    before: &Metadata,
    limit: u64,
    mut consume: impl FnMut(&[u8]) -> Result<(), PostgresSidecarError>,
) -> Result<u64, PostgresSidecarError> {
    check_file(before, limit)?;
    let expected = before.len();
    let mut read = 0_u64;
    let mut bounded = (&mut file).take(expected + 1);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = bounded.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read = read.checked_add(count as u64).ok_or_else(shape)?;
        if read > expected || read > limit {
            return Err(shape());
        }
        consume(&buffer[..count])?;
    }
    let after = file.metadata()?;
    check_file(&after, limit)?;
    if read != expected || after.len() != expected {
        return Err(shape());
    }
    Ok(read)
}

pub(super) fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, PostgresSidecarError> {
    let (file, metadata) = open_regular(path, limit)?;
    let mut bytes = Vec::new();
    consume_opened(file, &metadata, limit, |chunk| {
        bytes.write_all(chunk)?;
        Ok(())
    })?;
    Ok(bytes)
}

pub(super) fn hash_file(path: &Path, limit: u64) -> Result<([u8; 32], u64), PostgresSidecarError> {
    let (file, metadata) = open_regular(path, limit)?;
    let mut hash = Sha256::new();
    let read = consume_opened(file, &metadata, limit, |chunk| {
        hash.update(chunk);
        Ok(())
    })?;
    Ok((hash.finalize().into(), read))
}

pub(super) fn inventory(
    root: &Path,
    expected: Option<&BTreeMap<String, String>>,
) -> Result<BTreeSet<String>, PostgresSidecarError> {
    inventory_with_limit(root, expected, BUNDLE_MAX_ENTRIES)
}

fn inventory_with_limit(
    root: &Path,
    expected: Option<&BTreeMap<String, String>>,
    entry_limit: usize,
) -> Result<BTreeSet<String>, PostgresSidecarError> {
    let mut pending: Vec<PathBuf> = vec![root.to_owned()];
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut total_bytes = 0_u64;
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(shape());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(shape());
            }
        }
        for entry in fs::read_dir(directory)? {
            entries = entries.checked_add(1).ok_or_else(shape)?;
            if entries > entry_limit {
                return Err(shape());
            }
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = normalized_relative(root, &path)?;
            if metadata.file_type().is_symlink() {
                return Err(shape());
            }
            if metadata.is_dir() {
                let prefix = format!("{relative}/");
                if expected.is_some_and(|files| !files.keys().any(|file| file.starts_with(&prefix)))
                {
                    return Err(shape());
                }
                directories.insert(relative);
                pending.push(path);
            } else {
                check_file(&metadata, BUNDLE_MAX_BYTES)?;
                if relative == MANIFEST_FILE {
                    continue;
                }
                if expected.is_some_and(|files| !files.contains_key(&relative)) {
                    return Err(shape());
                }
                total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(shape)?;
                if total_bytes > BUNDLE_MAX_BYTES
                    || !files.insert(relative)
                    || files.len() > BUNDLE_MAX_FILES
                {
                    return Err(shape());
                }
            }
        }
    }
    // The manifest has no directory entries: even fixture scans cannot silently bless empty dirs.
    for directory in directories {
        let prefix = format!("{directory}/");
        if !files.iter().any(|file| file.starts_with(&prefix)) {
            return Err(shape());
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wrok-pg-bounded-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn directories_consume_entry_budget_and_empty_directories_are_not_inventory() {
        let root = Temp::new();
        for name in ["one", "two", "three"] {
            fs::create_dir(root.0.join(name)).unwrap();
        }
        assert!(inventory_with_limit(&root.0, None, 2).is_err());
        assert!(inventory(&root.0, None).is_err());
        for name in ["one", "two", "three"] {
            fs::write(root.0.join(name).join("value"), b"x").unwrap();
        }
        assert!(inventory_with_limit(&root.0, None, 5).is_err());
        assert_eq!(inventory_with_limit(&root.0, None, 6).unwrap().len(), 3);
        let expected = BTreeMap::from([("one/value".to_owned(), String::new())]);
        assert!(inventory(&root.0, Some(&expected)).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn opened_handle_growth_shrink_and_budget_are_rejected() {
        let root = Temp::new();
        let path = root.0.join("value");
        for replacement in [b"abcdefgh".as_slice(), b"a".as_slice()] {
            fs::write(&path, b"abcd").unwrap();
            let (file, before) = open_regular(&path, 8).unwrap();
            fs::write(&path, replacement).unwrap();
            let mut delivered = 0;
            assert!(
                consume_opened(file, &before, 8, |chunk| {
                    delivered += chunk.len();
                    Ok(())
                })
                .is_err()
            );
            assert!(delivered <= 4);
        }
        fs::write(&path, b"abcd").unwrap();
        assert!(read_bytes(&path, 3).is_err());
        assert_eq!(read_bytes(&path, 4).unwrap(), b"abcd");
        assert_eq!(
            hash_file(&path, 4).unwrap(),
            (Sha256::digest(b"abcd").into(), 4)
        );
        assert!(read_bytes(&root.0, 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn links_are_rejected_at_open_and_again_on_the_live_handle() {
        use std::os::unix::fs::symlink;
        let root = Temp::new();
        let path = root.0.join("value");
        let link = root.0.join("link");
        fs::write(&path, b"abcd").unwrap();
        let (file, before) = open_regular(&path, 4).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(read_bytes(&path, 4).is_err());
        assert!(consume_opened(file, &before, 4, |_| Ok(())).is_err());
        fs::remove_file(&link).unwrap();
        symlink(&path, &link).unwrap();
        assert!(read_bytes(&link, 4).is_err());
        assert!(inventory(&root.0, None).is_err());
    }
}
