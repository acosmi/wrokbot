//! Bounded, read-only inputs for repository review commands.
//! Unix traversal holds directory descriptors and never follows an untrusted child link.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputError {
    Path,
    Symlink,
    Missing,
    Limit,
    Changed,
    #[cfg(not(unix))]
    Unsupported,
}

pub(crate) fn read_argument(path: &Path, max: u64) -> Result<Vec<u8>, InputError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(InputError::Path)?;
    read_under(parent, Path::new(name), max)
}

pub(crate) fn read_under(root: &Path, relative: &Path, max: u64) -> Result<Vec<u8>, InputError> {
    let mut bytes = Vec::new();
    stream_under(root, relative, max, |chunk| bytes.extend_from_slice(chunk))?;
    Ok(bytes)
}

pub(crate) fn hash_under(
    root: &Path,
    relative: &Path,
    max: u64,
) -> Result<(String, u64), InputError> {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    let length = stream_under(root, relative, max, |chunk| hash.update(chunk))?;
    Ok((format!("{:x}", hash.finalize()), length))
}

#[cfg(unix)]
fn stream_under(
    root: &Path,
    relative: &Path,
    max: u64,
    mut consume: impl FnMut(&[u8]),
) -> Result<u64, InputError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|p| !matches!(p, Component::Normal(_))) {
        return Err(InputError::Path);
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let root = root.canonicalize().map_err(|_| InputError::Missing)?;
    let mut directory = open(&root, flags | OFlags::DIRECTORY, Mode::empty()).map_err(map_open)?;
    for part in &parts[..parts.len() - 1] {
        directory = openat(
            &directory,
            part.as_os_str(),
            flags | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(map_open)?;
    }
    let descriptor = openat(
        &directory,
        parts.last().unwrap().as_os_str(),
        flags,
        Mode::empty(),
    )
    .map_err(map_open)?;
    let before = fstat(&descriptor).map_err(|_| InputError::Missing)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_nlink != 1 {
        return Err(InputError::Path);
    }
    let length = u64::try_from(before.st_size).map_err(|_| InputError::Limit)?;
    if length > max {
        return Err(InputError::Limit);
    }
    let mut file = File::from(descriptor);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        // Even a growing file is read only through a bounded chunk and budget.
        let count = file.read(&mut buffer).map_err(|_| InputError::Missing)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(InputError::Limit)?;
        if total > max || total > length {
            return Err(InputError::Limit);
        }
        consume(&buffer[..count]);
    }
    let after = fstat(&file).map_err(|_| InputError::Missing)?;
    if before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
        || total != length
    {
        return Err(InputError::Changed);
    }
    Ok(total)
}

#[cfg(unix)]
fn map_open(error: rustix::io::Errno) -> InputError {
    match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => InputError::Symlink,
        _ => InputError::Missing,
    }
}

#[cfg(not(unix))]
fn stream_under(
    _root: &Path,
    _relative: &Path,
    _max: u64,
    _consume: impl FnMut(&[u8]),
) -> Result<u64, InputError> {
    Err(InputError::Unsupported)
}

pub(crate) fn json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    // Validate duplicate keys before the typed pass; serde maps otherwise silently overwrite them.
    serde_json::from_slice::<UniqueJson>(bytes)?;
    serde_json::from_slice(bytes)
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded JSON with unique object keys")
            }
            fn visit_bool<E>(self, _: bool) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E>(self, _: i64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E>(self, _: u64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E>(self, _: f64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E>(self) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_none<E>(self) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueJson, A::Error> {
                let mut count = 0;
                while seq.next_element::<UniqueJson>()?.is_some() {
                    count += 1;
                    if count > 16384 {
                        return Err(serde::de::Error::custom("JSON collection budget"));
                    }
                }
                Ok(UniqueJson)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueJson, A::Error> {
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    if seen.len() > 16384 {
                        return Err(serde::de::Error::custom("JSON collection budget"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_at_any_depth_fail() {
        assert!(json::<serde_json::Value>(br#"{"outer":{"a":1,"a":2}}"#).is_err());
        assert!(json::<serde_json::Value>(br#"{"outer":[{"a":1},{"a":2}]}"#).is_ok());
    }

    #[test]
    fn descriptor_read_rejects_links_escape_and_oversize() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "review-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir(dir.join("inside")).unwrap();
        std::fs::write(dir.join("inside/file"), b"data").unwrap();
        assert_eq!(
            read_under(&dir, Path::new("inside/file"), 4).unwrap(),
            b"data"
        );
        assert_eq!(
            read_under(&dir, Path::new("inside/file"), 3),
            Err(InputError::Limit)
        );
        symlink("inside", dir.join("alias")).unwrap();
        assert_eq!(
            read_under(&dir, Path::new("alias/file"), 4),
            Err(InputError::Symlink)
        );
        symlink("inside/file", dir.join("link")).unwrap();
        assert_eq!(
            read_under(&dir, Path::new("link"), 4),
            Err(InputError::Symlink)
        );
        assert_eq!(
            read_under(&dir, Path::new("../outside"), 4),
            Err(InputError::Path)
        );
        std::fs::hard_link(dir.join("inside/file"), dir.join("hard")).unwrap();
        assert_eq!(
            read_under(&dir, Path::new("hard"), 4),
            Err(InputError::Path)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
