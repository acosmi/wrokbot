//! 句柄级文件核验。参考 Desktop `postgres_sidecar/bundle_fs.rs` 的方法，不依赖 Desktop。
//!
//! 校验针对**已打开的句柄**，不是只 stat 一次后盲信路径。无法证明安全的目标直接拒绝。
//! 本模块无应用 unsafe；Unix 使用既有锁定 rustix 的安全句柄 API。

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::Path;

use super::StagingFault;

/// 单块上限：4MiB。
pub const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn io_fail(err: io::Error, write: bool) -> StagingFault {
    match err.kind() {
        io::ErrorKind::AlreadyExists => StagingFault::StagingExists,
        io::ErrorKind::NotFound => StagingFault::OpenFailed,
        io::ErrorKind::StorageFull => StagingFault::CapacityExhausted,
        _ if write => StagingFault::WriteFailed,
        _ => StagingFault::OpenFailed,
    }
}

fn shape() -> StagingFault {
    StagingFault::LinkOrSpecialFile
}

pub(crate) fn check_file(metadata: &Metadata, limit: u64) -> Result<(), StagingFault> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(shape());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(shape());
        }
        let mode = metadata.mode();
        if (mode & 0o170000) != 0o100000 {
            return Err(shape());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Stable 1.98 不暴露 nlink。不能声称 Unix 的硬链接保证；无法证明时拒绝 reparse。
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(StagingFault::OsBindingUnprovable);
        }
    }
    Ok(())
}

/// 路径身份：dev/ino 或 Windows volume+index。两次 stat 仍不是原子 path-bind。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PathIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume: u32,
    #[cfg(windows)]
    index: u64,
}

pub(crate) fn identity_of(metadata: &Metadata) -> Result<PathIdentity, StagingFault> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(PathIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(PathIdentity {
            volume: metadata
                .volume_serial_number()
                .ok_or(StagingFault::OsBindingUnprovable)?,
            index: metadata
                .file_index()
                .ok_or(StagingFault::OsBindingUnprovable)?,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(StagingFault::OsBindingUnprovable)
    }
}

pub(crate) fn verify_owned_dir(
    path: &Path,
    expected: PathIdentity,
    replaced: StagingFault,
) -> Result<(), StagingFault> {
    let metadata = inspect_nofollow(path)?;
    if metadata.file_type().is_symlink() {
        return Err(replaced);
    }
    check_dir(&metadata)?;
    if identity_of(&metadata)? != expected {
        return Err(replaced);
    }
    Ok(())
}

pub(crate) fn check_dir(metadata: &Metadata) -> Result<(), StagingFault> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(shape());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(StagingFault::OsBindingUnprovable);
        }
    }
    Ok(())
}

pub(crate) fn inspect_nofollow(path: &Path) -> Result<Metadata, StagingFault> {
    fs::symlink_metadata(path).map_err(|err| io_fail(err, false))
}

pub(crate) fn validate_component(name: &str) -> Result<(), StagingFault> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
    {
        return Err(StagingFault::PathInvalid);
    }
    if name.len() >= 2 && name.as_bytes()[1] == b':' {
        return Err(StagingFault::PathInvalid);
    }
    Ok(())
}

/// 从已打开句柄按块读取，最多读 `expected+1` 以捕捉增长。
pub(crate) fn read_next(
    file: &mut File,
    before: &Metadata,
    limit: u64,
    expected: u64,
    already: u64,
    chunk_size: usize,
) -> Result<Vec<u8>, StagingFault> {
    check_file(before, limit)?;
    if already > expected {
        return Err(StagingFault::LengthExceeded);
    }
    let want = (expected - already)
        .min(chunk_size as u64)
        .min(u64::from(u32::MAX)) as usize;
    // 允许再读 1 字节以发现额外尾部。
    let take = want.saturating_add(if already + want as u64 >= expected {
        1
    } else {
        0
    });
    let mut buf = vec![0_u8; take];
    let n = file.read(&mut buf).map_err(|err| io_fail(err, false))?;
    buf.truncate(n);
    if already + n as u64 > expected {
        return Err(StagingFault::ExtraTail);
    }
    Ok(buf)
}

pub(crate) fn persist_file(
    file: &mut File,
    expected_len: u64,
    limit: u64,
) -> Result<(), StagingFault> {
    file.sync_all().map_err(|_| StagingFault::SyncFailed)?;
    let after = file.metadata().map_err(|err| io_fail(err, false))?;
    check_file(&after, limit)?;
    if after.len() != expected_len {
        return Err(StagingFault::DestinationReplaced);
    }
    Ok(())
}

pub(crate) fn revalidate_handle(
    file: &File,
    before: &Metadata,
    limit: u64,
) -> Result<(), StagingFault> {
    let after = file.metadata().map_err(|err| io_fail(err, false))?;
    check_file(&after, limit)?;
    check_file(before, limit)?;
    if after.len() != before.len() {
        return Err(StagingFault::SourceReplaced);
    }
    Ok(())
}

/// Open a trusted host root once, then use its descriptor for every archive component.
/// Root aliases (e.g. macOS /var) are resolved only at acquisition, never at a later effect.
#[cfg(unix)]
pub(crate) fn bind_directory(path: &Path) -> Result<File, StagingFault> {
    check_dir(&inspect_nofollow(path)?)?;
    let canonical = path.canonicalize().map_err(|e| io_fail(e, false))?;
    let mut dir = File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| StagingFault::OpenFailed)?,
    );
    for part in canonical.components() {
        match part {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                dir = open_dir_at(&dir, name)?;
            }
            _ => return Err(StagingFault::PathInvalid),
        }
    }
    if identity_of(&dir.metadata().map_err(|e| io_fail(e, false))?)?
        != identity_of(&inspect_nofollow(path)?)?
    {
        return Err(StagingFault::SourceReplaced);
    }
    Ok(dir)
}
#[cfg(not(unix))]
pub(crate) fn bind_directory(_: &Path) -> Result<File, StagingFault> {
    Err(StagingFault::OsBindingUnprovable)
}
#[cfg(unix)]
pub(crate) fn open_dir_at(parent: &File, name: &std::ffi::OsStr) -> Result<File, StagingFault> {
    let f = File::from(
        rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| StagingFault::LinkOrSpecialFile)?,
    );
    check_dir(&f.metadata().map_err(|e| io_fail(e, false))?)?;
    Ok(f)
}
#[cfg(not(unix))]
pub(crate) fn open_dir_at(_: &File, _: &std::ffi::OsStr) -> Result<File, StagingFault> {
    Err(StagingFault::OsBindingUnprovable)
}
#[cfg(unix)]
pub(crate) fn file_at(
    parent: &File,
    name: &std::ffi::OsStr,
    create: bool,
    limit: u64,
) -> Result<File, StagingFault> {
    use rustix::fs::{Mode, OFlags, openat};
    let access = if create {
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
    } else {
        OFlags::RDONLY
    };
    let file = File::from(
        openat(
            parent,
            name,
            access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| match e {
            rustix::io::Errno::EXIST => StagingFault::StagingExists,
            rustix::io::Errno::LOOP => StagingFault::LinkOrSpecialFile,
            _ => StagingFault::OpenFailed,
        })?,
    );
    check_file(&file.metadata().map_err(|e| io_fail(e, false))?, limit)?;
    Ok(file)
}
#[cfg(not(unix))]
pub(crate) fn file_at(
    _: &File,
    _: &std::ffi::OsStr,
    _: bool,
    _: u64,
) -> Result<File, StagingFault> {
    Err(StagingFault::OsBindingUnprovable)
}
