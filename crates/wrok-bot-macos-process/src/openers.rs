//! Read-only enumeration of processes holding open references under one data directory.

use crate::ProcessObservationError;
use std::ffi::{OsStr, c_int, c_void};
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const PROC_PIDFDVNODEPATHINFO: c_int = 2;
const MAX_PIDS: usize = 65_536;
const MAX_FDS: usize = 16_384;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: libc::vnode_info_path,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct OpenerKey {
    pub(super) pid: i32,
    pub(super) start_seconds: u64,
    pub(super) start_microseconds: u32,
    pub(super) boot_session: [u8; 16],
}

/// Double-scan openers of `data_dir` matching `expected_device`/`expected_inode`.
pub(super) fn observe_openers(
    data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<Vec<OpenerKey>, ProcessObservationError> {
    if expected_inode == 0 || !data_dir.is_absolute() {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let canonical = canonicalize_data_dir(data_dir)?;
    let sizes = (
        size_of::<ProcFileInfo>(),
        size_of::<VnodeFdInfoWithPath>(),
        size_of::<libc::vnode_info_path>(),
        size_of::<libc::proc_vnodepathinfo>(),
        size_of::<libc::proc_fdinfo>(),
    );
    if sizes != (24, 1200, 1176, 2352, 8) {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }

    let mut last = ProcessObservationError::ObservationChanged;
    for _ in 0..8 {
        match observe_openers_stable(&canonical, expected_device, expected_inode) {
            Ok(openers) => return Ok(openers),
            Err(ProcessObservationError::ObservationChanged) => {
                last = ProcessObservationError::ObservationChanged;
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

fn observe_openers_stable(
    canonical: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<Vec<OpenerKey>, ProcessObservationError> {
    let boot_a = crate::native::read_boot_session_for_openers()?;
    let first = scan_once(canonical, expected_device, expected_inode, boot_a)?;
    let second = scan_once(canonical, expected_device, expected_inode, boot_a)?;
    let boot_b = crate::native::read_boot_session_for_openers()?;
    if boot_a != boot_b || first != second {
        return Err(ProcessObservationError::ObservationChanged);
    }
    Ok(first)
}

fn canonicalize_data_dir(data_dir: &Path) -> Result<PathBuf, ProcessObservationError> {
    let canonical = data_dir
        .canonicalize()
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    if !canonical.is_absolute() {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    Ok(canonical)
}

fn scan_once(
    canonical_data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
    boot: [u8; 16],
) -> Result<Vec<OpenerKey>, ProcessObservationError> {
    let pids = list_all_pids()?;
    let mut matched = Vec::new();
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        match process_matches_data_dir(pid, canonical_data_dir, expected_device, expected_inode) {
            Ok(true) => {
                let birth = match crate::native::read_process_birth_for_openers(pid) {
                    Ok(birth) => birth,
                    Err(ProcessObservationError::ProcessUnavailable)
                    | Err(ProcessObservationError::ProcessDataInvalid) => continue,
                    Err(error) => return Err(error),
                };
                matched.push(OpenerKey {
                    pid: birth.pid,
                    start_seconds: birth.start_seconds,
                    start_microseconds: birth.start_microseconds,
                    boot_session: boot,
                });
            }
            Ok(false) => {}
            Err(ProcessObservationError::ProcessUnavailable) => continue,
            Err(error) => return Err(error),
        }
    }
    matched.sort_unstable();
    matched.dedup();
    Ok(matched)
}

fn clear_errno() {
    // SAFETY: writing zero to thread-local errno is the documented way to distinguish
    // libproc's "return 0 with errno" failure from a true empty result.
    unsafe { *libc::__error() = 0 };
}

fn list_all_pids() -> Result<Vec<i32>, ProcessObservationError> {
    // First ask for the byte count with a null buffer, then fill a bounded buffer.
    // SAFETY: null buffer with size 0 is the documented size-query form for `proc_listallpids`.
    clear_errno();
    let hinted = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if hinted < 0 {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let count = usize::try_from(hinted).map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    let capacity = count.saturating_add(64).min(MAX_PIDS);
    let mut buffer = vec![0_i32; capacity];
    let bytes = c_int::try_from(buffer.len().saturating_mul(size_of::<i32>()))
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    // SAFETY: buffer is writable for `bytes` and aligned for `pid_t`/`i32` values.
    clear_errno();
    let returned = unsafe { libc::proc_listallpids(buffer.as_mut_ptr().cast::<c_void>(), bytes) };
    if returned < 0 {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let filled =
        usize::try_from(returned).map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    if filled > buffer.len() {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    buffer.truncate(filled);
    Ok(buffer)
}

fn process_matches_data_dir(
    pid: i32,
    canonical_data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<bool, ProcessObservationError> {
    if cwd_or_root_matches(pid, canonical_data_dir, expected_device, expected_inode)? {
        return Ok(true);
    }
    let fds = list_fds(pid)?;
    for fd_info in fds {
        if fd_info.proc_fdtype != libc::PROX_FDTYPE_VNODE as u32 {
            continue;
        }
        if vnode_fd_matches(
            pid,
            fd_info.proc_fd,
            canonical_data_dir,
            expected_device,
            expected_inode,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unavailable_or_invalid() -> ProcessObservationError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) | Some(libc::ENOENT) | Some(libc::EPERM) | Some(libc::EACCES)
        | Some(libc::EBADF) => ProcessObservationError::ProcessUnavailable,
        _ => ProcessObservationError::ProcessDataInvalid,
    }
}

fn list_fds(pid: i32) -> Result<Vec<libc::proc_fdinfo>, ProcessObservationError> {
    let probe_size = c_int::try_from(size_of::<libc::proc_fdinfo>().saturating_mul(64))
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    // SAFETY: null-sized query is not used; a small probe discovers whether the process exists.
    let mut probe = vec![MaybeUninit::<libc::proc_fdinfo>::uninit(); 64];
    clear_errno();
    let first = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            probe.as_mut_ptr().cast::<c_void>(),
            probe_size,
        )
    };
    if first < 0 {
        return Err(unavailable_or_invalid());
    }
    if first == 0 {
        // Exact empty fd table, or a raced process. Prefer Empty over false Invalid.
        return Ok(Vec::new());
    }
    let first_bytes =
        usize::try_from(first).map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    if first_bytes % size_of::<libc::proc_fdinfo>() != 0 {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let needed = (first_bytes / size_of::<libc::proc_fdinfo>()).saturating_add(64);
    if needed > MAX_FDS {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let mut buffer = vec![MaybeUninit::<libc::proc_fdinfo>::uninit(); needed];
    let bytes = c_int::try_from(needed.saturating_mul(size_of::<libc::proc_fdinfo>()))
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    // SAFETY: buffer is writable for `bytes` and aligned for `proc_fdinfo`.
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast::<c_void>(),
            bytes,
        )
    };
    if returned <= 0 {
        return Err(unavailable_or_invalid());
    }
    let returned_bytes =
        usize::try_from(returned).map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    if returned_bytes % size_of::<libc::proc_fdinfo>() != 0
        || returned_bytes > needed.saturating_mul(size_of::<libc::proc_fdinfo>())
    {
        return Err(ProcessObservationError::ProcessDataInvalid);
    }
    let count = returned_bytes / size_of::<libc::proc_fdinfo>();
    let mut out = Vec::with_capacity(count);
    for slot in buffer.into_iter().take(count) {
        // SAFETY: libproc wrote exactly `count` complete `proc_fdinfo` values.
        out.push(unsafe { slot.assume_init() });
    }
    Ok(out)
}

fn vnode_fd_matches(
    pid: i32,
    fd: i32,
    canonical_data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<bool, ProcessObservationError> {
    let expected_size = c_int::try_from(size_of::<VnodeFdInfoWithPath>())
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    let mut info = MaybeUninit::<VnodeFdInfoWithPath>::zeroed();
    // SAFETY: buffer is zeroed, aligned, and sized exactly for `PROC_PIDFDVNODEPATHINFO`.
    let returned = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            info.as_mut_ptr().cast::<c_void>(),
            expected_size,
        )
    };
    if returned != expected_size {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) | Some(libc::EBADF) | Some(libc::EPERM)
            | Some(libc::EACCES) => Ok(false),
            _ => Err(unavailable_or_invalid()),
        };
    }
    // SAFETY: exact-size success is the libproc contract for one complete reply.
    let info = unsafe { info.assume_init() };
    Ok(vnode_path_matches(
        &info.pvip,
        canonical_data_dir,
        expected_device,
        expected_inode,
    ))
}

fn cwd_or_root_matches(
    pid: i32,
    canonical_data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<bool, ProcessObservationError> {
    let expected_size = c_int::try_from(size_of::<libc::proc_vnodepathinfo>())
        .map_err(|_| ProcessObservationError::ProcessDataInvalid)?;
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    // SAFETY: buffer is zeroed and sized for `PROC_PIDVNODEPATHINFO`.
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            expected_size,
        )
    };
    if returned != expected_size {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) | Some(libc::EPERM) | Some(libc::EACCES) => {
                Err(ProcessObservationError::ProcessUnavailable)
            }
            _ => Ok(false),
        };
    }
    // SAFETY: exact-size success fills one `proc_vnodepathinfo`.
    let info = unsafe { info.assume_init() };
    Ok(vnode_path_matches(
        &info.pvi_cdir,
        canonical_data_dir,
        expected_device,
        expected_inode,
    ) || vnode_path_matches(
        &info.pvi_rdir,
        canonical_data_dir,
        expected_device,
        expected_inode,
    ))
}

fn vnode_path_matches(
    path_info: &libc::vnode_info_path,
    canonical_data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> bool {
    let device = u64::from(path_info.vip_vi.vi_stat.vst_dev);
    if device != expected_device {
        return false;
    }
    if path_info.vip_vi.vi_stat.vst_ino == expected_inode {
        return true;
    }
    let Some(path) = vip_path_as_path(path_info) else {
        return false;
    };
    path_is_equal_or_strict_child(&path, canonical_data_dir)
}

fn vip_path_as_path(path_info: &libc::vnode_info_path) -> Option<PathBuf> {
    // libc stores MAXPATHLEN as [[c_char; 32]; 32].
    let raw = unsafe { std::slice::from_raw_parts(path_info.vip_path.as_ptr().cast::<u8>(), 1024) };
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&raw[..end])))
}

fn path_is_equal_or_strict_child(candidate: &Path, parent: &Path) -> bool {
    if candidate == parent {
        return true;
    }
    let mut parent_components = parent.components();
    let mut candidate_components = candidate.components();
    loop {
        match (parent_components.next(), candidate_components.next()) {
            (None, None) => return true,
            (None, Some(_)) => return true,
            (Some(_), None) => return false,
            (Some(left), Some(right)) => {
                if left != right {
                    return false;
                }
            }
        }
    }
}

#[cfg(test)]
mod path_tests {
    use super::path_is_equal_or_strict_child;
    use std::path::Path;

    #[test]
    fn equal_and_child_paths_match() {
        assert!(path_is_equal_or_strict_child(
            Path::new("/tmp/data"),
            Path::new("/tmp/data")
        ));
        assert!(path_is_equal_or_strict_child(
            Path::new("/tmp/data/base"),
            Path::new("/tmp/data")
        ));
        assert!(!path_is_equal_or_strict_child(
            Path::new("/tmp/data-extra"),
            Path::new("/tmp/data")
        ));
        assert!(!path_is_equal_or_strict_child(
            Path::new("/tmp"),
            Path::new("/tmp/data")
        ));
    }
}
