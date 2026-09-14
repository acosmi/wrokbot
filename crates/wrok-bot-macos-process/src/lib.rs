//! Read-only macOS process-birth and boot-session observation boundary.
//!
//! The observed identity is additional fail-closed evidence. It is not a process handle,
//! termination capability, quiescence proof, or recovery authority.
#![allow(unsafe_code)]

use core::fmt;
use std::path::Path;

#[cfg(target_os = "macos")]
mod native;
#[cfg(target_os = "macos")]
mod openers;

/// A private, non-serializable observation of one PID in one macOS boot session.
///
/// This type intentionally has no `Clone`, field getters, or external constructor. Keeping an
/// instance only permits a later read-only [`Self::revalidate`] call.
pub struct ProcessIdentity {
    #[cfg(target_os = "macos")]
    pid: i32,
    #[cfg(target_os = "macos")]
    start_seconds: u64,
    #[cfg(target_os = "macos")]
    start_microseconds: u32,
    #[cfg(target_os = "macos")]
    boot_session: [u8; 16],
    #[cfg(not(target_os = "macos"))]
    unsupported: (),
}

impl ProcessIdentity {
    /// Capture one stable `boot -> process -> process -> boot` observation.
    ///
    /// The PID must identify a live non-zombie process. This method never signals the process and
    /// never turns the result into authority to terminate, recover, or remove persistent evidence.
    #[cfg(target_os = "macos")]
    pub fn capture(pid: u32) -> Result<Self, ProcessObservationError> {
        let pid = i32::try_from(pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or(ProcessObservationError::InvalidPid)?;
        let observation = native::observe(pid)?;
        Ok(Self {
            pid,
            start_seconds: observation.start_seconds,
            start_microseconds: observation.start_microseconds,
            boot_session: observation.boot_session,
        })
    }

    /// Capture is unavailable off macOS; no synthetic identity is constructed.
    #[cfg(not(target_os = "macos"))]
    pub fn capture(_pid: u32) -> Result<Self, ProcessObservationError> {
        Err(ProcessObservationError::UnsupportedPlatform)
    }

    /// Re-read all four facts and require exact equality with this captured identity.
    #[cfg(target_os = "macos")]
    pub fn revalidate(&self) -> Result<(), ProcessObservationError> {
        let observation = native::observe(self.pid)?;
        if observation.start_seconds != self.start_seconds
            || observation.start_microseconds != self.start_microseconds
            || observation.boot_session != self.boot_session
        {
            return Err(ProcessObservationError::ObservationChanged);
        }
        Ok(())
    }

    /// Return the exact private journal evidence after a fresh four-read revalidation.
    #[cfg(target_os = "macos")]
    pub fn evidence_bytes(&self) -> Result<[u8; 32], ProcessObservationError> {
        self.revalidate()?;
        let pid = u32::try_from(self.pid).map_err(|_| ProcessObservationError::InvalidPid)?;
        let mut evidence = [0_u8; 32];
        evidence[..4].copy_from_slice(&pid.to_be_bytes());
        evidence[4..12].copy_from_slice(&self.start_seconds.to_be_bytes());
        evidence[12..16].copy_from_slice(&self.start_microseconds.to_be_bytes());
        evidence[16..].copy_from_slice(&self.boot_session);
        Ok(evidence)
    }

    /// Revalidation is unavailable off macOS.
    #[cfg(not(target_os = "macos"))]
    pub fn revalidate(&self) -> Result<(), ProcessObservationError> {
        let _ = self.unsupported;
        Err(ProcessObservationError::UnsupportedPlatform)
    }

    /// No process evidence is fabricated off macOS.
    #[cfg(not(target_os = "macos"))]
    pub fn evidence_bytes(&self) -> Result<[u8; 32], ProcessObservationError> {
        Err(ProcessObservationError::UnsupportedPlatform)
    }

    /// Exact four-tuple equality for ignore lists. Does not expose fields.
    #[cfg(target_os = "macos")]
    pub fn same_as(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.start_seconds == other.start_seconds
            && self.start_microseconds == other.start_microseconds
            && self.boot_session == other.boot_session
    }

    #[cfg(not(target_os = "macos"))]
    pub fn same_as(&self, _other: &Self) -> bool {
        let _ = self.unsupported;
        false
    }
}

impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessIdentity(<observed>)")
    }
}

/// Closed observation of processes holding open references under one data directory.
///
/// `Empty` is only a single successful scan result after `ignore`. It is not quiescence, lock
/// deletion authority, or proof that an unregistered child never existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataDirectoryOpenerObservation {
    /// No non-ignored opener was observed in a complete double scan.
    Empty,
    /// At least one non-ignored opener was observed.
    Observed,
}

/// Observe live openers of `data_dir` matching the already-held directory device/inode.
///
/// `ignore` removes caller-owned observers (typically the current supervisor process). This API
/// never signals processes, deletes evidence, or grants recovery authority. A missing startup
/// journal entry must not be treated as [`DataDirectoryOpenerObservation::Empty`].
pub fn observe_data_directory_openers(
    data_dir: &Path,
    expected_device: u64,
    expected_inode: u64,
    ignore: &[ProcessIdentity],
) -> Result<DataDirectoryOpenerObservation, ProcessObservationError> {
    #[cfg(target_os = "macos")]
    {
        let openers = openers::observe_openers(data_dir, expected_device, expected_inode)?;
        let foreign = openers.into_iter().any(|opener| {
            let identity = ProcessIdentity {
                pid: opener.pid,
                start_seconds: opener.start_seconds,
                start_microseconds: opener.start_microseconds,
                boot_session: opener.boot_session,
            };
            !ignore.iter().any(|allowed| allowed.same_as(&identity))
        });
        Ok(if foreign {
            DataDirectoryOpenerObservation::Observed
        } else {
            DataDirectoryOpenerObservation::Empty
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (data_dir, expected_device, expected_inode, ignore);
        Err(ProcessObservationError::UnsupportedPlatform)
    }
}

/// Closed, non-sensitive failure classes for read-only process observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessObservationError {
    /// The PID was zero or outside signed macOS `pid_t` range.
    InvalidPid,
    /// The process query did not return one complete `proc_bsdinfo` value.
    ProcessUnavailable,
    /// The process reply had a wrong PID, invalid creation time, or zombie state.
    ProcessDataInvalid,
    /// The IOKit root-domain boot property was absent, mistyped, malformed, or unavailable.
    BootUnavailable,
    /// The bracketed reads changed, or revalidation no longer matches the capture.
    ObservationChanged,
    /// This host is not macOS.
    UnsupportedPlatform,
}

impl fmt::Display for ProcessObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPid => "macos_process_invalid_pid",
            Self::ProcessUnavailable => "macos_process_unavailable",
            Self::ProcessDataInvalid => "macos_process_data_invalid",
            Self::BootUnavailable => "macos_boot_session_unavailable",
            Self::ObservationChanged => "macos_process_observation_changed",
            Self::UnsupportedPlatform => "macos_process_unsupported_platform",
        })
    }
}

impl std::error::Error for ProcessObservationError {}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{
        DataDirectoryOpenerObservation, ProcessIdentity, observe_data_directory_openers,
    };
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    fn temp_dir() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wrok-v6-pr-011-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("temp dir");
        root
    }

    fn observe_ignoring_self(
        dir: &Path,
        device: u64,
        inode: u64,
    ) -> Result<DataDirectoryOpenerObservation, super::ProcessObservationError> {
        let self_identity = ProcessIdentity::capture(std::process::id()).expect("self");
        observe_data_directory_openers(dir, device, inode, &[self_identity])
    }

    #[test]
    fn empty_after_ignoring_self_directory_open() {
        let dir = temp_dir();
        let _held = File::open(&dir).expect("open dir");
        let metadata = fs::metadata(&dir).expect("meta");
        assert_eq!(
            observe_ignoring_self(&dir, metadata.dev(), metadata.ino()).expect("observe"),
            DataDirectoryOpenerObservation::Empty
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_child_with_open_file_under_data_dir() {
        let dir = temp_dir();
        let child_path = dir.join("held.txt");
        {
            let mut file = File::create(&child_path).expect("create");
            file.write_all(b"held").expect("write");
        }
        let metadata = fs::metadata(&dir).expect("meta");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 3<\"$1\"; while true; do sleep 1; done")
            .arg("opener")
            .arg(&child_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn opener");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_observed = false;
        while Instant::now() < deadline {
            match observe_ignoring_self(&dir, metadata.dev(), metadata.ino()) {
                Ok(DataDirectoryOpenerObservation::Observed) => {
                    saw_observed = true;
                    break;
                }
                Ok(_) | Err(super::ProcessObservationError::ObservationChanged) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("observe failed: {error:?}"),
            }
        }
        assert!(saw_observed, "foreign opener was not observed");
        let _ = child.kill();
        let _ = child.wait();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut cleared = false;
        while Instant::now() < deadline {
            match observe_ignoring_self(&dir, metadata.dev(), metadata.ino()) {
                Ok(DataDirectoryOpenerObservation::Empty) => {
                    cleared = true;
                    break;
                }
                Ok(_) | Err(super::ProcessObservationError::ObservationChanged) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("observe failed: {error:?}"),
            }
        }
        assert!(cleared, "opener remained after child exit");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_relative_data_dir() {
        let err = observe_data_directory_openers(Path::new("relative"), 1, 1, &[])
            .expect_err("relative");
        assert_eq!(err, super::ProcessObservationError::ProcessDataInvalid);
    }

    #[test]
    fn empty_does_not_imply_recovery_authority_contract() {
        // Documented non-inference: Empty is only a scan result after ignore.
        assert_ne!(
            DataDirectoryOpenerObservation::Empty,
            DataDirectoryOpenerObservation::Observed
        );
    }
}
