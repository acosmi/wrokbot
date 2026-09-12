//! Read-only macOS process-birth and boot-session observation boundary.
//!
//! The observed identity is additional fail-closed evidence. It is not a process handle,
//! termination capability, quiescence proof, or recovery authority.
#![allow(unsafe_code)]

use core::fmt;

#[cfg(target_os = "macos")]
mod native;

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
}

impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessIdentity(<observed>)")
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
