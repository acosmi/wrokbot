//! Narrow Windows unsafe OS boundary: Engine confinement plus Credential Manager (v4 R119/R127).
//!
//! This is the workspace's only crate allowed to contain Win32 `unsafe` FFI. Its public API owns
//! every raw handle, never exposes a handle or pointer, creates the child suspended, attaches the
//! Job Object before resume, passes only three explicit stdio handles, and fails closed on every
//! token/ACL/Job/pipe error. The safety review lives beside the implementation in `SECURITY.md`.

#![allow(unsafe_code)]

mod command_line;
#[cfg(any(windows, test))]
mod environment;

pub use command_line::{FILETIME_UNIX_EPOCH_TICKS, filetime_ticks_to_unix_millis};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    NamedPipeConnection, NamedPipeListener, ProcessIdentity, RestrictedChild, SpawnPolicy,
    WindowsCredentialSecret, current_user_pipe_security_sddl, delete_generic_credential,
    read_generic_credential, read_pe_resource, replace_pe_resource, secure_engine_directory,
    spawn_restricted, write_generic_credential,
};

/// Stable failures from the Windows Engine security boundary.
#[derive(Debug, thiserror::Error)]
pub enum WindowsSandboxError {
    /// A path/argument/environment value was empty, relative, contained NUL, or exceeded a bound.
    #[error("windows_sandbox_invalid_input")]
    InvalidInput,
    /// A Win32 operation failed. Raw OS detail remains available as the source for diagnostics.
    #[error("windows_sandbox_os")]
    Os(#[from] std::io::Error),
    /// A peer PID or exact process creation time differed from the spawned Engine identity.
    #[error("windows_sandbox_peer_identity")]
    PeerIdentity,
    /// A process creation FILETIME predates the Unix epoch and cannot match Electron metrics.
    #[error("windows_sandbox_creation_time")]
    CreationTime,
    /// Restricted token was not actually restricted or did not retain medium integrity.
    #[error("windows_sandbox_token_integrity")]
    TokenIntegrity,
}
