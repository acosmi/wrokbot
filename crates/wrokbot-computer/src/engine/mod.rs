//! Rust-owned dual-role Electron engine lifecycle (v4 §10.6 / §11 / P1).
//!
//! The shim owns no authority: Rust mints the role/scope digest, computer/generation, one-shot boot
//! capability and every operation ID; validates OS peer credentials and bundle digests before any
//! command; and rejects malformed/stale binary frames before exposing them to ScreenHub.

mod frame;
mod process;
mod protocol;
mod scope;

pub use frame::{EngineFrame, EngineFrameError, EngineFrameReader, ImageFormat};
#[cfg(any(unix, windows))]
pub use process::EngineScreenSource;
#[cfg(target_os = "linux")]
pub use process::RunscAttestation;
pub use process::{
    EngineBundle, EngineBundleDigest, EngineLaunchConfig, EngineProcess, EngineProcessError,
    EngineSandboxFidelity, ScreenIngressStats, ScreenStopReceipt, ScreenStreamKey, StartedSession,
};
pub use protocol::{EngineOperationId, EngineProtocolError};
pub use scope::{
    ComponentRenderScope, ComputerSecurityScope, DesktopWindowSessionId, EngineRole,
    EngineRoleKind, ScopeError, ScreenAudience, WorkspaceScope,
};
