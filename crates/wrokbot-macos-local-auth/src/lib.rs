//! Fixed macOS OS confirmation and session invalidation boundary; no product authority.
#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
mod auth;
#[cfg(target_os = "macos")]
pub mod session;

#[cfg(target_os = "macos")]
pub use auth::{
    AttemptId, ConfirmationLocale, LocalAuthAttempt, LocalAuthConfirmation, LocalAuthOutcome,
    LocalAuthStartError, MacLocalAuthOwner, SYSTEM_CONFIRMATION_TIMEOUT,
};
