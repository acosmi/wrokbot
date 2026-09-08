//! Server compatibility facade for the shared infra database initializer.
//!
//! The implementation lives in `openbot-infra` because Desktop Local must execute the exact same
//! fresh/legacy/native migration decision rather than maintaining a transport-owned copy.

pub use openbot_infra::db::initialization::{
    DatabaseInitializationError, DatabaseOrigin, initialize,
};
