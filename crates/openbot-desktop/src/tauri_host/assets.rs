//! Immutable release UI bytes and the single static-file budget shared with release verification.

#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
use std::sync::Arc;

#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
use super::{TauriHostError, validate_index};

/// Index stays 1 MiB; only WebAssembly receives the reviewed 16 MiB budget.
pub(crate) fn static_asset_max_bytes(relative: &str) -> u64 {
    if relative == "index.html" {
        1024 * 1024
    } else if Path::new(relative)
        .extension()
        .and_then(|value| value.to_str())
        == Some("wasm")
    {
        16 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    }
}

pub(super) enum StaticAssets {
    Path(PathBuf),
    #[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
    Verified(BTreeMap<String, Arc<[u8]>>),
}

/// No path is retained. Only the host release verifier may transfer its exact checked bytes.
#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
pub(crate) struct VerifiedUiAssets {
    pub(super) index: Arc<str>,
    pub(super) files: BTreeMap<String, Arc<[u8]>>,
}

#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
impl VerifiedUiAssets {
    pub(crate) fn from_verified_release(
        mut files: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, TauriHostError> {
        // Resource membership/hash verification belongs to the release reader. This transfer checks
        // the same consumption budgets again and owns all allocations independently of disk.
        if files
            .iter()
            .any(|(path, body)| body.len() as u64 > static_asset_max_bytes(path))
        {
            return Err(TauriHostError::InvalidBundle);
        }
        let index = String::from_utf8(
            files
                .remove("index.html")
                .ok_or(TauriHostError::InvalidBundle)?,
        )
        .map_err(|_| TauriHostError::InvalidBundle)?;
        validate_index(&index)?;
        if !files.contains_key("openbot-bootstrap.mjs") {
            return Err(TauriHostError::InvalidBundle);
        }
        Ok(Self {
            index: Arc::from(index),
            files: files
                .into_iter()
                .map(|(path, bytes)| (path, Arc::from(bytes)))
                .collect(),
        })
    }
}

#[cfg(any(all(feature = "desktop-launcher", target_os = "macos"), test))]
impl core::fmt::Debug for VerifiedUiAssets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedUiAssets")
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}
