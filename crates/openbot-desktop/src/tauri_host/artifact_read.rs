//! Trusted Rust-only first-chunk consumer. No renderer route or serialized body exists.

use super::{DesktopTauriProtocol, WindowAuthority};
use openbot_contracts::error::AppError;

impl DesktopTauriProtocol {
    /// Read one current first chunk through the original host-owned window, without framing.
    pub async fn read_current_artifact_chunk(
        &self,
        window_label: &str,
        artifact_id: String,
    ) -> Result<Vec<u8>, AppError> {
        let authority = self
            .window_registry
            .windows
            .try_read()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?
            .get(window_label)
            .cloned()
            .ok_or(AppError::Unauthenticated)?;
        self.check_read_window(window_label, &authority)?;
        // Await the real worker; closing the window does not claim admitted IO has stopped.
        let result = self
            .transport
            .read_current_artifact_chunk(authority.auth.clone(), artifact_id)
            .await;
        self.check_read_window(window_label, &authority)?;
        let pending = result?;
        pending.handoff(&authority.auth)
    }

    fn check_read_window(&self, label: &str, original: &WindowAuthority) -> Result<(), AppError> {
        if !self.request_binding_issuer.observation().is_current() || original.closed.is_cancelled()
        {
            return Err(AppError::Unauthenticated);
        }
        let original_binding =
            original
                .auth
                .request_binding()
                .ok_or(AppError::DependencyUnavailable {
                    dependency: "host_request_binding",
                })?;
        if !self.request_binding_issuer.matches_desktop_window_epoch(
            original_binding.identity(),
            label,
            original.binding_id,
        ) {
            return Err(AppError::Unauthenticated);
        }
        let windows = self.window_registry.windows.try_read().map_err(|_| {
            AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            }
        })?;
        match windows.get(label) {
            Some(current)
                if current.binding_id == original.binding_id
                    && !current.closed.is_cancelled()
                    && current.auth == original.auth
                    && current.auth.request_binding().is_some_and(|binding| {
                        original_binding.identity().same_binding(binding.identity())
                    }) =>
            {
                Ok(())
            }
            _ => Err(AppError::Unauthenticated),
        }
    }
}

#[cfg(test)]
mod tests;
