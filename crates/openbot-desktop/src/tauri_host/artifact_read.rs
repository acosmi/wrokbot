//! Trusted Rust-only first-chunk consumer. No renderer route or serialized body exists.

use std::sync::Weak;

use super::{DesktopTauriProtocol, WindowAuthority, WindowBindingRegistry};
use crate::CancellationToken;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::RequestBindingIssuer;

/// Sequential Rust reads remain tied to the original host window without owning its lease.
pub struct DesktopArtifactReadOperation {
    operation: openbot_application::CurrentArtifactReadOperation,
    auth: AuthContext,
    label: String,
    binding_id: u64,
    closed: CancellationToken,
    registry: Weak<WindowBindingRegistry>,
    issuer: RequestBindingIssuer,
}

impl DesktopArtifactReadOperation {
    /// Hand off the next block only while the original host window remains current.
    pub async fn next_block(
        &mut self,
    ) -> Result<Option<openbot_contracts::artifact_read::LeasedArtifactReadBlock>, AppError> {
        self.check_window()?;
        let result = self.operation.next_block(&self.auth).await;
        self.check_window()?;
        let block = result?.handoff(&self.auth)?;
        self.check_window()?;
        Ok(block)
    }

    fn check_window(&self) -> Result<(), AppError> {
        if !self.issuer.observation().is_current() || self.closed.is_cancelled() {
            return Err(AppError::Unauthenticated);
        }
        let original = self
            .auth
            .request_binding()
            .ok_or(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?;
        if !self.issuer.matches_desktop_window_epoch(
            original.identity(),
            &self.label,
            self.binding_id,
        ) {
            return Err(AppError::Unauthenticated);
        }
        let registry = self.registry.upgrade().ok_or(AppError::Unauthenticated)?;
        let windows = registry
            .windows
            .try_read()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?;
        match windows.get(&self.label) {
            Some(current)
                if current.binding_id == self.binding_id
                    && !current.closed.is_cancelled()
                    && current.auth == self.auth
                    && current.auth.request_binding().is_some_and(|binding| {
                        original.identity().same_binding(binding.identity())
                    }) =>
            {
                Ok(())
            }
            _ => Err(AppError::Unauthenticated),
        }
    }
}

impl DesktopTauriProtocol {
    /// Prepare a sequential Rust read bound to the original host window and application.
    pub async fn open_current_artifact_read(
        &self,
        window_label: &str,
        artifact_id: String,
    ) -> Result<DesktopArtifactReadOperation, AppError> {
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
        let result = self
            .transport
            .open_current_artifact_read(authority.auth.clone(), artifact_id)
            .await;
        self.check_read_window(window_label, &authority)?;
        Ok(DesktopArtifactReadOperation {
            operation: result?,
            auth: authority.auth,
            label: window_label.to_owned(),
            binding_id: authority.binding_id,
            closed: authority.closed,
            registry: std::sync::Arc::downgrade(&self.window_registry),
            issuer: self.request_binding_issuer.clone(),
        })
    }

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

#[cfg(test)]
mod lifecycle_tests;
