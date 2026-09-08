//! Local-only, query-free OS confirmation framing and the host window critical sections.

use std::sync::Arc;

use openbot_contracts::desktop::local_confirmation::LocalConfirmationReceipt;
use serde::Serialize;

use crate::local_confirmation::ConfirmationAttempt;
use crate::local_confirmation_host::{BoundLocalConfirmationWindow, LocalConfirmationHost};
use crate::local_confirmation_service::{FinishLocalConfirmation, PrepareLocalConfirmation};

use super::{
    AppError, DesktopTauriProtocol, Method, Request, Response, StatusCode, TauriHostError,
    WindowAuthority, empty_response, error_response, json_response,
};

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "desktop_local_confirmation",
    }
}

impl DesktopTauriProtocol {
    /// Install the attested Local service before any window binding exists. The reverse protocol
    /// reference in the native dispatcher is weak; this does not create a process-lifetime cycle.
    pub(crate) fn install_local_confirmation(
        &self,
        local: LocalConfirmationHost,
    ) -> Result<(), TauriHostError> {
        let windows = self
            .windows
            .write()
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        if !windows.is_empty() {
            return Err(TauriHostError::AuthorityUnavailable);
        }
        self.local_confirmation
            .set(local)
            .map_err(|_| TauriHostError::ProtocolAlreadyReady)
    }

    pub(crate) fn prepare_local_confirmation(
        &self,
        label: &str,
        binding_id: u64,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        let windows = self.windows.read().map_err(|_| unavailable())?;
        let authority = windows
            .get(label)
            .filter(|current| current.binding_id == binding_id && !current.closed.is_cancelled())
            .ok_or(AppError::Unauthenticated)?;
        let local = authority
            .local_confirmation
            .as_ref()
            .ok_or_else(unavailable)?;
        job.execute(&local.grant)
    }

    pub(crate) fn finish_local_confirmation(
        &self,
        label: &str,
        binding_id: u64,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        let windows = self.windows.read().map_err(|_| unavailable())?;
        let authority = windows
            .get(label)
            .filter(|current| current.binding_id == binding_id && !current.closed.is_cancelled())
            .ok_or(AppError::Unauthenticated)?;
        let local = authority
            .local_confirmation
            .as_ref()
            .ok_or_else(unavailable)?;
        // Keep windows current until the pure grant CAS/cancel has completed. Unbind takes
        // the write guard and revokes the same shared grant before releasing that guard.
        job.execute(&local.grant)
    }

    pub(crate) fn clear_window_confirmation(&self, label: &str) -> Result<(), TauriHostError> {
        let windows = self
            .windows
            .read()
            .map_err(|_| TauriHostError::AuthorityUnavailable)?;
        if let Some(local) = windows
            .get(label)
            .and_then(|window| window.local_confirmation.as_ref())
        {
            local.grant.clear_existing_grant();
        }
        Ok(())
    }

    pub(crate) fn clear_existing_confirmations(&self) -> Result<(), TauriHostError> {
        // Native App notifications must not wait on the host windows registry. The independent
        // grant epoch clears all old grants without changing the in-progress attempt epoch.
        if let Some(local) = self.local_confirmation.get() {
            local.service.clear_existing_grants();
        }
        Ok(())
    }

    pub(crate) fn invalidate_local_confirmations(&self) {
        if let Some(local) = self.local_confirmation.get() {
            local.service.invalidate_all();
        }
    }

    pub(crate) fn shutdown_local_confirmation(&self) {
        if let Some(local) = self.local_confirmation.get() {
            local.service.shutdown();
        }
    }

    pub(crate) fn cleanup_local_confirmation_on_main_thread(&self) -> Result<(), AppError> {
        if let Some(local) = self.local_confirmation.get() {
            local.service.shutdown();
            local.dispatcher.cleanup_on_main_thread()?;
        }
        Ok(())
    }

    pub(crate) async fn wait_local_confirmation_stopped(&self) {
        if let Some(local) = self.local_confirmation.get() {
            // The runtime's existing five-second non-database deadline owns this wait. It is
            // never a prerequisite for running independent PostgreSQL cleanup afterwards.
            while !local.dispatcher.is_native_stopped() {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }

    pub(super) async fn local_confirmation_request(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        admitted: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if !admitted.auth.is_single_user() {
            request.body_mut().fill(0);
            return empty_response(StatusCode::NOT_FOUND);
        }
        if request.method() != Method::GET && request.method() != Method::POST {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.uri().query().is_some() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        if !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        let Some(local) = self.local_confirmation.get() else {
            return error_response(unavailable());
        };
        let Some(binding) = &admitted.local_confirmation else {
            return error_response(unavailable());
        };
        if !Arc::ptr_eq(&local.service, &binding.service) {
            return error_response(AppError::Unauthenticated);
        }
        if request.method() == Method::GET {
            return match local
                .service
                .status(&binding.grant, &admitted.auth, &admitted.closed)
                .await
            {
                Ok(status) => self.confirmation_response(label, &admitted, &status),
                Err(error) => error_response(error),
            };
        }
        let window = BoundLocalConfirmationWindow {
            dispatcher: local.dispatcher.as_ref(),
            label,
            binding_id: admitted.binding_id,
        };
        match local
            .service
            .confirm(
                &binding.grant,
                &admitted.auth,
                &admitted.closed,
                self.os_locale,
                &window,
            )
            .await
        {
            Ok(receipt) => self.confirmation_response(label, &admitted, &receipt),
            Err(error) => error_response(error),
        }
    }

    fn confirmation_response<T: Serialize>(
        &self,
        label: &str,
        admitted: &WindowAuthority,
        value: &T,
    ) -> Response<Vec<u8>> {
        let Ok(windows) = self.windows.read() else {
            return error_response(unavailable());
        };
        if windows.get(label).is_none_or(|current| {
            current.binding_id != admitted.binding_id || current.closed.is_cancelled()
        }) {
            return error_response(AppError::Unauthenticated);
        }
        json_response(value)
    }
}
