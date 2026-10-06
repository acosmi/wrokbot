//! Original-window framing for a current-authorized persisted Save receipt observation.

use http::{Method, Request, Response, StatusCode};
use openbot_contracts::artifacts::GetArtifactSaveReceipt;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;

use super::{
    DesktopTauriProtocol, WindowAuthority, dependency_response, empty_response, error_response,
    json_response, percent_decode_segment,
};

impl DesktopTauriProtocol {
    pub(super) async fn artifact_save_receipt(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if let Err(error) = self.artifact_save_receipt_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if request.method() != Method::GET {
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
        let Some(segment) = request
            .uri()
            .path()
            .strip_prefix("/api/artifacts/save-requests/")
            .filter(|segment| {
                !segment.is_empty() && !segment.contains('/') && segment.len() <= 108
            })
        else {
            return error_response(AppError::MalformedPayload {
                field: "request_id",
            });
        };
        let Some(request_id) = percent_decode_segment(segment) else {
            return error_response(AppError::MalformedPayload {
                field: "request_id",
            });
        };
        if let Err(error) = self.artifact_save_receipt_binding_current(label, &authority) {
            return error_response(error);
        }
        let result = self
            .transport
            .execute(
                authority.auth.clone(),
                AppCommand::GetArtifactSaveReceipt(GetArtifactSaveReceipt { request_id }),
            )
            .await;
        // Preserve both successful and refused results until the original bounded window tail.
        if let Err(error) = self.artifact_save_receipt_binding_current(label, &authority) {
            return error_response(error);
        }
        match result {
            Ok(AppReply::ArtifactRegistrationReceipt(receipt)) => json_response(&receipt),
            Err(error) => error_response(error),
            Ok(_) => dependency_response(),
        }
    }

    fn artifact_save_receipt_binding_current(
        &self,
        label: &str,
        original: &WindowAuthority,
    ) -> Result<(), AppError> {
        if !self.request_binding_issuer.observation().is_current() || original.closed.is_cancelled()
        {
            return Err(AppError::Unauthenticated);
        }
        let binding = original
            .auth
            .request_binding()
            .ok_or(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?;
        if !self.request_binding_issuer.matches_desktop_window_epoch(
            binding.identity(),
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
                    && current
                        .auth
                        .request_binding()
                        .is_some_and(|current_binding| {
                            binding.identity().same_binding(current_binding.identity())
                        }) =>
            {
                Ok(())
            }
            _ => Err(AppError::Unauthenticated),
        }
    }
}

#[cfg(all(test, feature = "desktop-local-runtime"))]
#[path = "artifact_save_receipt_tests.rs"]
mod tests;
