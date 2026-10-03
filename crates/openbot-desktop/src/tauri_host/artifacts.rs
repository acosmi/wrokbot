//! Current host-bound explicit save and metadata framing; no filesystem path ingress.

use http::{Method, Request, Response, StatusCode};
use openbot_contracts::artifacts::{GetArtifactMetadata, SaveRunMessageTextArtifact};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::{AppError, SensitiveWriteReason};

use super::{
    CHANNEL_THREAD_BODY_MAX_BYTES, DesktopTauriProtocol, WindowAuthority, dependency_response,
    empty_response, error_response, json_response, parse_sensitive_body, payload_too_large,
    percent_decode_segment, sensitive_body_error_response,
};

impl DesktopTauriProtocol {
    pub(super) async fn artifacts(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if request.body().len() > CHANNEL_THREAD_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        if request.uri().query().is_some_and(|query| !query.is_empty()) {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        let path = request.uri().path().to_owned();
        let write = path == "/api/artifacts/save-run-message-text";
        if write && !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let command = if write {
            if request.method() != Method::POST {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            match parse_sensitive_body::<SaveRunMessageTextArtifact>(
                &mut request,
                CHANNEL_THREAD_BODY_MAX_BYTES,
            ) {
                Ok(input) => AppCommand::SaveRunMessageTextArtifact(input),
                Err(error) => return sensitive_body_error_response(error),
            }
        } else {
            let Some(segment) = path
                .strip_prefix("/api/artifacts/")
                .filter(|id| !id.is_empty() && !id.contains('/'))
            else {
                request.body_mut().fill(0);
                return empty_response(StatusCode::NOT_FOUND);
            };
            if request.method() != Method::GET {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            if !request.body().is_empty() {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "body" });
            }
            let Some(artifact_id) = percent_decode_segment(segment) else {
                return error_response(AppError::MalformedPayload {
                    field: "artifact_id",
                });
            };
            AppCommand::GetArtifactMetadata(GetArtifactMetadata { artifact_id })
        };
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            return error_response(error);
        }
        if write && !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        // Never cancel admitted IO on window closure or send the result to a replacement owner.
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            return if write {
                error_response(AppError::DependencyUnavailable {
                    dependency: "artifacts",
                })
            } else {
                error_response(error)
            };
        }
        match (write, result) {
            (true, Ok(AppReply::ArtifactRegistrationReceipt(receipt))) => json_response(&receipt),
            (false, Ok(AppReply::ArtifactMetadata(metadata))) => json_response(&metadata),
            (_, Err(error)) => error_response(error),
            (_, Ok(_)) => dependency_response(),
        }
    }

    fn artifact_binding_current(
        &self,
        label: &str,
        admitted: &WindowAuthority,
    ) -> Result<(), AppError> {
        match self.authority(label) {
            Ok(Some(current))
                if current.binding_id == admitted.binding_id && !admitted.closed.is_cancelled() =>
            {
                Ok(())
            }
            Ok(_) => Err(AppError::Unauthenticated),
            Err(_) => Err(AppError::DependencyUnavailable {
                dependency: "desktop_window_authority",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::artifacts::ArtifactGoneStatus;

    #[test]
    fn gone_and_fixed_artifact_quota_errors_keep_closed_no_store_framing() {
        for status in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
            let response = error_response(AppError::ArtifactGone { status });
            assert_eq!(response.status(), StatusCode::GONE);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
                serde_json::json!({"code":"artifact_gone","status":status})
            );
        }
        for rule in ["artifact_disk_space", "artifact_quota"] {
            let response = error_response(AppError::PolicyRefused {
                rule: rule.to_owned(),
                decision: Some(openbot_contracts::ids::PolicyDecisionId::new(
                    "private-decision",
                )),
            });
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
                serde_json::json!({"code":"policy_refused","rule":rule})
            );
        }
    }

    #[test]
    fn preexisting_nonartifact_policy_error_projection_is_preserved() {
        let response = error_response(AppError::PolicyRefused {
            rule: "memory_writes_disabled".into(),
            decision: None,
        });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            serde_json::json!({"code":"policy_refused"})
        );
    }
}
