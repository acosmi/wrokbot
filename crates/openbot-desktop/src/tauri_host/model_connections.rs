//! Personal model-connection framing; ownership and persistence stay in Application.

use openbot_application::model_connections::require_model_connection_actor;
use openbot_contracts::model_connections::{
    CreateModelConnection, DeleteModelConnection, ModelConnectionPageRequest, UpdateModelConnection,
};

use super::{
    AppCommand, AppError, AppReply, DesktopTauriProtocol, Method, Request, Response,
    SensitiveWriteReason, StatusCode, WindowAuthority, channel_list_query, dependency_response,
    empty_response, error_response, json_response, json_response_with_status, parse_sensitive_body,
    payload_too_large, percent_decode_segment, sensitive_body_error_response,
};

// Same materialized JSON budget as credential_administration (including JSON escapes and
// metadata). ModelApiKey independently retains MAX_CREDENTIAL_TOKEN_BYTES = 16 KiB; metadata
// limits and endpoint normalization remain in the shared Application/Contracts boundary.
const MODEL_CONNECTION_BODY_MAX_BYTES: usize = 512 * 1024;
const COLLECTION: &str = "/api/me/model-connections";

enum ReplyKind {
    Page,
    Connection(StatusCode),
    Deleted,
}

impl DesktopTauriProtocol {
    pub(super) async fn model_connections(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if let Err(error) = self.model_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if let Err(error) = require_model_connection_actor(&authority.auth) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        let path = request.uri().path();
        let collection = path == COLLECTION;
        let raw_id = path.strip_prefix("/api/me/model-connections/");
        if !collection && !raw_id.is_some_and(|id| !id.is_empty() && !id.contains('/')) {
            request.body_mut().fill(0);
            return empty_response(StatusCode::NOT_FOUND);
        }
        let allowed = if collection {
            request.method() == Method::GET || request.method() == Method::POST
        } else {
            matches!(
                *request.method(),
                Method::GET | Method::PUT | Method::DELETE
            )
        };
        if !allowed {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let write = request.method() != Method::GET;
        // Native host freshness and role checks precede all secret-bearing JSON parsing. The
        // renderer cannot supply or refresh either authority; Admin still acts as its own owner.
        if write && !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        if request.body().len() > MODEL_CONNECTION_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        if !write && !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        let list = collection && !write;
        if !list && request.uri().query().is_some() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        let connection_id = if let Some(raw_id) = raw_id {
            let Some(id) = percent_decode_segment(raw_id) else {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload {
                    field: "connection_id",
                });
            };
            Some(id)
        } else {
            None
        };
        let (command, reply_kind) = if list {
            let Some((None, cursor)) = channel_list_query(request.uri().query()) else {
                return error_response(AppError::MalformedPayload { field: "query" });
            };
            (
                AppCommand::ListModelConnections(ModelConnectionPageRequest { cursor }),
                ReplyKind::Page,
            )
        } else if collection {
            let input = match parse_sensitive_body::<CreateModelConnection>(
                &mut request,
                MODEL_CONNECTION_BODY_MAX_BYTES,
            ) {
                Ok(input) => input,
                Err(error) => return sensitive_body_error_response(error),
            };
            (
                AppCommand::CreateModelConnection(input),
                ReplyKind::Connection(StatusCode::CREATED),
            )
        } else {
            let Some(connection_id) = connection_id else {
                return dependency_response();
            };
            match *request.method() {
                Method::GET => (
                    AppCommand::GetModelConnection { connection_id },
                    ReplyKind::Connection(StatusCode::OK),
                ),
                Method::PUT => {
                    let input = match parse_sensitive_body::<UpdateModelConnection>(
                        &mut request,
                        MODEL_CONNECTION_BODY_MAX_BYTES,
                    ) {
                        Ok(input) => input,
                        Err(error) => return sensitive_body_error_response(error),
                    };
                    (
                        AppCommand::UpdateModelConnection {
                            connection_id,
                            input,
                        },
                        ReplyKind::Connection(StatusCode::OK),
                    )
                }
                Method::DELETE => {
                    let input = match parse_sensitive_body::<DeleteModelConnection>(
                        &mut request,
                        MODEL_CONNECTION_BODY_MAX_BYTES,
                    ) {
                        Ok(input) => input,
                        Err(error) => return sensitive_body_error_response(error),
                    };
                    (
                        AppCommand::DeleteModelConnection {
                            connection_id,
                            input,
                        },
                        ReplyKind::Deleted,
                    )
                }
                _ => return empty_response(StatusCode::METHOD_NOT_ALLOWED),
            }
        };
        if let Err(error) = self.model_binding_current(label, &authority) {
            return error_response(error);
        }
        if write && !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        // Do not cancel or retry admitted writes on close/rebind: commit may already have happened.
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        if let Err(error) = self.model_binding_current(label, &authority) {
            return if write
                && (result.is_ok()
                    || matches!(
                        result,
                        Err(AppError::ReconciliationRequired { accepted: true })
                    ))
            {
                error_response(AppError::ReconciliationRequired { accepted: true })
            } else {
                error_response(error)
            };
        }
        match (reply_kind, result) {
            (ReplyKind::Page, Ok(AppReply::ModelConnections(page))) => json_response(&page),
            (ReplyKind::Connection(status), Ok(AppReply::ModelConnection(row))) => {
                json_response_with_status(&row, status)
            }
            (ReplyKind::Deleted, Ok(AppReply::ModelConnectionDeleted(row))) => json_response(&row),
            (_, Err(error)) => error_response(error),
            (_, Ok(_)) => dependency_response(),
        }
    }

    fn model_binding_current(
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
mod tests;
