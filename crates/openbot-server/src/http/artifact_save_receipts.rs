//! Current-authorized observation of an original persisted positive Save receipt.

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header::CACHE_CONTROL};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, GetArtifactSaveReceipt};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;

use crate::auth::Authenticated;
use crate::error::HttpError;
use crate::http::ServerState;

/// Closed prefix for original request locators; no source or authority selector is accepted.
pub const SAVE_REQUESTS_PATH: &str = "/api/artifacts/save-requests";

/// Empty authenticated GET through the same ApplicationService and original request binding.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    uri: Uri,
    request: Request,
) -> Result<(HeaderMap, Json<ArtifactRegistrationReceipt>), HttpError> {
    if uri.query().is_some() {
        return Err(AppError::MalformedPayload { field: "query" }.into());
    }
    to_bytes(request.into_body(), 0)
        .await
        .map_err(|_| AppError::MalformedPayload { field: "body" })?;
    let segment = uri
        .path()
        .strip_prefix("/api/artifacts/save-requests/")
        .filter(|segment| !segment.is_empty() && !segment.contains('/') && segment.len() <= 108)
        .ok_or(AppError::MalformedPayload {
            field: "request_id",
        })?;
    let request_id = decode_once(segment).ok_or(AppError::MalformedPayload {
        field: "request_id",
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetArtifactSaveReceipt(GetArtifactSaveReceipt { request_id }),
        )
        .await?
    {
        AppReply::ArtifactRegistrationReceipt(receipt) => {
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((headers, Json(receipt)))
        }
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

/// A HEAD request never invokes receipt observation.
pub(super) async fn reject_head() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// Cover all outer transport, body-limit, authentication and selector failures on this prefix.
pub(super) async fn response_policy(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let protected = path == SAVE_REQUESTS_PATH || path.starts_with("/api/artifacts/save-requests/");
    let mut response = next.run(request).await;
    if protected {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn decode_once(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let high = hex(*bytes.get(at + 1)?)?;
            let low = hex(*bytes.get(at + 2)?)?;
            decoded.push((high << 4) | low);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "artifact_save_receipt_tests.rs"]
mod tests;
