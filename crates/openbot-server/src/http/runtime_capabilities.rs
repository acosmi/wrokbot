//! Authenticated current capability observation through the one ApplicationService.

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::request::Parts;
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header::CACHE_CONTROL};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::runtime_capabilities::RuntimeCapabilitiesResponse;
use tracing::Span;

use crate::error::HttpError;
use crate::http::ServerState;
use crate::telemetry::ACTOR_ID_FIELD;

/// The exact authenticated current-capability route; no actor or target selector is accepted.
pub const RUNTIME_CAPABILITIES_PATH: &str = "/api/me/capabilities";

/// Read-only authentication for this observation. It does not advance session idle activity.
/// The normal resolver remains the sole producer of the carried AuthContext.
pub struct RuntimeCapabilitiesAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for RuntimeCapabilitiesAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// Empty authenticated GET. The Application alone collects and projects current host facts.
pub async fn get(
    State(state): State<ServerState>,
    RuntimeCapabilitiesAuthenticated(auth): RuntimeCapabilitiesAuthenticated,
    uri: Uri,
    request: Request,
) -> Result<(HeaderMap, Json<RuntimeCapabilitiesResponse>), HttpError> {
    if uri.query().is_some() {
        return Err(AppError::MalformedPayload { field: "query" }.into());
    }
    // Bound collection at zero bytes: a body is rejected without materializing its payload.
    to_bytes(request.into_body(), 0)
        .await
        .map_err(|_| AppError::MalformedPayload { field: "body" })?;
    match state
        .application()
        .execute(auth, AppCommand::GetRuntimeCapabilities)
        .await?
    {
        AppReply::RuntimeCapabilities(reply) => {
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((headers, Json(reply)))
        }
        _ => Err(AppError::DependencyUnavailable {
            dependency: "runtime_capabilities",
        }
        .into()),
    }
}

/// Do not silently dispatch a capability GET when Axum receives HEAD.
pub(super) async fn reject_head() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// Cover framing, authentication and outer transport failures on this exact route.
pub(super) async fn response_policy(request: Request, next: Next) -> Response {
    let is_capabilities = request.uri().path() == RUNTIME_CAPABILITIES_PATH;
    let mut response = next.run(request).await;
    if is_capabilities {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}
