//! Current-owner custom definitions, carried by their original one-use delivery.

use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use http::{
    HeaderMap, HeaderValue, Method, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use openbot_application::PublicCustomModelCatalogDelivery;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::custom_model_catalog::{
    CustomModelCatalogPageRequest, MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES,
};
use openbot_contracts::error::AppError;

use crate::auth::OriginAuthenticated;
use crate::error::HttpError;
use crate::http::ServerState;

pub const PATH: &str = "/api/me/custom-model-catalog";

/// Enclose transport/extractor/authentication and owned 404/405 responses as well.
pub async fn response_policy(request: Request, next: Next) -> Response {
    let belongs = request.uri().path() == PATH
        || request
            .uri()
            .path()
            .starts_with("/api/me/custom-model-catalog/");
    let mut response = next.run(request).await;
    if belongs {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// HEAD is closed explicitly: Axum must never execute the GET handler for it.
pub(super) async fn reject_head() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// The sole Server successful catalog exit consumes the complete original reply.
pub async fn list(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    request: Request,
) -> Result<Response, HttpError> {
    if request.method() != Method::GET {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let input = parse_raw_query(request.uri().query())?;
    to_bytes(request.into_body(), 0)
        .await
        .map_err(|_| AppError::MalformedPayload { field: "body" })?;
    let reply = state
        .application()
        .execute(auth.clone(), AppCommand::ListCustomModelCatalog(input))
        .await?;
    if !matches!(&reply, AppReply::CustomModelCatalog(_)) {
        return Err(unavailable().into());
    }
    let delivery = state
        .application()
        .take_custom_model_catalog_delivery(auth.clone(), reply)?;
    // Put both fields in their final ordered owner before encoding can fail or panic.
    let mut owner = CatalogHttpOwner {
        encoded: Vec::new(),
        delivery,
    };
    let encoded = serde_json::to_writer(BoundedWriter(&mut owner.encoded), owner.delivery.page());
    if encoded.is_err() {
        drop(owner);
        return Err(unavailable().into());
    }
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok((
        headers,
        Body::from_stream(CatalogHttpBody {
            auth,
            owner: Some(owner),
        }),
    )
        .into_response())
}

fn parse_raw_query(query: Option<&str>) -> Result<CustomModelCatalogPageRequest, AppError> {
    let cursor = match query {
        None | Some("") => None,
        Some(raw) if raw.len() == 43 && raw.starts_with("cursor=") => Some(raw[7..].to_owned()),
        Some(_) => return Err(AppError::MalformedPayload { field: "query" }),
    };
    let input = CustomModelCatalogPageRequest { cursor };
    if !input.is_valid() {
        return Err(AppError::MalformedPayload { field: "query" });
    }
    Ok(input)
}

/// Rust field order is deliberate on every cancellation/error/Bytes-final-drop path.
struct CatalogHttpOwner {
    encoded: Vec<u8>,
    delivery: PublicCustomModelCatalogDelivery,
}

impl AsRef<[u8]> for CatalogHttpOwner {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

struct CatalogHttpBody {
    auth: AuthContext,
    owner: Option<CatalogHttpOwner>,
}

impl Stream for CatalogHttpBody {
    type Item = Result<Bytes, AppError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(mut owner) = self.owner.take() else {
            return Poll::Ready(None);
        };
        if let Err(error) = owner.delivery.verify_current_tail_once(&self.auth) {
            // Drop the whole owner, encoded first. A failed first poll emits no JSON frame;
            // status and headers may already have reached the transport at this point.
            drop(owner);
            return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(Some(Ok(Bytes::from_owner(owner))))
    }
}

struct BoundedWriter<'a>(&'a mut Vec<u8>);
impl Write for BoundedWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("custom_model_catalog_response_too_large"));
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "custom_model_catalog",
    }
}

#[cfg(test)]
#[path = "custom_model_catalog_tests.rs"]
mod tests;
