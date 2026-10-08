//! Original-window current custom definitions, bounded before the actual framework handoff.

use std::io::{self, Write};

use http::{Method, Request, Response, StatusCode};
use openbot_application::PublicCustomModelCatalogDelivery;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::custom_model_catalog::{
    CustomModelCatalogPageRequest, MAX_CUSTOM_MODEL_CATALOG_RESPONSE_BYTES,
};
use openbot_contracts::error::AppError;

use super::{DesktopTauriProtocol, WindowAuthority, empty_response, error_response, response};

const PATH: &str = "/api/me/custom-model-catalog";

pub(super) fn owns_path(path: &str) -> bool {
    path == PATH || path.starts_with("/api/me/custom-model-catalog/")
}

/// Field order covers prepare cancellation, encoding failure and prefinish abandonment.
pub(super) struct PrivatePreparedCustomModelCatalogOwner {
    encoded: Vec<u8>,
    delivery: PublicCustomModelCatalogDelivery,
}

pub(super) enum PreparedCustomModelCatalogResponse {
    Immediate(Response<Vec<u8>>),
    Current(PrivatePreparedCustomModelCatalogOwner),
}

impl DesktopTauriProtocol {
    pub(super) async fn prepare_custom_model_catalog_response(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
    ) -> PreparedCustomModelCatalogResponse {
        let immediate =
            |error| PreparedCustomModelCatalogResponse::Immediate(error_response(error));
        let authority = match self.custom_model_catalog_authority(label) {
            Ok(authority) => authority,
            Err(error) => {
                request.body_mut().fill(0);
                return immediate(error);
            }
        };
        if let Err(error) = self.custom_model_catalog_window_current(label, &authority) {
            request.body_mut().fill(0);
            return immediate(error);
        }
        if request.uri().path() != PATH {
            request.body_mut().fill(0);
            return PreparedCustomModelCatalogResponse::Immediate(empty_response(
                StatusCode::NOT_FOUND,
            ));
        }
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return PreparedCustomModelCatalogResponse::Immediate(empty_response(
                StatusCode::METHOD_NOT_ALLOWED,
            ));
        }
        let input = match parse_raw_query(request.uri().query()) {
            Ok(input) => input,
            Err(error) => {
                request.body_mut().fill(0);
                return immediate(error);
            }
        };
        if !request.body().is_empty() {
            request.body_mut().fill(0);
            return immediate(AppError::MalformedPayload { field: "body" });
        }
        let reply = match self
            .transport
            .execute(
                authority.auth.clone(),
                AppCommand::ListCustomModelCatalog(input),
            )
            .await
        {
            Ok(reply @ AppReply::CustomModelCatalog(_)) => reply,
            Ok(_) => return immediate(unavailable()),
            Err(error) => return immediate(error),
        };
        let delivery = match self
            .transport
            .service()
            .take_custom_model_catalog_delivery(authority.auth.clone(), reply)
        {
            Ok(delivery) => delivery,
            Err(error) => return immediate(error),
        };
        // Own both fields before the writer can fail or unwind. No unbounded to_vec stage.
        let mut owner = PrivatePreparedCustomModelCatalogOwner {
            encoded: Vec::new(),
            delivery,
        };
        if serde_json::to_writer(BoundedWriter(&mut owner.encoded), owner.delivery.page()).is_err()
        {
            drop(owner);
            return immediate(unavailable());
        }
        PreparedCustomModelCatalogResponse::Current(owner)
    }

    /// Shared by the deterministic handler and actual UriSchemeResponder branch. No await
    /// intervenes between the last label/window/tail observation and the framework call.
    pub(super) fn finish_prepared_custom_model_catalog_response<R>(
        &self,
        label: &str,
        prepared: PreparedCustomModelCatalogResponse,
        respond: impl FnOnce(Response<Vec<u8>>) -> R,
    ) -> R {
        let mut owner = match prepared {
            PreparedCustomModelCatalogResponse::Immediate(response) => return respond(response),
            PreparedCustomModelCatalogResponse::Current(owner) => owner,
        };
        let authority = match self.custom_model_catalog_authority(label) {
            Ok(authority) => authority,
            Err(error) => {
                drop(owner);
                return respond(error_response(error));
            }
        };
        let current = self
            .custom_model_catalog_window_current(label, &authority)
            .and_then(|()| owner.delivery.verify_current_tail_once(&authority.auth));
        if let Err(error) = current {
            drop(owner);
            return respond(error_response(error));
        }
        let result = respond(response(
            StatusCode::OK,
            "application/json",
            std::mem::take(&mut owner.encoded),
            true,
        ));
        // The original Delivery remains live through respond returning. The framework owns
        // the moved Vec afterwards; neither renderer receipt nor its later Drop is observed.
        drop(owner);
        result
    }

    fn custom_model_catalog_authority(&self, label: &str) -> Result<WindowAuthority, AppError> {
        self.window_registry
            .windows
            .try_read()
            .map_err(|_| unavailable())?
            .get(label)
            .cloned()
            .ok_or(AppError::Unauthenticated)
    }

    fn custom_model_catalog_window_current(
        &self,
        label: &str,
        admitted: &WindowAuthority,
    ) -> Result<(), AppError> {
        let current = self.custom_model_catalog_authority(label)?;
        if admitted.closed.is_cancelled()
            || current.closed.is_cancelled()
            || current.binding_id != admitted.binding_id
            || current.auth != admitted.auth
            || !self.request_binding_issuer.observation().is_current()
            || !admitted.auth.request_binding().is_some_and(|binding| {
                self.request_binding_issuer.matches_desktop_window_epoch(
                    binding.identity(),
                    label,
                    admitted.binding_id,
                )
            })
        {
            return Err(AppError::NotVisible);
        }
        Ok(())
    }
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
