//! Current original-window public reader framing, including the real responder boundary.

use http::{Method, Request, Response, StatusCode};
use openbot_application::{PublicArtifactReadControlDelivery, PublicArtifactReadDelivery};
use openbot_contracts::artifact_read_protocol::{
    AcknowledgeArtifactReadBlock, ArtifactReadChunkDescriptor, CloseArtifactRead, OpenArtifactRead,
    ReadArtifactReadBlock, is_canonical_artifact_read_handle,
};
use openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    API_BODY_MAX_BYTES, DesktopTauriProtocol, WindowAuthority, empty_response, error_response,
    parse_sensitive_body, sensitive_body_error_response,
};

const PREFIX: &str = "/api/artifact-reads";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SequenceBody {
    sequence: u32,
}

pub(super) enum PreparedPublicReadResponse {
    Immediate(Response<Vec<u8>>),
    Control {
        authority: WindowAuthority,
        delivery: Box<PublicArtifactReadControlDelivery>,
        encoded: Zeroizing<Vec<u8>>,
    },
    Block {
        authority: WindowAuthority,
        delivery: PublicArtifactReadDelivery,
        descriptor: ArtifactReadChunkDescriptor,
    },
}

pub(super) fn owns_path(path: &str) -> bool {
    path == PREFIX || path.starts_with("/api/artifact-reads/")
}

enum Route {
    Open,
    Next(String),
    Acknowledge(String),
    Close(String),
}

impl DesktopTauriProtocol {
    pub(super) async fn prepare_public_artifact_read_response(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
    ) -> PreparedPublicReadResponse {
        let immediate = |error| PreparedPublicReadResponse::Immediate(error_response(error));
        let authority = match self.public_artifact_read_authority(label) {
            Ok(authority) => authority,
            Err(error) => {
                request.body_mut().fill(0);
                return immediate(error);
            }
        };
        if let Err(error) = self.public_artifact_read_window_current(label, &authority) {
            request.body_mut().fill(0);
            return immediate(error);
        }
        if request.uri().query().is_some() || request.uri().path().contains('%') {
            request.body_mut().fill(0);
            return immediate(AppError::MalformedPayload { field: "query" });
        }
        let route = match route(request.uri().path()) {
            Ok(route) => route,
            Err(error) => {
                request.body_mut().fill(0);
                return immediate(error);
            }
        };
        let method = match route {
            Route::Close(_) => Method::DELETE,
            _ => Method::POST,
        };
        if request.method() != method {
            request.body_mut().fill(0);
            return PreparedPublicReadResponse::Immediate(empty_response(
                StatusCode::METHOD_NOT_ALLOWED,
            ));
        }
        let command = match route {
            Route::Open => {
                match parse_sensitive_body::<OpenArtifactRead>(&mut request, API_BODY_MAX_BYTES) {
                    Ok(input) => AppCommand::OpenArtifactRead(input),
                    Err(error) => {
                        return PreparedPublicReadResponse::Immediate(
                            sensitive_body_error_response(error),
                        );
                    }
                }
            }
            Route::Next(handle_id) | Route::Acknowledge(handle_id) => {
                let input =
                    match parse_sensitive_body::<SequenceBody>(&mut request, API_BODY_MAX_BYTES) {
                        Ok(input) => input,
                        Err(error) => {
                            return PreparedPublicReadResponse::Immediate(
                                sensitive_body_error_response(error),
                            );
                        }
                    };
                if request.uri().path().ends_with("/next") {
                    AppCommand::ReadArtifactReadBlock(ReadArtifactReadBlock {
                        handle_id,
                        sequence: input.sequence,
                    })
                } else {
                    AppCommand::AcknowledgeArtifactReadBlock(AcknowledgeArtifactReadBlock {
                        handle_id,
                        sequence: input.sequence,
                    })
                }
            }
            Route::Close(handle_id) => {
                if !request.body().is_empty() {
                    request.body_mut().fill(0);
                    return immediate(AppError::MalformedPayload { field: "body" });
                }
                AppCommand::CloseArtifactRead(CloseArtifactRead { handle_id })
            }
        };
        let selected = match &command {
            AppCommand::ReadArtifactReadBlock(input) => Some(input.clone()),
            _ => None,
        };
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        let reply = match result {
            Ok(reply) => reply,
            Err(error) => {
                return immediate(
                    self.public_artifact_read_window_current(label, &authority)
                        .err()
                        .unwrap_or(error),
                );
            }
        };
        if let Some(input) = selected {
            let AppReply::ArtifactReadChunkDescriptor(descriptor) = reply else {
                return immediate(unavailable());
            };
            let delivery = match self
                .transport
                .service()
                .take_artifact_read_delivery(authority.auth.clone(), input.clone())
            {
                Ok(delivery) => delivery,
                Err(error) => return immediate(error),
            };
            // Own the actual pending delivery before a fallible host check. A refusal now
            // drops that same real owner instead of leaving a scalar descriptor pending.
            if let Err(error) = self.public_artifact_read_window_current(label, &authority) {
                return immediate(error);
            }
            if descriptor.handle_id != input.handle_id
                || descriptor.sequence != input.sequence
                || descriptor.byte_length as usize > MAX_ARTIFACT_READ_CHUNK_BYTES
                || descriptor.eof != (descriptor.byte_length == 0)
                || delivery.descriptor() != &descriptor
            {
                return immediate(unavailable());
            }
            return PreparedPublicReadResponse::Block {
                authority,
                delivery,
                descriptor,
            };
        }
        let delivery = match self
            .transport
            .service()
            .take_artifact_read_control_delivery(authority.auth.clone(), reply)
        {
            Ok(delivery) => delivery,
            Err(error) => return immediate(error),
        };
        if let Err(error) = self.public_artifact_read_window_current(label, &authority) {
            return immediate(error);
        }
        let encoded = match encode_control(delivery.reply()) {
            Ok(encoded) => encoded,
            Err(error) => return immediate(error),
        };
        PreparedPublicReadResponse::Control {
            authority,
            delivery: Box::new(delivery),
            encoded: Zeroizing::new(encoded),
        }
    }

    /// Both deterministic `handle` and the real UriSchemeResponder call this same final bridge.
    /// A responder return is only a framework handoff; it is never renderer delivery proof.
    pub(super) fn finish_public_artifact_read_response<R>(
        &self,
        label: &str,
        prepared: PreparedPublicReadResponse,
        respond: impl FnOnce(Response<Vec<u8>>) -> R,
    ) -> R {
        match prepared {
            PreparedPublicReadResponse::Immediate(response) => respond(response),
            PreparedPublicReadResponse::Control {
                authority,
                delivery,
                mut encoded,
            } => {
                let mut response =
                    super::response(StatusCode::OK, "application/json", Vec::new(), true);
                let checked = self
                    .public_artifact_read_window_current(label, &authority)
                    .and_then(|()| delivery.verify_current_tail(&authority.auth));
                if let Err(error) = checked {
                    return respond(error_response(error));
                }
                *response.body_mut() = std::mem::take(&mut *encoded);
                let result = respond(response);
                drop(delivery);
                result
            }
            PreparedPublicReadResponse::Block {
                authority,
                delivery,
                descriptor,
            } => {
                let mut response =
                    super::response(StatusCode::OK, "application/octet-stream", Vec::new(), true);
                if let Err(error) = insert_block_headers(&mut response, &descriptor) {
                    return respond(error_response(error));
                }
                if let Err(error) = self.public_artifact_read_window_current(label, &authority) {
                    return respond(error_response(error));
                }
                let block = match delivery.handoff(&authority.auth) {
                    Ok(block) => block,
                    Err(error) => return respond(error_response(error)),
                };
                let Some(block) = block else {
                    if !descriptor.eof || descriptor.byte_length != 0 {
                        return respond(error_response(unavailable()));
                    }
                    // The last synchronous handoff just checked the original EOF/control tail.
                    return respond(response);
                };
                let mut copy = Zeroizing::new(Vec::new());
                if descriptor.eof
                    || block.as_ref().len() != descriptor.byte_length as usize
                    || block.as_ref().len() > MAX_ARTIFACT_READ_CHUNK_BYTES
                    || copy.try_reserve_exact(block.as_ref().len()).is_err()
                {
                    block.close();
                    return respond(error_response(unavailable()));
                }
                if let Err(error) = block.verify_current_tail(&authority.auth) {
                    block.close();
                    return respond(error_response(error));
                }
                copy.resize(block.as_ref().len(), 0);
                copy.copy_from_slice(block.as_ref());
                tracing::trace!(
                    public_artifact_read_host_phase = "desktop_copy_complete_before_final_tail"
                );
                let checked = self
                    .public_artifact_read_window_current(label, &authority)
                    .and_then(|()| block.verify_current_tail(&authority.auth));
                if let Err(error) = checked {
                    block.close();
                    return respond(error_response(error));
                }
                *response.body_mut() = std::mem::take(&mut *copy);
                // Original allocation remains locally owned throughout the responder call.
                // The transferred Vec/NSData/client copies are outside this controlled owner.
                let result = respond(response);
                drop(block);
                result
            }
        }
    }

    fn public_artifact_read_authority(&self, label: &str) -> Result<WindowAuthority, AppError> {
        self.window_registry
            .windows
            .try_read()
            .map_err(|_| host_unavailable())?
            .get(label)
            .cloned()
            .ok_or(AppError::Unauthenticated)
    }

    fn public_artifact_read_window_current(
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
            .ok_or_else(host_unavailable)?;
        if !self.request_binding_issuer.matches_desktop_window_epoch(
            binding.identity(),
            label,
            original.binding_id,
        ) {
            return Err(AppError::Unauthenticated);
        }
        let windows = self
            .window_registry
            .windows
            .try_read()
            .map_err(|_| host_unavailable())?;
        match windows.get(label) {
            Some(current)
                if current.binding_id == original.binding_id
                    && !current.closed.is_cancelled()
                    && current.auth == original.auth
                    && current.auth.request_binding().is_some_and(|current| {
                        binding.identity().same_binding(current.identity())
                    }) =>
            {
                Ok(())
            }
            _ => Err(AppError::Unauthenticated),
        }
    }
}

fn route(path: &str) -> Result<Route, AppError> {
    if path == PREFIX {
        return Ok(Route::Open);
    }
    let rest = path
        .strip_prefix("/api/artifact-reads/")
        .ok_or(AppError::NotVisible)?;
    let parts = rest.split('/').collect::<Vec<_>>();
    let (handle, suffix) = match parts.as_slice() {
        [handle] if !handle.is_empty() => (*handle, ""),
        [handle, suffix] if !handle.is_empty() && !suffix.is_empty() => (*handle, *suffix),
        _ => return Err(AppError::NotVisible),
    };
    if !is_canonical_artifact_read_handle(handle) {
        return Err(AppError::MalformedPayload { field: "handle_id" });
    }
    match suffix {
        "" => Ok(Route::Close(handle.to_owned())),
        "next" => Ok(Route::Next(handle.to_owned())),
        "ack" => Ok(Route::Acknowledge(handle.to_owned())),
        _ => Err(AppError::NotVisible),
    }
}

fn encode_control(reply: &AppReply) -> Result<Vec<u8>, AppError> {
    let encoded = match reply {
        AppReply::ArtifactReadOpened(value) => serde_json::to_vec(value),
        AppReply::ArtifactReadAcknowledged(value) => serde_json::to_vec(value),
        AppReply::ArtifactReadClosed(value) => serde_json::to_vec(value),
        _ => return Err(unavailable()),
    };
    encoded.map_err(|_| unavailable())
}

fn insert_block_headers(
    response: &mut Response<Vec<u8>>,
    descriptor: &ArtifactReadChunkDescriptor,
) -> Result<(), AppError> {
    for (name, value) in [
        ("x-artifact-read-handle", descriptor.handle_id.clone()),
        ("x-artifact-read-sequence", descriptor.sequence.to_string()),
        ("x-artifact-read-length", descriptor.byte_length.to_string()),
        ("x-artifact-read-eof", descriptor.eof.to_string()),
    ] {
        response.headers_mut().insert(
            name,
            http::HeaderValue::from_str(&value).map_err(|_| unavailable())?,
        );
    }
    Ok(())
}

const fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifact_reads",
    }
}

const fn host_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "host_request_binding",
    }
}

#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]
#[path = "artifact_reads_tests.rs"]
mod tests;
