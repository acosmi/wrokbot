//! Memory custom-protocol framing. All ownership, scope and content rules stay in Application.

use openbot_contracts::memory::{
    CorrectMemory, MemoryMutation, RecallMemories, RememberMemory, UpdateMemoryControl,
};

use super::{
    AppCommand, AppError, AppReply, CHANNEL_THREAD_BODY_MAX_BYTES, DesktopTauriProtocol, Method,
    Request, Response, SensitiveBodyError, StatusCode, WindowAuthority, channel_list_query,
    dependency_response, empty_response, error_response, json_response, json_response_with_status,
    parse_sensitive_body, payload_too_large, percent_decode_segment, sensitive_body_error_response,
};

enum MemoryRoute<'a> {
    Collection,
    Control,
    Recall,
    Record(&'a str),
    Forbid(&'a str),
}

enum MemoryReplyKind {
    Page,
    Control,
    Recall,
    Record(StatusCode),
}

enum MemoryInputError {
    Malformed(&'static str),
    Body(SensitiveBodyError),
}

impl DesktopTauriProtocol {
    pub(super) async fn memories(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        // Recheck the native binding captured by handle, without accepting a renderer identity or
        // treating the sensitive-write freshness deadline as a durable authorization generation.
        if let Err(error) = self.memory_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        // Same 1 MiB materialized-body boundary as Server, including bodyless operations.
        if request.body().len() > CHANNEL_THREAD_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        let path = request.uri().path().to_owned();
        let Some(route) = memory_route(&path) else {
            request.body_mut().fill(0);
            return empty_response(StatusCode::NOT_FOUND);
        };
        let method = request.method();
        let allowed = match route {
            MemoryRoute::Collection => method == Method::GET || method == Method::POST,
            MemoryRoute::Control => method == Method::GET || method == Method::PUT,
            MemoryRoute::Recall | MemoryRoute::Forbid(_) => method == Method::POST,
            MemoryRoute::Record(_) => method == Method::PUT || method == Method::DELETE,
        };
        if !allowed {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        // Desktop closes unused framing inputs. Server currently ignores these query/body inputs
        // on handlers without an extractor; the difference is intentional, not a new business rule.
        let list = matches!(route, MemoryRoute::Collection) && request.method() == Method::GET;
        if !list && request.uri().query().is_some_and(|query| !query.is_empty()) {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        let bodyless = request.method() == Method::GET
            || request.method() == Method::DELETE
            || matches!(route, MemoryRoute::Forbid(_));
        if bodyless && !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        let parsed = memory_command(route, &mut request);
        let (command, reply_kind, write) = match parsed {
            Ok(command) => command,
            Err(error) => {
                request.body_mut().fill(0);
                return match error {
                    MemoryInputError::Malformed(field) => {
                        error_response(AppError::MalformedPayload { field })
                    }
                    MemoryInputError::Body(error) => sensitive_body_error_response(error),
                };
            }
        };
        if let Err(error) = self.memory_binding_current(label, &authority) {
            return error_response(error);
        }
        // Do not cancel/retry an admitted write on window closure: it may already have committed.
        // Always retain the original host authority, never retarget work to a replacement binding.
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        if let Err(error) = self.memory_binding_current(label, &authority) {
            return if write
                && (result.is_ok()
                    || matches!(result, Err(AppError::ReconciliationRequired { .. })))
            {
                error_response(AppError::ReconciliationRequired { accepted: true })
            } else {
                error_response(error)
            };
        }
        match (reply_kind, result) {
            (MemoryReplyKind::Page, Ok(AppReply::Memories(page))) => json_response(&page),
            (MemoryReplyKind::Control, Ok(AppReply::MemoryControl(control))) => {
                json_response(&control)
            }
            (MemoryReplyKind::Recall, Ok(AppReply::MemoryRecall(recall))) => json_response(&recall),
            (MemoryReplyKind::Record(status), Ok(AppReply::Memory(memory))) => {
                json_response_with_status(&memory, status)
            }
            (_, Err(error)) => error_response(error),
            (_, Ok(_)) => dependency_response(),
        }
    }

    fn memory_binding_current(
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

fn memory_route(path: &str) -> Option<MemoryRoute<'_>> {
    match path {
        "/api/memories" => Some(MemoryRoute::Collection),
        "/api/memories/control" => Some(MemoryRoute::Control),
        "/api/memories/recall" => Some(MemoryRoute::Recall),
        _ => {
            let rest = path.strip_prefix("/api/memories/")?;
            if let Some(id) = rest.strip_suffix("/forbid") {
                (!id.is_empty() && !id.contains('/')).then_some(MemoryRoute::Forbid(id))
            } else {
                (!rest.is_empty() && !rest.contains('/')).then_some(MemoryRoute::Record(rest))
            }
        }
    }
}

fn memory_command(
    route: MemoryRoute<'_>,
    request: &mut Request<Vec<u8>>,
) -> Result<(AppCommand, MemoryReplyKind, bool), MemoryInputError> {
    match route {
        MemoryRoute::Collection if request.method() == Method::GET => {
            let (limit, cursor) = channel_list_query(request.uri().query())
                .ok_or(MemoryInputError::Malformed("query"))?;
            Ok((
                AppCommand::ListMemories { cursor, limit },
                MemoryReplyKind::Page,
                false,
            ))
        }
        MemoryRoute::Collection => Ok((
            AppCommand::RememberMemory(
                parse_sensitive_body::<RememberMemory>(request, CHANNEL_THREAD_BODY_MAX_BYTES)
                    .map_err(MemoryInputError::Body)?,
            ),
            MemoryReplyKind::Record(StatusCode::CREATED),
            true,
        )),
        MemoryRoute::Control if request.method() == Method::GET => Ok((
            AppCommand::GetMemoryControl,
            MemoryReplyKind::Control,
            false,
        )),
        MemoryRoute::Control => Ok((
            AppCommand::UpdateMemoryControl(
                parse_sensitive_body::<UpdateMemoryControl>(request, CHANNEL_THREAD_BODY_MAX_BYTES)
                    .map_err(MemoryInputError::Body)?,
            ),
            MemoryReplyKind::Control,
            true,
        )),
        MemoryRoute::Recall => Ok((
            AppCommand::RecallMemories(
                parse_sensitive_body::<RecallMemories>(request, CHANNEL_THREAD_BODY_MAX_BYTES)
                    .map_err(MemoryInputError::Body)?,
            ),
            MemoryReplyKind::Recall,
            false,
        )),
        MemoryRoute::Record(raw_id) | MemoryRoute::Forbid(raw_id) => {
            let memory_id =
                percent_decode_segment(raw_id).ok_or(MemoryInputError::Malformed("memory_id"))?;
            let command = if matches!(route, MemoryRoute::Forbid(_)) {
                AppCommand::MutateMemory {
                    memory_id,
                    mutation: MemoryMutation::Forbid,
                }
            } else if request.method() == Method::DELETE {
                AppCommand::MutateMemory {
                    memory_id,
                    mutation: MemoryMutation::Delete,
                }
            } else {
                AppCommand::CorrectMemory {
                    memory_id,
                    correction: parse_sensitive_body::<CorrectMemory>(
                        request,
                        CHANNEL_THREAD_BODY_MAX_BYTES,
                    )
                    .map_err(MemoryInputError::Body)?,
                }
            };
            Ok((command, MemoryReplyKind::Record(StatusCode::OK), true))
        }
    }
}

#[cfg(test)]
mod tests;
