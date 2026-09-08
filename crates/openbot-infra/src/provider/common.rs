//! Provider adapters 的共享 bounded request 与 immediate terminal session。

use async_trait::async_trait;
use core::time::Duration;
use http::HeaderValue;
use http::header::RETRY_AFTER;
use openbot_application::{
    ProviderEvent, ProviderMessageRole, ProviderPortError, ProviderRequest, ProviderSession,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use crate::net::safe_http::{SafeHttpError, SafeHttpStreamResponse};

pub(crate) const MAX_PROVIDER_MESSAGES: usize = 4096;
pub(crate) const MAX_PROVIDER_TOOLS: usize = 256;
pub(crate) const MAX_PROVIDER_FIELD_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_request(request: &ProviderRequest) -> Result<(), ProviderPortError> {
    if request.messages.is_empty()
        || request.messages.len() > MAX_PROVIDER_MESSAGES
        || request.tools.len() > MAX_PROVIDER_TOOLS
        || request.max_output_tokens == Some(0)
    {
        return Err(ProviderPortError::InvalidRequest {
            field: "provider_request",
        });
    }
    let mut pending_tool_calls = BTreeMap::<String, String>::new();
    for message in &request.messages {
        if message.content.len() > MAX_PROVIDER_FIELD_BYTES
            || message.content.as_bytes().contains(&0)
            || (message.role == ProviderMessageRole::Tool) != message.tool_call_id.is_some()
            || (message.role == ProviderMessageRole::Tool) != message.tool_name.is_some()
            || (message.role != ProviderMessageRole::Assistant && !message.tool_calls.is_empty())
        {
            return Err(ProviderPortError::InvalidRequest {
                field: "provider_message",
            });
        }
        let mut call_ids = BTreeSet::new();
        for call in &message.tool_calls {
            if call.call_id.is_empty()
                || call.call_id.len() > MAX_PROVIDER_FIELD_BYTES
                || call.call_id.as_bytes().contains(&0)
                || call.name.is_empty()
                || call.name.len() > 256
                || call.name.as_bytes().contains(&0)
                || !call.arguments.is_object()
                || serde_json::to_vec(&call.arguments)
                    .map_or(true, |value| value.len() > MAX_PROVIDER_FIELD_BYTES)
                || !call_ids.insert(call.call_id.as_str())
            {
                return Err(ProviderPortError::InvalidRequest {
                    field: "provider_tool_call",
                });
            }
        }
        if message.role == ProviderMessageRole::Assistant {
            if !pending_tool_calls.is_empty() {
                return Err(ProviderPortError::InvalidRequest {
                    field: "provider_tool_pair",
                });
            }
            for call in &message.tool_calls {
                pending_tool_calls.insert(call.call_id.clone(), call.name.clone());
            }
        } else if message.role == ProviderMessageRole::Tool {
            let (Some(call_id), Some(name)) = (
                message.tool_call_id.as_deref(),
                message.tool_name.as_deref(),
            ) else {
                return Err(ProviderPortError::InvalidRequest {
                    field: "provider_tool_pair",
                });
            };
            if pending_tool_calls.remove(call_id).as_deref() != Some(name) {
                return Err(ProviderPortError::InvalidRequest {
                    field: "provider_tool_pair",
                });
            }
        } else if !pending_tool_calls.is_empty() {
            return Err(ProviderPortError::InvalidRequest {
                field: "provider_tool_pair",
            });
        }
    }
    if !pending_tool_calls.is_empty() {
        return Err(ProviderPortError::InvalidRequest {
            field: "provider_tool_pair",
        });
    }
    for tool in &request.tools {
        if tool.name.is_empty()
            || tool.name.len() > 256
            || tool.name.as_bytes().contains(&0)
            || tool.description.len() > 64 * 1024
            || !tool.input_schema.is_object()
        {
            return Err(ProviderPortError::InvalidRequest {
                field: "provider_tool",
            });
        }
    }
    Ok(())
}

pub(crate) struct ImmediateSession {
    event: Option<ProviderEvent>,
}

impl ImmediateSession {
    pub(crate) const fn new(event: ProviderEvent) -> Self {
        Self { event: Some(event) }
    }
}

#[async_trait]
impl ProviderSession for ImmediateSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.event.take())
    }
}

pub(crate) fn map_start_error(error: SafeHttpError) -> ProviderPortError {
    match error {
        SafeHttpError::DnsUnavailable | SafeHttpError::ConnectFailed | SafeHttpError::TlsFailed => {
            ProviderPortError::Unavailable
        }
        SafeHttpError::DeadlineExceeded
        | SafeHttpError::ProtocolFailed
        | SafeHttpError::ResponseTooLarge
        | SafeHttpError::StreamStalled => ProviderPortError::CommitUnknown,
        SafeHttpError::InvalidUrl
        | SafeHttpError::SchemeRejected
        | SafeHttpError::InvalidBudget
        | SafeHttpError::InvalidHeader
        | SafeHttpError::InvalidAllowlist
        | SafeHttpError::DestinationDenied
        | SafeHttpError::PeerMismatch
        | SafeHttpError::RedirectInvalid
        | SafeHttpError::RedirectLimit
        | SafeHttpError::RedirectMethodRejected
        | SafeHttpError::SensitiveRedirectRejected => ProviderPortError::InvalidRequest {
            field: "provider_transport",
        },
    }
}

pub(crate) fn response_retry_after(response: &SafeHttpStreamResponse) -> Option<Duration> {
    response
        .header(&RETRY_AFTER)
        .and_then(|value| parse_retry_after(value, SystemTime::now()))
}

fn parse_retry_after(value: &HeaderValue, now: SystemTime) -> Option<Duration> {
    let value = value.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_accepts_delta_or_http_date_and_rejects_vendor_prose() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            parse_retry_after(&HeaderValue::from_static("12"), now),
            Some(Duration::from_secs(12))
        );
        let future = now + Duration::from_secs(30);
        let date = HeaderValue::from_str(&httpdate::fmt_http_date(future)).unwrap();
        assert_eq!(parse_retry_after(&date, now), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_retry_after(&HeaderValue::from_static("try again soon"), now),
            None
        );
    }

    #[test]
    fn pre_send_and_commit_unknown_transport_failures_are_distinct() {
        assert_eq!(
            map_start_error(SafeHttpError::ConnectFailed),
            ProviderPortError::Unavailable
        );
        assert_eq!(
            map_start_error(SafeHttpError::DeadlineExceeded),
            ProviderPortError::CommitUnknown
        );
        assert!(matches!(
            map_start_error(SafeHttpError::DestinationDenied),
            ProviderPortError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn assistant_tool_calls_and_results_must_form_an_exact_closed_pair() {
        let request = ProviderRequest {
            route: openbot_application::ProviderRoute::Managed,
            messages: vec![
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::Assistant,
                    content: String::new(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: vec![openbot_application::ProviderToolCall {
                        call_id: "call-1".to_owned(),
                        name: "remember".to_owned(),
                        arguments: serde_json::json!({}),
                    }],
                },
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::Tool,
                    content: "done".to_owned(),
                    tool_call_id: Some("call-1".to_owned()),
                    tool_name: Some("remember".to_owned()),
                    tool_calls: Vec::new(),
                },
            ],
            tools: Vec::new(),
            max_output_tokens: Some(1),
            rate_card: None,
            cost_cap: None,
        };
        assert_eq!(validate_request(&request), Ok(()));
        let mut mismatched = request.clone();
        mismatched.messages[1].tool_name = Some("other".to_owned());
        assert!(validate_request(&mismatched).is_err());
        let mut unfinished = request;
        unfinished.messages.pop();
        assert!(validate_request(&unfinished).is_err());
    }
}
