//! Anthropic Messages streaming adapter（v3 §7.3）。

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderMessageRole, ProviderOutputKind,
    ProviderPortError, ProviderRequest, ProviderSession, ProviderUsage,
};
use openbot_domain::vault::SecretBytes;
use serde_json::{Value, json};
use url::Url;

use super::common::{
    ImmediateSession, MAX_PROVIDER_FIELD_BYTES, map_start_error, response_retry_after,
    validate_request,
};
use super::sse::SseDecoder;
use crate::net::safe_http::{
    ProviderApiKeyValue, SafeDialer, SafeHttpBudget, SafeHttpError, SafeHttpRequest,
    SafeHttpStreamResponse, SchemePolicy,
};

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";
const FALLBACK_MAX_OUTPUT_TOKENS: u32 = 4096;

/// Anthropic API key；不可 Clone/Serialize，Debug 恒脱敏。
pub struct AnthropicApiKey(SecretBytes);

impl AnthropicApiKey {
    /// UTF-8、非空、无 CR/LF/NUL。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProviderPortError> {
        Self::from_secret(SecretBytes::new(bytes))
    }

    pub(crate) fn from_secret(secret: SecretBytes) -> Result<Self, ProviderPortError> {
        let value = secret.expose();
        if value.is_empty()
            || value.len() > 16 * 1024
            || value.iter().any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
            || core::str::from_utf8(value).is_err()
        {
            return Err(ProviderPortError::InvalidRequest { field: "api_key" });
        }
        Ok(Self(secret))
    }
}

impl core::fmt::Debug for AnthropicApiKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AnthropicApiKey([redacted])")
    }
}

/// Verified Anthropic endpoint/model/budget config。
pub struct AnthropicProviderConfig {
    endpoint: Url,
    model: String,
    api_key: AnthropicApiKey,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    scheme_policy: SchemePolicy,
}

impl AnthropicProviderConfig {
    /// Production HTTPS-only config。
    pub fn new(
        endpoint: Url,
        model: String,
        api_key: AnthropicApiKey,
        connect_budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
    ) -> Result<Self, ProviderPortError> {
        Self::new_with_transport_policy(
            endpoint,
            model,
            api_key,
            connect_budget,
            stall_timeout,
            SchemePolicy::HttpsOnly,
        )
    }

    /// Admin-verified self-hosted transport override；destination 仍由 SafeDialer 判定。
    pub fn new_with_transport_policy(
        endpoint: Url,
        model: String,
        api_key: AnthropicApiKey,
        connect_budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
        scheme_policy: SchemePolicy,
    ) -> Result<Self, ProviderPortError> {
        if model.is_empty()
            || model.len() > 512
            || model.as_bytes().contains(&0)
            || stall_timeout.is_some_and(|value| value.is_zero())
            || !scheme_policy.accepts(endpoint.scheme())
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ProviderPortError::InvalidRequest {
                field: "provider_config",
            });
        }
        Ok(Self {
            endpoint,
            model,
            api_key,
            connect_budget,
            stall_timeout,
            scheme_policy,
        })
    }
}

impl core::fmt::Debug for AnthropicProviderConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AnthropicProviderConfig")
            .field("origin", &self.endpoint.origin().ascii_serialization())
            .field("model", &self.model)
            .field("has_stall_timeout", &self.stall_timeout.is_some())
            .finish_non_exhaustive()
    }
}

/// Production Anthropic adapter。
pub struct AnthropicProvider {
    config: AnthropicProviderConfig,
    dialer: SafeDialer,
}

impl AnthropicProvider {
    /// 用唯一 SafeDialer 构造。
    #[must_use]
    pub const fn new(config: AnthropicProviderConfig, dialer: SafeDialer) -> Self {
        Self { config, dialer }
    }
}

impl core::fmt::Debug for AnthropicProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AnthropicProvider")
            .field("config", &self.config)
            .field("dialer", &self.dialer)
            .finish()
    }
}

#[async_trait]
impl ProviderAdapter for AnthropicProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        validate_request(&request)?;
        let body = build_request_body(&self.config.model, &request)?;
        let key = core::str::from_utf8(self.config.api_key.0.expose())
            .map_err(|_| ProviderPortError::InvalidRequest { field: "api_key" })?;
        let request = SafeHttpRequest::post_json_with_scheme(
            self.config.endpoint.clone(),
            self.config.scheme_policy,
            body,
            None,
            self.config.connect_budget,
        )
        .map_err(|_| ProviderPortError::InvalidRequest {
            field: "provider_request",
        })?
        .with_anthropic_api_key(
            ProviderApiKeyValue::parse(key)
                .map_err(|_| ProviderPortError::InvalidRequest { field: "api_key" })?,
        );
        let response = self
            .dialer
            .execute_stream(request)
            .await
            .map_err(map_start_error)?;
        if let Some(failure) = status_failure(response.status(), response_retry_after(&response)) {
            return Ok(Box::new(ImmediateSession::new(ProviderEvent::Failed(
                failure,
            ))));
        }
        if !response.status().is_success() {
            return Ok(Box::new(ImmediateSession::new(ProviderEvent::Failed(
                ProviderFailure::GenerationFailed,
            ))));
        }
        let content_type = response
            .header(&CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        if !content_type.eq_ignore_ascii_case(EVENT_STREAM_CONTENT_TYPE) {
            return Ok(Box::new(ImmediateSession::new(ProviderEvent::Failed(
                ProviderFailure::InvalidResponse,
            ))));
        }
        Ok(Box::new(AnthropicSession {
            response,
            sse: SseDecoder::default(),
            decoder: AnthropicDecoder::default(),
            pending: VecDeque::new(),
            stall_timeout: self.config.stall_timeout,
            ended: false,
        }))
    }
}

fn build_request_body(
    model: &str,
    request: &ProviderRequest,
) -> Result<Vec<u8>, ProviderPortError> {
    let mut system = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    for message in &request.messages {
        match message.role {
            ProviderMessageRole::System => system.push(message.content.as_str()),
            ProviderMessageRole::User => {
                push_message_block(
                    &mut messages,
                    "user",
                    json!({
                        "type":"text","text":message.content
                    }),
                )?;
            }
            ProviderMessageRole::Assistant => {
                if !message.content.is_empty() {
                    push_message_block(
                        &mut messages,
                        "assistant",
                        json!({
                            "type":"text","text":message.content
                        }),
                    )?;
                }
                for call in &message.tool_calls {
                    push_message_block(
                        &mut messages,
                        "assistant",
                        json!({
                            "type":"tool_use",
                            "id":call.call_id,
                            "name":call.name,
                            "input":call.arguments,
                        }),
                    )?;
                }
            }
            ProviderMessageRole::Tool => {
                push_message_block(
                    &mut messages,
                    "user",
                    json!({
                        "type":"tool_result",
                        "tool_use_id":message.tool_call_id,
                        "content":message.content,
                    }),
                )?;
            }
        }
    }
    if messages.is_empty() {
        return Err(ProviderPortError::InvalidRequest {
            field: "provider_messages",
        });
    }
    let tools = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name":tool.name,
                "description":tool.description,
                "input_schema":tool.input_schema,
            })
        })
        .collect::<Vec<_>>();
    let max_tokens = request
        .max_output_tokens
        .unwrap_or_else(|| default_max_output_tokens(model));
    let mut body = json!({
        "model":model,
        "messages":messages,
        "max_tokens":max_tokens,
        "stream":true,
    });
    if !system.is_empty() {
        body["system"] = json!(system.join("\n\n"));
    }
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    serde_json::to_vec(&body).map_err(|_| ProviderPortError::InvalidRequest {
        field: "provider_request",
    })
}

fn push_message_block(
    messages: &mut Vec<Value>,
    role: &'static str,
    block: Value,
) -> Result<(), ProviderPortError> {
    if let Some(last) = messages.last_mut()
        && last.get("role").and_then(Value::as_str) == Some(role)
    {
        let content = last
            .get_mut("content")
            .and_then(Value::as_array_mut)
            .ok_or(ProviderPortError::InvalidRequest {
                field: "provider_messages",
            })?;
        content.push(block);
        return Ok(());
    }
    messages.push(json!({"role":role,"content":[block]}));
    Ok(())
}

fn default_max_output_tokens(model: &str) -> u32 {
    const DEFAULTS: [(&str, u32); 14] = [
        ("claude-opus-4-6", 16_384),
        ("claude-sonnet-4-6", 16_384),
        ("claude-opus-4-5", 16_384),
        ("claude-sonnet-4-5", 16_384),
        ("claude-haiku-4-5", 16_384),
        ("claude-opus-4-1", 16_384),
        ("claude-sonnet-4", 16_384),
        ("claude-opus-4", 16_384),
        ("claude-3-7-sonnet", 8192),
        ("claude-3-5-sonnet", 8192),
        ("claude-3-5-haiku", 8192),
        ("claude-3-opus", 4096),
        ("claude-3-sonnet", 4096),
        ("claude-3-haiku", 4096),
    ];
    DEFAULTS
        .iter()
        .find_map(|(prefix, limit)| model.starts_with(prefix).then_some(*limit))
        .unwrap_or(FALLBACK_MAX_OUTPUT_TOKENS)
}

fn status_failure(status: StatusCode, retry_after: Option<Duration>) -> Option<ProviderFailure> {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Some(ProviderFailure::Authentication),
        StatusCode::TOO_MANY_REQUESTS => Some(ProviderFailure::RateLimited { retry_after }),
        status if status.is_server_error() => {
            Some(ProviderFailure::ServerUnavailable { retry_after })
        }
        _ => None,
    }
}

struct AnthropicSession {
    response: SafeHttpStreamResponse,
    sse: SseDecoder,
    decoder: AnthropicDecoder,
    pending: VecDeque<ProviderEvent>,
    stall_timeout: Option<Duration>,
    ended: bool,
}

#[async_trait]
impl ProviderSession for AnthropicSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            if self.ended {
                return Ok(None);
            }
            match self.response.next_chunk(self.stall_timeout).await {
                Ok(Some(chunk)) => {
                    let data = match self.sse.push(&chunk) {
                        Ok(data) => data,
                        Err(_) => {
                            self.fail(ProviderFailure::InvalidResponse);
                            continue;
                        }
                    };
                    for event in data {
                        match self.decoder.ingest(&event) {
                            Ok(events) => self.pending.extend(events),
                            Err(failure) => {
                                self.fail(failure);
                                break;
                            }
                        }
                    }
                }
                Ok(None) => {
                    if self.sse.finish().is_err() {
                        self.fail(ProviderFailure::InvalidResponse);
                    } else {
                        match self.decoder.finish() {
                            Ok(events) => {
                                self.pending.extend(events);
                                self.ended = true;
                            }
                            Err(failure) => self.fail(failure),
                        }
                    }
                }
                Err(SafeHttpError::StreamStalled) => self.fail(ProviderFailure::StreamStalled),
                Err(_) => self.fail(ProviderFailure::Transport),
            }
        }
    }
}

impl AnthropicSession {
    fn fail(&mut self, failure: ProviderFailure) {
        self.pending.clear();
        self.pending.push_back(ProviderEvent::Failed(failure));
        self.ended = true;
    }
}

#[derive(Default)]
struct AnthropicDecoder {
    response_id: Option<String>,
    blocks: BTreeMap<u32, AnthropicBlock>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    stop_seen: bool,
    terminal: bool,
}

enum AnthropicBlock {
    Text,
    Reasoning,
    Tool {
        call_id: String,
        name: String,
        initial_input: Value,
        arguments: String,
    },
    Extension,
}

impl AnthropicDecoder {
    fn ingest(&mut self, data: &str) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            return Err(ProviderFailure::InvalidResponse);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProviderFailure::InvalidResponse)?;
        let event_type = string_field(&value, "type")?;
        let mut output = Vec::new();
        match event_type {
            "message_start" => {
                if self.response_id.is_some() || !self.blocks.is_empty() {
                    return Err(ProviderFailure::InvalidResponse);
                }
                let message = object_field(&value, "message")?;
                let id = string_field(message, "id")?.to_owned();
                let content = message
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                if !content.is_empty() {
                    return Err(ProviderFailure::InvalidResponse);
                }
                self.response_id = Some(id.clone());
                self.update_usage(message.get("usage"))?;
                output.push(ProviderEvent::ResponseStarted { response_id: id });
            }
            "content_block_start" => {
                self.require_started()?;
                let index = u32_field(&value, "index")?;
                let block = object_field(&value, "content_block")?;
                let block_type = string_field(block, "type")?;
                let (state, kind) = match block_type {
                    "text" => {
                        let initial = bounded_string_field(block, "text")?;
                        if !initial.is_empty() {
                            output.push(ProviderEvent::TextDelta {
                                index,
                                delta: initial.to_owned(),
                            });
                        }
                        (AnthropicBlock::Text, ProviderOutputKind::Message)
                    }
                    "thinking" => {
                        let initial = bounded_string_field(block, "thinking")?;
                        if !initial.is_empty() {
                            output.push(ProviderEvent::ReasoningDelta {
                                index,
                                delta: initial.to_owned(),
                            });
                        }
                        (AnthropicBlock::Reasoning, ProviderOutputKind::Reasoning)
                    }
                    "tool_use" => {
                        let call_id = string_field(block, "id")?.to_owned();
                        let name = string_field(block, "name")?.to_owned();
                        let initial_input = block
                            .get("input")
                            .filter(|value| value.is_object())
                            .cloned()
                            .ok_or(ProviderFailure::InvalidResponse)?;
                        output.push(ProviderEvent::ToolCallStarted {
                            index,
                            call_id: call_id.clone(),
                            name: Some(name.clone()),
                        });
                        (
                            AnthropicBlock::Tool {
                                call_id,
                                name,
                                initial_input,
                                arguments: String::new(),
                            },
                            ProviderOutputKind::FunctionCall,
                        )
                    }
                    _ => (AnthropicBlock::Extension, ProviderOutputKind::Extension),
                };
                if self.blocks.insert(index, state).is_some() {
                    return Err(ProviderFailure::InvalidResponse);
                }
                output.insert(0, ProviderEvent::OutputItemAdded { index, kind });
            }
            "content_block_delta" => {
                self.require_started()?;
                let index = u32_field(&value, "index")?;
                let delta = object_field(&value, "delta")?;
                let delta_type = string_field(delta, "type")?;
                let block = self
                    .blocks
                    .get_mut(&index)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                match (block, delta_type) {
                    (AnthropicBlock::Text, "text_delta") => {
                        let text = bounded_string_field(delta, "text")?;
                        if !text.is_empty() {
                            output.push(ProviderEvent::TextDelta {
                                index,
                                delta: text.to_owned(),
                            });
                        }
                    }
                    (AnthropicBlock::Reasoning, "thinking_delta") => {
                        let thinking = bounded_string_field(delta, "thinking")?;
                        if !thinking.is_empty() {
                            output.push(ProviderEvent::ReasoningDelta {
                                index,
                                delta: thinking.to_owned(),
                            });
                        }
                    }
                    (AnthropicBlock::Reasoning, "signature_delta")
                    | (AnthropicBlock::Text, "citations_delta")
                    | (AnthropicBlock::Extension, _) => {}
                    (
                        AnthropicBlock::Tool {
                            call_id, arguments, ..
                        },
                        "input_json_delta",
                    ) => {
                        let partial = bounded_string_field(delta, "partial_json")?;
                        if partial.len() > MAX_PROVIDER_FIELD_BYTES.saturating_sub(arguments.len())
                        {
                            return Err(ProviderFailure::InvalidResponse);
                        }
                        arguments.push_str(partial);
                        if !partial.is_empty() {
                            output.push(ProviderEvent::ToolArgumentsDelta {
                                index,
                                call_id: call_id.clone(),
                                delta: partial.to_owned(),
                            });
                        }
                    }
                    _ => return Err(ProviderFailure::InvalidResponse),
                }
            }
            "content_block_stop" => {
                self.require_started()?;
                let index = u32_field(&value, "index")?;
                let block = self
                    .blocks
                    .remove(&index)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                if let AnthropicBlock::Tool {
                    call_id,
                    name,
                    initial_input,
                    arguments,
                } = block
                {
                    let arguments = if arguments.is_empty() {
                        initial_input
                    } else {
                        if initial_input
                            .as_object()
                            .is_some_and(|value| !value.is_empty())
                        {
                            return Err(ProviderFailure::InvalidResponse);
                        }
                        serde_json::from_str(&arguments)
                            .map_err(|_| ProviderFailure::InvalidResponse)?
                    };
                    if !arguments.is_object() {
                        return Err(ProviderFailure::InvalidResponse);
                    }
                    output.push(ProviderEvent::ToolCallCompleted {
                        index,
                        call_id,
                        name,
                        arguments,
                    });
                }
            }
            "message_delta" => {
                self.require_started()?;
                self.update_usage(value.get("usage"))?;
                let delta = object_field(&value, "delta")?;
                match delta.get("stop_reason") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(reason)) => match reason.as_str() {
                        "end_turn" | "stop_sequence" | "tool_use" | "pause_turn" | "refusal" => {
                            self.stop_seen = true;
                        }
                        "max_tokens" | "model_context_window_exceeded" => {
                            self.terminal = true;
                            output.push(ProviderEvent::Failed(ProviderFailure::GenerationFailed));
                        }
                        _ => return Err(ProviderFailure::InvalidResponse),
                    },
                    _ => return Err(ProviderFailure::InvalidResponse),
                }
            }
            "message_stop" => {
                self.require_started()?;
                if !self.blocks.is_empty()
                    || !self.stop_seen
                    || self.input_tokens.is_none()
                    || self.output_tokens.is_none()
                {
                    return Err(ProviderFailure::InvalidResponse);
                }
                let usage = ProviderUsage {
                    input_tokens: self.input_tokens.expect("checked"),
                    output_tokens: self.output_tokens.expect("checked"),
                    total_tokens: self
                        .input_tokens
                        .expect("checked")
                        .checked_add(self.output_tokens.expect("checked"))
                        .ok_or(ProviderFailure::InvalidResponse)?,
                };
                output.push(ProviderEvent::Usage(usage));
                output.push(ProviderEvent::Completed);
                self.terminal = true;
            }
            "error" => {
                let error = object_field(&value, "error")?;
                let failure = match string_field(error, "type")? {
                    "authentication_error" | "permission_error" => ProviderFailure::Authentication,
                    "rate_limit_error" => ProviderFailure::RateLimited { retry_after: None },
                    "overloaded_error" | "api_error" => {
                        ProviderFailure::ServerUnavailable { retry_after: None }
                    }
                    "invalid_request_error" => ProviderFailure::InvalidResponse,
                    _ => ProviderFailure::GenerationFailed,
                };
                output.push(ProviderEvent::Failed(failure));
                self.terminal = true;
            }
            "ping" => {}
            _ => {}
        }
        Ok(output)
    }

    fn require_started(&self) -> Result<(), ProviderFailure> {
        self.response_id
            .as_ref()
            .map(|_| ())
            .ok_or(ProviderFailure::InvalidResponse)
    }

    fn update_usage(&mut self, usage: Option<&Value>) -> Result<(), ProviderFailure> {
        let Some(usage) = usage else {
            return Ok(());
        };
        if usage.is_null() {
            return Ok(());
        }
        if let Some(input) = usage.get("input_tokens") {
            let input = input.as_u64().ok_or(ProviderFailure::InvalidResponse)?;
            if self.input_tokens.is_some_and(|known| input < known) {
                return Err(ProviderFailure::InvalidResponse);
            }
            self.input_tokens = Some(input);
        }
        if let Some(output) = usage.get("output_tokens") {
            let output = output.as_u64().ok_or(ProviderFailure::InvalidResponse)?;
            if self.output_tokens.is_some_and(|known| output < known) {
                return Err(ProviderFailure::InvalidResponse);
            }
            self.output_tokens = Some(output);
        }
        Ok(())
    }

    fn finish(&self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            Ok(Vec::new())
        } else {
            Err(ProviderFailure::InvalidResponse)
        }
    }
}

fn object_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, ProviderFailure> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or(ProviderFailure::InvalidResponse)
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_PROVIDER_FIELD_BYTES)
        .ok_or(ProviderFailure::InvalidResponse)
}

fn bounded_string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_PROVIDER_FIELD_BYTES)
        .ok_or(ProviderFailure::InvalidResponse)
}

fn u32_field(value: &Value, field: &str) -> Result<u32, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ProviderFailure::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::net::safe_http::{CidrAllowlist, EgressPolicy};

    #[test]
    fn official_flow_normalizes_thinking_text_partial_tool_json_usage_and_unknown_events() {
        let mut decoder = AnthropicDecoder::default();
        let mut events = Vec::new();
        for data in [
            r#"{"type":"message_start","message":{"id":"msg_1","content":[],"usage":{"input_tokens":25,"output_tokens":1}}}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"consider"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"opaque"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"hello"}}"#,
            r#"{"type":"content_block_stop","index":1}"#,
            r#"{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"weather","input":{}}}"#,
            r#"{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}"#,
            r#"{"type":"future_extension","opaque":true}"#,
            r#"{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"Paris\"}"}}"#,
            r#"{"type":"content_block_stop","index":2}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":15}}"#,
            r#"{"type":"message_stop"}"#,
        ] {
            events.extend(decoder.ingest(data).unwrap());
        }
        assert!(matches!(events[0], ProviderEvent::ResponseStarted { .. }));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::ReasoningDelta { delta, .. } if delta == "consider"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::ToolCallCompleted { name, arguments, .. }
                if name == "weather" && arguments == &json!({"city":"Paris"})
        )));
        assert_eq!(
            events[events.len() - 2],
            ProviderEvent::Usage(ProviderUsage {
                input_tokens: 25,
                output_tokens: 15,
                total_tokens: 40,
            })
        );
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
        assert_eq!(decoder.finish(), Ok(Vec::new()));
    }

    #[test]
    fn malformed_event_order_and_partial_tool_json_fail_closed() {
        let mut decoder = AnthropicDecoder::default();
        assert_eq!(
            decoder.ingest(r#"{"type":"content_block_stop","index":0}"#),
            Err(ProviderFailure::InvalidResponse)
        );
        decoder
            .ingest(r#"{"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}"#)
            .unwrap();
        decoder
            .ingest(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"x","input":{}}}"#)
            .unwrap();
        decoder
            .ingest(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{"}}"#)
            .unwrap();
        assert_eq!(
            decoder.ingest(r#"{"type":"content_block_stop","index":0}"#),
            Err(ProviderFailure::InvalidResponse)
        );
    }

    #[test]
    fn request_shape_separates_system_merges_roles_and_matches_locked_max_token_default() {
        let request = ProviderRequest {
            route: openbot_application::ProviderRoute::Managed,
            messages: vec![
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::System,
                    content: "standing".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                },
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "one".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                },
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "two".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                },
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::Assistant,
                    content: String::new(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: vec![openbot_application::ProviderToolCall {
                        call_id: "call-1".to_owned(),
                        name: "remember".to_owned(),
                        arguments: json!({"content":"tea"}),
                    }],
                },
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::Tool,
                    content: "remembered".to_owned(),
                    tool_call_id: Some("call-1".to_owned()),
                    tool_name: Some("remember".to_owned()),
                    tool_calls: Vec::new(),
                },
            ],
            tools: vec![openbot_application::ProviderToolDefinition {
                name: "lookup".to_owned(),
                description: "look up".to_owned(),
                input_schema: json!({"type":"object"}),
            }],
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        };
        let body: Value =
            serde_json::from_slice(&build_request_body("claude-sonnet-4-5", &request).unwrap())
                .unwrap();
        assert_eq!(body["system"], "standing");
        assert_eq!(body["messages"].as_array().unwrap().len(), 3);
        assert_eq!(body["messages"][0]["content"].as_array().unwrap().len(), 2);
        assert_eq!(body["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
        assert_eq!(body["max_tokens"], 16_384);
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
    }

    #[tokio::test]
    async fn adapter_sends_fixed_headers_and_streams_through_safe_dialer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with("POST /v1/messages "));
            assert!(request.contains("x-api-key: anthropic-test-key"));
            assert!(request.contains("anthropic-version: 2023-06-01"));
            let body = concat!(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_local\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
                "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
                "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
                "data: {\"type\":\"message_stop\"}\n\n",
            );
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(body.as_bytes()).await.unwrap();
        });
        let config = AnthropicProviderConfig::new_with_transport_policy(
            Url::parse(&format!("http://{address}/v1/messages")).unwrap(),
            "claude-sonnet-4-5".to_owned(),
            AnthropicApiKey::from_bytes(b"anthropic-test-key".to_vec()).unwrap(),
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap(),
            Some(Duration::from_secs(1)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert!(!format!("{config:?}").contains("anthropic-test-key"));
        let adapter = AnthropicProvider::new(
            config,
            SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
        );
        let mut session = adapter
            .start(ProviderRequest {
                route: openbot_application::ProviderRoute::Managed,
                messages: vec![openbot_application::ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "hello".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                }],
                tools: Vec::new(),
                max_output_tokens: Some(16),
                rate_card: None,
                cost_cap: None,
            })
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Some(event) = session.next_event().await.unwrap() {
            events.push(event);
        }
        assert!(matches!(
            events.first(),
            Some(ProviderEvent::ResponseStarted { response_id }) if response_id == "msg_local"
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::TextDelta { delta, .. } if delta == "hello"
        )));
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
        server.await.unwrap();
    }

    #[test]
    fn status_and_in_stream_errors_normalize_without_vendor_text() {
        assert_eq!(
            status_failure(StatusCode::TOO_MANY_REQUESTS, Some(Duration::from_secs(2))),
            Some(ProviderFailure::RateLimited {
                retry_after: Some(Duration::from_secs(2))
            })
        );
        let mut decoder = AnthropicDecoder::default();
        assert_eq!(
            decoder
                .ingest(r#"{"type":"error","error":{"type":"overloaded_error","message":"secret vendor text"}}"#)
                .unwrap(),
            [ProviderEvent::Failed(ProviderFailure::ServerUnavailable {
                retry_after: None
            })]
        );
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        let header_end;
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = position + 4;
                break;
            }
        }
        let headers = core::str::from_utf8(&bytes[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap();
        while bytes.len() < header_end + content_length {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(bytes).unwrap()
    }
}
