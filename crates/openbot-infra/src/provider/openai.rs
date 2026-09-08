//! OpenAI-compatible Responses / Chat Completions streaming adapter（v3 §7.3）。
//!
//! Wire schema 依据 OpenAI 官方 streaming events reference；vendor JSON 在本模块终止，输出只剩
//! `openbot_application::ProviderEvent`。

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
use serde_json::{Map, Value, json};
use url::Url;
use zeroize::Zeroizing;

use super::common::{
    ImmediateSession, MAX_PROVIDER_FIELD_BYTES, map_start_error, response_retry_after,
    validate_request,
};
use super::sse::SseDecoder;
use crate::net::safe_http::{
    AuthorizationValue, SafeDialer, SafeHttpBudget, SafeHttpError, SafeHttpRequest,
    SafeHttpStreamResponse, SchemePolicy,
};

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";

/// OpenAI-compatible wire protocol。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAiProtocol {
    /// `/v1/responses` typed streaming events。
    Responses,
    /// `/v1/chat/completions` chunk stream。
    ChatCompletions,
}

/// API key secret；不可 Clone/Serialize，Debug 恒脱敏。
pub struct OpenAiApiKey(SecretBytes);

impl OpenAiApiKey {
    /// UTF-8、非空、无 CR/LF/NUL。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProviderPortError> {
        Self::from_secret(SecretBytes::new(bytes))
    }

    pub(crate) fn from_secret(secret: SecretBytes) -> Result<Self, ProviderPortError> {
        let bytes = secret.expose();
        let valid = !bytes.is_empty()
            && bytes.len() <= 16 * 1024
            && !bytes.iter().any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
            && core::str::from_utf8(bytes).is_ok();
        if !valid {
            return Err(ProviderPortError::InvalidRequest { field: "api_key" });
        }
        Ok(Self(secret))
    }
}

impl core::fmt::Debug for OpenAiApiKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpenAiApiKey([redacted])")
    }
}

/// Verified provider config；endpoint 是 exact API URL，不在 adapter 内猜 path。
pub struct OpenAiProviderConfig {
    endpoint: Url,
    model: String,
    protocol: OpenAiProtocol,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    scheme_policy: SchemePolicy,
}

impl OpenAiProviderConfig {
    /// Production config：HTTPS only。
    pub fn new(
        endpoint: Url,
        model: String,
        protocol: OpenAiProtocol,
        connect_budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
    ) -> Result<Self, ProviderPortError> {
        Self::new_with_transport_policy(
            endpoint,
            model,
            protocol,
            connect_budget,
            stall_timeout,
            SchemePolicy::HttpsOnly,
        )
    }

    /// Admin-verified transport override for self-hosted endpoints；HTTP still passes SafeDialer CIDR.
    pub fn new_with_transport_policy(
        endpoint: Url,
        model: String,
        protocol: OpenAiProtocol,
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
            || endpoint.fragment().is_some()
        {
            return Err(ProviderPortError::InvalidRequest {
                field: "provider_config",
            });
        }
        Ok(Self {
            endpoint,
            model,
            protocol,
            connect_budget,
            stall_timeout,
            scheme_policy,
        })
    }
}

/// Fresh credential resolution failure；secret/source identity 不跨边界。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiCredentialError {
    /// No active stored credential and no environment fallback。
    #[error("openai_credential_missing")]
    Missing,
    /// PostgreSQL/vault dependency temporarily unavailable。
    #[error("openai_credential_unavailable")]
    Unavailable,
    /// Stored credential binding/ciphertext/value invalid；never falls back。
    #[error("openai_credential_corrupt")]
    Corrupt,
}

/// 每次 sampling 重新解析 credential；支持即时 revoke/rotation，且 secret 不进入 application。
#[async_trait]
pub trait OpenAiCredentialSource: Send + Sync {
    /// Resolve one owned, zeroizing API key。
    async fn resolve(&self) -> Result<OpenAiApiKey, OpenAiCredentialError>;
}

#[async_trait]
impl OpenAiCredentialSource for OpenAiApiKey {
    async fn resolve(&self) -> Result<OpenAiApiKey, OpenAiCredentialError> {
        OpenAiApiKey::from_bytes(self.0.expose().to_vec())
            .map_err(|_| OpenAiCredentialError::Corrupt)
    }
}

impl core::fmt::Debug for OpenAiProviderConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenAiProviderConfig")
            .field("origin", &self.endpoint.origin().ascii_serialization())
            .field("protocol", &self.protocol)
            .field("model", &self.model)
            .field("has_stall_timeout", &self.stall_timeout.is_some())
            .finish_non_exhaustive()
    }
}

/// Production OpenAI-compatible adapter。
pub struct OpenAiProvider {
    config: OpenAiProviderConfig,
    credentials: std::sync::Arc<dyn OpenAiCredentialSource>,
    dialer: SafeDialer,
}

impl OpenAiProvider {
    /// 用唯一 safe dialer 构造。
    #[must_use]
    pub fn new(config: OpenAiProviderConfig, api_key: OpenAiApiKey, dialer: SafeDialer) -> Self {
        Self::new_with_credential_source(config, std::sync::Arc::new(api_key), dialer)
    }

    /// 用 fresh credential resolver 与唯一 safe dialer 构造。
    #[must_use]
    pub const fn new_with_credential_source(
        config: OpenAiProviderConfig,
        credentials: std::sync::Arc<dyn OpenAiCredentialSource>,
        dialer: SafeDialer,
    ) -> Self {
        Self {
            config,
            credentials,
            dialer,
        }
    }
}

impl core::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenAiProvider")
            .field("config", &self.config)
            .field("credentials", &"fresh/[redacted]")
            .field("dialer", &self.dialer)
            .finish()
    }
}

#[async_trait]
impl ProviderAdapter for OpenAiProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        validate_request(&request)?;
        let body = build_request_body(self.config.protocol, &self.config.model, &request)?;
        let api_key = match self.credentials.resolve().await {
            Ok(value) => value,
            Err(OpenAiCredentialError::Missing | OpenAiCredentialError::Corrupt) => {
                return Ok(Box::new(ImmediateSession::new(ProviderEvent::Failed(
                    ProviderFailure::Authentication,
                ))));
            }
            Err(OpenAiCredentialError::Unavailable) => {
                return Ok(Box::new(ImmediateSession::new(ProviderEvent::Failed(
                    ProviderFailure::Transport,
                ))));
            }
        };
        let mut bearer = Zeroizing::new(String::from("Bearer "));
        bearer.push_str(
            core::str::from_utf8(api_key.0.expose())
                .map_err(|_| ProviderPortError::InvalidRequest { field: "api_key" })?,
        );
        let authorization = AuthorizationValue::parse(&bearer)
            .map_err(|_| ProviderPortError::InvalidRequest { field: "api_key" })?;
        let request = SafeHttpRequest::post_json_with_scheme(
            self.config.endpoint.clone(),
            self.config.scheme_policy,
            body,
            Some(authorization),
            self.config.connect_budget,
        )
        .map_err(|_| ProviderPortError::InvalidRequest {
            field: "provider_request",
        })?;
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
        Ok(Box::new(OpenAiSession {
            response,
            sse: SseDecoder::default(),
            decoder: Decoder::new(self.config.protocol),
            pending: VecDeque::new(),
            stall_timeout: self.config.stall_timeout,
            ended: false,
        }))
    }
}

fn build_request_body(
    protocol: OpenAiProtocol,
    model: &str,
    request: &ProviderRequest,
) -> Result<Vec<u8>, ProviderPortError> {
    let value = match protocol {
        OpenAiProtocol::Responses => {
            let mut input = Vec::new();
            for message in &request.messages {
                match message.role {
                    ProviderMessageRole::Tool => input.push(json!({
                        "type":"function_call_output",
                        "call_id":message.tool_call_id,
                        "output":message.content,
                    })),
                    ProviderMessageRole::Assistant => {
                        if !message.content.is_empty() {
                            input.push(json!({
                                "role":"assistant",
                                "content":message.content,
                            }));
                        }
                        for call in &message.tool_calls {
                            let arguments =
                                serde_json::to_string(&call.arguments).map_err(|_| {
                                    ProviderPortError::InvalidRequest {
                                        field: "provider_tool_call",
                                    }
                                })?;
                            input.push(json!({
                                "type":"function_call",
                                "call_id":call.call_id,
                                "name":call.name,
                                "arguments":arguments,
                            }));
                        }
                    }
                    role => input.push(json!({
                        "role":role_literal(role),
                        "content":message.content,
                    })),
                }
            }
            let tools = request
                .tools
                .iter()
                .map(|tool| {
                    json!({
                        "type":"function",
                        "name":tool.name,
                        "description":tool.description,
                        "parameters":tool.input_schema,
                        "strict":true,
                    })
                })
                .collect::<Vec<_>>();
            let mut body = json!({"model":model,"input":input,"stream":true});
            if !tools.is_empty() {
                body["tools"] = Value::Array(tools);
            }
            if let Some(limit) = request.max_output_tokens {
                body["max_output_tokens"] = json!(limit);
            }
            body
        }
        OpenAiProtocol::ChatCompletions => {
            let messages = request
                .messages
                .iter()
                .map(|message| {
                    let mut value = json!({
                        "role":role_literal(message.role),
                        "content":message.content,
                    });
                    if let Some(call_id) = &message.tool_call_id {
                        value["tool_call_id"] = json!(call_id);
                    }
                    if !message.tool_calls.is_empty() {
                        value["tool_calls"] = Value::Array(
                            message
                                .tool_calls
                                .iter()
                                .map(|call| {
                                    Ok(json!({
                                        "id":call.call_id,
                                        "type":"function",
                                        "function":{
                                            "name":call.name,
                                            "arguments":serde_json::to_string(&call.arguments)
                                                .map_err(|_| ProviderPortError::InvalidRequest {
                                                    field: "provider_tool_call",
                                                })?,
                                        }
                                    }))
                                })
                                .collect::<Result<Vec<_>, ProviderPortError>>()?,
                        );
                    }
                    Ok(value)
                })
                .collect::<Result<Vec<_>, ProviderPortError>>()?;
            let tools = request
                .tools
                .iter()
                .map(|tool| {
                    json!({
                        "type":"function",
                        "function":{
                            "name":tool.name,
                            "description":tool.description,
                            "parameters":tool.input_schema,
                            "strict":true,
                        }
                    })
                })
                .collect::<Vec<_>>();
            let mut body = json!({
                "model":model,
                "messages":messages,
                "stream":true,
                "stream_options":{"include_usage":true},
            });
            if !tools.is_empty() {
                body["tools"] = Value::Array(tools);
            }
            if let Some(limit) = request.max_output_tokens {
                body["max_tokens"] = json!(limit);
            }
            body
        }
    };
    serde_json::to_vec(&value).map_err(|_| ProviderPortError::InvalidRequest {
        field: "provider_request",
    })
}

const fn role_literal(role: ProviderMessageRole) -> &'static str {
    match role {
        ProviderMessageRole::System => "system",
        ProviderMessageRole::User => "user",
        ProviderMessageRole::Assistant => "assistant",
        ProviderMessageRole::Tool => "tool",
    }
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

struct OpenAiSession {
    response: SafeHttpStreamResponse,
    sse: SseDecoder,
    decoder: Decoder,
    pending: VecDeque<ProviderEvent>,
    stall_timeout: Option<Duration>,
    ended: bool,
}

#[async_trait]
impl ProviderSession for OpenAiSession {
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

impl OpenAiSession {
    fn fail(&mut self, failure: ProviderFailure) {
        self.pending.clear();
        self.pending.push_back(ProviderEvent::Failed(failure));
        self.ended = true;
    }
}

enum Decoder {
    Responses(ResponsesDecoder),
    Chat(ChatDecoder),
}

impl Decoder {
    fn new(protocol: OpenAiProtocol) -> Self {
        match protocol {
            OpenAiProtocol::Responses => Self::Responses(ResponsesDecoder::default()),
            OpenAiProtocol::ChatCompletions => Self::Chat(ChatDecoder::default()),
        }
    }

    fn ingest(&mut self, data: &str) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        match self {
            Self::Responses(decoder) => decoder.ingest(data),
            Self::Chat(decoder) => decoder.ingest(data),
        }
    }

    fn finish(&mut self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        match self {
            Self::Responses(decoder) => decoder.finish(),
            Self::Chat(decoder) => decoder.finish(),
        }
    }
}

#[derive(Default)]
struct ResponsesDecoder {
    last_sequence: Option<u64>,
    terminal: bool,
    tools: BTreeMap<String, ToolAccumulator>,
}

impl ResponsesDecoder {
    fn ingest(&mut self, data: &str) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            return Err(ProviderFailure::InvalidResponse);
        }
        if data == "[DONE]" {
            return Err(ProviderFailure::InvalidResponse);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProviderFailure::InvalidResponse)?;
        let event_type = string_field(&value, "type")?;
        if is_known_response_event(event_type) {
            let sequence = u64_field(&value, "sequence_number")?;
            if self.last_sequence.is_some_and(|last| sequence <= last) {
                return Err(ProviderFailure::InvalidResponse);
            }
            self.last_sequence = Some(sequence);
        } else if let Some(sequence) = value.get("sequence_number").and_then(Value::as_u64) {
            if self.last_sequence.is_some_and(|last| sequence <= last) {
                return Err(ProviderFailure::InvalidResponse);
            }
            self.last_sequence = Some(sequence);
        }
        let mut output = Vec::new();
        match event_type {
            "response.created" => {
                let response = object_field(&value, "response")?;
                output.push(ProviderEvent::ResponseStarted {
                    response_id: string_field(response, "id")?.to_owned(),
                });
            }
            "response.output_item.added" => {
                let index = u32_field(&value, "output_index")?;
                let item = object_field(&value, "item")?;
                match string_field(item, "type")? {
                    "message" => output.push(ProviderEvent::OutputItemAdded {
                        index,
                        kind: ProviderOutputKind::Message,
                    }),
                    "reasoning" => output.push(ProviderEvent::OutputItemAdded {
                        index,
                        kind: ProviderOutputKind::Reasoning,
                    }),
                    "function_call" => {
                        let item_id = string_field(item, "id")?.to_owned();
                        let call_id = string_field(item, "call_id")?.to_owned();
                        let name = optional_nonempty_string(item, "name")?;
                        if self
                            .tools
                            .insert(
                                item_id,
                                ToolAccumulator::new(index, call_id.clone(), name.clone()),
                            )
                            .is_some()
                        {
                            return Err(ProviderFailure::InvalidResponse);
                        }
                        output.push(ProviderEvent::OutputItemAdded {
                            index,
                            kind: ProviderOutputKind::FunctionCall,
                        });
                        output.push(ProviderEvent::ToolCallStarted {
                            index,
                            call_id,
                            name,
                        });
                    }
                    _ => output.push(ProviderEvent::OutputItemAdded {
                        index,
                        kind: ProviderOutputKind::Extension,
                    }),
                }
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                let delta = string_field_allow_empty(&value, "delta")?;
                if !delta.is_empty() {
                    output.push(ProviderEvent::TextDelta {
                        index: u32_field(&value, "output_index")?,
                        delta: delta.to_owned(),
                    });
                }
            }
            "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => {
                let delta = string_field_allow_empty(&value, "delta")?;
                if !delta.is_empty() {
                    output.push(ProviderEvent::ReasoningDelta {
                        index: u32_field(&value, "output_index")?,
                        delta: delta.to_owned(),
                    });
                }
            }
            "response.function_call_arguments.delta" => {
                let item_id = string_field(&value, "item_id")?;
                let delta = string_field_allow_empty(&value, "delta")?;
                let tool = self
                    .tools
                    .get_mut(item_id)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                if tool.index != u32_field(&value, "output_index")? {
                    return Err(ProviderFailure::InvalidResponse);
                }
                if delta.len() > MAX_PROVIDER_FIELD_BYTES.saturating_sub(tool.arguments.len()) {
                    return Err(ProviderFailure::InvalidResponse);
                }
                tool.arguments.push_str(delta);
                if !delta.is_empty() {
                    output.push(ProviderEvent::ToolArgumentsDelta {
                        index: tool.index,
                        call_id: tool.call_id.clone(),
                        delta: delta.to_owned(),
                    });
                }
            }
            "response.function_call_arguments.done" => {
                let item_id = string_field(&value, "item_id")?;
                let name = match value.get("name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(name))
                        if !name.is_empty() && name.len() <= MAX_PROVIDER_FIELD_BYTES =>
                    {
                        Some(name.as_str())
                    }
                    _ => return Err(ProviderFailure::InvalidResponse),
                };
                let arguments = string_field(&value, "arguments")?;
                let tool = self
                    .tools
                    .remove(item_id)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                if value.get("output_index").is_some()
                    && u32_field(&value, "output_index")? != tool.index
                {
                    return Err(ProviderFailure::InvalidResponse);
                }
                output.push(tool.complete(name, arguments)?);
            }
            "response.completed" => {
                if !self.tools.is_empty() {
                    return Err(ProviderFailure::InvalidResponse);
                }
                let response = object_field(&value, "response")?;
                let usage =
                    parse_usage(response.get("usage"))?.ok_or(ProviderFailure::InvalidResponse)?;
                output.push(ProviderEvent::Usage(usage));
                output.push(ProviderEvent::Completed);
                self.terminal = true;
            }
            "response.failed" | "response.incomplete" | "error" => {
                output.push(ProviderEvent::Failed(ProviderFailure::GenerationFailed));
                self.terminal = true;
            }
            _ => {}
        }
        Ok(output)
    }

    fn finish(&self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            Ok(Vec::new())
        } else {
            Err(ProviderFailure::InvalidResponse)
        }
    }
}

#[derive(Default)]
struct ChatDecoder {
    response_id: Option<String>,
    tools: BTreeMap<(u32, u32), ChatToolAccumulator>,
    finish_seen: bool,
    usage_seen: bool,
    terminal: bool,
}

impl ChatDecoder {
    fn ingest(&mut self, data: &str) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            return Err(ProviderFailure::InvalidResponse);
        }
        if data == "[DONE]" {
            return self.complete_stream();
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProviderFailure::InvalidResponse)?;
        if value.get("error").is_some() {
            self.terminal = true;
            return Ok(vec![ProviderEvent::Failed(
                ProviderFailure::GenerationFailed,
            )]);
        }
        let id = string_field(&value, "id")?;
        let mut output = Vec::new();
        match &self.response_id {
            Some(existing) if existing != id => return Err(ProviderFailure::InvalidResponse),
            Some(_) => {}
            None => {
                self.response_id = Some(id.to_owned());
                output.push(ProviderEvent::ResponseStarted {
                    response_id: id.to_owned(),
                });
            }
        }
        if let Some(usage) = parse_usage(value.get("usage"))? {
            if self.usage_seen {
                return Err(ProviderFailure::InvalidResponse);
            }
            self.usage_seen = true;
            output.push(ProviderEvent::Usage(usage));
        }
        let choices = value
            .get("choices")
            .and_then(Value::as_array)
            .ok_or(ProviderFailure::InvalidResponse)?;
        for choice in choices {
            let choice_index = u32_field(choice, "index")?;
            let delta = object_field(choice, "delta")?;
            if let Some(content) = optional_bounded_string(delta, "content")?
                && !content.is_empty()
            {
                output.push(ProviderEvent::TextDelta {
                    index: choice_index,
                    delta: content.to_owned(),
                });
            }
            if let Some(reasoning) = optional_bounded_string(delta, "reasoning_content")?
                && !reasoning.is_empty()
            {
                output.push(ProviderEvent::ReasoningDelta {
                    index: choice_index,
                    delta: reasoning.to_owned(),
                });
            }
            if let Some(calls) = optional_array(delta, "tool_calls")? {
                for call in calls {
                    let tool_index = u32_field(call, "index")?;
                    let key = (choice_index, tool_index);
                    let tool = self.tools.entry(key).or_insert_with(|| {
                        output.push(ProviderEvent::OutputItemAdded {
                            index: tool_index,
                            kind: ProviderOutputKind::FunctionCall,
                        });
                        ChatToolAccumulator::new(tool_index)
                    });
                    let id = optional_nonempty_string(call, "id")?;
                    let function = match call.get("function") {
                        None | Some(Value::Null) => None,
                        Some(Value::Object(value)) => Some(value),
                        _ => return Err(ProviderFailure::InvalidResponse),
                    };
                    let name = match function {
                        Some(value) => optional_nonempty_string_map(value, "name")?,
                        None => None,
                    };
                    let arguments = function
                        .map(|value| optional_bounded_string_map(value, "arguments"))
                        .transpose()?
                        .flatten()
                        .unwrap_or_default();
                    output.extend(tool.push(id, name, arguments)?);
                }
            }
            match choice.get("finish_reason") {
                None | Some(Value::Null) => {}
                Some(Value::String(reason)) => match reason.as_str() {
                    "stop" | "tool_calls" => self.finish_seen = true,
                    "length" | "content_filter" => {
                        self.terminal = true;
                        output.push(ProviderEvent::Failed(ProviderFailure::GenerationFailed));
                    }
                    _ => return Err(ProviderFailure::InvalidResponse),
                },
                _ => return Err(ProviderFailure::InvalidResponse),
            }
        }
        Ok(output)
    }

    fn finish(&mut self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            Ok(Vec::new())
        } else {
            self.complete_stream()
        }
    }

    fn complete_stream(&mut self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if !self.finish_seen || !self.usage_seen || self.response_id.is_none() {
            return Err(ProviderFailure::InvalidResponse);
        }
        let mut output = Vec::new();
        for (_, tool) in core::mem::take(&mut self.tools) {
            output.push(tool.complete()?);
        }
        output.push(ProviderEvent::Completed);
        self.terminal = true;
        Ok(output)
    }
}

struct ToolAccumulator {
    index: u32,
    call_id: String,
    name: Option<String>,
    arguments: String,
}

impl ToolAccumulator {
    const fn new(index: u32, call_id: String, name: Option<String>) -> Self {
        Self {
            index,
            call_id,
            name,
            arguments: String::new(),
        }
    }

    fn complete(
        self,
        completed_name: Option<&str>,
        arguments: &str,
    ) -> Result<ProviderEvent, ProviderFailure> {
        let name = match (self.name.as_deref(), completed_name) {
            (Some(known), Some(completed)) if known != completed => {
                return Err(ProviderFailure::InvalidResponse);
            }
            (Some(known), _) => known,
            (None, Some(completed)) => completed,
            (None, None) => return Err(ProviderFailure::InvalidResponse),
        };
        if !self.arguments.is_empty() && self.arguments != arguments {
            return Err(ProviderFailure::InvalidResponse);
        }
        let arguments: Value =
            serde_json::from_str(arguments).map_err(|_| ProviderFailure::InvalidResponse)?;
        if !arguments.is_object() {
            return Err(ProviderFailure::InvalidResponse);
        }
        Ok(ProviderEvent::ToolCallCompleted {
            index: self.index,
            call_id: self.call_id,
            name: name.to_owned(),
            arguments,
        })
    }
}

struct ChatToolAccumulator {
    index: u32,
    call_id: Option<String>,
    name: Option<String>,
    arguments: String,
    emitted_arguments: usize,
    started: bool,
}

impl ChatToolAccumulator {
    const fn new(index: u32) -> Self {
        Self {
            index,
            call_id: None,
            name: None,
            arguments: String::new(),
            emitted_arguments: 0,
            started: false,
        }
    }

    fn push(
        &mut self,
        call_id: Option<String>,
        name: Option<String>,
        arguments: &str,
    ) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if let Some(call_id) = call_id {
            match &self.call_id {
                Some(existing) if existing != &call_id => {
                    return Err(ProviderFailure::InvalidResponse);
                }
                Some(_) => {}
                None => self.call_id = Some(call_id),
            }
        }
        if let Some(name) = name {
            match &self.name {
                Some(existing) if existing != &name => {
                    return Err(ProviderFailure::InvalidResponse);
                }
                Some(_) => {}
                None => self.name = Some(name),
            }
        }
        if arguments.len() > MAX_PROVIDER_FIELD_BYTES.saturating_sub(self.arguments.len()) {
            return Err(ProviderFailure::InvalidResponse);
        }
        self.arguments.push_str(arguments);
        let mut output = Vec::new();
        if !self.started
            && let Some(call_id) = &self.call_id
        {
            output.push(ProviderEvent::ToolCallStarted {
                index: self.index,
                call_id: call_id.clone(),
                name: self.name.clone(),
            });
            self.started = true;
        }
        if self.started && self.emitted_arguments < self.arguments.len() {
            let delta = self.arguments[self.emitted_arguments..].to_owned();
            self.emitted_arguments = self.arguments.len();
            output.push(ProviderEvent::ToolArgumentsDelta {
                index: self.index,
                call_id: self.call_id.clone().expect("started requires id"),
                delta,
            });
        }
        Ok(output)
    }

    fn complete(self) -> Result<ProviderEvent, ProviderFailure> {
        let call_id = self.call_id.ok_or(ProviderFailure::InvalidResponse)?;
        let name = self.name.ok_or(ProviderFailure::InvalidResponse)?;
        let arguments: Value =
            serde_json::from_str(&self.arguments).map_err(|_| ProviderFailure::InvalidResponse)?;
        if !arguments.is_object() {
            return Err(ProviderFailure::InvalidResponse);
        }
        Ok(ProviderEvent::ToolCallCompleted {
            index: self.index,
            call_id,
            name,
            arguments,
        })
    }
}

fn is_known_response_event(value: &str) -> bool {
    matches!(
        value,
        "response.created"
            | "response.output_item.added"
            | "response.output_text.delta"
            | "response.refusal.delta"
            | "response.reasoning_text.delta"
            | "response.reasoning_summary_text.delta"
            | "response.function_call_arguments.delta"
            | "response.function_call_arguments.done"
            | "response.completed"
            | "response.failed"
            | "response.incomplete"
            | "error"
    )
}

fn parse_usage(value: Option<&Value>) -> Result<Option<ProviderUsage>, ProviderFailure> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let input = value
        .get("input_tokens")
        .or_else(|| value.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .ok_or(ProviderFailure::InvalidResponse)?;
    let output = value
        .get("output_tokens")
        .or_else(|| value.get("completion_tokens"))
        .and_then(Value::as_u64)
        .ok_or(ProviderFailure::InvalidResponse)?;
    let known = input
        .checked_add(output)
        .ok_or(ProviderFailure::InvalidResponse)?;
    let total = value
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(known);
    if total < known {
        return Err(ProviderFailure::InvalidResponse);
    }
    Ok(Some(ProviderUsage {
        input_tokens: input,
        output_tokens: output,
        total_tokens: total,
    }))
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

fn string_field_allow_empty<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_PROVIDER_FIELD_BYTES)
        .ok_or(ProviderFailure::InvalidResponse)
}

fn optional_bounded_string<'a>(
    value: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, ProviderFailure> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_PROVIDER_FIELD_BYTES => {
            Ok(Some(value.as_str()))
        }
        _ => Err(ProviderFailure::InvalidResponse),
    }
}

fn optional_bounded_string_map<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, ProviderFailure> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_PROVIDER_FIELD_BYTES => {
            Ok(Some(value.as_str()))
        }
        _ => Err(ProviderFailure::InvalidResponse),
    }
}

fn optional_array<'a>(
    value: &'a Value,
    field: &str,
) -> Result<Option<&'a [Value]>, ProviderFailure> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(value)) => Ok(Some(value.as_slice())),
        _ => Err(ProviderFailure::InvalidResponse),
    }
}

fn optional_nonempty_string(value: &Value, field: &str) -> Result<Option<String>, ProviderFailure> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_PROVIDER_FIELD_BYTES => {
            Ok(Some(value.clone()))
        }
        _ => Err(ProviderFailure::InvalidResponse),
    }
}

fn optional_nonempty_string_map(
    value: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ProviderFailure> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_PROVIDER_FIELD_BYTES => {
            Ok(Some(value.clone()))
        }
        _ => Err(ProviderFailure::InvalidResponse),
    }
}

fn u64_field(value: &Value, field: &str) -> Result<u64, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ProviderFailure::InvalidResponse)
}

fn u32_field(value: &Value, field: &str) -> Result<u32, ProviderFailure> {
    u32::try_from(u64_field(value, field)?).map_err(|_| ProviderFailure::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::net::safe_http::{CidrAllowlist, EgressPolicy};

    #[test]
    fn responses_accepts_skeleton_partial_json_reasoning_and_unknown_extensions() {
        let mut decoder = ResponsesDecoder::default();
        let mut events = Vec::new();
        for data in [
            r#"{"type":"response.created","response":{"id":"resp_1"},"sequence_number":0}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message"},"sequence_number":1}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"delta":"hello","sequence_number":2}"#,
            r#"{"type":"response.reasoning_text.delta","output_index":1,"delta":"think","sequence_number":3}"#,
            r#"{"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"item_1","call_id":"call_1","name":null},"sequence_number":4}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":2,"item_id":"item_1","delta":"{\"city\":","sequence_number":5}"#,
            r#"{"type":"response.extension.future","sequence_number":6,"opaque":true}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":2,"item_id":"item_1","delta":"\"Paris\"}","sequence_number":7}"#,
            r#"{"type":"response.function_call_arguments.done","item_id":"item_1","name":"weather","arguments":"{\"city\":\"Paris\"}","sequence_number":8}"#,
            r#"{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}},"sequence_number":9}"#,
        ] {
            events.extend(decoder.ingest(data).unwrap());
        }
        assert!(matches!(events[0], ProviderEvent::ResponseStarted { .. }));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::ToolCallCompleted { name, arguments, .. }
                if name == "weather" && arguments == &json!({"city":"Paris"})
        )));
        assert_eq!(
            events[events.len() - 2],
            ProviderEvent::Usage(ProviderUsage {
                input_tokens: 3,
                output_tokens: 4,
                total_tokens: 7,
            })
        );
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
        assert_eq!(decoder.finish(), Ok(Vec::new()));
    }

    #[test]
    fn responses_rejects_sequence_regression_and_partial_argument_mismatch() {
        let mut decoder = ResponsesDecoder::default();
        decoder
            .ingest(r#"{"type":"response.created","response":{"id":"r"},"sequence_number":2}"#)
            .unwrap();
        assert_eq!(
            decoder.ingest(r#"{"type":"response.output_text.delta","output_index":0,"delta":"x","sequence_number":2}"#),
            Err(ProviderFailure::InvalidResponse)
        );

        let mut decoder = ResponsesDecoder::default();
        for data in [
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"item","call_id":"call","name":"tool"},"sequence_number":0}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"item","delta":"{","sequence_number":1}"#,
        ] {
            decoder.ingest(data).unwrap();
        }
        assert_eq!(
            decoder.ingest(r#"{"type":"response.function_call_arguments.done","item_id":"item","name":"tool","arguments":"{}","sequence_number":2}"#),
            Err(ProviderFailure::InvalidResponse)
        );
    }

    #[test]
    fn responses_function_call_done_rejects_identity_drift_or_missing_name() {
        let added_with_name = r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"item","call_id":"call","name":"tool"},"sequence_number":0}"#;

        let mut renamed = ResponsesDecoder::default();
        renamed.ingest(added_with_name).unwrap();
        assert_eq!(
            renamed.ingest(r#"{"type":"response.function_call_arguments.done","item_id":"item","name":"other","arguments":"{}","sequence_number":1}"#),
            Err(ProviderFailure::InvalidResponse)
        );

        let mut reindexed = ResponsesDecoder::default();
        reindexed.ingest(added_with_name).unwrap();
        assert_eq!(
            reindexed.ingest(r#"{"type":"response.function_call_arguments.done","item_id":"item","output_index":1,"arguments":"{}","sequence_number":1}"#),
            Err(ProviderFailure::InvalidResponse)
        );

        let mut unnamed = ResponsesDecoder::default();
        unnamed
            .ingest(r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"item","call_id":"call","name":null},"sequence_number":0}"#)
            .unwrap();
        assert_eq!(
            unnamed.ingest(r#"{"type":"response.function_call_arguments.done","item_id":"item","arguments":"{}","sequence_number":1}"#),
            Err(ProviderFailure::InvalidResponse)
        );
    }

    #[test]
    fn empty_deltas_are_noops_but_malformed_or_oversized_fields_fail_closed() {
        let mut responses = ResponsesDecoder::default();
        assert!(
            responses
                .ingest(
                    r#"{"type":"response.output_text.delta","output_index":0,"delta":"","sequence_number":0}"#
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            responses.ingest(
                r#"{"type":"response.output_text.delta","output_index":0,"delta":7,"sequence_number":1}"#
            ),
            Err(ProviderFailure::InvalidResponse)
        );

        let mut chat = ChatDecoder::default();
        assert_eq!(
            chat.ingest(r#"{"id":"chat","choices":[{"index":0,"delta":{"content":7},"finish_reason":null}]}"#),
            Err(ProviderFailure::InvalidResponse)
        );
        let mut tool = ChatToolAccumulator::new(0);
        tool.push(
            Some("call".to_owned()),
            Some("tool".to_owned()),
            &"x".repeat(MAX_PROVIDER_FIELD_BYTES),
        )
        .unwrap();
        assert_eq!(
            tool.push(None, None, "x"),
            Err(ProviderFailure::InvalidResponse)
        );
    }

    #[test]
    fn chat_interleaved_tool_chunks_wait_for_done_and_preserve_call_order() {
        let mut decoder = ChatDecoder::default();
        let mut events = Vec::new();
        for data in [
            r#"{"id":"chat_1","choices":[{"index":0,"delta":{"content":"hi","tool_calls":[{"index":0,"id":"call_a","function":{"name":"alpha","arguments":"{\"x\":"}},{"index":1,"id":"call_b","function":{"name":"beta","arguments":"{\"y\":"}}]},"finish_reason":null}]}"#,
            r#"{"id":"chat_1","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}},{"index":0,"function":{"arguments":"1}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}"#,
            "[DONE]",
        ] {
            events.extend(decoder.ingest(data).unwrap());
        }
        let completed = events
            .iter()
            .filter_map(|event| match event {
                ProviderEvent::ToolCallCompleted { call_id, .. } => Some(call_id.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(completed, ["call_a", "call_b"]);
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
    }

    #[test]
    fn request_shapes_keep_responses_and_chat_distinct() {
        let request = ProviderRequest {
            route: openbot_application::ProviderRoute::PackageOpenAi,
            messages: vec![
                openbot_application::ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "hello".to_owned(),
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
            tools: Vec::new(),
            max_output_tokens: Some(32),
            rate_card: None,
            cost_cap: None,
        };
        let responses: Value = serde_json::from_slice(
            &build_request_body(OpenAiProtocol::Responses, "model", &request).unwrap(),
        )
        .unwrap();
        let chat: Value = serde_json::from_slice(
            &build_request_body(OpenAiProtocol::ChatCompletions, "model", &request).unwrap(),
        )
        .unwrap();
        assert!(responses.get("input").is_some());
        assert_eq!(responses["input"][1]["type"], "function_call");
        assert_eq!(responses["input"][2]["type"], "function_call_output");
        assert_eq!(responses["max_output_tokens"], 32);
        assert!(chat.get("messages").is_some());
        assert_eq!(chat["messages"][1]["tool_calls"][0]["id"], "call-1");
        assert_eq!(chat["messages"][2]["tool_call_id"], "call-1");
        assert_eq!(chat["max_tokens"], 32);
        assert_eq!(responses["stream"], true);
        assert_eq!(chat["stream_options"]["include_usage"], true);
    }

    #[tokio::test]
    async fn adapter_posts_through_safe_dialer_and_streams_normalized_events() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let lower = request.to_ascii_lowercase();
            assert!(lower.starts_with("post /v1/responses "));
            assert!(lower.contains("authorization: bearer test-provider-key"));
            let body = request.split("\r\n\r\n").nth(1).unwrap();
            let body: Value = serde_json::from_str(body).unwrap();
            assert_eq!(body["model"], "model-test");
            assert_eq!(body["stream"], true);
            let sse = concat!(
                "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_local\"},\"sequence_number\":0}\n\n",
                "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"hello\",\"sequence_number\":1}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}},\"sequence_number\":2}\n\n",
            );
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                sse.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            for chunk in sse.as_bytes().chunks(3) {
                stream.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let config = OpenAiProviderConfig::new_with_transport_policy(
            Url::parse(&format!("http://{address}/v1/responses")).unwrap(),
            "model-test".to_owned(),
            OpenAiProtocol::Responses,
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap(),
            Some(Duration::from_secs(1)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert!(!format!("{config:?}").contains("test-provider-key"));
        let policy = EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap());
        let adapter = OpenAiProvider::new(
            config,
            OpenAiApiKey::from_bytes(b"test-provider-key".to_vec()).unwrap(),
            SafeDialer::new(policy),
        );
        let mut session = adapter
            .start(ProviderRequest {
                route: openbot_application::ProviderRoute::PackageOpenAi,
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
            Some(ProviderEvent::ResponseStarted { response_id }) if response_id == "resp_local"
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::TextDelta { delta, .. } if delta == "hello"
        )));
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
        server.await.unwrap();
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
