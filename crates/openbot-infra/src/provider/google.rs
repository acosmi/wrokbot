//! Google Generative AI `streamGenerateContent` SSE adapter（v3 §7.3）。

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
use sha2::{Digest as _, Sha256};
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
const TEXT_OUTPUT_INDEX: u32 = 0;
const REASONING_OUTPUT_INDEX: u32 = 1;

/// Google API key；不可 Clone/Serialize，Debug 恒脱敏。
pub struct GoogleApiKey(SecretBytes);

impl GoogleApiKey {
    /// UTF-8、非空、无 CR/LF/NUL。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProviderPortError> {
        let secret = SecretBytes::new(bytes);
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

impl core::fmt::Debug for GoogleApiKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GoogleApiKey([redacted])")
    }
}

/// Verified exact stream endpoint/model/budget config。
pub struct GoogleProviderConfig {
    endpoint: Url,
    model: String,
    api_key: GoogleApiKey,
    connect_budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    scheme_policy: SchemePolicy,
}

impl GoogleProviderConfig {
    /// Production HTTPS-only config。
    pub fn new(
        endpoint: Url,
        model: String,
        api_key: GoogleApiKey,
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
        api_key: GoogleApiKey,
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
            || endpoint.query() != Some("alt=sse")
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

impl core::fmt::Debug for GoogleProviderConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GoogleProviderConfig")
            .field("origin", &self.endpoint.origin().ascii_serialization())
            .field("model", &self.model)
            .field("has_stall_timeout", &self.stall_timeout.is_some())
            .finish_non_exhaustive()
    }
}

/// Production Google Generative AI adapter。
pub struct GoogleProvider {
    config: GoogleProviderConfig,
    dialer: SafeDialer,
}

impl GoogleProvider {
    /// 用唯一 SafeDialer 构造。
    #[must_use]
    pub const fn new(config: GoogleProviderConfig, dialer: SafeDialer) -> Self {
        Self { config, dialer }
    }
}

impl core::fmt::Debug for GoogleProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GoogleProvider")
            .field("config", &self.config)
            .field("dialer", &self.dialer)
            .finish()
    }
}

#[async_trait]
impl ProviderAdapter for GoogleProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        validate_request(&request)?;
        let body = build_request_body(&request)?;
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
        .with_google_api_key(
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
        Ok(Box::new(GoogleSession {
            response,
            sse: SseDecoder::default(),
            decoder: GoogleDecoder::default(),
            pending: VecDeque::new(),
            stall_timeout: self.config.stall_timeout,
            ended: false,
        }))
    }
}

fn build_request_body(request: &ProviderRequest) -> Result<Vec<u8>, ProviderPortError> {
    let mut system = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    for message in &request.messages {
        match message.role {
            ProviderMessageRole::System => system.push(message.content.as_str()),
            ProviderMessageRole::User => {
                push_content_part(&mut contents, "user", json!({"text":message.content}))?
            }
            ProviderMessageRole::Assistant => {
                if !message.content.is_empty() {
                    push_content_part(&mut contents, "model", json!({"text":message.content}))?;
                }
                for call in &message.tool_calls {
                    push_content_part(
                        &mut contents,
                        "model",
                        json!({
                            "functionCall":{
                                "id":call.call_id,
                                "name":call.name,
                                "args":call.arguments,
                            }
                        }),
                    )?;
                }
            }
            ProviderMessageRole::Tool => push_content_part(
                &mut contents,
                "user",
                json!({
                    "functionResponse":{
                        "name":message.tool_name,
                        "response":{"result":message.content},
                    }
                }),
            )?,
        }
    }
    if contents.is_empty() {
        return Err(ProviderPortError::InvalidRequest {
            field: "provider_messages",
        });
    }
    let declarations = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name":tool.name,
                "description":tool.description,
                "parameters":tool.input_schema,
            })
        })
        .collect::<Vec<_>>();
    let mut body = json!({"contents":contents});
    if !system.is_empty() {
        body["systemInstruction"] = json!({
            "role":"system",
            "parts":[{"text":system.join("\n\n")}],
        });
    }
    if !declarations.is_empty() {
        body["tools"] = json!([{"functionDeclarations":declarations}]);
    }
    if let Some(limit) = request.max_output_tokens {
        body["generationConfig"] = json!({"maxOutputTokens":limit});
    } else {
        body["generationConfig"] = json!({});
    }
    serde_json::to_vec(&body).map_err(|_| ProviderPortError::InvalidRequest {
        field: "provider_request",
    })
}

fn push_content_part(
    contents: &mut Vec<Value>,
    role: &'static str,
    part: Value,
) -> Result<(), ProviderPortError> {
    if let Some(last) = contents.last_mut()
        && last.get("role").and_then(Value::as_str) == Some(role)
    {
        last.get_mut("parts")
            .and_then(Value::as_array_mut)
            .ok_or(ProviderPortError::InvalidRequest {
                field: "provider_messages",
            })?
            .push(part);
        return Ok(());
    }
    contents.push(json!({"role":role,"parts":[part]}));
    Ok(())
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

struct GoogleSession {
    response: SafeHttpStreamResponse,
    sse: SseDecoder,
    decoder: GoogleDecoder,
    pending: VecDeque<ProviderEvent>,
    stall_timeout: Option<Duration>,
    ended: bool,
}

#[async_trait]
impl ProviderSession for GoogleSession {
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

impl GoogleSession {
    fn fail(&mut self, failure: ProviderFailure) {
        self.pending.clear();
        self.pending.push_back(ProviderEvent::Failed(failure));
        self.ended = true;
    }
}

#[derive(Default)]
struct GoogleDecoder {
    response_id: Option<String>,
    text_started: bool,
    reasoning_started: bool,
    next_output_index: u32,
    tools: BTreeMap<String, (String, Value)>,
    usage_input: Option<u64>,
    usage_output: Option<u64>,
    usage_total: Option<u64>,
    finish_seen: bool,
    terminal: bool,
    chunk_ordinal: u64,
}

impl GoogleDecoder {
    fn ingest(&mut self, data: &str) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal || self.finish_seen {
            return Err(ProviderFailure::InvalidResponse);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProviderFailure::InvalidResponse)?;
        if let Some(error) = value.get("error") {
            let failure = google_error(error)?;
            self.terminal = true;
            return Ok(vec![ProviderEvent::Failed(failure)]);
        }
        let mut output = Vec::new();
        if let Some(response_id) = optional_bounded_string(&value, "responseId")? {
            match &self.response_id {
                Some(existing) if existing != response_id => {
                    return Err(ProviderFailure::InvalidResponse);
                }
                Some(_) => {}
                None => {
                    self.response_id = Some(response_id.to_owned());
                    output.push(ProviderEvent::ResponseStarted {
                        response_id: response_id.to_owned(),
                    });
                }
            }
        }
        if self.response_id.is_none()
            && (value.get("candidates").is_some() || value.get("usageMetadata").is_some())
        {
            let response_id = synthetic_response_id(data);
            self.response_id = Some(response_id.clone());
            output.push(ProviderEvent::ResponseStarted { response_id });
        }
        if let Some(usage) = value.get("usageMetadata") {
            self.update_usage(usage)?;
        }
        if value
            .get("promptFeedback")
            .and_then(|feedback| feedback.get("blockReason"))
            .and_then(Value::as_str)
            .is_some_and(|reason| !reason.is_empty() && reason != "BLOCK_REASON_UNSPECIFIED")
        {
            self.terminal = true;
            output.push(ProviderEvent::Failed(ProviderFailure::GenerationFailed));
            return Ok(output);
        }
        let candidates = match value.get("candidates") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(candidates)) => candidates.as_slice(),
            _ => return Err(ProviderFailure::InvalidResponse),
        };
        if candidates.len() > 1 {
            return Err(ProviderFailure::InvalidResponse);
        }
        if let Some(candidate) = candidates.first() {
            let candidate_index = candidate.get("index").and_then(Value::as_u64).unwrap_or(0);
            if candidate_index != 0 || self.response_id.is_none() {
                return Err(ProviderFailure::InvalidResponse);
            }
            if let Some(content) = candidate.get("content") {
                let content = content
                    .as_object()
                    .ok_or(ProviderFailure::InvalidResponse)?;
                if content.get("role").and_then(Value::as_str) != Some("model") {
                    return Err(ProviderFailure::InvalidResponse);
                }
                let parts = content
                    .get("parts")
                    .and_then(Value::as_array)
                    .ok_or(ProviderFailure::InvalidResponse)?;
                for (part_index, part) in parts.iter().enumerate() {
                    output.extend(self.ingest_part(part, part_index)?);
                }
            }
            match candidate.get("finishReason") {
                None | Some(Value::Null) => {}
                Some(Value::String(reason)) if reason == "FINISH_REASON_UNSPECIFIED" => {}
                Some(Value::String(reason)) if reason == "STOP" => self.finish_seen = true,
                Some(Value::String(_)) => {
                    self.terminal = true;
                    output.push(ProviderEvent::Failed(ProviderFailure::GenerationFailed));
                }
                _ => return Err(ProviderFailure::InvalidResponse),
            }
        }
        self.chunk_ordinal = self
            .chunk_ordinal
            .checked_add(1)
            .ok_or(ProviderFailure::InvalidResponse)?;
        Ok(output)
    }

    fn ingest_part(
        &mut self,
        part: &Value,
        part_index: usize,
    ) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        let part = part.as_object().ok_or(ProviderFailure::InvalidResponse)?;
        let mut output = Vec::new();
        let text = part.get("text").and_then(Value::as_str);
        let function = part.get("functionCall").and_then(Value::as_object);
        if text.is_some() && function.is_some() {
            return Err(ProviderFailure::InvalidResponse);
        }
        if text.is_none() && function.is_none() {
            let index = self.take_output_index()?;
            output.push(ProviderEvent::OutputItemAdded {
                index,
                kind: ProviderOutputKind::Extension,
            });
            return Ok(output);
        }
        if let Some(text) = text {
            if text.len() > MAX_PROVIDER_FIELD_BYTES {
                return Err(ProviderFailure::InvalidResponse);
            }
            let thought = match part.get("thought") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err(ProviderFailure::InvalidResponse),
            };
            if thought {
                if !self.reasoning_started {
                    output.push(ProviderEvent::OutputItemAdded {
                        index: REASONING_OUTPUT_INDEX,
                        kind: ProviderOutputKind::Reasoning,
                    });
                    self.reasoning_started = true;
                }
                if !text.is_empty() {
                    output.push(ProviderEvent::ReasoningDelta {
                        index: REASONING_OUTPUT_INDEX,
                        delta: text.to_owned(),
                    });
                }
            } else {
                if !self.text_started {
                    output.push(ProviderEvent::OutputItemAdded {
                        index: TEXT_OUTPUT_INDEX,
                        kind: ProviderOutputKind::Message,
                    });
                    self.text_started = true;
                }
                if !text.is_empty() {
                    output.push(ProviderEvent::TextDelta {
                        index: TEXT_OUTPUT_INDEX,
                        delta: text.to_owned(),
                    });
                }
            }
            return Ok(output);
        }
        let function = function.expect("exclusive branch checked");
        let name = map_string_field(function, "name")?.to_owned();
        let arguments = match function.get("args") {
            None | Some(Value::Null) => json!({}),
            Some(value) if value.is_object() => value.clone(),
            _ => return Err(ProviderFailure::InvalidResponse),
        };
        let call_id = match function.get("id") {
            None | Some(Value::Null) => format!(
                "{}:tool:{}:{part_index}",
                self.response_id
                    .as_deref()
                    .ok_or(ProviderFailure::InvalidResponse)?,
                self.chunk_ordinal,
            ),
            Some(Value::String(value)) if value.is_empty() => format!(
                "{}:tool:{}:{part_index}",
                self.response_id
                    .as_deref()
                    .ok_or(ProviderFailure::InvalidResponse)?,
                self.chunk_ordinal,
            ),
            Some(Value::String(value)) if value.len() <= MAX_PROVIDER_FIELD_BYTES => value.clone(),
            _ => return Err(ProviderFailure::InvalidResponse),
        };
        if let Some((known_name, known_args)) = self.tools.get(&call_id) {
            return if known_name == &name && known_args == &arguments {
                Ok(Vec::new())
            } else {
                Err(ProviderFailure::InvalidResponse)
            };
        }
        let arguments_json =
            serde_json::to_string(&arguments).map_err(|_| ProviderFailure::InvalidResponse)?;
        if arguments_json.len() > MAX_PROVIDER_FIELD_BYTES {
            return Err(ProviderFailure::InvalidResponse);
        }
        let index = self.take_output_index()?;
        self.tools
            .insert(call_id.clone(), (name.clone(), arguments.clone()));
        output.push(ProviderEvent::OutputItemAdded {
            index,
            kind: ProviderOutputKind::FunctionCall,
        });
        output.push(ProviderEvent::ToolCallStarted {
            index,
            call_id: call_id.clone(),
            name: Some(name.clone()),
        });
        output.push(ProviderEvent::ToolArgumentsDelta {
            index,
            call_id: call_id.clone(),
            delta: arguments_json,
        });
        output.push(ProviderEvent::ToolCallCompleted {
            index,
            call_id,
            name,
            arguments,
        });
        Ok(output)
    }

    fn take_output_index(&mut self) -> Result<u32, ProviderFailure> {
        let index = self.next_output_index.max(2);
        self.next_output_index = index
            .checked_add(1)
            .ok_or(ProviderFailure::InvalidResponse)?;
        Ok(index)
    }

    fn update_usage(&mut self, value: &Value) -> Result<(), ProviderFailure> {
        update_monotonic_usage_field(value, "promptTokenCount", &mut self.usage_input)?;
        update_monotonic_usage_field(value, "candidatesTokenCount", &mut self.usage_output)?;
        update_monotonic_usage_field(value, "totalTokenCount", &mut self.usage_total)?;
        if let (Some(input), Some(output), Some(total)) =
            (self.usage_input, self.usage_output, self.usage_total)
            && total
                < input
                    .checked_add(output)
                    .ok_or(ProviderFailure::InvalidResponse)?
        {
            return Err(ProviderFailure::InvalidResponse);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<Vec<ProviderEvent>, ProviderFailure> {
        if self.terminal {
            return Ok(Vec::new());
        }
        if !self.finish_seen || self.response_id.is_none() {
            return Err(ProviderFailure::InvalidResponse);
        }
        let usage = ProviderUsage {
            input_tokens: self.usage_input.ok_or(ProviderFailure::InvalidResponse)?,
            output_tokens: self.usage_output.ok_or(ProviderFailure::InvalidResponse)?,
            total_tokens: self.usage_total.ok_or(ProviderFailure::InvalidResponse)?,
        };
        self.terminal = true;
        Ok(vec![ProviderEvent::Usage(usage), ProviderEvent::Completed])
    }
}

fn google_error(value: &Value) -> Result<ProviderFailure, ProviderFailure> {
    let code = value
        .get("code")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(match (code, status) {
        (401 | 403, _) | (_, "UNAUTHENTICATED" | "PERMISSION_DENIED") => {
            ProviderFailure::Authentication
        }
        (429, _) | (_, "RESOURCE_EXHAUSTED") => ProviderFailure::RateLimited { retry_after: None },
        (500..=599, _) | (_, "UNAVAILABLE" | "INTERNAL" | "DEADLINE_EXCEEDED") => {
            ProviderFailure::ServerUnavailable { retry_after: None }
        }
        (400, _) | (_, "INVALID_ARGUMENT" | "FAILED_PRECONDITION") => {
            ProviderFailure::InvalidResponse
        }
        _ => ProviderFailure::GenerationFailed,
    })
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

fn map_string_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_PROVIDER_FIELD_BYTES)
        .ok_or(ProviderFailure::InvalidResponse)
}

fn update_monotonic_usage_field(
    value: &Value,
    field: &str,
    target: &mut Option<u64>,
) -> Result<(), ProviderFailure> {
    let Some(value) = value.get(field) else {
        return Ok(());
    };
    let value = value.as_u64().ok_or(ProviderFailure::InvalidResponse)?;
    if target.is_some_and(|known| value < known) {
        return Err(ProviderFailure::InvalidResponse);
    }
    *target = Some(value);
    Ok(())
}

fn synthetic_response_id(data: &str) -> String {
    let digest = Sha256::digest(data.as_bytes());
    let mut id = String::with_capacity(7 + 32);
    id.push_str("google:");
    for byte in &digest[..16] {
        use core::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::net::safe_http::{CidrAllowlist, EgressPolicy};

    #[test]
    fn official_chunks_normalize_text_thought_function_call_usage_and_finish() {
        let mut decoder = GoogleDecoder::default();
        let mut events = Vec::new();
        events.extend(
            decoder
                .ingest(
                    r#"{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"consider","thought":true},{"text":"hello"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"totalTokenCount":7}}"#,
                )
                .unwrap(),
        );
        events.extend(
            decoder
                .ingest(
                    r#"{"candidates":[{"index":0,"content":{"role":"model","parts":[{"functionCall":{"name":"weather","args":{"city":"Paris"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":10},"futureExtension":true}"#,
                )
                .unwrap(),
        );
        events.extend(decoder.finish().unwrap());
        assert!(matches!(events[0], ProviderEvent::ResponseStarted { .. }));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::ReasoningDelta { delta, .. } if delta == "consider"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::ToolCallCompleted { call_id, name, arguments, .. }
                if call_id.starts_with("google:") && call_id.ends_with(":tool:1:0")
                    && name == "weather"
                    && arguments == &json!({"city":"Paris"})
        )));
        assert_eq!(
            events[events.len() - 2],
            ProviderEvent::Usage(ProviderUsage {
                input_tokens: 3,
                output_tokens: 5,
                total_tokens: 10,
            })
        );
        assert_eq!(events.last(), Some(&ProviderEvent::Completed));
    }

    #[test]
    fn request_shape_preserves_system_tools_results_and_omits_unspecified_token_cap() {
        let body: Value = serde_json::from_slice(
            &build_request_body(&ProviderRequest {
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
                            name: "weather".to_owned(),
                            arguments: json!({"city":"Paris"}),
                        }],
                    },
                    openbot_application::ProviderMessage {
                        role: ProviderMessageRole::Tool,
                        content: "sunny".to_owned(),
                        tool_call_id: Some("call-1".to_owned()),
                        tool_name: Some("weather".to_owned()),
                        tool_calls: Vec::new(),
                    },
                ],
                tools: vec![openbot_application::ProviderToolDefinition {
                    name: "weather".to_owned(),
                    description: "weather".to_owned(),
                    input_schema: json!({"type":"object"}),
                }],
                max_output_tokens: None,
                rate_card: None,
                cost_cap: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(body["systemInstruction"]["role"], "system");
        assert_eq!(body["contents"].as_array().unwrap().len(), 3);
        assert_eq!(
            body["contents"][1]["parts"][0]["functionCall"]["name"],
            "weather"
        );
        assert_eq!(
            body["contents"][2]["parts"][0]["functionResponse"]["name"],
            "weather"
        );
        assert_eq!(
            body["tools"][0]["functionDeclarations"][0]["parameters"]["type"],
            "object"
        );
        assert_eq!(body["generationConfig"], json!({}));
    }

    #[test]
    fn usage_regression_multiple_candidates_and_error_status_fail_closed() {
        let mut decoder = GoogleDecoder::default();
        decoder
            .ingest(r#"{"responseId":"r","usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":3,"totalTokenCount":7}}"#)
            .unwrap();
        assert_eq!(
            decoder.ingest(r#"{"responseId":"r","usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":3,"totalTokenCount":6}}"#),
            Err(ProviderFailure::InvalidResponse)
        );
        let mut decoder = GoogleDecoder::default();
        assert_eq!(
            decoder
                .ingest(r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"vendor secret"}}"#)
                .unwrap(),
            [ProviderEvent::Failed(ProviderFailure::RateLimited {
                retry_after: None
            })]
        );
    }

    #[tokio::test]
    async fn adapter_uses_header_not_query_key_and_streams_safe_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with(
                "POST /v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse "
            ));
            assert!(request.contains("x-goog-api-key: google-test-key"));
            assert!(!request.contains("key=google-test-key"));
            let body = "data: {\"responseId\":\"r-local\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hello\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":2,\"totalTokenCount\":3}}\n\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(body.as_bytes()).await.unwrap();
        });
        let config = GoogleProviderConfig::new_with_transport_policy(
            Url::parse(&format!(
                "http://{address}/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
            ))
            .unwrap(),
            "gemini-2.5-flash".to_owned(),
            GoogleApiKey::from_bytes(b"google-test-key".to_vec()).unwrap(),
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap(),
            Some(Duration::from_secs(1)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert!(!format!("{config:?}").contains("google-test-key"));
        let adapter = GoogleProvider::new(
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
                max_output_tokens: None,
                rate_card: None,
                cost_cap: None,
            })
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Some(event) = session.next_event().await.unwrap() {
            events.push(event);
        }
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
