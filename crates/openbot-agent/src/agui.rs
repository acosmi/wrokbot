//! Pinned `@ag-ui/core@0.0.57` event boundary.
//!
//! The decoder accepts complete SSE `data:` values. HTTP/SSE framing remains an infra concern;
//! community SDK types never cross into domain/application. Open payload families are retained as
//! explicitly untrusted JSON and can never carry authorization facts.

use std::collections::{BTreeMap, BTreeSet};

use openbot_application::{
    ProviderMessage, ProviderMessageRole, ProviderRemoteResume, ProviderToolDefinition,
};
use serde_json::{Map, Value};

/// Pinned AG-UI version used by the upstream oracle.
pub const AGUI_SCHEMA_VERSION: &str = "0.0.57";
/// Every EventType literal exported by pinned `@ag-ui/core@0.0.57`.
pub const AGUI_EVENT_TYPES: &[&str] = &[
    "TEXT_MESSAGE_START",
    "TEXT_MESSAGE_CONTENT",
    "TEXT_MESSAGE_END",
    "TEXT_MESSAGE_CHUNK",
    "THINKING_TEXT_MESSAGE_START",
    "THINKING_TEXT_MESSAGE_CONTENT",
    "THINKING_TEXT_MESSAGE_END",
    "TOOL_CALL_START",
    "TOOL_CALL_ARGS",
    "TOOL_CALL_END",
    "TOOL_CALL_CHUNK",
    "TOOL_CALL_RESULT",
    "THINKING_START",
    "THINKING_END",
    "STATE_SNAPSHOT",
    "STATE_DELTA",
    "MESSAGES_SNAPSHOT",
    "ACTIVITY_SNAPSHOT",
    "ACTIVITY_DELTA",
    "RAW",
    "CUSTOM",
    "RUN_STARTED",
    "RUN_FINISHED",
    "RUN_ERROR",
    "STEP_STARTED",
    "STEP_FINISHED",
    "REASONING_START",
    "REASONING_MESSAGE_START",
    "REASONING_MESSAGE_CONTENT",
    "REASONING_MESSAGE_END",
    "REASONING_MESSAGE_CHUNK",
    "REASONING_END",
    "REASONING_ENCRYPTED_VALUE",
];
/// Maximum decoded JSON event bytes.
pub const MAX_AGUI_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum encoded RunAgentInput bytes; independently bounds the outbound request body.
pub const MAX_AGUI_RUN_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of messages or patch operations in one event.
pub const MAX_AGUI_COLLECTION_ITEMS: usize = 4096;

/// Stable, content-free protocol failure categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AguiProtocolError {
    /// JSON/event exceeds a fixed bound.
    #[error("agui_too_large")]
    TooLarge,
    /// JSON or required field shape is malformed.
    #[error("agui_invalid_event")]
    InvalidEvent,
    /// Event ordering or ID pairing is invalid.
    #[error("agui_invalid_sequence")]
    InvalidSequence,
    /// Thread/run identity does not match the authoritative lease.
    #[error("agui_identity_mismatch")]
    IdentityMismatch,
    /// RFC 6902 patch is malformed or cannot apply to the current state.
    #[error("agui_invalid_patch")]
    InvalidPatch,
    /// Stream ended without exactly one terminal lifecycle event.
    #[error("agui_incomplete_stream")]
    Incomplete,
}

/// AG-UI message roles in 0.0.57.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AguiRole {
    /// Developer instruction.
    Developer,
    /// System instruction.
    System,
    /// Assistant output.
    Assistant,
    /// User input.
    User,
    /// Tool result.
    Tool,
    /// Visible reasoning summary.
    Reasoning,
}

/// Known-field-only fixed-schema interrupt descriptor.
#[derive(Clone, Debug, PartialEq)]
pub struct AguiInterrupt {
    pub(crate) id: String,
    pub(crate) reason: String,
    pub(crate) message: Option<String>,
    pub(crate) tool_call_id: Option<String>,
    pub(crate) response_schema: Option<Value>,
    pub(crate) expires_at: Option<String>,
    pub(crate) metadata: Option<Value>,
}

/// Normalized, bounded protocol event. Open JSON is always marked `untrusted` in the variant name.
#[derive(Clone, Debug, PartialEq)]
pub enum AguiEvent {
    /// Mandatory first lifecycle event.
    RunStarted,
    /// Normal success terminal.
    RunFinished,
    /// Interrupt terminal; resume is represented on the next RunAgentInput.
    RunInterrupted {
        /// Bounded, schema-validated interrupt descriptors.
        interrupts: Vec<AguiInterrupt>,
    },
    /// Error terminal. Message is untrusted display content, never a log/audit value.
    RunError {
        /// Remote message.
        message: String,
        /// Optional remote stable-ish code; it is not trusted as a local code.
        code: Option<String>,
    },
    /// Step lifecycle start.
    StepStarted {
        /// Remote step name.
        name: String,
    },
    /// Step lifecycle end.
    StepFinished {
        /// Remote step name paired with the start event.
        name: String,
    },
    /// Text message start.
    TextStarted {
        /// Message id.
        id: String,
        /// Declared message role.
        role: AguiRole,
        /// Optional participant name.
        name: Option<String>,
    },
    /// Text delta.
    TextDelta {
        /// Message id.
        id: String,
        /// Text fragment.
        delta: String,
    },
    /// Text message end.
    TextEnded {
        /// Message id.
        id: String,
    },
    /// Tool call start.
    ToolStarted {
        /// Provider/remote pairing id.
        id: String,
        /// Tool name.
        name: String,
        /// Optional parent text message.
        parent_message_id: Option<String>,
    },
    /// Tool argument delta.
    ToolArguments {
        /// Tool call id.
        id: String,
        /// JSON argument fragment.
        delta: String,
    },
    /// Complete tool call after end; arguments must be one JSON object.
    ToolCompleted {
        /// Tool call id.
        id: String,
        /// Tool name.
        name: String,
        /// Complete object arguments.
        arguments: Value,
    },
    /// Tool execution result emitted by the remote agent.
    ToolResult {
        /// Tool-result message id.
        message_id: String,
        /// Paired tool call id.
        call_id: String,
        /// Complete untrusted result content.
        content: String,
    },
    /// State snapshot replaces the previous state.
    StateSnapshot {
        /// Complete untrusted state value.
        untrusted_snapshot: Value,
    },
    /// State delta after it has been applied successfully.
    StateDelta {
        /// Untrusted RFC 6902 operations after successful application.
        untrusted_patch: Vec<Value>,
    },
    /// Complete message snapshot after structural validation.
    MessagesSnapshot {
        /// Structurally validated but untrusted messages.
        untrusted_messages: Vec<Value>,
    },
    /// Activity snapshot.
    ActivitySnapshot {
        /// Activity message id.
        message_id: String,
        /// Activity discriminator.
        activity_type: String,
        /// Complete untrusted activity content.
        untrusted_content: Value,
        /// Whether an existing activity was replaced.
        replace: bool,
    },
    /// Activity JSON Patch.
    ActivityDelta {
        /// Activity message id.
        message_id: String,
        /// Activity discriminator paired with the snapshot.
        activity_type: String,
        /// Applied untrusted RFC 6902 patch.
        untrusted_patch: Vec<Value>,
    },
    /// Reasoning lifecycle start.
    ReasoningStarted {
        /// Reasoning lifecycle id.
        id: String,
    },
    /// Reasoning message start.
    ReasoningMessageStarted {
        /// Reasoning message id.
        id: String,
    },
    /// Visible reasoning delta.
    ReasoningDelta {
        /// Reasoning message id.
        id: String,
        /// Visible summary fragment.
        delta: String,
    },
    /// Reasoning message end.
    ReasoningMessageEnded {
        /// Reasoning message id.
        id: String,
    },
    /// Reasoning lifecycle end.
    ReasoningEnded {
        /// Reasoning lifecycle id.
        id: String,
    },
    /// Opaque encrypted reasoning value. It is never decrypted or treated as an instruction.
    ReasoningEncrypted {
        /// `message` or `tool-call`.
        subtype: String,
        /// Opaque entity id.
        entity_id: String,
        /// Opaque encrypted blob.
        encrypted_value: String,
    },
    /// External raw event, explicitly untrusted.
    Raw {
        /// Optional remote source label.
        source: Option<String>,
        /// Untrusted passthrough payload.
        untrusted_event: Value,
    },
    /// Application-specific custom event, explicitly untrusted.
    Custom {
        /// Custom event name.
        name: String,
        /// Untrusted custom payload.
        untrusted_value: Value,
    },
}

#[derive(Clone, Debug)]
struct ToolAccumulator {
    name: String,
    arguments: String,
    ended: bool,
}

/// Stateful decoder enforcing lifecycle/pairing and maintaining state/activity projections.
#[derive(Debug)]
pub struct AguiDecoder {
    thread_id: String,
    run_id: String,
    started: bool,
    terminal: bool,
    open_text: BTreeMap<String, AguiRole>,
    tools: BTreeMap<String, ToolAccumulator>,
    open_steps: BTreeSet<String>,
    reasoning_runs: BTreeSet<String>,
    reasoning_messages: BTreeSet<String>,
    state: Value,
    activities: BTreeMap<String, (String, Value)>,
    messages: Vec<Value>,
    text_chunk_id: Option<String>,
    tool_chunk_id: Option<String>,
    reasoning_chunk_id: Option<String>,
}

impl AguiDecoder {
    /// Construct from authoritative thread/run IDs and the state sent in RunAgentInput.
    pub fn new(
        thread_id: impl Into<String>,
        run_id: impl Into<String>,
        initial_state: Value,
    ) -> Result<Self, AguiProtocolError> {
        let thread_id = bounded_id(thread_id.into())?;
        let run_id = bounded_id(run_id.into())?;
        ensure_value_bound(&initial_state)?;
        Ok(Self {
            thread_id,
            run_id,
            started: false,
            terminal: false,
            open_text: BTreeMap::new(),
            tools: BTreeMap::new(),
            open_steps: BTreeSet::new(),
            reasoning_runs: BTreeSet::new(),
            reasoning_messages: BTreeSet::new(),
            state: initial_state,
            activities: BTreeMap::new(),
            messages: Vec::new(),
            text_chunk_id: None,
            tool_chunk_id: None,
            reasoning_chunk_id: None,
        })
    }

    /// Decode one complete SSE `data:` value.
    pub fn ingest(&mut self, data: &str) -> Result<Vec<AguiEvent>, AguiProtocolError> {
        if data.is_empty() || data.len() > MAX_AGUI_EVENT_BYTES || data.as_bytes().contains(&0) {
            return Err(AguiProtocolError::TooLarge);
        }
        if self.terminal {
            return Err(AguiProtocolError::InvalidSequence);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| AguiProtocolError::InvalidEvent)?;
        ensure_value_bound(&value)?;
        let object = value.as_object().ok_or(AguiProtocolError::InvalidEvent)?;
        if object
            .get("timestamp")
            .is_some_and(|value| !value.is_number())
        {
            return Err(AguiProtocolError::InvalidEvent);
        }
        let event_type = required_string(object, "type")?;
        let mut output = Vec::new();
        if event_type != "RUN_ERROR" {
            self.close_convenience_before(event_type, &mut output)?;
        }
        if !self.started && event_type != "RUN_STARTED" {
            return Err(AguiProtocolError::InvalidSequence);
        }
        match event_type {
            "RUN_STARTED" => {
                if self.started {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                self.check_run_identity(object)?;
                self.started = true;
                output.push(AguiEvent::RunStarted);
            }
            "RUN_FINISHED" => {
                self.check_run_identity(object)?;
                self.require_no_open_explicit_streams()?;
                let outcome = object.get("outcome");
                match outcome {
                    None | Some(Value::Null) => output.push(AguiEvent::RunFinished),
                    Some(Value::Object(value))
                        if value.get("type").and_then(Value::as_str) == Some("success") =>
                    {
                        output.push(AguiEvent::RunFinished)
                    }
                    Some(Value::Object(value))
                        if value.get("type").and_then(Value::as_str) == Some("interrupt") =>
                    {
                        let interrupts = validate_interrupts(value.get("interrupts"))?;
                        output.push(AguiEvent::RunInterrupted { interrupts });
                    }
                    _ => return Err(AguiProtocolError::InvalidEvent),
                }
                self.terminal = true;
            }
            "RUN_ERROR" => {
                let message = required_bounded_string_allow_empty(object, "message")?;
                let code = optional_bounded_string(object, "code")?;
                self.terminal = true;
                self.abort_open_streams();
                output.push(AguiEvent::RunError { message, code });
            }
            "STEP_STARTED" => {
                let name = required_bounded_string(object, "stepName")?;
                if !self.open_steps.insert(name.clone()) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::StepStarted { name });
            }
            "STEP_FINISHED" => {
                let name = required_bounded_string(object, "stepName")?;
                if !self.open_steps.remove(&name) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::StepFinished { name });
            }
            "TEXT_MESSAGE_START" => self.text_start(object, &mut output)?,
            "TEXT_MESSAGE_CONTENT" => self.text_content(object, &mut output)?,
            "TEXT_MESSAGE_END" => self.text_end(object, &mut output)?,
            "TEXT_MESSAGE_CHUNK" => self.text_chunk(object, &mut output)?,
            "TOOL_CALL_START" => self.tool_start(object, &mut output)?,
            "TOOL_CALL_ARGS" => self.tool_args(object, &mut output)?,
            "TOOL_CALL_END" => self.tool_end(object, &mut output)?,
            "TOOL_CALL_CHUNK" => self.tool_chunk(object, &mut output)?,
            "TOOL_CALL_RESULT" => self.tool_result(object, &mut output)?,
            "STATE_SNAPSHOT" => {
                let snapshot = object
                    .get("snapshot")
                    .cloned()
                    .ok_or(AguiProtocolError::InvalidEvent)?;
                ensure_value_bound(&snapshot)?;
                self.state = snapshot.clone();
                output.push(AguiEvent::StateSnapshot {
                    untrusted_snapshot: snapshot,
                });
            }
            "STATE_DELTA" => {
                let patch = patch_array(object, "delta")?;
                apply_patch(&mut self.state, &patch)?;
                output.push(AguiEvent::StateDelta {
                    untrusted_patch: patch,
                });
            }
            "MESSAGES_SNAPSHOT" => {
                let messages = validate_messages(object.get("messages"))?;
                self.messages = messages.clone();
                output.push(AguiEvent::MessagesSnapshot {
                    untrusted_messages: messages,
                });
            }
            "ACTIVITY_SNAPSHOT" => {
                let message_id = required_bounded_string(object, "messageId")?;
                let activity_type = required_bounded_string(object, "activityType")?;
                let content = object
                    .get("content")
                    .filter(|value| value.is_object())
                    .cloned()
                    .ok_or(AguiProtocolError::InvalidEvent)?;
                let replace = optional_bool(object, "replace")?.unwrap_or(true);
                if replace || !self.activities.contains_key(&message_id) {
                    self.activities
                        .insert(message_id.clone(), (activity_type.clone(), content.clone()));
                }
                output.push(AguiEvent::ActivitySnapshot {
                    message_id,
                    activity_type,
                    untrusted_content: content,
                    replace,
                });
            }
            "ACTIVITY_DELTA" => {
                let message_id = required_bounded_string(object, "messageId")?;
                let activity_type = required_bounded_string(object, "activityType")?;
                let patch = patch_array(object, "patch")?;
                let (known_type, content) = self
                    .activities
                    .get_mut(&message_id)
                    .ok_or(AguiProtocolError::InvalidSequence)?;
                if known_type != &activity_type {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                apply_patch(content, &patch)?;
                output.push(AguiEvent::ActivityDelta {
                    message_id,
                    activity_type,
                    untrusted_patch: patch,
                });
            }
            "RAW" => {
                let event = object
                    .get("event")
                    .cloned()
                    .ok_or(AguiProtocolError::InvalidEvent)?;
                output.push(AguiEvent::Raw {
                    source: optional_bounded_string(object, "source")?,
                    untrusted_event: event,
                });
            }
            "CUSTOM" => output.push(AguiEvent::Custom {
                name: required_bounded_string(object, "name")?,
                untrusted_value: object
                    .get("value")
                    .cloned()
                    .ok_or(AguiProtocolError::InvalidEvent)?,
            }),
            "REASONING_START" => {
                let id = reasoning_id(object)?;
                if !self.reasoning_runs.insert(id.clone()) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningStarted { id });
            }
            "THINKING_START" => {
                optional_bounded_string(object, "title")?;
                let id = self.thinking_run_id();
                if !self.reasoning_runs.insert(id.clone()) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningStarted { id });
            }
            "REASONING_MESSAGE_START" => {
                if object.get("role").and_then(Value::as_str) != Some("reasoning") {
                    return Err(AguiProtocolError::InvalidEvent);
                }
                let id = reasoning_id(object)?;
                if !self.reasoning_messages.insert(id.clone()) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningMessageStarted { id });
            }
            "THINKING_TEXT_MESSAGE_START" => {
                let id = self.thinking_message_id();
                if !self.reasoning_messages.insert(id.clone()) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningMessageStarted { id });
            }
            "REASONING_MESSAGE_CONTENT" => {
                let id = reasoning_id(object)?;
                if !self.reasoning_messages.contains(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningDelta {
                    id,
                    delta: required_bounded_string_allow_empty(object, "delta")?,
                });
            }
            "THINKING_TEXT_MESSAGE_CONTENT" => {
                let id = self.thinking_message_id();
                if !self.reasoning_messages.contains(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningDelta {
                    id,
                    delta: required_bounded_string_allow_empty(object, "delta")?,
                });
            }
            "REASONING_MESSAGE_END" => {
                let id = reasoning_id(object)?;
                if !self.reasoning_messages.remove(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningMessageEnded { id });
            }
            "THINKING_TEXT_MESSAGE_END" => {
                let id = self.thinking_message_id();
                if !self.reasoning_messages.remove(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningMessageEnded { id });
            }
            "REASONING_MESSAGE_CHUNK" => self.reasoning_chunk(object, &mut output)?,
            "REASONING_END" => {
                let id = reasoning_id(object)?;
                if !self.reasoning_runs.remove(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningEnded { id });
            }
            "THINKING_END" => {
                let id = self.thinking_run_id();
                if !self.reasoning_runs.remove(&id) {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                output.push(AguiEvent::ReasoningEnded { id });
            }
            "REASONING_ENCRYPTED_VALUE" => {
                let subtype = required_bounded_string(object, "subtype")?;
                if subtype != "tool-call" && subtype != "message" {
                    return Err(AguiProtocolError::InvalidEvent);
                }
                output.push(AguiEvent::ReasoningEncrypted {
                    subtype,
                    entity_id: required_bounded_string(object, "entityId")?,
                    encrypted_value: required_bounded_string(object, "encryptedValue")?,
                });
            }
            _ => return Err(AguiProtocolError::InvalidEvent),
        }
        Ok(output)
    }

    /// Finish SSE event decoding, expanding any convenience chunks and requiring one terminal.
    pub fn finish(&mut self) -> Result<Vec<AguiEvent>, AguiProtocolError> {
        let mut output = Vec::new();
        self.close_all_convenience(&mut output)?;
        if !self.started || !self.terminal {
            return Err(AguiProtocolError::Incomplete);
        }
        Ok(output)
    }

    /// Current state after validated snapshots/patches.
    #[must_use]
    pub const fn state(&self) -> &Value {
        &self.state
    }

    /// Current activity content by message id.
    #[must_use]
    pub fn activity(&self, message_id: &str) -> Option<&Value> {
        self.activities.get(message_id).map(|(_, value)| value)
    }

    /// Last structurally validated messages snapshot.
    #[must_use]
    pub fn messages(&self) -> &[Value] {
        &self.messages
    }

    fn check_run_identity(&self, object: &Map<String, Value>) -> Result<(), AguiProtocolError> {
        if required_string(object, "threadId")? != self.thread_id
            || required_string(object, "runId")? != self.run_id
        {
            return Err(AguiProtocolError::IdentityMismatch);
        }
        Ok(())
    }

    fn thinking_run_id(&self) -> String {
        format!("thinking:{}", self.run_id)
    }

    fn thinking_message_id(&self) -> String {
        format!("thinking-text:{}", self.run_id)
    }

    fn require_no_open_explicit_streams(&self) -> Result<(), AguiProtocolError> {
        if !self.open_text.is_empty()
            || self.tools.values().any(|tool| !tool.ended)
            || !self.open_steps.is_empty()
            || !self.reasoning_messages.is_empty()
            || !self.reasoning_runs.is_empty()
        {
            Err(AguiProtocolError::InvalidSequence)
        } else {
            Ok(())
        }
    }

    fn abort_open_streams(&mut self) {
        self.open_text.clear();
        self.tools.clear();
        self.open_steps.clear();
        self.reasoning_runs.clear();
        self.reasoning_messages.clear();
        self.text_chunk_id = None;
        self.tool_chunk_id = None;
        self.reasoning_chunk_id = None;
    }

    fn text_start(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "messageId")?;
        let role = parse_text_role(object.get("role"))?;
        if self.open_text.insert(id.clone(), role).is_some() {
            return Err(AguiProtocolError::InvalidSequence);
        }
        output.push(AguiEvent::TextStarted {
            id,
            role,
            name: optional_bounded_string(object, "name")?,
        });
        Ok(())
    }

    fn text_content(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "messageId")?;
        if !self.open_text.contains_key(&id) {
            return Err(AguiProtocolError::InvalidSequence);
        }
        output.push(AguiEvent::TextDelta {
            id,
            delta: required_bounded_string_allow_empty(object, "delta")?,
        });
        Ok(())
    }

    fn text_end(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "messageId")?;
        if self.open_text.remove(&id).is_none() {
            return Err(AguiProtocolError::InvalidSequence);
        }
        output.push(AguiEvent::TextEnded { id });
        Ok(())
    }

    fn text_chunk(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let incoming = optional_bounded_string(object, "messageId")?;
        if let Some(incoming) = incoming
            && self.text_chunk_id.as_deref() != Some(incoming.as_str())
        {
            self.close_text_chunk(output)?;
            let role = parse_text_role(object.get("role"))?;
            self.text_chunk_id = Some(incoming.clone());
            self.open_text.insert(incoming.clone(), role);
            output.push(AguiEvent::TextStarted {
                id: incoming,
                role,
                name: optional_bounded_string(object, "name")?,
            });
        }
        let id = self
            .text_chunk_id
            .clone()
            .ok_or(AguiProtocolError::InvalidSequence)?;
        if let Some(delta) = optional_bounded_string_allow_empty(object, "delta")? {
            if delta.is_empty() {
                self.close_text_chunk(output)?;
            } else {
                output.push(AguiEvent::TextDelta { id, delta });
            }
        }
        Ok(())
    }

    fn tool_start(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "toolCallId")?;
        let name = required_bounded_string(object, "toolCallName")?;
        let parent_message_id = optional_bounded_string(object, "parentMessageId")?;
        if self
            .tools
            .insert(
                id.clone(),
                ToolAccumulator {
                    name: name.clone(),
                    arguments: String::new(),
                    ended: false,
                },
            )
            .is_some()
        {
            return Err(AguiProtocolError::InvalidSequence);
        }
        output.push(AguiEvent::ToolStarted {
            id,
            name,
            parent_message_id,
        });
        Ok(())
    }

    fn tool_args(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "toolCallId")?;
        let delta = required_bounded_string_allow_empty(object, "delta")?;
        let tool = self
            .tools
            .get_mut(&id)
            .filter(|tool| !tool.ended)
            .ok_or(AguiProtocolError::InvalidSequence)?;
        if delta.len() > MAX_AGUI_EVENT_BYTES.saturating_sub(tool.arguments.len()) {
            return Err(AguiProtocolError::TooLarge);
        }
        tool.arguments.push_str(&delta);
        output.push(AguiEvent::ToolArguments { id, delta });
        Ok(())
    }

    fn tool_end(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let id = required_bounded_string(object, "toolCallId")?;
        self.finish_tool(id, output)
    }

    fn finish_tool(
        &mut self,
        id: String,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let tool = self
            .tools
            .get_mut(&id)
            .filter(|tool| !tool.ended)
            .ok_or(AguiProtocolError::InvalidSequence)?;
        let arguments: Value = serde_json::from_str(&tool.arguments)
            .ok()
            .filter(Value::is_object)
            .ok_or(AguiProtocolError::InvalidEvent)?;
        tool.ended = true;
        output.push(AguiEvent::ToolCompleted {
            id,
            name: tool.name.clone(),
            arguments,
        });
        Ok(())
    }

    fn tool_chunk(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let incoming = optional_bounded_string(object, "toolCallId")?;
        if let Some(incoming) = incoming
            && self.tool_chunk_id.as_deref() != Some(incoming.as_str())
        {
            self.close_tool_chunk(output)?;
            let name = required_bounded_string(object, "toolCallName")?;
            let parent = optional_bounded_string(object, "parentMessageId")?;
            self.tool_chunk_id = Some(incoming.clone());
            self.tools.insert(
                incoming.clone(),
                ToolAccumulator {
                    name: name.clone(),
                    arguments: String::new(),
                    ended: false,
                },
            );
            output.push(AguiEvent::ToolStarted {
                id: incoming,
                name,
                parent_message_id: parent,
            });
        }
        let id = self
            .tool_chunk_id
            .clone()
            .ok_or(AguiProtocolError::InvalidSequence)?;
        if let Some(delta) = optional_bounded_string_allow_empty(object, "delta")? {
            if delta.is_empty() {
                self.close_tool_chunk(output)?;
            } else {
                let tool = self
                    .tools
                    .get_mut(&id)
                    .ok_or(AguiProtocolError::InvalidSequence)?;
                if delta.len() > MAX_AGUI_EVENT_BYTES.saturating_sub(tool.arguments.len()) {
                    return Err(AguiProtocolError::TooLarge);
                }
                tool.arguments.push_str(&delta);
                output.push(AguiEvent::ToolArguments { id, delta });
            }
        }
        Ok(())
    }

    fn tool_result(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let call_id = required_bounded_string(object, "toolCallId")?;
        if object
            .get("role")
            .is_some_and(|value| value.as_str() != Some("tool"))
        {
            return Err(AguiProtocolError::InvalidEvent);
        }
        if !self.tools.get(&call_id).is_some_and(|tool| tool.ended) {
            return Err(AguiProtocolError::InvalidSequence);
        }
        output.push(AguiEvent::ToolResult {
            message_id: required_bounded_string(object, "messageId")?,
            call_id,
            content: required_bounded_string_allow_empty(object, "content")?,
        });
        Ok(())
    }

    fn reasoning_chunk(
        &mut self,
        object: &Map<String, Value>,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        let incoming = optional_bounded_string(object, "messageId")?;
        if let Some(incoming) = incoming
            && self.reasoning_chunk_id.as_deref() != Some(incoming.as_str())
        {
            self.close_reasoning_chunk(output)?;
            self.reasoning_chunk_id = Some(incoming.clone());
            self.reasoning_messages.insert(incoming.clone());
            output.push(AguiEvent::ReasoningMessageStarted { id: incoming });
        }
        let id = self
            .reasoning_chunk_id
            .clone()
            .ok_or(AguiProtocolError::InvalidSequence)?;
        if let Some(delta) = optional_bounded_string_allow_empty(object, "delta")? {
            if delta.is_empty() {
                self.close_reasoning_chunk(output)?;
            } else {
                output.push(AguiEvent::ReasoningDelta { id, delta });
            }
        }
        Ok(())
    }

    fn close_convenience_before(
        &mut self,
        event_type: &str,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        if event_type != "TEXT_MESSAGE_CHUNK" {
            self.close_text_chunk(output)?;
        }
        if event_type != "TOOL_CALL_CHUNK" {
            self.close_tool_chunk(output)?;
        }
        if event_type != "REASONING_MESSAGE_CHUNK" {
            self.close_reasoning_chunk(output)?;
        }
        Ok(())
    }

    fn close_all_convenience(
        &mut self,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        self.close_text_chunk(output)?;
        self.close_tool_chunk(output)?;
        self.close_reasoning_chunk(output)
    }

    fn close_text_chunk(&mut self, output: &mut Vec<AguiEvent>) -> Result<(), AguiProtocolError> {
        if let Some(id) = self.text_chunk_id.take() {
            if self.open_text.remove(&id).is_none() {
                return Err(AguiProtocolError::InvalidSequence);
            }
            output.push(AguiEvent::TextEnded { id });
        }
        Ok(())
    }

    fn close_tool_chunk(&mut self, output: &mut Vec<AguiEvent>) -> Result<(), AguiProtocolError> {
        if let Some(id) = self.tool_chunk_id.take() {
            self.finish_tool(id, output)?;
        }
        Ok(())
    }

    fn close_reasoning_chunk(
        &mut self,
        output: &mut Vec<AguiEvent>,
    ) -> Result<(), AguiProtocolError> {
        if let Some(id) = self.reasoning_chunk_id.take() {
            if !self.reasoning_messages.remove(&id) {
                return Err(AguiProtocolError::InvalidSequence);
            }
            output.push(AguiEvent::ReasoningMessageEnded { id });
        }
        Ok(())
    }
}

/// Encode the pinned 0.0.57 `RunAgentInput` shape from authoritative Rust history/catalog.
pub fn encode_run_agent_input(
    thread_id: &str,
    run_id: &str,
    messages: &[ProviderMessage],
    tools: &[ProviderToolDefinition],
    forwarded_props: Value,
) -> Result<Vec<u8>, AguiProtocolError> {
    encode_run_agent_input_with_resume(
        thread_id,
        run_id,
        messages,
        tools,
        forwarded_props,
        None,
        None,
    )
}

/// Encode a resumed 0.0.57 request with explicit protocol lineage and `resume[]`.
pub fn encode_run_agent_input_with_resume(
    thread_id: &str,
    run_id: &str,
    messages: &[ProviderMessage],
    tools: &[ProviderToolDefinition],
    forwarded_props: Value,
    parent_run_id: Option<&str>,
    resume: Option<&ProviderRemoteResume>,
) -> Result<Vec<u8>, AguiProtocolError> {
    bounded_id(thread_id.to_owned())?;
    bounded_id(run_id.to_owned())?;
    if let Some(parent_run_id) = parent_run_id {
        bounded_id(parent_run_id.to_owned())?;
    }
    if resume.is_some_and(|resume| {
        resume.protocol_run_id() != run_id || Some(resume.parent_protocol_run_id()) != parent_run_id
    }) || parent_run_id.is_some() != resume.is_some()
    {
        return Err(AguiProtocolError::InvalidSequence);
    }
    if messages.is_empty()
        || messages.len() > MAX_AGUI_COLLECTION_ITEMS
        || tools.len() > 256
        || !forwarded_props.is_object()
    {
        return Err(AguiProtocolError::InvalidEvent);
    }
    let mut pending_tools = BTreeMap::<String, String>::new();
    let mut projected_messages = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        bounded_string(&message.content)?;
        let id = format!("openbot:{run_id}:message:{index}");
        let mut projected = Map::new();
        projected.insert("id".to_owned(), Value::String(id));
        match message.role {
            ProviderMessageRole::System => {
                if !pending_tools.is_empty() || !message.tool_calls.is_empty() {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                projected.insert("role".to_owned(), Value::String("system".to_owned()));
                projected.insert("content".to_owned(), Value::String(message.content.clone()));
            }
            ProviderMessageRole::User => {
                if !pending_tools.is_empty() || !message.tool_calls.is_empty() {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                projected.insert("role".to_owned(), Value::String("user".to_owned()));
                projected.insert("content".to_owned(), Value::String(message.content.clone()));
            }
            ProviderMessageRole::Assistant => {
                if !pending_tools.is_empty() {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                projected.insert("role".to_owned(), Value::String("assistant".to_owned()));
                if !message.content.is_empty() {
                    projected.insert("content".to_owned(), Value::String(message.content.clone()));
                }
                if !message.tool_calls.is_empty() {
                    let calls = message
                        .tool_calls
                        .iter()
                        .map(|call| {
                            bounded_id(call.call_id.clone())?;
                            bounded_id(call.name.clone())?;
                            if !call.arguments.is_object()
                                || pending_tools
                                    .insert(call.call_id.clone(), call.name.clone())
                                    .is_some()
                            {
                                return Err(AguiProtocolError::InvalidSequence);
                            }
                            Ok(serde_json::json!({
                                "id":call.call_id,
                                "type":"function",
                                "function":{
                                    "name":call.name,
                                    "arguments":serde_json::to_string(&call.arguments)
                                        .map_err(|_| AguiProtocolError::InvalidEvent)?,
                                }
                            }))
                        })
                        .collect::<Result<Vec<_>, AguiProtocolError>>()?;
                    projected.insert("toolCalls".to_owned(), Value::Array(calls));
                }
            }
            ProviderMessageRole::Tool => {
                let (Some(call_id), Some(name)) = (
                    message.tool_call_id.as_deref(),
                    message.tool_name.as_deref(),
                ) else {
                    return Err(AguiProtocolError::InvalidSequence);
                };
                if !message.tool_calls.is_empty()
                    || pending_tools.remove(call_id).as_deref() != Some(name)
                {
                    return Err(AguiProtocolError::InvalidSequence);
                }
                projected.insert("role".to_owned(), Value::String("tool".to_owned()));
                projected.insert("content".to_owned(), Value::String(message.content.clone()));
                projected.insert("toolCallId".to_owned(), Value::String(call_id.to_owned()));
                projected.insert("name".to_owned(), Value::String(name.to_owned()));
            }
        }
        projected_messages.push(Value::Object(projected));
    }
    if !pending_tools.is_empty() {
        return Err(AguiProtocolError::InvalidSequence);
    }
    let projected_tools = tools
        .iter()
        .map(|tool| {
            bounded_id(tool.name.clone())?;
            bounded_string(&tool.description)?;
            if !tool.input_schema.is_object() {
                return Err(AguiProtocolError::InvalidEvent);
            }
            Ok(serde_json::json!({
                "name":tool.name,
                "description":tool.description,
                "parameters":tool.input_schema,
            }))
        })
        .collect::<Result<Vec<_>, AguiProtocolError>>()?;
    let mut body = serde_json::json!({
        "threadId":thread_id,
        "runId":run_id,
        "state":{},
        "messages":projected_messages,
        "tools":projected_tools,
        "context":[],
        "forwardedProps":forwarded_props,
    });
    let body_object = body
        .as_object_mut()
        .ok_or(AguiProtocolError::InvalidEvent)?;
    if let Some(parent_run_id) = parent_run_id {
        body_object.insert(
            "parentRunId".to_owned(),
            Value::String(parent_run_id.to_owned()),
        );
    }
    if let Some(resume) = resume {
        body_object.insert(
            "resume".to_owned(),
            Value::Array(resume.wire_entries().to_vec()),
        );
    }
    let encoded = serde_json::to_vec(&body).map_err(|_| AguiProtocolError::InvalidEvent)?;
    if encoded.len() > MAX_AGUI_RUN_INPUT_BYTES {
        return Err(AguiProtocolError::TooLarge);
    }
    Ok(encoded)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, AguiProtocolError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AguiProtocolError::InvalidEvent)
}

fn required_bounded_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, AguiProtocolError> {
    bounded_id(required_string(object, field)?.to_owned())
}

fn required_bounded_string_allow_empty(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, AguiProtocolError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AguiProtocolError::InvalidEvent)?;
    bounded_string(value)
}

fn optional_bounded_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, AguiProtocolError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => bounded_string(value).map(Some),
        _ => Err(AguiProtocolError::InvalidEvent),
    }
}

fn optional_bounded_string_allow_empty(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, AguiProtocolError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => bounded_string(value).map(Some),
        _ => Err(AguiProtocolError::InvalidEvent),
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<bool>, AguiProtocolError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        _ => Err(AguiProtocolError::InvalidEvent),
    }
}

fn bounded_id(value: String) -> Result<String, AguiProtocolError> {
    if value.is_empty() || value.len() > 4096 || value.as_bytes().contains(&0) {
        Err(AguiProtocolError::InvalidEvent)
    } else {
        Ok(value)
    }
}

fn bounded_string(value: &str) -> Result<String, AguiProtocolError> {
    if value.len() > MAX_AGUI_EVENT_BYTES || value.as_bytes().contains(&0) {
        Err(AguiProtocolError::TooLarge)
    } else {
        Ok(value.to_owned())
    }
}

fn ensure_value_bound(value: &Value) -> Result<(), AguiProtocolError> {
    serde_json::to_vec(value)
        .ok()
        .filter(|bytes| bytes.len() <= MAX_AGUI_EVENT_BYTES)
        .map(|_| ())
        .ok_or(AguiProtocolError::TooLarge)
}

fn parse_text_role(value: Option<&Value>) -> Result<AguiRole, AguiProtocolError> {
    let value = match value {
        None => "assistant",
        Some(Value::String(value)) => value.as_str(),
        Some(_) => return Err(AguiProtocolError::InvalidEvent),
    };
    match value {
        "developer" => Ok(AguiRole::Developer),
        "system" => Ok(AguiRole::System),
        "assistant" => Ok(AguiRole::Assistant),
        "user" => Ok(AguiRole::User),
        _ => Err(AguiProtocolError::InvalidEvent),
    }
}

fn reasoning_id(object: &Map<String, Value>) -> Result<String, AguiProtocolError> {
    required_bounded_string(object, "messageId")
}

fn patch_array(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Vec<Value>, AguiProtocolError> {
    let patch = object
        .get(field)
        .and_then(Value::as_array)
        .filter(|patch| patch.len() <= MAX_AGUI_COLLECTION_ITEMS)
        .cloned()
        .ok_or(AguiProtocolError::InvalidPatch)?;
    ensure_value_bound(&Value::Array(patch.clone()))?;
    Ok(patch)
}

fn validate_interrupts(value: Option<&Value>) -> Result<Vec<AguiInterrupt>, AguiProtocolError> {
    let values = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 256)
        .ok_or(AguiProtocolError::InvalidEvent)?;
    let mut interrupts = Vec::with_capacity(values.len());
    for value in values {
        let object = value.as_object().ok_or(AguiProtocolError::InvalidEvent)?;
        let id = required_bounded_string(object, "id")?;
        let reason = required_bounded_string(object, "reason")?;
        let message = optional_bounded_string(object, "message")?;
        let tool_call_id = optional_bounded_string(object, "toolCallId")?;
        let expires_at = optional_bounded_string(object, "expiresAt")?;
        for field in ["responseSchema", "metadata"] {
            if object.get(field).is_some_and(|value| !value.is_object()) {
                return Err(AguiProtocolError::InvalidEvent);
            }
        }
        interrupts.push(AguiInterrupt {
            id,
            reason,
            message,
            tool_call_id,
            response_schema: object.get("responseSchema").cloned(),
            expires_at,
            metadata: object.get("metadata").cloned(),
        });
    }
    Ok(interrupts)
}

fn validate_messages(value: Option<&Value>) -> Result<Vec<Value>, AguiProtocolError> {
    let messages = value
        .and_then(Value::as_array)
        .filter(|values| values.len() <= MAX_AGUI_COLLECTION_ITEMS)
        .ok_or(AguiProtocolError::InvalidEvent)?;
    for message in messages {
        let object = message.as_object().ok_or(AguiProtocolError::InvalidEvent)?;
        required_bounded_string(object, "id")?;
        let role = required_string(object, "role")?;
        match role {
            "developer" | "system" | "user" => {
                optional_bounded_string(object, "name")?;
                optional_bounded_string(object, "encryptedValue")?;
                required_bounded_string_allow_empty(object, "content")?;
            }
            "reasoning" => {
                optional_bounded_string(object, "encryptedValue")?;
                required_bounded_string_allow_empty(object, "content")?;
            }
            "assistant" => {
                optional_bounded_string(object, "name")?;
                optional_bounded_string(object, "encryptedValue")?;
                if let Some(content) = object.get("content") {
                    bounded_string(content.as_str().ok_or(AguiProtocolError::InvalidEvent)?)?;
                }
                if let Some(calls) = object.get("toolCalls") {
                    let calls = calls
                        .as_array()
                        .filter(|calls| calls.len() <= 256)
                        .ok_or(AguiProtocolError::InvalidEvent)?;
                    for call in calls {
                        let call = call.as_object().ok_or(AguiProtocolError::InvalidEvent)?;
                        required_bounded_string(call, "id")?;
                        if call.get("type").and_then(Value::as_str) != Some("function") {
                            return Err(AguiProtocolError::InvalidEvent);
                        }
                        let function = call
                            .get("function")
                            .and_then(Value::as_object)
                            .ok_or(AguiProtocolError::InvalidEvent)?;
                        required_bounded_string(function, "name")?;
                        let arguments = required_bounded_string_allow_empty(function, "arguments")?;
                        serde_json::from_str::<Value>(&arguments)
                            .ok()
                            .filter(Value::is_object)
                            .ok_or(AguiProtocolError::InvalidEvent)?;
                    }
                }
            }
            "tool" => {
                required_bounded_string_allow_empty(object, "content")?;
                required_bounded_string(object, "toolCallId")?;
                optional_bounded_string(object, "error")?;
                optional_bounded_string(object, "encryptedValue")?;
            }
            "activity" => {
                required_bounded_string(object, "activityType")?;
                object
                    .get("content")
                    .filter(|value| value.is_object())
                    .ok_or(AguiProtocolError::InvalidEvent)?;
            }
            _ => return Err(AguiProtocolError::InvalidEvent),
        }
    }
    ensure_value_bound(&Value::Array(messages.clone()))?;
    Ok(messages.clone())
}

/// Apply a bounded RFC 6902 patch atomically.
pub fn apply_patch(target: &mut Value, patch: &[Value]) -> Result<(), AguiProtocolError> {
    if patch.len() > MAX_AGUI_COLLECTION_ITEMS {
        return Err(AguiProtocolError::InvalidPatch);
    }
    let mut next = target.clone();
    for operation in patch {
        let operation = operation
            .as_object()
            .ok_or(AguiProtocolError::InvalidPatch)?;
        let op = operation
            .get("op")
            .and_then(Value::as_str)
            .ok_or(AguiProtocolError::InvalidPatch)?;
        let path = operation
            .get("path")
            .and_then(Value::as_str)
            .ok_or(AguiProtocolError::InvalidPatch)?;
        match op {
            "add" => add_value(
                &mut next,
                path,
                operation
                    .get("value")
                    .cloned()
                    .ok_or(AguiProtocolError::InvalidPatch)?,
            )?,
            "remove" => {
                remove_value(&mut next, path)?;
            }
            "replace" => {
                get_value(&next, path)?;
                remove_value(&mut next, path)?;
                add_value(
                    &mut next,
                    path,
                    operation
                        .get("value")
                        .cloned()
                        .ok_or(AguiProtocolError::InvalidPatch)?,
                )?;
            }
            "move" => {
                let from = operation
                    .get("from")
                    .and_then(Value::as_str)
                    .ok_or(AguiProtocolError::InvalidPatch)?;
                if path.starts_with(&format!("{from}/")) {
                    return Err(AguiProtocolError::InvalidPatch);
                }
                let value = get_value(&next, from)?.clone();
                remove_value(&mut next, from)?;
                add_value(&mut next, path, value)?;
            }
            "copy" => {
                let from = operation
                    .get("from")
                    .and_then(Value::as_str)
                    .ok_or(AguiProtocolError::InvalidPatch)?;
                let value = get_value(&next, from)?.clone();
                add_value(&mut next, path, value)?;
            }
            "test" => {
                if get_value(&next, path)?
                    != operation
                        .get("value")
                        .ok_or(AguiProtocolError::InvalidPatch)?
                {
                    return Err(AguiProtocolError::InvalidPatch);
                }
            }
            _ => return Err(AguiProtocolError::InvalidPatch),
        }
        ensure_value_bound(&next)?;
    }
    *target = next;
    Ok(())
}

fn pointer(path: &str) -> Result<Vec<String>, AguiProtocolError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if !path.starts_with('/') || path.len() > 4096 {
        return Err(AguiProtocolError::InvalidPatch);
    }
    path[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                if ch != '~' {
                    decoded.push(ch);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err(AguiProtocolError::InvalidPatch),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn get_value<'a>(target: &'a Value, path: &str) -> Result<&'a Value, AguiProtocolError> {
    let tokens = pointer(path)?;
    let mut current = target;
    for token in tokens {
        current = match current {
            Value::Object(object) => object.get(&token),
            Value::Array(array) => array_index(&token).and_then(|index| array.get(index)),
            _ => None,
        }
        .ok_or(AguiProtocolError::InvalidPatch)?;
    }
    Ok(current)
}

fn parent_mut<'a>(
    target: &'a mut Value,
    tokens: &[String],
) -> Result<(&'a mut Value, String), AguiProtocolError> {
    let (last, parents) = tokens.split_last().ok_or(AguiProtocolError::InvalidPatch)?;
    let mut current = target;
    for token in parents {
        current = match current {
            Value::Object(object) => object.get_mut(token),
            Value::Array(array) => array_index(token).and_then(|index| array.get_mut(index)),
            _ => None,
        }
        .ok_or(AguiProtocolError::InvalidPatch)?;
    }
    Ok((current, last.clone()))
}

fn add_value(target: &mut Value, path: &str, value: Value) -> Result<(), AguiProtocolError> {
    let tokens = pointer(path)?;
    if tokens.is_empty() {
        *target = value;
        return Ok(());
    }
    let (parent, token) = parent_mut(target, &tokens)?;
    match parent {
        Value::Object(object) => {
            object.insert(token, value);
            Ok(())
        }
        Value::Array(array) if token == "-" => {
            array.push(value);
            Ok(())
        }
        Value::Array(array) => {
            let index = array_index(&token)
                .filter(|index| *index <= array.len())
                .ok_or(AguiProtocolError::InvalidPatch)?;
            array.insert(index, value);
            Ok(())
        }
        _ => Err(AguiProtocolError::InvalidPatch),
    }
}

fn remove_value(target: &mut Value, path: &str) -> Result<Value, AguiProtocolError> {
    let tokens = pointer(path)?;
    if tokens.is_empty() {
        return Ok(core::mem::take(target));
    }
    let (parent, token) = parent_mut(target, &tokens)?;
    match parent {
        Value::Object(object) => object.remove(&token).ok_or(AguiProtocolError::InvalidPatch),
        Value::Array(array) => array_index(&token)
            .filter(|index| *index < array.len())
            .map(|index| array.remove(index))
            .ok_or(AguiProtocolError::InvalidPatch),
        _ => Err(AguiProtocolError::InvalidPatch),
    }
}

fn array_index(token: &str) -> Option<usize> {
    if token == "0"
        || (!token.is_empty()
            && !token.starts_with('0')
            && token.bytes().all(|byte| byte.is_ascii_digit()))
    {
        token.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::BTreeSet;

    use super::*;
    use openbot_application::{
        ProviderMessage, ProviderMessageRole, ProviderRemoteResume, ProviderRemoteResumeEntry,
        ProviderRemoteResumeStatus, ProviderToolCall,
    };

    fn event(decoder: &mut AguiDecoder, value: Value) -> Vec<AguiEvent> {
        decoder.ingest(&value.to_string()).unwrap()
    }

    #[test]
    fn all_pinned_families_validate_and_project_without_trusting_open_payloads() {
        let mut decoder = AguiDecoder::new("thread-1", "run-1", json!({"count":0})).unwrap();
        let mut output = Vec::new();
        for value in [
            json!({"type":"RUN_STARTED","threadId":"thread-1","runId":"run-1"}),
            json!({"type":"STEP_STARTED","stepName":"plan"}),
            json!({"type":"TEXT_MESSAGE_START","messageId":"m1","role":"assistant"}),
            json!({"type":"TEXT_MESSAGE_CONTENT","messageId":"m1","delta":"hello"}),
            json!({"type":"TEXT_MESSAGE_END","messageId":"m1"}),
            json!({"type":"TOOL_CALL_START","toolCallId":"c1","toolCallName":"remember"}),
            json!({"type":"TOOL_CALL_ARGS","toolCallId":"c1","delta":"{\"content\":"}),
            json!({"type":"TOOL_CALL_ARGS","toolCallId":"c1","delta":"\"tea\"}"}),
            json!({"type":"TOOL_CALL_END","toolCallId":"c1"}),
            json!({"type":"TOOL_CALL_RESULT","messageId":"tr1","toolCallId":"c1","content":"ok","role":"tool"}),
            json!({"type":"STATE_SNAPSHOT","snapshot":{"count":0}}),
            json!({"type":"STATE_DELTA","delta":[{"op":"replace","path":"/count","value":1}]}),
            json!({"type":"MESSAGES_SNAPSHOT","messages":[{"id":"u1","role":"user","content":"hi"}]}),
            json!({"type":"ACTIVITY_SNAPSHOT","messageId":"a1","activityType":"PLAN","content":{"done":false}}),
            json!({"type":"ACTIVITY_DELTA","messageId":"a1","activityType":"PLAN","patch":[{"op":"replace","path":"/done","value":true}]}),
            json!({"type":"REASONING_START","messageId":"r1"}),
            json!({"type":"REASONING_MESSAGE_START","messageId":"rm1","role":"reasoning"}),
            json!({"type":"REASONING_MESSAGE_CONTENT","messageId":"rm1","delta":"summary"}),
            json!({"type":"REASONING_MESSAGE_END","messageId":"rm1"}),
            json!({"type":"REASONING_END","messageId":"r1"}),
            json!({"type":"REASONING_ENCRYPTED_VALUE","subtype":"message","entityId":"m1","encryptedValue":"opaque"}),
            json!({"type":"THINKING_START","title":"legacy"}),
            json!({"type":"THINKING_TEXT_MESSAGE_START"}),
            json!({"type":"THINKING_TEXT_MESSAGE_CONTENT","delta":"legacy summary"}),
            json!({"type":"THINKING_TEXT_MESSAGE_END"}),
            json!({"type":"THINKING_END"}),
            json!({"type":"RAW","event":{"permission":"ignore"},"source":"vendor"}),
            json!({"type":"CUSTOM","name":"future","value":{"actor":"admin"}}),
            json!({"type":"STEP_FINISHED","stepName":"plan"}),
            json!({"type":"RUN_FINISHED","threadId":"thread-1","runId":"run-1","outcome":{"type":"success"}}),
        ] {
            output.extend(event(&mut decoder, value));
        }
        assert_eq!(decoder.finish(), Ok(Vec::new()));
        assert_eq!(decoder.state(), &json!({"count":1}));
        assert_eq!(decoder.activity("a1"), Some(&json!({"done":true})));
        assert_eq!(
            decoder.messages(),
            [json!({"id":"u1","role":"user","content":"hi"})]
        );
        assert!(output.iter().any(|event| matches!(
            event,
            AguiEvent::ToolCompleted { arguments, .. } if arguments == &json!({"content":"tea"})
        )));
        assert!(
            output
                .iter()
                .any(|event| matches!(event, AguiEvent::Raw { .. }))
        );
        assert!(
            output
                .iter()
                .any(|event| matches!(event, AguiEvent::Custom { .. }))
        );
    }

    #[test]
    fn convenience_chunks_expand_and_interrupt_is_the_only_terminal() {
        let mut decoder = AguiDecoder::new("t", "r", json!({})).unwrap();
        event(
            &mut decoder,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            event(
                &mut decoder,
                json!({"type":"TEXT_MESSAGE_CHUNK","messageId":"m","delta":"a"})
            ),
            [
                AguiEvent::TextStarted {
                    id: "m".to_owned(),
                    role: AguiRole::Assistant,
                    name: None
                },
                AguiEvent::TextDelta {
                    id: "m".to_owned(),
                    delta: "a".to_owned()
                },
            ]
        );
        event(
            &mut decoder,
            json!({"type":"TOOL_CALL_CHUNK","toolCallId":"c","toolCallName":"x","delta":"{}"}),
        );
        let output = event(
            &mut decoder,
            json!({
                "type":"RUN_FINISHED","threadId":"t","runId":"r",
                "outcome":{"type":"interrupt","interrupts":[{"id":"i1","reason":"approval"}]}
            }),
        );
        assert!(
            output
                .iter()
                .any(|event| matches!(event, AguiEvent::ToolCompleted { id, .. } if id == "c"))
        );
        assert!(matches!(
            output.last(),
            Some(AguiEvent::RunInterrupted { .. })
        ));
        assert_eq!(decoder.finish(), Ok(Vec::new()));

        let mut malformed = AguiDecoder::new("t", "r", json!({})).unwrap();
        event(
            &mut malformed,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            malformed.ingest(
                &json!({
                    "type":"RUN_FINISHED","threadId":"t","runId":"r",
                    "outcome":{"type":"interrupt","interrupts":[{
                        "id":"i1","reason":"approval","metadata":[]
                    }]}
                })
                .to_string()
            ),
            Err(AguiProtocolError::InvalidEvent)
        );
    }

    #[test]
    fn malformed_order_identity_patch_and_partial_tool_json_fail_closed() {
        let mut decoder = AguiDecoder::new("t", "r", json!({"a":1})).unwrap();
        assert_eq!(
            decoder.ingest(r#"{"type":"RUN_STARTED","threadId":"t","runId":"r","timestamp":null}"#),
            Err(AguiProtocolError::InvalidEvent)
        );
        assert_eq!(
            decoder.ingest(r#"{"type":"TEXT_MESSAGE_CONTENT","messageId":"m","delta":"x"}"#),
            Err(AguiProtocolError::InvalidSequence)
        );
        assert_eq!(
            decoder.ingest(r#"{"type":"RUN_STARTED","threadId":"other","runId":"r"}"#),
            Err(AguiProtocolError::IdentityMismatch)
        );
        event(
            &mut decoder,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            decoder.ingest(
                &json!({"type":"TEXT_MESSAGE_START","messageId":"m","role":null}).to_string()
            ),
            Err(AguiProtocolError::InvalidEvent)
        );
        assert_eq!(
            decoder.ingest(
                &json!({"type":"STATE_DELTA","delta":[{"op":"remove","path":"/missing"}]})
                    .to_string()
            ),
            Err(AguiProtocolError::InvalidPatch)
        );
        event(
            &mut decoder,
            json!({"type":"TOOL_CALL_START","toolCallId":"c","toolCallName":"x"}),
        );
        event(
            &mut decoder,
            json!({"type":"TOOL_CALL_ARGS","toolCallId":"c","delta":"{"}),
        );
        assert_eq!(
            decoder.ingest(&json!({"type":"TOOL_CALL_END","toolCallId":"c"}).to_string()),
            Err(AguiProtocolError::InvalidEvent)
        );
    }

    #[test]
    fn run_error_closes_an_in_progress_remote_stream_and_rejects_every_later_event() {
        let mut decoder = AguiDecoder::new("t", "r", json!({})).unwrap();
        event(
            &mut decoder,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        event(
            &mut decoder,
            json!({"type":"TEXT_MESSAGE_START","messageId":"m"}),
        );
        event(
            &mut decoder,
            json!({"type":"TOOL_CALL_CHUNK","toolCallId":"partial","toolCallName":"x","delta":"{"}),
        );
        assert_eq!(
            event(
                &mut decoder,
                json!({"type":"RUN_ERROR","message":"","code":"remote_failed"})
            ),
            [AguiEvent::RunError {
                message: String::new(),
                code: Some("remote_failed".to_owned())
            }]
        );
        assert_eq!(decoder.finish(), Ok(Vec::new()));
        assert_eq!(
            decoder.ingest(r#"{"type":"CUSTOM","name":"late","value":1}"#),
            Err(AguiProtocolError::InvalidSequence)
        );
    }

    #[test]
    fn reasoning_chunk_expands_to_a_closed_message_before_the_next_event() {
        let mut decoder = AguiDecoder::new("t", "r", json!({})).unwrap();
        event(
            &mut decoder,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            event(
                &mut decoder,
                json!({"type":"REASONING_MESSAGE_CHUNK","messageId":"rm","delta":"summary"})
            ),
            [
                AguiEvent::ReasoningMessageStarted {
                    id: "rm".to_owned()
                },
                AguiEvent::ReasoningDelta {
                    id: "rm".to_owned(),
                    delta: "summary".to_owned()
                }
            ]
        );
        let output = event(
            &mut decoder,
            json!({"type":"RUN_FINISHED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            output,
            [
                AguiEvent::ReasoningMessageEnded {
                    id: "rm".to_owned()
                },
                AguiEvent::RunFinished
            ]
        );

        let mut malformed = AguiDecoder::new("t", "r", json!({})).unwrap();
        event(
            &mut malformed,
            json!({"type":"RUN_STARTED","threadId":"t","runId":"r"}),
        );
        assert_eq!(
            malformed.ingest(
                &json!({"type":"REASONING_START","thinkingId":"not-in-0.0.57"}).to_string()
            ),
            Err(AguiProtocolError::InvalidEvent)
        );
    }

    #[test]
    fn json_patch_supports_all_six_rfc6902_operations_atomically() {
        let mut value = json!({"a":[1,2],"copy":{"x":1},"test":true});
        apply_patch(
            &mut value,
            &[
                json!({"op":"add","path":"/a/-","value":3}),
                json!({"op":"replace","path":"/a/0","value":0}),
                json!({"op":"copy","from":"/copy/x","path":"/copied"}),
                json!({"op":"move","from":"/copy/x","path":"/moved"}),
                json!({"op":"test","path":"/test","value":true}),
                json!({"op":"remove","path":"/test"}),
            ],
        )
        .unwrap();
        assert_eq!(value, json!({"a":[0,2,3],"copy":{},"copied":1,"moved":1}));

        let before = value.clone();
        assert_eq!(
            apply_patch(
                &mut value,
                &[json!({"op":"replace","path":"/missing","value":1})]
            ),
            Err(AguiProtocolError::InvalidPatch)
        );
        assert_eq!(value, before, "failed patch must be atomic");
        assert_eq!(
            apply_patch(&mut value, &[json!({"op":"remove","path":"/a/01"})]),
            Err(AguiProtocolError::InvalidPatch)
        );
        assert_eq!(value, before, "non-canonical array index must be atomic");
    }

    #[test]
    fn run_agent_input_encoder_preserves_closed_tool_pairs_and_has_no_identity_input_slots() {
        let encoded = encode_run_agent_input(
            "thread-1",
            "run-1",
            &[
                ProviderMessage {
                    role: ProviderMessageRole::System,
                    content: "standing".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                },
                ProviderMessage {
                    role: ProviderMessageRole::Assistant,
                    content: String::new(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: vec![ProviderToolCall {
                        call_id: "call-1".to_owned(),
                        name: "remember".to_owned(),
                        arguments: json!({"content":"tea"}),
                    }],
                },
                ProviderMessage {
                    role: ProviderMessageRole::Tool,
                    content: "remembered".to_owned(),
                    tool_call_id: Some("call-1".to_owned()),
                    tool_name: Some("remember".to_owned()),
                    tool_calls: Vec::new(),
                },
            ],
            &[ProviderToolDefinition {
                name: "remember".to_owned(),
                description: "remember".to_owned(),
                input_schema: json!({"type":"object"}),
            }],
            json!({"openbotBotId":"bot-1"}),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(body["messages"][1]["toolCalls"][0]["id"], "call-1");
        assert_eq!(body["messages"][2]["toolCallId"], "call-1");
        assert_eq!(body["tools"][0]["parameters"]["type"], "object");
        assert_eq!(body["forwardedProps"]["openbotBotId"], "bot-1");
        assert!(body.get("actor").is_none());
        assert!(body.get("capability").is_none());
        assert!(body.get("target").is_none());
    }

    #[test]
    fn resumed_run_input_has_new_run_lineage_and_exact_closed_entries() {
        let resume = ProviderRemoteResume::new(
            "run-1".to_owned(),
            "run-2".to_owned(),
            vec![
                ProviderRemoteResumeEntry::new(
                    "interrupt-1".to_owned(),
                    ProviderRemoteResumeStatus::Resolved,
                    Some(json!({"approved":true})),
                )
                .unwrap(),
                ProviderRemoteResumeEntry::new(
                    "interrupt-2".to_owned(),
                    ProviderRemoteResumeStatus::Cancelled,
                    None,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let messages = [ProviderMessage {
            role: ProviderMessageRole::System,
            content: "standing".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }];
        let encoded = encode_run_agent_input_with_resume(
            "thread-1",
            "run-2",
            &messages,
            &[],
            json!({"openbotRun":"signed-local-run"}),
            Some("run-1"),
            Some(&resume),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(body["runId"], "run-2");
        assert_eq!(body["parentRunId"], "run-1");
        assert_eq!(body["resume"][0]["interruptId"], "interrupt-1");
        assert_eq!(body["resume"][0]["status"], "resolved");
        assert_eq!(body["resume"][0]["payload"]["approved"], true);
        assert_eq!(body["resume"][1]["status"], "cancelled");
        assert!(body["resume"][1].get("payload").is_none());
        assert_eq!(body["forwardedProps"]["openbotRun"], "signed-local-run");
        assert_eq!(
            encode_run_agent_input_with_resume(
                "thread-1",
                "run-2",
                &messages,
                &[],
                json!({}),
                Some("wrong-parent"),
                Some(&resume),
            ),
            Err(AguiProtocolError::InvalidSequence)
        );
    }

    #[test]
    fn pinned_event_type_catalog_has_thirty_three_unique_literals() {
        assert_eq!(AGUI_EVENT_TYPES.len(), 33);
        assert_eq!(
            AGUI_EVENT_TYPES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            33
        );
    }
}
