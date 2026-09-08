//! Native channel conversation: atomic snapshot, durable SSE replay/live, and idle sends.

#![cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, unused_variables)
)]

use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet};

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest, ThreadRunCancellationState};
use openbot_contracts::command::{
    ChannelDetail, ThreadConversationSnapshot, ThreadForegroundRunState, ThreadHistoryMessage,
    ThreadHistoryRole, ThreadRunAnchor, ThreadRunEvent, ThreadRunEventKind,
};
use openbot_contracts::components::{
    ComponentHumanDecisionAnswer, PendingComponentHumanDecision,
    compiled_component_parameter_schema,
};
use openbot_contracts::ids::{BotId, RunId, ThreadId};
use openbot_contracts::remote_interrupt::{
    PendingRemoteInterrupt, RemoteInterruptAnswer, RemoteInterruptAnswerStatus,
};
use openbot_contracts::sandboxed::is_sandboxed_component_name;
use openbot_contracts::text::trim_ecmascript;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredConnection, DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
use crate::api::mint_run_id;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    answer_component_human_decision, answer_remote_interrupt, begin_thread_run_with_skills,
    cancel_thread_run, list_pending_component_human_decisions, list_pending_remote_interrupts,
    load_thread_conversation, mint_thread_id, thread_event_stream_path,
};
use crate::features::agents::{AgentPresence, AgentPresenceState};
use crate::features::channels::composer::queue::{QueueAction, QueuedMessage, reduce_queue};
use crate::features::channels::composer::skills::{SkillComposer, SkillPicker};
use crate::features::channels::markdown::{MarkdownBody, StreamingMarkdownBody};
use crate::features::computer::workspace::{ComputerWorkspace, WorkspaceActivity};
use crate::features::gallery::{ConversationComponent, GalleryFrame, HumanDecisionCard};
use crate::features::memory::remember::{RememberDialog, RememberReview, RememberTarget};
use crate::features::threads::tool_name::read_tool_name;
use crate::features::threads::tool_result::for_display;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Avatar, AvatarSize, Bubble, BubbleKind, Button, ButtonSize, ButtonVariant, IconSize, IconView,
    Message, MessageAlign, MessageAvatar, MessageContent, MessageFooter, MessageHeader,
    MessageScroller, MessageScrollerButton, MessageScrollerContent, MessageScrollerItem,
    MessageScrollerViewport, Textarea,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast as _;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use web_sys::{Event, EventSource, MessageEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranscriptKind {
    User,
    Assistant,
    ToolCall,
    ToolResult,
    Component,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptComponent {
    name: String,
    provider_call_id: String,
    arguments: serde_json::Value,
    result: Option<String>,
    error_code: Option<String>,
    agent_id: Option<BotId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptLine {
    id: String,
    kind: TranscriptKind,
    content: String,
    component: Option<TranscriptComponent>,
    selected_skill_slugs: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalNotice {
    Failed,
    Cancelled,
    ReconciliationRequired,
}

impl TerminalNotice {
    #[cfg(test)]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConversationState {
    messages: Vec<TranscriptLine>,
    active_run_id: Option<RunId>,
    active_run_state: Option<ThreadForegroundRunState>,
    active_run_cancellable: bool,
    streaming_text: String,
    cursor: Option<u64>,
    terminal_notice: Option<TerminalNotice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveEffect {
    None,
    ReloadSnapshot,
}

/// Closed composer Stop inputs. Every field is a fact this mount already holds; the control is
/// never derived from a raw provider/HTTP error or from an actor identity sent by the client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StopControl {
    /// A local send is in flight or awaiting retry, so no new control may be minted.
    input_locked: bool,
    /// A durable cancellation request minted by this mount is still unacknowledged.
    cancelling_request: bool,
    /// An empty draft is what turns the primary control from Send into Stop.
    draft_empty: bool,
    /// Snapshot fact: this actor may mint the **first** durable cancellation request.
    cancellable: bool,
    /// Durable foreground projection; `Cancelling` keeps Stop visible but inert.
    run_state: Option<ThreadForegroundRunState>,
}

impl StopControl {
    /// Stop replaces Send exactly while the durable facts show a stoppable or stopping foreground.
    const fn visible(self) -> bool {
        self.draft_empty
            && (self.cancellable
                || matches!(self.run_state, Some(ThreadForegroundRunState::Cancelling))
                || self.cancelling_request)
    }

    /// Stop is actionable only for the first request this actor is allowed to mint; a run already
    /// `Cancelling` (here or on another replica) is observable but not re-requestable from the GUI.
    const fn enabled(self) -> bool {
        !self.input_locked && !self.cancelling_request && self.draft_empty && self.cancellable
    }
}

/// A durable retry owns its Agent/message already, so an empty or now-unselected composer must not
/// disable the only button that can replay it. Editing remains locked separately by `input_locked`.
const fn send_control_disabled(
    submitting: bool,
    channel_active: bool,
    has_selected_agent: bool,
    snapshot_error: bool,
    loading: bool,
    draft_empty: bool,
    has_resumable: bool,
) -> bool {
    submitting
        || !channel_active
        || snapshot_error
        || loading
        || (!has_resumable && (!has_selected_agent || draft_empty))
}

/// A parked queue drains on exactly one busy -> idle edge, never into an inactive channel and
/// never twice for the same edge. `previous` is the last observed in-flight fact of this mount.
const fn should_drain_queue(
    previous: bool,
    in_flight: bool,
    channel_active: bool,
    queue_empty: bool,
) -> bool {
    previous && !in_flight && channel_active && !queue_empty
}

impl ConversationState {
    fn install_snapshot(&mut self, snapshot: ThreadConversationSnapshot) {
        self.messages = project_history(&snapshot.messages);
        self.active_run_id = snapshot.active_run_id;
        self.active_run_state = snapshot.active_run_state;
        self.active_run_cancellable = snapshot.active_run_cancellable;
        self.streaming_text = snapshot.active_run_text;
        self.cursor = snapshot.last_event_sequence;
        match self.active_run_state {
            Some(ThreadForegroundRunState::ReconciliationRequired) => {
                self.terminal_notice = Some(TerminalNotice::ReconciliationRequired);
            }
            Some(
                ThreadForegroundRunState::Queued
                | ThreadForegroundRunState::Running
                | ThreadForegroundRunState::Cancelling,
            ) => self.terminal_notice = None,
            None => {}
        }
    }
}

fn apply_live_event(
    state: &mut ConversationState,
    expected_thread: &ThreadId,
    event: &ThreadRunEvent,
) -> Result<LiveEffect, ()> {
    if &event.thread_id != expected_thread || event.terminal != event.event_type.is_terminal() {
        return Err(());
    }
    if state
        .cursor
        .is_some_and(|cursor| event.event_sequence <= cursor)
    {
        return Ok(LiveEffect::None);
    }
    if state
        .cursor
        .is_some_and(|cursor| cursor.checked_add(1) != Some(event.event_sequence))
    {
        return Ok(LiveEffect::ReloadSnapshot);
    }
    state.cursor = Some(event.event_sequence);
    match event.event_type {
        ThreadRunEventKind::Started => {
            // 本 mount 已经从 durable begin receipt 学到过这个 run 的 cancellable 事实。若在这里
            // 抹掉再靠一次全量 reload 恢复，每个 turn 都要多拆一次 SSE、多闪一次 loading，并在
            // 那一帧里把 Send/Stop 一起禁用 —— 事实没变，不该有这次往返。
            let already_tracked = state.active_run_id.as_ref() == Some(&event.run_id);
            state.active_run_id = Some(event.run_id.clone());
            state.active_run_state = Some(ThreadForegroundRunState::Running);
            state.streaming_text.clear();
            state.terminal_notice = None;
            if already_tracked {
                Ok(LiveEffect::None)
            } else {
                // 另一 tab / 另一副本发起的 run：本 mount 没有权威依据，cancellable 只能来自
                // durable snapshot，绝不沿用上一个 run 的值。
                state.active_run_cancellable = false;
                Ok(LiveEffect::ReloadSnapshot)
            }
        }
        ThreadRunEventKind::SemanticChunk => {
            if state.active_run_id.as_ref() != Some(&event.run_id) {
                return Ok(LiveEffect::ReloadSnapshot);
            }
            let Some(channel) = event
                .payload
                .get("channel")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(());
            };
            let Some(delta) = event
                .payload
                .get("delta")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(());
            };
            match channel {
                "text" => state.streaming_text.push_str(delta),
                "reasoning" => {}
                _ => return Err(()),
            }
            Ok(LiveEffect::None)
        }
        ThreadRunEventKind::Checkpoint => {
            if event
                .payload
                .get("kind")
                .and_then(serde_json::Value::as_str)
                == Some("remote_agui_projection")
            {
                if remote_projection_is_quarantined(&event.payload) {
                    Ok(LiveEffect::None)
                } else {
                    Err(())
                }
            } else {
                // A tool checkpoint materializes a durable assistant/tool pair. Reload so the
                // completed component replaces any pending surface before resampling finishes.
                Ok(LiveEffect::ReloadSnapshot)
            }
        }
        ThreadRunEventKind::Completed => {
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = None;
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::Failed => {
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::Failed);
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::Cancelled => {
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::Cancelled);
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::ReconciliationRequired => {
            state.active_run_id = Some(event.run_id.clone());
            state.active_run_state = Some(ThreadForegroundRunState::ReconciliationRequired);
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::ReconciliationRequired);
            Ok(LiveEffect::ReloadSnapshot)
        }
    }
}

fn remote_projection_is_quarantined(payload: &serde_json::Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if object.get("kind").and_then(serde_json::Value::as_str) != Some("remote_agui_projection")
        || object.get("source").and_then(serde_json::Value::as_str) != Some("remote_ag_ui")
        || object.get("untrusted").and_then(serde_json::Value::as_bool) != Some(true)
    {
        return false;
    }
    if object.get("retained").and_then(serde_json::Value::as_bool) == Some(false) {
        return object.len() == 4;
    }
    let family = object.get("family").and_then(serde_json::Value::as_str);
    let known_family = matches!(
        family,
        Some(
            "state"
                | "messages"
                | "activity"
                | "step_started"
                | "step_finished"
                | "tool_result"
                | "raw"
                | "custom"
        )
    );
    known_family
        && object.len() == 7
        && object.contains_key("untrustedKey")
        && object.contains_key("untrustedType")
        && object.contains_key("untrustedValue")
        && [object.get("untrustedKey"), object.get("untrustedType")]
            .into_iter()
            .flatten()
            .all(|value| {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|value| !value.is_empty() && !value.as_bytes().contains(&0))
            })
}

fn project_history(messages: &[ThreadHistoryMessage]) -> Vec<TranscriptLine> {
    let mut projected = Vec::new();
    let mut pending_components = BTreeMap::<String, usize>::new();
    for message in messages {
        match message.role {
            ThreadHistoryRole::System => {}
            ThreadHistoryRole::User => projected.push(TranscriptLine {
                id: message.id.clone(),
                kind: TranscriptKind::User,
                content: message.content.clone(),
                component: None,
                selected_skill_slugs: message.selected_skill_slugs.clone(),
            }),
            ThreadHistoryRole::Assistant => {
                if !message.content.is_empty() {
                    projected.push(TranscriptLine {
                        id: message.id.clone(),
                        kind: TranscriptKind::Assistant,
                        content: message.content.clone(),
                        component: None,
                        selected_skill_slugs: Vec::new(),
                    });
                }
                if let Some(tool_calls) = &message.tool_calls {
                    let mut names = Vec::new();
                    for call in tool_calls {
                        let Some((call_id, name, arguments)) = durable_tool_call(call) else {
                            continue;
                        };
                        if compiled_component_parameter_schema(&name).is_some()
                            || is_sandboxed_component_name(&name)
                        {
                            let index = projected.len();
                            projected.push(TranscriptLine {
                                id: format!("{}:{call_id}", message.id),
                                kind: TranscriptKind::Component,
                                content: name.clone(),
                                selected_skill_slugs: Vec::new(),
                                component: Some(TranscriptComponent {
                                    name,
                                    provider_call_id: call_id.clone(),
                                    arguments,
                                    result: None,
                                    error_code: Some("component_result_missing".to_owned()),
                                    agent_id: message.agent_id.clone(),
                                }),
                            });
                            pending_components.insert(call_id, index);
                        } else {
                            let display = read_tool_name(&name);
                            names.push(display.detail.map_or(display.label.clone(), |detail| {
                                format!("{} · {detail}", display.label)
                            }));
                        }
                    }
                    if !names.is_empty() {
                        projected.push(TranscriptLine {
                            id: format!("{}:tools", message.id),
                            kind: TranscriptKind::ToolCall,
                            content: names.join("\n"),
                            component: None,
                            selected_skill_slugs: Vec::new(),
                        });
                    }
                }
            }
            ThreadHistoryRole::Tool => {
                if let Some(index) = message
                    .tool_call_id
                    .as_ref()
                    .and_then(|call_id| pending_components.remove(call_id))
                {
                    if let Some(component) = projected[index].component.as_mut() {
                        component.error_code = if message.tool_name.as_deref()
                            == Some(component.name.as_str())
                            && message.agent_id == component.agent_id
                        {
                            component.result = Some(message.content.clone());
                            message.tool_error_code.clone()
                        } else {
                            Some("component_result_mismatch".to_owned())
                        };
                    }
                } else {
                    projected.push(TranscriptLine {
                        id: message.id.clone(),
                        kind: TranscriptKind::ToolResult,
                        content: for_display(&message.content),
                        component: None,
                        selected_skill_slugs: Vec::new(),
                    });
                }
            }
        }
    }
    projected
}

fn durable_tool_call(call: &serde_json::Value) -> Option<(String, String, serde_json::Value)> {
    let call_id = call.get("id")?.as_str()?.to_owned();
    let function = call.get("function")?.as_object()?;
    let name = function.get("name")?.as_str()?.to_owned();
    let arguments = function.get("arguments")?.clone();
    Some((call_id, name, arguments))
}

#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct PendingTurn {
    thread_id: ThreadId,
    run_id: RunId,
    agent_id: BotId,
    message: String,
    selected_skill_slugs: Vec<String>,
}

/// Data-backed channel transcript using the shared native thread conversation surface.
#[component]
pub fn ChannelConversation(
    /// Current membership-authorized channel projection from the Server.
    channel: ChannelDetail,
) -> impl IntoView {
    let selected_agent = channel.agent_ids.first().cloned();
    let agent_seed = selected_agent.as_ref().map_or_else(
        || channel.id.as_str().to_owned(),
        |id| id.as_str().to_owned(),
    );
    view! {
        <ConversationSurface
            thread=channel.thread_id
            agent_id=selected_agent
            agent_name=channel.name
            agent_seed
            channel_active=channel.active
            anchor=ThreadRunAnchor::Channel { channel_id: channel.id }
            fresh_thread=false
        />
    }
}

/// Direct-Bot transcript/new-turn surface sharing the exact channel runtime state machine.
#[component]
pub fn DirectBotConversation(
    /// Server-minted thread selected by the per-Agent remembered-thread controller.
    thread: ThreadId,
    /// Current Server-authorized runnable Agent projection.
    agent: AgentProfile,
    /// The Server minted this identity, but no first run has persisted it yet.
    fresh: bool,
) -> impl IntoView {
    view! {
        <ConversationSurface
            thread=Some(thread)
            agent_id=Some(agent.id)
            agent_name=agent.name
            agent_seed=agent.avatar_seed
            channel_active=true
            anchor=ThreadRunAnchor::DirectBot
            fresh_thread=fresh
        />
    }
}

#[component]
fn ConversationSurface(
    thread: Option<ThreadId>,
    agent_id: Option<BotId>,
    agent_name: String,
    agent_seed: String,
    channel_active: bool,
    anchor: ThreadRunAnchor,
    fresh_thread: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let run_anchor = StoredValue::new(anchor);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = run_anchor;
    let agent_id = StoredValue::new(agent_id);
    let streaming_agent_seed = StoredValue::new(agent_seed.clone());
    let streaming_agent_name = StoredValue::new(agent_name.clone());
    let thread_id = RwSignal::new(thread);
    let allow_missing_snapshot = RwSignal::new(fresh_thread);
    let state = RwSignal::new(ConversationState::default());
    let loading = RwSignal::new(true);
    let snapshot_error = RwSignal::new(false);
    let stream_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    install_conversation_sync(
        thread_id,
        state,
        loading,
        snapshot_error,
        stream_error,
        reload_generation,
        allow_missing_snapshot,
    );
    let human_decisions = RwSignal::new(Vec::<PendingComponentHumanDecision>::new());
    let human_decision_answers =
        RwSignal::new(BTreeMap::<String, ComponentHumanDecisionAnswer>::new());
    let human_decision_in_flight = RwSignal::new(BTreeSet::<String>::new());
    let human_decision_failures = RwSignal::new(BTreeSet::<String>::new());
    let human_decision_load_error = RwSignal::new(false);
    install_component_human_decision_sync(
        human_decisions,
        human_decision_answers,
        human_decision_load_error,
    );
    let remote_interrupts = RwSignal::new(Vec::<PendingRemoteInterrupt>::new());
    let remote_interrupt_in_flight = RwSignal::new(BTreeSet::<String>::new());
    let remote_interrupt_failures = RwSignal::new(BTreeSet::<String>::new());
    let remote_interrupt_load_error = RwSignal::new(false);
    install_remote_interrupt_sync(remote_interrupts, remote_interrupt_load_error);
    Effect::new(move |_| {
        let snapshot = state.get();
        let durable_provider_calls = snapshot
            .messages
            .iter()
            .filter_map(|message| {
                message.component.as_ref().and_then(|component| {
                    component
                        .result
                        .as_ref()
                        .map(|_| &component.provider_call_id)
                })
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let answered = human_decision_answers.get();
        if answered.is_empty() {
            return;
        }
        let remove = human_decisions
            .get()
            .into_iter()
            .filter(|decision| {
                answered.contains_key(&decision.decision_id)
                    && (durable_provider_calls.contains(&decision.provider_call_id)
                        || snapshot.active_run_id.as_ref() != Some(&decision.run_id))
            })
            .map(|decision| decision.decision_id)
            .collect::<BTreeSet<_>>();
        if remove.is_empty() {
            return;
        }
        human_decisions.update(|decisions| {
            decisions.retain(|decision| !remove.contains(&decision.decision_id));
        });
        human_decision_answers.update(|answers| answers.retain(|id, _| !remove.contains(id)));
        human_decision_in_flight.update(|ids| ids.retain(|id| !remove.contains(id)));
        human_decision_failures.update(|ids| ids.retain(|id| !remove.contains(id)));
    });

    let remember_review = RememberReview::new();
    let on_remember = UnsyncCallback::new(move |(message_id, content): (String, String)| {
        if let Some(thread) = thread_id.get_untracked() {
            remember_review.review(RememberTarget {
                thread,
                message_id,
                content,
            });
        }
    });
    let draft = RwSignal::new(String::new());
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || agent_id.get_value()),
        "channel-message",
    );
    let queued = RwSignal::new(Vec::<QueuedMessage>::new());
    let queue_skills_invalid = Signal::derive(move || {
        let mut slugs = Vec::new();
        for slug in queued
            .get()
            .iter()
            .flat_map(|q| &q.command_ids)
            .chain(skill_composer.selected.get().iter())
        {
            if !slugs.contains(slug) {
                slugs.push(slug.clone());
            }
        }
        !openbot_contracts::command::valid_selected_skill_slugs(&slugs)
    });
    let submitting = RwSignal::new(false);
    let cancelling_request = RwSignal::new(false);
    let send_error = RwSignal::new(false);
    let cancel_error = RwSignal::new(false);
    let resumable = RwSignal::new(None::<PendingTurn>);
    Effect::new(move |_| {
        let Some(attempt) = resumable.get() else {
            return;
        };
        if state.get().active_run_id.as_ref() == Some(&attempt.run_id) {
            resumable.set(None);
            skill_composer.clear();
            send_error.set(false);
        }
    });
    let busy = Signal::derive(move || state.get().active_run_id.is_some() || submitting.get());
    let input_locked = Signal::derive(move || submitting.get() || resumable.get().is_some());
    let textarea_disabled = Signal::derive(move || input_locked.get() || !channel_active);
    let send_disabled = Signal::derive(move || {
        send_control_disabled(
            submitting.get(),
            channel_active,
            agent_id.get_value().is_some(),
            snapshot_error.get(),
            loading.get(),
            trim_ecmascript(&draft.get()).is_empty(),
            resumable.get().is_some(),
        ) || (resumable.get().is_none()
            && (skill_composer.invalid.get() || queue_skills_invalid.get()))
    });
    let stop_control = Signal::derive(move || {
        let snapshot = state.get();
        StopControl {
            input_locked: input_locked.get(),
            cancelling_request: cancelling_request.get(),
            draft_empty: trim_ecmascript(&draft.get()).is_empty(),
            cancellable: snapshot.active_run_cancellable,
            run_state: snapshot.active_run_state,
        }
    });
    let can_stop = Signal::derive(move || stop_control.get().enabled());
    let show_stop = Signal::derive(move || stop_control.get().visible());
    let stop_disabled = Signal::derive(move || !can_stop.get());
    let send_now = UnsyncCallback::new(
        move |(requested_agent, message, selected_skill_slugs): (BotId, String, Vec<String>)| {
            if submitting.get_untracked()
                || state.get_untracked().active_run_id.is_some()
                || !channel_active
            {
                return;
            }
            if resumable.get_untracked().is_none() && trim_ecmascript(&message).is_empty() {
                return;
            }
            submitting.set(true);
            send_error.set(false);
            #[cfg(target_arch = "wasm32")]
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let was_retry = resumable.get_untracked().is_some();
                let attempt = match resumable.get_untracked() {
                    Some(attempt) => attempt,
                    None => {
                        let resolved_thread = match thread_id.get_untracked() {
                            Some(thread) => thread,
                            None => match mint_thread_id().await {
                                Ok(thread) => thread,
                                Err(_) => {
                                    send_error.set(true);
                                    submitting.set(false);
                                    return;
                                }
                            },
                        };
                        let attempt = PendingTurn {
                            thread_id: resolved_thread,
                            run_id: mint_run_id(),
                            agent_id: requested_agent,
                            message,
                            selected_skill_slugs,
                        };
                        resumable.set(Some(attempt.clone()));
                        attempt
                    }
                };
                match begin_thread_run_with_skills(
                    &attempt.thread_id,
                    &attempt.agent_id,
                    &attempt.run_id,
                    run_anchor.get_value(),
                    &attempt.message,
                    &attempt.selected_skill_slugs,
                )
                .await
                {
                    Ok(_) => {
                        allow_missing_snapshot.set(false);
                        thread_id.set(Some(attempt.thread_id));
                        state.update(|state| {
                            state.active_run_id = Some(attempt.run_id);
                            state.active_run_state = Some(ThreadForegroundRunState::Running);
                            state.active_run_cancellable = true;
                            state.streaming_text.clear();
                            state.terminal_notice = None;
                        });
                        if draft.get_untracked() == attempt.message
                            && skill_composer.selected.get_untracked()
                                == attempt.selected_skill_slugs
                        {
                            skill_composer.clear();
                        }
                        resumable.set(None);
                        reload_generation.update(|value| *value = value.saturating_add(1));
                    }
                    Err(error) => {
                        if !was_retry
                            && matches!(
                                error,
                                crate::api::ApiError::NotFound
                                    | crate::api::ApiError::Forbidden
                                    | crate::api::ApiError::Unauthorized
                            )
                        {
                            resumable.set(None);
                            skill_composer.reload();
                        }
                        send_error.set(true);
                        reload_generation.update(|value| *value = value.saturating_add(1));
                    }
                }
                submitting.set(false);
            });
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = (requested_agent, message, selected_skill_slugs);
                submitting.set(false);
                send_error.set(true);
            }
        },
    );
    let component_ask_disabled = Signal::derive(move || {
        submitting.get()
            || resumable.get().is_some()
            || state.get().active_run_id.is_some()
            || !channel_active
            || snapshot_error.get()
            || loading.get()
    });
    let ask_from_component = UnsyncCallback::new(move |(agent_id, message): (BotId, String)| {
        if component_ask_disabled.get_untracked() || trim_ecmascript(&message).is_empty() {
            return;
        }
        send_now.run((agent_id, message, Vec::new()));
    });
    let answer_human_decision = UnsyncCallback::new(
        move |(decision_id, answer): (String, ComponentHumanDecisionAnswer)| {
            if human_decision_in_flight.with_untracked(|ids| ids.contains(&decision_id)) {
                return;
            }
            human_decision_in_flight.update(|ids| {
                ids.insert(decision_id.clone());
            });
            human_decision_failures.update(|ids| {
                ids.remove(&decision_id);
            });
            #[cfg(target_arch = "wasm32")]
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match answer_component_human_decision(&decision_id, &answer).await {
                    Ok(resolved) => {
                        human_decision_answers.update(|answers| {
                            answers.insert(decision_id.clone(), resolved.answer);
                        });
                    }
                    Err(_) => {
                        human_decision_failures.update(|ids| {
                            ids.insert(decision_id.clone());
                        });
                    }
                }
                human_decision_in_flight.update(|ids| {
                    ids.remove(&decision_id);
                });
            });
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = answer;
                human_decision_failures.update(|ids| {
                    ids.insert(decision_id.clone());
                });
                human_decision_in_flight.update(|ids| {
                    ids.remove(&decision_id);
                });
            }
        },
    );
    let answer_remote = UnsyncCallback::new(
        move |(request_id, answer): (String, RemoteInterruptAnswer)| {
            if remote_interrupt_in_flight.with_untracked(|ids| ids.contains(&request_id)) {
                return;
            }
            remote_interrupt_in_flight.update(|ids| {
                ids.insert(request_id.clone());
            });
            remote_interrupt_failures.update(|ids| {
                ids.remove(&request_id);
            });
            #[cfg(target_arch = "wasm32")]
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match answer_remote_interrupt(&request_id, &answer).await {
                    Ok(_) => remote_interrupts.update(|interrupts| {
                        interrupts.retain(|interrupt| interrupt.request_id != request_id);
                    }),
                    Err(_) => remote_interrupt_failures.update(|ids| {
                        ids.insert(request_id.clone());
                    }),
                }
                remote_interrupt_in_flight.update(|ids| {
                    ids.remove(&request_id);
                });
            });
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = answer;
                remote_interrupt_failures.update(|ids| {
                    ids.insert(request_id.clone());
                });
                remote_interrupt_in_flight.update(|ids| {
                    ids.remove(&request_id);
                });
            }
        },
    );
    let submit = UnsyncCallback::new(move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        if let Some(attempt) = resumable.get_untracked() {
            send_now.run((
                attempt.agent_id,
                attempt.message,
                attempt.selected_skill_slugs,
            ));
            return;
        }
        let composer_draft = skill_composer.compose();
        if composer_draft.is_empty {
            return;
        }
        let queue_id = mint_run_id().as_str().to_owned();
        let current = queued.get_untracked();
        let transition = reduce_queue(
            &current,
            QueueAction::Submit {
                id: &queue_id,
                draft: &composer_draft,
                busy: busy.get_untracked(),
            },
        );
        let next_queue = transition.queue.into_owned();
        let run = transition.run.map(|run| run.into_owned());
        queued.set(next_queue);
        if busy.get_untracked() {
            skill_composer.clear();
        }
        if let Some(run) = run
            && let Some(agent_id) = agent_id.get_value()
        {
            send_now.run((agent_id, run.text, run.command_ids));
        }
    });
    let stop = UnsyncCallback::new(move |_| {
        if !can_stop.get_untracked() {
            return;
        }
        let Some(thread) = thread_id.get_untracked() else {
            return;
        };
        let Some(run) = state.get_untracked().active_run_id else {
            return;
        };
        cancelling_request.set(true);
        cancel_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match cancel_thread_run(&thread, &run).await {
                Ok(reply) => {
                    if matches!(
                        reply.state,
                        ThreadRunCancellationState::Requested
                            | ThreadRunCancellationState::AlreadyRequested
                    ) {
                        state.update(|state| {
                            if state.active_run_id.as_ref() == Some(&run) {
                                state.active_run_state = Some(ThreadForegroundRunState::Cancelling);
                                state.active_run_cancellable = false;
                            }
                        });
                    }
                    reload_generation.update(|value| *value = value.saturating_add(1));
                }
                Err(_) => {
                    cancel_error.set(true);
                    reload_generation.update(|value| *value = value.saturating_add(1));
                }
            }
            cancelling_request.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (thread, run);
            cancelling_request.set(false);
            cancel_error.set(true);
        }
    });
    // `send_now` 用 `spawn_local_scoped_with_cancellation`，任务绑定的是**调用时**的 reactive
    // owner。若从 Effect 体内调用，这个 owner 就是该 Effect 本次运行的 owner；而 send 本身会写
    // `submitting` 与 `state.active_run_id`，两者都被下面 Effect 追踪的 `busy` 依赖 —— Effect 立刻
    // 重跑并 dispose 上一次的 owner，把刚发出的 send 连同末尾的 `submitting.set(false)` 一起取消。
    // 结果是排队消息永远发不出去，且 `submitting` 卡在 true 让整个 Composer 死锁。改成在组件 owner
    // 里执行：它活过每一次 Effect 运行，与用户点击 Send 走的是同一个 owner。
    let composer_owner = Owner::current();
    let was_in_flight = RwSignal::new(false);
    Effect::new(move |_| {
        let in_flight = busy.get();
        let previous = was_in_flight.get_untracked();
        was_in_flight.set(in_flight);
        if !should_drain_queue(
            previous,
            in_flight,
            channel_active,
            queued.get_untracked().is_empty(),
        ) {
            return;
        }
        let current = queued.get_untracked();
        let transition = reduce_queue(&current, QueueAction::Settle);
        let next_queue = transition.queue.into_owned();
        let run = transition.run.map(|run| run.into_owned());
        queued.set(next_queue);
        if let Some(run) = run {
            let Some(agent_id) = agent_id.get_value() else {
                return;
            };
            match composer_owner.as_ref() {
                Some(owner) => owner.with(|| send_now.run((agent_id, run.text, run.command_ids))),
                None => send_now.run((agent_id, run.text, run.command_ids)),
            }
        }
    });
    let retry_snapshot = move |_| {
        reload_generation.update(|value| *value = value.saturating_add(1));
    };
    let visible_human_decisions = Signal::derive(move || {
        let active = state.get().active_run_id;
        human_decisions
            .get()
            .into_iter()
            .filter(|decision| active.as_ref() == Some(&decision.run_id))
            .collect::<Vec<_>>()
    });
    let visible_remote_interrupts = Signal::derive(move || {
        let active = state.get().active_run_id;
        remote_interrupts
            .get()
            .into_iter()
            .filter(|interrupt| {
                active
                    .as_ref()
                    .is_some_and(|run| run.as_str() == interrupt.run_id)
            })
            .collect::<Vec<_>>()
    });

    view! {
        <div class="ob-channel-conversation">
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || snapshot_error.get()>
                <div class="ob-alert" role="alert">
                    <span>{move || t!(i18n, channels.conversation_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry_snapshot
                    >{move || t!(i18n, common.retry)}</Button>
                </div>
            </Show>
            <Show when=move || stream_error.get() && !snapshot_error.get()>
                <p class="ob-alert" role="status">{move || t!(i18n, channels.conversation_stream_error)}</p>
            </Show>
            <Show when=move || human_decision_load_error.get() && state.get().active_run_id.is_some()>
                <p class="ob-alert" role="status">{move || t!(i18n, gallery.decision_load_error)}</p>
            </Show>
            <Show when=move || remote_interrupt_load_error.get() && state.get().active_run_id.is_some()>
                <p class="ob-alert" role="status">{move || t!(i18n, channels.remote_interrupt_load_error)}</p>
            </Show>
            <MessageScroller
                id="channel-transcript"
                aria_label=move || t_string!(i18n, channels.transcript_label).to_owned()
            >
                <MessageScrollerViewport>
                    <MessageScrollerContent busy=busy>
                        <Show when=move || {
                            !loading.get()
                                && state.get().messages.is_empty()
                                && state.get().streaming_text.is_empty()
                                && visible_human_decisions.get().is_empty()
                                && visible_remote_interrupts.get().is_empty()
                        }>
                            <p class="ob-page-empty">{move || t!(i18n, channels.conversation_empty)}</p>
                        </Show>
                        <For
                            each=move || state.get().messages
                            key=|message| (message.id.clone(), message.content.clone(), message.component.as_ref().and_then(|c| c.result.clone()), message.component.as_ref().and_then(|c| c.error_code.clone()))
                            children={
                                let agent_seed = agent_seed.clone();
                                let agent_name = agent_name.clone();
                                move |message| view! {
                                    <TranscriptMessage
                                        message
                                        agent_seed=agent_seed.clone()
                                        agent_name=agent_name.clone()
                                        on_component_ask=ask_from_component
                                        component_ask_disabled
                                        on_remember
                                        memory_available=thread_id.get().is_some()
                                    />
                                }
                            }
                        />
                        <For
                            each=move || visible_human_decisions.get()
                            key=|decision| decision.decision_id.clone()
                            children={
                                let agent_name = agent_name.clone();
                                move |decision| view! {
                                    <PendingHumanDecisionMessage
                                        decision
                                        agent_name=agent_name.clone()
                                        answers=human_decision_answers
                                        in_flight=human_decision_in_flight
                                        failures=human_decision_failures
                                        on_answer=answer_human_decision
                                    />
                                }
                            }
                        />
                        <For
                            each=move || visible_remote_interrupts.get()
                            key=|interrupt| interrupt.request_id.clone()
                            children={
                                let agent_name = agent_name.clone();
                                move |interrupt| view! {
                                    <PendingRemoteInterruptMessage
                                        interrupt
                                        agent_name=agent_name.clone()
                                        in_flight=remote_interrupt_in_flight
                                        failures=remote_interrupt_failures
                                        on_answer=answer_remote
                                    />
                                }
                            }
                        />
                        <Show when=move || !state.get().streaming_text.is_empty()>
                            {move || state.get().active_run_id.map(|run_id| view! {
                                <MessageScrollerItem
                                    message_id=transcript_dom_id(run_id.as_str())
                                >
                                    <div data-streaming-message="">
                                        <Message
                                            aria_label=move || t_string!(i18n, channels.streaming_reply_label).to_owned()
                                        >
                                            <MessageAvatar>
                                                <span aria-hidden="true">
                                                    <Avatar
                                                        principal_id=streaming_agent_seed.get_value()
                                                        name=streaming_agent_name.get_value()
                                                        size=AvatarSize::Small
                                                    />
                                                </span>
                                            </MessageAvatar>
                                            <MessageContent>
                                                <MessageHeader>{streaming_agent_name.get_value()}</MessageHeader>
                                                <Bubble kind=BubbleKind::Assistant>
                                                    <StreamingMarkdownBody content=Signal::derive(move || state.get().streaming_text)/>
                                                </Bubble>
                                            </MessageContent>
                                        </Message>
                                    </div>
                                </MessageScrollerItem>
                            })}
                        </Show>
                        <Show when=move || {
                            busy.get()
                                && state.get().streaming_text.is_empty()
                                && visible_human_decisions.get().is_empty()
                                && visible_remote_interrupts.get().is_empty()
                                && !matches!(
                                    state.get().active_run_state,
                                    Some(
                                        ThreadForegroundRunState::Cancelling
                                            | ThreadForegroundRunState::ReconciliationRequired
                                    )
                                )
                        }>
                            <div class="ob-conversation-thinking" role="status">
                                <AgentPresence state=Signal::derive(move || AgentPresenceState::Thinking) />
                                <span>{move || t!(i18n, channels.tool_running)}</span>
                            </div>
                        </Show>
                        <Show when=move || {
                            cancelling_request.get()
                                || matches!(
                                    state.get().active_run_state,
                                    Some(ThreadForegroundRunState::Cancelling)
                                )
                        }>
                            <p class="ob-conversation-cancelling" role="status">
                                {move || t!(i18n, channels.cancelling)}
                            </p>
                        </Show>
                        <Show when=move || state.get().terminal_notice.is_some()>
                            <p class="ob-alert" role="status">{move || terminal_text(i18n, state.get().terminal_notice)}</p>
                        </Show>
                        <For
                            each=move || queued.get()
                            key=|message| message.id.clone()
                            children=move |message| {
                                let queue_id = message.id.clone();
                                let text = message.text.clone();
                                let visible_text = text.clone();
                                let remove_label = t_string!(
                                    i18n,
                                    channels.queued_remove_label,
                                    message = text
                                )
                                .to_owned();
                                view! {
                                    <MessageScrollerItem
                                        message_id=transcript_dom_id(&format!("queue:{queue_id}"))
                                    >
                                        <div class="ob-queued-message" data-queued-message="">
                                            <Message
                                                align=MessageAlign::End
                                                aria_label=move || t_string!(i18n, channels.queued_message_label).to_owned()
                                            >
                                                <MessageContent>
                                                    <Bubble kind=BubbleKind::User>
                                                        <div class="ob-skill-chips">{message.command_ids.into_iter().map(|slug| view! { <code>{format!("/{slug}")}</code> }).collect_view()}</div>
                                                        <p class="ob-transcript-text">{visible_text}</p>
                                                    </Bubble>
                                                    <MessageFooter>
                                                        <span role="status">{move || t!(i18n, channels.queued_status)}</span>
                                                        <Button
                                                            variant=ButtonVariant::Ghost
                                                            size=ButtonSize::Small
                                                            aria_label=remove_label
                                                            on_activate=move |_| {
                                                                let current = queued.get_untracked();
                                                                let transition = reduce_queue(
                                                                    &current,
                                                                    QueueAction::Remove { id: &queue_id },
                                                                );
                                                                queued.set(transition.queue.into_owned());
                                                            }
                                                        >{move || t!(i18n, channels.queued_remove)}</Button>
                                                    </MessageFooter>
                                                </MessageContent>
                                            </Message>
                                        </div>
                                    </MessageScrollerItem>
                                }
                            }
                        />
                    </MessageScrollerContent>
                </MessageScrollerViewport>
                <MessageScrollerButton
                    aria_label=move || t_string!(i18n, channels.transcript_back_to_bottom).to_owned()
                />
            </MessageScroller>
            <ComputerWorkspace activity=Signal::derive(move || {
                state.get().messages.into_iter().filter(|m| matches!(m.kind, TranscriptKind::ToolCall | TranscriptKind::ToolResult | TranscriptKind::Component)).rev().take(100).map(|m| {
                    let label = if m.kind == TranscriptKind::ToolResult { t_string!(i18n, channels.tool_result_label).to_owned() } else { m.content.chars().take(160).collect() };
                    let output = m.component.and_then(|c| c.result).unwrap_or(m.content).chars().take(32768).collect();
                    WorkspaceActivity { id: m.id, label, output }
                }).collect()
            }) running=Signal::derive(move || state.get().active_run_id.is_some())/>
            <RememberDialog review=remember_review/>
            <div class="ob-channel-composer">
                <div class="ob-skill-editor">
                <SkillPicker state=skill_composer disabled=textarea_disabled/>
                <Textarea
                    value=draft
                    id="channel-message"
                    aria_label=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                    placeholder=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                    disabled=textarea_disabled
                    on_submit=submit
                    combobox_controls="channel-skill-results"
                    combobox_open=skill_composer.open
                    active_descendant=skill_composer.active_descendant
                    on_keydown=UnsyncCallback::new(move |event| skill_composer.keyboard(event))
                />
                <Show when=move || !skill_composer.selected.get().is_empty() && trim_ecmascript(&draft.get()).is_empty()>
                    <p class="ob-page-empty">{move || t!(i18n, skills.task_required)}</p>
                </Show>
                <Show when=move || queue_skills_invalid.get()><p class="ob-alert" role="alert">{move || t!(i18n, skills.selection_limit)}</p></Show>
                </div>
                <Show
                    when=move || show_stop.get()
                    fallback=move || view! {
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            disabled=send_disabled
                            loading=submitting
                            on_activate=submit
                        >
                            <IconView icon=Icon::Send size=IconSize::Inline />
                            <span>{move || if resumable.get().is_some() {
                                t_string!(i18n, common.retry).to_owned()
                            } else if busy.get() {
                                t_string!(i18n, channels.composer_queue).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                    }
                >
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Medium
                        disabled=stop_disabled
                        loading=cancelling_request
                        aria_label=move || t_string!(i18n, channels.composer_stop).to_owned()
                        on_activate=stop
                    >
                        <IconView icon=Icon::CircleStop size=IconSize::Inline />
                        <span>{move || if cancelling_request.get()
                            || matches!(
                                state.get().active_run_state,
                                Some(ThreadForegroundRunState::Cancelling)
                            ) {
                                t_string!(i18n, channels.cancelling).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_stop).to_owned()
                            }}</span>
                    </Button>
                </Show>
            </div>
            <Show when=move || send_error.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, channels.send_error)}</p>
            </Show>
            <Show when=move || cancel_error.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, channels.cancel_error)}</p>
            </Show>
            <Show when=move || !channel_active>
                <p class="ob-page-empty">{move || t!(i18n, channels.detail_inactive)}</p>
            </Show>
        </div>
    }
}

#[component]
fn PendingRemoteInterruptMessage(
    interrupt: PendingRemoteInterrupt,
    agent_name: String,
    in_flight: RwSignal<BTreeSet<String>>,
    failures: RwSignal<BTreeSet<String>>,
    on_answer: UnsyncCallback<(String, RemoteInterruptAnswer)>,
) -> impl IntoView {
    let i18n = use_i18n();
    let request_id = interrupt.request_id.clone();
    let submitting_id = interrupt.request_id.clone();
    let failure_id = interrupt.request_id.clone();
    let resolve_id = interrupt.request_id.clone();
    let cancel_id = interrupt.request_id.clone();
    let title = interrupt.untrusted_reason;
    let message = interrupt.untrusted_message.unwrap_or_default();
    let has_message = !message.is_empty();
    let message = StoredValue::new(message);
    let agent_seed = interrupt.agent_id;
    let payload = RwSignal::new("{}".to_owned());
    let invalid_payload = RwSignal::new(false);
    let submitting = Signal::derive(move || in_flight.get().contains(&submitting_id));
    let failed = Signal::derive(move || failures.get().contains(&failure_id));
    let resolve = on_answer;
    let cancel = on_answer;
    let avatar_name = StoredValue::new(agent_name);
    view! {
        <MessageScrollerItem message_id=transcript_dom_id(&format!("interrupt:{request_id}"))>
            <Message aria_label=move || t_string!(i18n, channels.assistant_message_label).to_owned()>
                <MessageAvatar>
                    <span aria-hidden="true">
                        <Avatar
                            principal_id=agent_seed.clone()
                            name=avatar_name.get_value()
                            size=AvatarSize::Small
                        />
                    </span>
                </MessageAvatar>
                <MessageContent>
                    <MessageHeader>{avatar_name.get_value()}</MessageHeader>
                    <div data-remote-interrupt="" data-untrusted-remote-content="">
                        <GalleryFrame
                            title=title
                            caption=move || t_string!(i18n, channels.remote_interrupt_caption).to_owned()
                        >
                            <Show when=move || has_message>
                                <p class="ob-gallery-decision-summary">{message.get_value()}</p>
                            </Show>
                            <div class="ob-gallery-decision-controls">
                                <Textarea
                                    value=payload
                                    aria_label=move || t_string!(i18n, channels.remote_interrupt_payload_label).to_owned()
                                    disabled=submitting
                                    invalid=invalid_payload
                                />
                                <Show when=move || invalid_payload.get()>
                                    <p class="ob-gallery-decision-error" role="alert">
                                        {move || t!(i18n, channels.remote_interrupt_payload_invalid)}
                                    </p>
                                </Show>
                                <Show when=move || failed.get()>
                                    <p class="ob-gallery-decision-error" role="alert">
                                        {move || t!(i18n, channels.remote_interrupt_answer_error)}
                                    </p>
                                </Show>
                                <div class="ob-gallery-decision-actions">
                                    <Button
                                        variant=ButtonVariant::Primary
                                        size=ButtonSize::Small
                                        disabled=submitting
                                        loading=submitting
                                        on_activate=move |_| {
                                            let raw = trim_ecmascript(&payload.get_untracked()).to_owned();
                                            let parsed = if raw.is_empty() {
                                                Ok(None)
                                            } else {
                                                serde_json::from_str::<serde_json::Value>(&raw).map(Some)
                                            };
                                            match parsed {
                                                Ok(value) => {
                                                    invalid_payload.set(false);
                                                    resolve.run((
                                                        resolve_id.clone(),
                                                        RemoteInterruptAnswer {
                                                            status: RemoteInterruptAnswerStatus::Resolved,
                                                            payload: value,
                                                        },
                                                    ));
                                                }
                                                Err(_) => invalid_payload.set(true),
                                            }
                                        }
                                    >{move || t!(i18n, channels.remote_interrupt_submit)}</Button>
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Small
                                        disabled=submitting
                                        on_activate=move |_| cancel.run((
                                            cancel_id.clone(),
                                            RemoteInterruptAnswer {
                                                status: RemoteInterruptAnswerStatus::Cancelled,
                                                payload: None,
                                            },
                                        ))
                                    >{move || t!(i18n, channels.remote_interrupt_cancel)}</Button>
                                </div>
                            </div>
                        </GalleryFrame>
                    </div>
                </MessageContent>
            </Message>
        </MessageScrollerItem>
    }
}

#[component]
fn PendingHumanDecisionMessage(
    decision: PendingComponentHumanDecision,
    agent_name: String,
    answers: RwSignal<BTreeMap<String, ComponentHumanDecisionAnswer>>,
    in_flight: RwSignal<BTreeSet<String>>,
    failures: RwSignal<BTreeSet<String>>,
    on_answer: UnsyncCallback<(String, ComponentHumanDecisionAnswer)>,
) -> impl IntoView {
    let i18n = use_i18n();
    let decision_id = StoredValue::new(decision.decision_id.clone());
    let answer_id = decision.decision_id.clone();
    let submitting_id = decision.decision_id.clone();
    let failure_id = decision.decision_id.clone();
    let callback_id = decision.decision_id.clone();
    let answer = Signal::derive(move || answers.get().get(&answer_id).cloned());
    let submitting = Signal::derive(move || in_flight.get().contains(&submitting_id));
    let error = Signal::derive(move || failures.get().contains(&failure_id));
    let answer_callback = UnsyncCallback::new(move |answer| {
        on_answer.run((callback_id.clone(), answer));
    });
    let avatar_seed = StoredValue::new(decision.agent_id.as_str().to_owned());
    let avatar_name = StoredValue::new(agent_name);
    view! {
        <MessageScrollerItem
            message_id=transcript_dom_id(&format!("decision:{}", decision_id.get_value()))
        >
            <Message aria_label=move || t_string!(i18n, channels.assistant_message_label).to_owned()>
                <MessageAvatar>
                    <span aria-hidden="true">
                        <Avatar
                            principal_id=avatar_seed.get_value()
                            name=avatar_name.get_value()
                            size=AvatarSize::Small
                        />
                    </span>
                </MessageAvatar>
                <MessageContent>
                    <MessageHeader>{avatar_name.get_value()}</MessageHeader>
                    <HumanDecisionCard
                        name=decision.component_name
                        arguments=decision.arguments
                        answer
                        submitting
                        error
                        on_answer=answer_callback
                    />
                </MessageContent>
            </Message>
        </MessageScrollerItem>
    }
}

#[component]
fn TranscriptMessage(
    message: TranscriptLine,
    agent_seed: String,
    agent_name: String,
    on_component_ask: UnsyncCallback<(BotId, String)>,
    component_ask_disabled: Signal<bool>,
    on_remember: UnsyncCallback<(String, String)>,
    memory_available: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let remember_source = (message.id.clone(), message.content.clone());
    let can_remember = memory_available
        && matches!(
            message.kind,
            TranscriptKind::User | TranscriptKind::Assistant
        )
        && !message.content.trim().is_empty();
    let user = message.kind == TranscriptKind::User;
    let kind = message.kind;
    let content = message.content;
    let body = match message.component {
        Some(component) => view! {
            <ConversationComponent
                name=component.name
                arguments=component.arguments
                result=component.result
                error_code=component.error_code.or_else(|| {
                    component.agent_id.is_none().then(|| "component_agent_missing".to_owned())
                })
                agent_id=component.agent_id.unwrap_or_else(|| BotId::new("unavailable"))
                on_ask=on_component_ask
                ask_disabled=component_ask_disabled
            />
        }
        .into_any(),
        None => view! {
            <Bubble kind=if user { BubbleKind::User } else { BubbleKind::Assistant }>
                <div class="ob-skill-chips">{message.selected_skill_slugs.into_iter().map(|slug| view! { <code>{format!("/{slug}")}</code> }).collect_view()}</div>
                {if kind == TranscriptKind::Assistant { view! { <MarkdownBody content/> }.into_any() } else { view! { <p class="ob-transcript-text">{content}</p> }.into_any() }}
            </Bubble>
        }
        .into_any(),
    };
    let avatar_seed = StoredValue::new(agent_seed);
    let avatar_name = StoredValue::new(agent_name);
    let label = move || match kind {
        TranscriptKind::User => t_string!(i18n, channels.user_message_label).to_owned(),
        TranscriptKind::Assistant => t_string!(i18n, channels.assistant_message_label).to_owned(),
        TranscriptKind::ToolCall => t_string!(i18n, channels.tool_call_label).to_owned(),
        TranscriptKind::ToolResult => t_string!(i18n, channels.tool_result_label).to_owned(),
        TranscriptKind::Component => t_string!(i18n, channels.assistant_message_label).to_owned(),
    };
    view! {
        <MessageScrollerItem
            message_id=transcript_dom_id(&message.id)
            scroll_anchor=user
        >
            <Message
                align=if user { MessageAlign::End } else { MessageAlign::Start }
                aria_label=label
            >
                <MessageAvatar>
                    <span aria-hidden="true">
                        <Avatar
                            principal_id=if user { "current-user".to_owned() } else { avatar_seed.get_value() }
                            name=if user {
                                t_string!(i18n, channels.you).to_owned()
                            } else {
                                avatar_name.get_value()
                            }
                            size=AvatarSize::Small
                        />
                    </span>
                </MessageAvatar>
                <MessageContent>
                    <MessageHeader>{move || if user {
                        t_string!(i18n, channels.you).to_owned()
                    } else {
                        avatar_name.get_value()
                    }}</MessageHeader>
                    {body}
                    {can_remember.then(|| view! { <MessageFooter><Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| on_remember.run(remember_source.clone())>{move || t!(i18n, memory.remember_action)}</Button></MessageFooter> })}
                </MessageContent>
            </Message>
        </MessageScrollerItem>
    }
}

fn install_component_human_decision_sync(
    decisions: RwSignal<Vec<PendingComponentHumanDecision>>,
    answers: RwSignal<BTreeMap<String, ComponentHumanDecisionAnswer>>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        loop {
            match list_pending_component_human_decisions().await {
                Ok(page) => {
                    let local_answers = answers.get_untracked();
                    decisions.update(|current| {
                        merge_component_human_decisions(current, page.decisions, &local_answers);
                    });
                    load_error.set(false);
                }
                Err(_) => load_error.set(true),
            }
            component_human_decision_poll_delay().await;
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (decisions, answers);
        load_error.set(true);
    }
}

fn install_remote_interrupt_sync(
    interrupts: RwSignal<Vec<PendingRemoteInterrupt>>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        loop {
            match list_pending_remote_interrupts().await {
                Ok(page) => {
                    interrupts.set(page.interrupts);
                    load_error.set(false);
                }
                Err(_) => load_error.set(true),
            }
            component_human_decision_poll_delay().await;
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = interrupts;
        load_error.set(true);
    }
}

fn merge_component_human_decisions(
    current: &mut Vec<PendingComponentHumanDecision>,
    mut incoming: Vec<PendingComponentHumanDecision>,
    answers: &BTreeMap<String, ComponentHumanDecisionAnswer>,
) {
    for local in current.iter() {
        if answers.contains_key(&local.decision_id)
            && !incoming
                .iter()
                .any(|decision| decision.decision_id == local.decision_id)
        {
            incoming.push(local.clone());
        }
    }
    incoming.sort_by(|left, right| {
        (left.requested_at, &left.decision_id).cmp(&(right.requested_at, &right.decision_id))
    });
    *current = incoming;
}

#[cfg(target_arch = "wasm32")]
async fn component_human_decision_poll_delay() {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .expect("CSR component decision polling requires Window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1_000)
            .expect("browser rejected component decision polling timer");
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

fn transcript_dom_id(source: &str) -> String {
    let mut id = String::from("transcript-");
    for byte in Sha256::digest(source.as_bytes()) {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

fn terminal_text(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    notice: Option<TerminalNotice>,
) -> String {
    match notice {
        Some(TerminalNotice::Failed) => t_string!(i18n, channels.run_failed).to_owned(),
        Some(TerminalNotice::Cancelled) => t_string!(i18n, channels.run_cancelled).to_owned(),
        Some(TerminalNotice::ReconciliationRequired) => {
            t_string!(i18n, channels.run_reconciliation).to_owned()
        }
        None => String::new(),
    }
}

#[cfg(target_arch = "wasm32")]
struct EventConnection {
    source: EventSource,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _open: Closure<dyn FnMut(Event)>,
    _error: Closure<dyn FnMut(Event)>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for EventConnection {
    fn drop(&mut self) {
        self.source.close();
    }
}

#[allow(clippy::too_many_arguments)]
fn install_conversation_sync(
    thread_id: RwSignal<Option<ThreadId>>,
    state: RwSignal<ConversationState>,
    loading: RwSignal<bool>,
    snapshot_error: RwSignal<bool>,
    stream_error: RwSignal<bool>,
    generation: RwSignal<u64>,
    allow_missing_snapshot: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let connection = StoredValue::new_local(None::<EventConnection>);
        let desktop_connection = StoredValue::new_local(None::<DesktopStructuredConnection>);
        Effect::new(move |_| {
            let current_generation = generation.get();
            let current_thread = thread_id.get();
            connection.update_value(|current| {
                _ = current.take();
            });
            desktop_connection.update_value(|current| {
                _ = current.take();
            });
            snapshot_error.set(false);
            stream_error.set(false);
            let Some(thread) = current_thread else {
                state.set(ConversationState::default());
                loading.set(false);
                return;
            };
            if allow_missing_snapshot.get_untracked() {
                state.set(ConversationState::default());
                loading.set(false);
                return;
            }
            loading.set(true);
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let snapshot = load_thread_conversation(&thread).await;
                if generation.get_untracked() != current_generation
                    || thread_id.get_untracked().as_ref() != Some(&thread)
                {
                    return;
                }
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        loading.set(false);
                        snapshot_error.set(true);
                        return;
                    }
                };
                let cursor = snapshot.last_event_sequence;
                state.update(|state| state.install_snapshot(snapshot));
                loading.set(false);
                if is_tauri_host() {
                    let expected_thread = thread.clone();
                    let handlers = DesktopStructuredHandlers::new(
                        move |event| match apply_thread_stream_event(event, &expected_thread, state)
                        {
                            ThreadStreamOutcome::Keep => true,
                            ThreadStreamOutcome::Reload => false,
                            ThreadStreamOutcome::Error => {
                                stream_error.set(true);
                                false
                            }
                        },
                        move |_| stream_error.set(true),
                        move || stream_error.set(true),
                    );
                    match open_desktop_structured(
                        SubscriptionRequest::ThreadEvents {
                            thread_id: thread.clone(),
                            after_event_sequence: cursor,
                        },
                        handlers,
                    ) {
                        Ok(opened) => {
                            stream_error.set(false);
                            let finished = opened.finished_promise();
                            if generation.get_untracked() != current_generation
                                || thread_id.get_untracked().as_ref() != Some(&thread)
                            {
                                return;
                            }
                            desktop_connection.set_value(Some(opened));
                            _ = wasm_bindgen_futures::JsFuture::from(finished).await;
                        }
                        Err(()) => stream_error.set(true),
                    }
                    if generation.get_untracked() == current_generation
                        && thread_id.get_untracked().as_ref() == Some(&thread)
                    {
                        thread_reconnect_delay().await;
                        if generation.get_untracked() == current_generation {
                            generation.update(|value| *value = value.saturating_add(1));
                        }
                    }
                    return;
                }
                match open_event_source(&thread, cursor, state, stream_error, generation) {
                    Ok(opened) => {
                        if generation.get_untracked() == current_generation {
                            connection.set_value(Some(opened));
                        }
                    }
                    Err(()) => stream_error.set(true),
                }
            });
        });
        on_cleanup(move || {
            connection.update_value(|current| {
                _ = current.take();
            });
            desktop_connection.update_value(|current| {
                _ = current.take();
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        thread_id,
        state,
        loading,
        snapshot_error,
        stream_error,
        generation,
        allow_missing_snapshot,
    );
}

#[cfg(target_arch = "wasm32")]
enum ThreadStreamOutcome {
    Keep,
    Reload,
    Error,
}

#[cfg(target_arch = "wasm32")]
fn apply_thread_stream_event(
    event: AppEvent,
    expected_thread: &ThreadId,
    state: RwSignal<ConversationState>,
) -> ThreadStreamOutcome {
    match event {
        AppEvent::ThreadRunEvent(event) => {
            let effect = state.try_update(|state| apply_live_event(state, expected_thread, &event));
            match effect {
                Some(Ok(LiveEffect::ReloadSnapshot)) | Some(Err(())) => ThreadStreamOutcome::Reload,
                Some(Ok(LiveEffect::None)) => ThreadStreamOutcome::Keep,
                None => ThreadStreamOutcome::Error,
            }
        }
        AppEvent::ThreadStreamError { .. }
        | AppEvent::Heartbeat { .. }
        | AppEvent::ChannelActivity(_)
        | AppEvent::ChannelStreamError { .. }
        | AppEvent::ToolApprovalActivity(_)
        | AppEvent::ToolApprovalStreamError { .. } => ThreadStreamOutcome::Error,
    }
}

#[cfg(target_arch = "wasm32")]
async fn thread_reconnect_delay() {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .expect("CSR Desktop thread reconnect requires Window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 500)
            .expect("browser rejected Desktop thread reconnect timer");
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn open_event_source(
    thread: &ThreadId,
    cursor: Option<u64>,
    state: RwSignal<ConversationState>,
    stream_error: RwSignal<bool>,
    generation: RwSignal<u64>,
) -> Result<EventConnection, ()> {
    let path = thread_event_stream_path(thread, cursor).map_err(|_| ())?;
    let source = EventSource::new(&path).map_err(|_| ())?;
    let expected_thread = thread.clone();
    let event_source = source.clone();
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |message: MessageEvent| {
        let Some(text) = message.data().as_string() else {
            stream_error.set(true);
            event_source.close();
            return;
        };
        let Ok(event) = serde_json::from_str::<AppEvent>(&text) else {
            stream_error.set(true);
            event_source.close();
            return;
        };
        match apply_thread_stream_event(event, &expected_thread, state) {
            ThreadStreamOutcome::Keep => {}
            ThreadStreamOutcome::Reload => {
                generation.update(|value| *value = value.saturating_add(1));
            }
            ThreadStreamOutcome::Error => {
                stream_error.set(true);
                event_source.close();
            }
        }
    });
    source
        .add_event_listener_with_callback("thread_run_event", message.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    source
        .add_event_listener_with_callback("thread_stream_error", message.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    let open = Closure::<dyn FnMut(Event)>::new(move |_| stream_error.set(false));
    source
        .add_event_listener_with_callback("open", open.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    let error = Closure::<dyn FnMut(Event)>::new(move |_| stream_error.set(true));
    source
        .add_event_listener_with_callback("error", error.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    Ok(EventConnection {
        source,
        _message: message,
        _open: open,
        _error: error,
    })
}

#[cfg(test)]
mod tests {
    use openbot_contracts::command::ThreadRunEvent;
    use time::OffsetDateTime;

    use super::*;

    fn event(
        sequence: u64,
        kind: ThreadRunEventKind,
        payload: serde_json::Value,
    ) -> ThreadRunEvent {
        ThreadRunEvent {
            thread_id: ThreadId::new("thread-1"),
            run_id: RunId::new("run-1"),
            event_sequence: sequence,
            event_type: kind,
            payload,
            terminal: kind.is_terminal(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn snapshot_carries_durable_history_active_text_and_cursor_without_a_seed() {
        let mut state = ConversationState::default();
        state.install_snapshot(ThreadConversationSnapshot {
            messages: vec![ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "user-1".to_owned(),
                role: ThreadHistoryRole::User,
                content: "hello".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            }],
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            active_run_text: "partial".to_owned(),
            last_event_sequence: Some(3),
        });
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.streaming_text, "partial");
        assert_eq!(state.cursor, Some(3));
        assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
    }

    #[test]
    fn history_projects_user_assistant_tool_activity_but_not_system_prompt() {
        let lines = project_history(&[
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "system".to_owned(),
                role: ThreadHistoryRole::System,
                content: "secret standing instruction".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "user".to_owned(),
                role: ThreadHistoryRole::User,
                content: "hello".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "assistant".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![
                    serde_json::json!({"id":"call-1","function":{"name":"mcp__notes__search_notes","arguments":{}}}),
                ]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "tool".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: serde_json::to_string("found it").unwrap(),
                agent_id: None,
                tool_call_id: Some("call-1".to_owned()),
                tool_name: Some("mcp__notes__search_notes".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ]);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].kind, TranscriptKind::User);
        assert_eq!(lines[1].content, "Search notes");
        assert_eq!(lines[2].content, "found it");
        assert!(!format!("{lines:?}").contains("secret standing instruction"));
    }

    #[test]
    fn durable_component_call_and_result_pair_into_one_transcript_renderer() {
        let messages = [
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "component-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-call-1",
                    "type":"function",
                    "function":{
                        "name":"showQuote",
                        "arguments":{"quote":"Exact words","attribution":"the report"}
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "component-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: "The quotation is now on screen for the person.".to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-call-1".to_owned()),
                tool_name: Some("showQuote".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ];
        let lines = project_history(&messages);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].kind, TranscriptKind::Component);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "showQuote");
        assert_eq!(component.provider_call_id, "provider-call-1");
        assert_eq!(component.arguments["quote"], "Exact words");
        assert_eq!(
            component.result.as_deref(),
            Some("The quotation is now on screen for the person.")
        );
        assert_eq!(component.error_code, None);
        assert_eq!(component.agent_id, Some(BotId::new("bot-1")));

        let mut refused = messages;
        refused[1].tool_error_code = Some("component_withheld".to_owned());
        assert_eq!(
            project_history(&refused)[0]
                .component
                .as_ref()
                .unwrap()
                .error_code
                .as_deref(),
            Some("component_withheld")
        );

        refused[1].tool_error_code = None;
        refused[1].agent_id = Some(BotId::new("bot-2"));
        assert_eq!(
            project_history(&refused)[0]
                .component
                .as_ref()
                .unwrap()
                .error_code
                .as_deref(),
            Some("component_result_mismatch")
        );
    }

    #[test]
    fn durable_decision_result_is_retained_for_completed_renderer_replay() {
        let lines = project_history(&[
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "decision-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-choice-1",
                    "type":"function",
                    "function":{
                        "name":"askChoice",
                        "arguments":{
                            "title":"Where?",
                            "options":[{"id":"prod","label":"Production"}]
                        }
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "decision-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: r#"{"choice":"prod","label":"Production"}"#.to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-choice-1".to_owned()),
                tool_name: Some("askChoice".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ]);
        assert_eq!(lines.len(), 1);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "askChoice");
        assert_eq!(component.provider_call_id, "provider-choice-1");
        assert_eq!(
            component.result.as_deref(),
            Some(r#"{"choice":"prod","label":"Production"}"#)
        );
        assert_eq!(component.error_code, None);
    }

    #[test]
    fn durable_sandboxed_call_is_projected_by_exact_namespace_not_prefix_guess() {
        let messages = [
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "sandbox-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-sandbox-1",
                    "type":"function",
                    "function":{
                        "name":"custom_delivery_eta",
                        "arguments":{"title":"Tomorrow"}
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "sandbox-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: "It is now on screen for the person.".to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-sandbox-1".to_owned()),
                tool_name: Some("custom_delivery_eta".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ];
        let lines = project_history(&messages);
        assert_eq!(lines.len(), 1);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "custom_delivery_eta");
        assert_eq!(component.arguments, serde_json::json!({"title":"Tomorrow"}));
        assert_eq!(
            component.result.as_deref(),
            Some("It is now on screen for the person.")
        );
    }

    #[test]
    fn polling_keeps_a_locally_answered_card_until_its_durable_pair_arrives() {
        let pending = PendingComponentHumanDecision {
            decision_id: "decision-1".to_owned(),
            run_id: RunId::new("run-1"),
            provider_call_id: "provider-1".to_owned(),
            agent_id: BotId::new("bot-1"),
            component_name: "askApproval".to_owned(),
            arguments: serde_json::json!({"title":"Approve?","summary":"Summary"}),
            requested_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
        };
        let mut current = vec![pending.clone()];
        let answers = BTreeMap::from([(
            pending.decision_id.clone(),
            ComponentHumanDecisionAnswer::Approval(
                openbot_contracts::components::ComponentApprovalAnswer {
                    decision: openbot_contracts::components::ComponentApprovalDecision::Approved,
                    note: None,
                },
            ),
        )]);
        merge_component_human_decisions(&mut current, Vec::new(), &answers);
        assert_eq!(current, [pending]);
        merge_component_human_decisions(&mut current, Vec::new(), &BTreeMap::new());
        assert!(current.is_empty());
    }

    #[test]
    fn durable_retry_keeps_its_agent_and_is_not_disabled_by_an_empty_composer() {
        assert!(!send_control_disabled(
            false, true, false, false, false, true, true,
        ));
        assert!(send_control_disabled(
            false, true, true, false, false, true, false,
        ));
        let pending = PendingTurn {
            thread_id: ThreadId::new("thread-1"),
            run_id: RunId::new("run-1"),
            agent_id: BotId::new("bot-from-component"),
            message: "Exact follow-up".to_owned(),
            selected_skill_slugs: vec!["review".to_owned()],
        };
        assert_eq!(pending.agent_id.as_str(), "bot-from-component");
        assert_eq!(pending.message, "Exact follow-up");
    }

    #[test]
    fn live_text_is_ordered_deduplicated_and_terminal_requests_snapshot_reload() {
        let mut state = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":"hel"})
                ),
            ),
            Ok(LiveEffect::None)
        );
        _ = apply_live_event(
            &mut state,
            &ThreadId::new("thread-1"),
            &event(
                1,
                ThreadRunEventKind::SemanticChunk,
                serde_json::json!({"channel":"text","delta":"duplicate"}),
            ),
        );
        _ = apply_live_event(
            &mut state,
            &ThreadId::new("thread-1"),
            &event(
                2,
                ThreadRunEventKind::SemanticChunk,
                serde_json::json!({"channel":"reasoning","delta":"hidden"}),
            ),
        );
        assert_eq!(state.streaming_text, "hel");
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    3,
                    ThreadRunEventKind::Checkpoint,
                    serde_json::json!({
                        "kind":"remote_agui_projection",
                        "source":"remote_ag_ui",
                        "family":"raw",
                        "untrusted":true,
                        "untrustedKey":"remote",
                        "untrustedType":null,
                        "untrustedValue":{"permission":"forged-admin","text":"not transcript"}
                    })
                ),
            ),
            Ok(LiveEffect::None)
        );
        assert_eq!(state.streaming_text, "hel");
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    4,
                    ThreadRunEventKind::Completed,
                    serde_json::json!({"status":"completed"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(state.active_run_id.is_none());
    }

    #[test]
    fn remote_projection_checkpoint_requires_closed_untrusted_wrapper() {
        for (sequence, payload, expected) in [
            (
                1,
                serde_json::json!({
                    "kind":"remote_agui_projection",
                    "source":"remote_ag_ui",
                    "family":"custom",
                    "untrusted":false,
                    "untrustedKey":"event",
                    "untrustedType":null,
                    "untrustedValue":{}
                }),
                Err(()),
            ),
            (
                2,
                serde_json::json!({
                    "kind":"remote_agui_projection",
                    "source":"remote_ag_ui",
                    "retained":false,
                    "untrusted":true
                }),
                Ok(LiveEffect::None),
            ),
        ] {
            let mut state = ConversationState {
                active_run_id: Some(RunId::new("run-1")),
                cursor: Some(sequence - 1),
                ..ConversationState::default()
            };
            assert_eq!(
                apply_live_event(
                    &mut state,
                    &ThreadId::new("thread-1"),
                    &event(sequence, ThreadRunEventKind::Checkpoint, payload),
                ),
                expected
            );
            assert!(state.streaming_text.is_empty());
            assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
        }
    }

    #[test]
    fn gap_wrong_thread_and_invalid_payload_never_become_visible_text() {
        let mut state = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    2,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":"gap"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        let mut wrong = event(
            1,
            ThreadRunEventKind::SemanticChunk,
            serde_json::json!({"channel":"text","delta":"wrong"}),
        );
        wrong.thread_id = ThreadId::new("thread-2");
        assert_eq!(
            apply_live_event(&mut state, &ThreadId::new("thread-1"), &wrong),
            Err(())
        );
        assert!(state.streaming_text.is_empty());
    }

    #[test]
    fn transcript_dom_identity_is_bounded_and_not_controlled_by_message_id() {
        let id = transcript_dom_id("message/one?x=1\n");
        assert_eq!(id, transcript_dom_id("message/one?x=1\n"));
        assert!(id.len() <= 128);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }

    #[test]
    fn terminal_notices_are_closed_codes_and_cannot_carry_raw_error_words() {
        assert_eq!(TerminalNotice::Failed.as_str(), "failed");
        assert_eq!(TerminalNotice::Cancelled.as_str(), "cancelled");
        assert_eq!(
            TerminalNotice::ReconciliationRequired.as_str(),
            "reconciliation_required"
        );
        assert_eq!(core::mem::size_of::<TerminalNotice>(), 1);
    }

    #[test]
    fn stop_is_visible_only_on_durable_facts_and_actionable_only_for_the_first_request() {
        let stoppable = StopControl {
            input_locked: false,
            cancelling_request: false,
            draft_empty: true,
            cancellable: true,
            run_state: Some(ThreadForegroundRunState::Running),
        };
        assert!(stoppable.visible() && stoppable.enabled());

        // 草稿非空时reviewer件仍是 Send，Stop 既不显示也不可点。
        let drafting = StopControl {
            draft_empty: false,
            ..stoppable
        };
        assert!(!drafting.visible() && !drafting.enabled());

        // 非 run 发起者拿到的 snapshot `cancellable=false`：GUI 不得给出可点的假 Stop，
        // 与 durable_cancel_is_scoped_idempotent_… 的 PostgreSQL 拒绝面一致。
        let bystander = StopControl {
            cancellable: false,
            ..stoppable
        };
        assert!(!bystander.visible() && !bystander.enabled());

        // 本地 send 在飞 / 本 mount 请求未确认：可见但 inert，不会重复铸造请求。
        for inert in [
            StopControl {
                input_locked: true,
                ..stoppable
            },
            StopControl {
                cancelling_request: true,
                ..stoppable
            },
        ] {
            assert!(inert.visible() && !inert.enabled());
        }

        // 已经 Cancelling（可能来自另一副本）：只观察，不再请求。
        let cancelling = StopControl {
            cancellable: false,
            run_state: Some(ThreadForegroundRunState::Cancelling),
            ..stoppable
        };
        assert!(cancelling.visible() && !cancelling.enabled());

        assert!(!StopControl::default().visible() && !StopControl::default().enabled());
    }

    #[test]
    fn cancelling_snapshot_holds_the_foreground_without_claiming_children_stopped() {
        let mut state = ConversationState::default();
        state.install_snapshot(ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Cancelling),
            active_run_cancellable: false,
            active_run_text: "partial".to_owned(),
            last_event_sequence: Some(4),
        });
        // Cancelling 不是 terminal：foreground 仍被占，且不得提前投影 Cancelled。
        assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
        assert!(!state.active_run_cancellable);
        assert_eq!(state.terminal_notice, None);

        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    5,
                    ThreadRunEventKind::Cancelled,
                    serde_json::json!({"status":"cancelled"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(state.active_run_id.is_none());
        assert_eq!(state.terminal_notice, Some(TerminalNotice::Cancelled));

        // commit 未知时 foreground 继续被占，Cancelled 不得抹掉不确定性。
        let mut unknown = ConversationState::default();
        unknown.install_snapshot(ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(RunId::new("run-2")),
            active_run_state: Some(ThreadForegroundRunState::ReconciliationRequired),
            active_run_cancellable: false,
            active_run_text: String::new(),
            last_event_sequence: Some(9),
        });
        assert_eq!(unknown.active_run_id, Some(RunId::new("run-2")));
        assert_eq!(
            unknown.terminal_notice,
            Some(TerminalNotice::ReconciliationRequired)
        );
    }

    #[test]
    fn started_for_an_already_tracked_run_costs_no_reload_and_keeps_cancellable() {
        // 本地 send：begin receipt 先把 run 与 cancellable 落进 state，随后 SSE 才送到 Started。
        let mut local = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut local,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::Started,
                    serde_json::json!({"runId":"run-1"})
                ),
            ),
            Ok(LiveEffect::None)
        );
        assert!(local.active_run_cancellable);

        // 别处发起的 run：不得沿用上一个 run 的 cancellable，必须回 durable snapshot 取。
        let mut foreign = ConversationState {
            active_run_id: None,
            active_run_cancellable: true,
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut foreign,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::Started,
                    serde_json::json!({"runId":"run-1"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(!foreign.active_run_cancellable);
        assert_eq!(foreign.active_run_id, Some(RunId::new("run-1")));
    }

    #[test]
    fn parked_queue_drains_on_exactly_one_busy_to_idle_edge() {
        // 唯一排空点 = busy -> idle 边沿。
        assert!(should_drain_queue(true, false, true, false));
        // 从未 busy、仍 busy、频道不可用、队列为空：四条都不排空。
        assert!(!should_drain_queue(false, false, true, false));
        assert!(!should_drain_queue(true, true, true, false));
        assert!(!should_drain_queue(true, false, false, false));
        assert!(!should_drain_queue(true, false, true, true));
        // 同一边沿只触发一次：上一拍记下 in_flight=false 后 previous 变 false。
        assert!(!should_drain_queue(false, false, true, false));
    }
}
