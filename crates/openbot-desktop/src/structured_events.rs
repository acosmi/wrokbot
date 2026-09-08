//! Host-owned multiplexing from typed Desktop sessions into Tauri structured IPC channels.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::SubscriptionRequest;
use openbot_contracts::ids::ThreadId;
use tauri::ipc::Channel;

use crate::broker::DisconnectReason;
use crate::budget::{CRITICAL_EVENT_QUEUE_CAPACITY, DeliveryClass, EventQueueBudget};
use crate::cancel::CancellationToken;
use crate::event::{AppEventRef, GapCause, SequenceError, SequenceGap, SequenceTracker};
use crate::transport::{InProcessTransport, OpenSessionError};
use crate::window::{ThreadSubscriptions, WindowLabel};

pub use openbot_contracts::desktop::{
    DESKTOP_STRUCTURED_SUBSCRIPTION_ID_EXCLUSIVE_LIMIT, DesktopStructuredDeliveryClass,
    DesktopStructuredEventFrame, DesktopStructuredGapCause, DesktopStructuredSequenceGap,
    DesktopStructuredStreamKind, DesktopStructuredTerminalReason,
};

/// Maximum live or in-flight structured subscriptions owned by one actual Webview.
///
/// This is a resource bound, not authority: every subscription still passes the closed request and
/// host-observed window checks. Reusing §13.2's 256 command/event bound keeps a hostile renderer
/// from multiplying tasks and terminal reserves while preserving the product's ordinary few-stream
/// shape.
pub const MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW: usize = CRITICAL_EVENT_QUEUE_CAPACITY;

struct WindowAggregate {
    token: Arc<()>,
    queue_budget: Arc<EventQueueBudget>,
    closed: CancellationToken,
    pending: usize,
    registrations: BTreeMap<u64, WindowLabel>,
}

impl WindowAggregate {
    fn new() -> Self {
        Self {
            token: Arc::new(()),
            queue_budget: Arc::new(EventQueueBudget::spec_window()),
            closed: CancellationToken::new(),
            pending: 0,
            registrations: BTreeMap::new(),
        }
    }
}

type ActiveSubscriptions = BTreeMap<WindowLabel, WindowAggregate>;

struct PendingWindowOpen {
    active: Arc<Mutex<ActiveSubscriptions>>,
    window: WindowLabel,
    token: Arc<()>,
    queue_budget: Arc<EventQueueBudget>,
    closed: CancellationToken,
    settled: bool,
}

impl PendingWindowOpen {
    fn queue_budget(&self) -> Arc<EventQueueBudget> {
        Arc::clone(&self.queue_budget)
    }

    fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }

    fn commit(mut self, subscription_id: u64, internal_label: WindowLabel) -> bool {
        let committed = {
            let mut active = self
                .active
                .lock()
                .expect("structured subscription registry lock must not be poisoned");
            let Some(aggregate) = active.get_mut(&self.window) else {
                self.settled = true;
                return false;
            };
            if !Arc::ptr_eq(&aggregate.token, &self.token) {
                self.settled = true;
                return false;
            }
            aggregate.pending = aggregate
                .pending
                .checked_sub(1)
                .expect("committed structured open must own one pending slot");
            aggregate
                .registrations
                .insert(subscription_id, internal_label);
            true
        };
        self.settled = true;
        committed
    }
}

impl Drop for PendingWindowOpen {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        release_pending_open(&self.active, &self.window, &self.token);
    }
}

/// Opening a host-owned structured subscription failed.
#[derive(Debug, thiserror::Error)]
pub enum DesktopStructuredOpenError {
    /// Host subscription counter is exhausted; wrapping could collide with a live route.
    #[error("structured_subscription_counter_exhausted")]
    CounterExhausted,
    /// One actual Webview already owns the maximum live/in-flight structured subscriptions.
    #[error("structured_subscription_window_budget_exhausted")]
    WindowBudgetExhausted,
    /// The actual window was closed/replaced while its application subscription was opening.
    #[error("structured_subscription_window_closed")]
    WindowClosed,
    /// Application or in-process transport rejected the subscription.
    #[error(transparent)]
    Session(#[from] OpenSessionError),
}

/// Reading/projecting one subscription violated the sequence contract.
#[derive(Debug, thiserror::Error)]
pub enum DesktopStructuredFrameError {
    /// Broker sequence/gap invariants were violated.
    #[error(transparent)]
    Sequence(#[from] SequenceError),
    /// Sender disappeared without the mandatory terminal frame.
    #[error("structured_stream_ended_without_terminal")]
    MissingTerminal,
    /// Application emitted an event outside the closed requested stream family/scope.
    #[error("structured_stream_event_mismatch")]
    EventMismatch,
}

/// Final outcome of a Tauri Channel pump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopStructuredPumpExit {
    /// Terminal frame was delivered to the renderer.
    Terminal(DesktopStructuredTerminalReason),
    /// Renderer/Tauri callback disappeared; subscription was dropped and cancelled.
    SinkClosed,
    /// Internal sequence or closed-stream integrity failed; no misleading frame was sent.
    IntegrityViolation,
    /// Session ended without its mandatory terminal frame.
    MissingTerminal,
}

/// One process-wide bridge; internal broker labels and subscription IDs are host-owned.
#[derive(Clone)]
pub struct DesktopStructuredEventBridge {
    transport: Arc<InProcessTransport>,
    next_subscription_id: Arc<AtomicU64>,
    active: Arc<Mutex<ActiveSubscriptions>>,
}

impl DesktopStructuredEventBridge {
    /// Wrap the exact transport used by unary custom-protocol requests.
    #[must_use]
    pub fn new(transport: Arc<InProcessTransport>) -> Self {
        Self {
            transport,
            next_subscription_id: Arc::new(AtomicU64::new(0)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Open one typed subscription for an already authenticated native window.
    pub async fn open(
        &self,
        window: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
    ) -> Result<DesktopStructuredSubscription, DesktopStructuredOpenError> {
        let pending_open = reserve_window_open(&self.active, window.clone())?;
        let subscription_id = self
            .next_subscription_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= DESKTOP_STRUCTURED_SUBSCRIPTION_ID_EXCLUSIVE_LIMIT)
            })
            .map_err(|_| DesktopStructuredOpenError::CounterExhausted)?;
        let stream = DesktopStructuredStreamKind::from_request(&request);
        let expected_thread = match &request {
            SubscriptionRequest::ThreadEvents { thread_id, .. } => Some(thread_id.clone()),
            SubscriptionRequest::Health
            | SubscriptionRequest::ChannelActivity
            | SubscriptionRequest::ToolApprovalActivity => None,
        };
        let thread_subscriptions = expected_thread
            .clone()
            .map_or_else(ThreadSubscriptions::none, |thread_id| {
                ThreadSubscriptions::from_threads([thread_id])
            });
        // Length-prefixing makes `(window, id)` injective even when a host label contains separators.
        let internal_label = WindowLabel::new(format!(
            "{}:{}:{}",
            window.as_str().len(),
            window.as_str(),
            subscription_id
        ));
        let queue_budget = pending_open.queue_budget();
        let window_closed = pending_open.closed();
        let session = tokio::select! {
            result = self.transport.open_session_with_budget(
                internal_label.clone(),
                auth,
                request,
                thread_subscriptions,
                queue_budget,
            ) => result?,
            () = window_closed.cancelled() => {
                return Err(DesktopStructuredOpenError::WindowClosed);
            }
        };
        if !pending_open.commit(subscription_id, internal_label.clone()) {
            let _ = self.transport.close_session(&internal_label);
            return Err(DesktopStructuredOpenError::WindowClosed);
        }
        Ok(DesktopStructuredSubscription {
            subscription_id,
            stream,
            expected_thread,
            window,
            internal_label,
            transport: Arc::clone(&self.transport),
            active: Arc::clone(&self.active),
            session,
            tracker: SequenceTracker::new(),
            terminal_seen: false,
        })
    }

    /// Close every subscription owned by one actual native window.
    ///
    /// The registry entry is removed before any route is cancelled, so a concurrently finishing
    /// pump cannot resurrect stale ownership. The returned count is the exact number of registered
    /// subscriptions selected for cleanup.
    pub fn close_window(&self, window: &WindowLabel) -> usize {
        let aggregate = self
            .active
            .lock()
            .expect("structured subscription registry lock must not be poisoned")
            .remove(window);
        let Some(aggregate) = aggregate else {
            return 0;
        };
        aggregate.closed.cancel();
        let count = aggregate.registrations.len();
        for internal_label in aggregate.registrations.into_values() {
            let _ = self.transport.close_session(&internal_label);
        }
        count
    }

    /// Close one exact subscription only when it belongs to the host-observed actual window.
    ///
    /// Returning `false` covers unknown, already-finished, and another-window identities without
    /// revealing which case occurred.
    pub fn close_subscription(&self, window: &WindowLabel, subscription_id: u64) -> bool {
        let Some(internal_label) = remove_registration(&self.active, window, subscription_id)
        else {
            return false;
        };
        let _ = self.transport.close_session(&internal_label);
        true
    }

    /// Number of subscriptions still registered under actual host window labels.
    #[must_use]
    pub fn active_subscription_count(&self) -> usize {
        self.active
            .lock()
            .expect("structured subscription registry lock must not be poisoned")
            .values()
            .map(|aggregate| aggregate.registrations.len())
            .sum()
    }

    /// Remaining queued event-ref permits for one actual Webview.
    ///
    /// `None` means the host has no live or in-flight structured subscription for that label.
    #[must_use]
    pub fn remaining_window_event_capacity(&self, window: &WindowLabel) -> Option<usize> {
        self.active
            .lock()
            .expect("structured subscription registry lock must not be poisoned")
            .get(window)
            .map(|aggregate| aggregate.queue_budget.remaining())
    }
}

/// One live subscription. Dropping it immediately cancels its host-owned event pump.
pub struct DesktopStructuredSubscription {
    subscription_id: u64,
    stream: DesktopStructuredStreamKind,
    expected_thread: Option<ThreadId>,
    window: WindowLabel,
    internal_label: WindowLabel,
    transport: Arc<InProcessTransport>,
    active: Arc<Mutex<ActiveSubscriptions>>,
    session: crate::DesktopSession,
    tracker: SequenceTracker,
    terminal_seen: bool,
}

impl DesktopStructuredSubscription {
    /// Host-visible actual window label, never the internal broker route label.
    #[must_use]
    pub fn window(&self) -> &WindowLabel {
        &self.window
    }

    /// Host-minted identity.
    #[must_use]
    pub const fn subscription_id(&self) -> u64 {
        self.subscription_id
    }

    /// Read, sequence-check, and project the next frame.
    pub async fn next_frame(
        &mut self,
    ) -> Result<Option<DesktopStructuredEventFrame>, DesktopStructuredFrameError> {
        if self.terminal_seen {
            return Ok(None);
        }
        let frame = self
            .session
            .next_frame()
            .await
            .ok_or(DesktopStructuredFrameError::MissingTerminal)?;
        self.tracker.observe(&frame)?;
        if frame.event().is_some_and(|event| {
            !self
                .stream
                .accepts_event(event, self.expected_thread.as_ref())
        }) {
            return Err(DesktopStructuredFrameError::EventMismatch);
        }
        let projected = project_frame(self.subscription_id, self.stream, &frame);
        self.terminal_seen = projected.terminal_reason().is_some();
        Ok(Some(projected))
    }
}

impl Drop for DesktopStructuredSubscription {
    fn drop(&mut self) {
        let _ = remove_registration(&self.active, &self.window, self.subscription_id);
        let _ = self.transport.close_session(&self.internal_label);
    }
}

fn reserve_window_open(
    active: &Arc<Mutex<ActiveSubscriptions>>,
    window: WindowLabel,
) -> Result<PendingWindowOpen, DesktopStructuredOpenError> {
    let (token, queue_budget, closed) = {
        let mut active = active
            .lock()
            .expect("structured subscription registry lock must not be poisoned");
        let aggregate = active
            .entry(window.clone())
            .or_insert_with(WindowAggregate::new);
        let total = aggregate
            .pending
            .checked_add(aggregate.registrations.len())
            .ok_or(DesktopStructuredOpenError::WindowBudgetExhausted)?;
        if total >= MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW {
            return Err(DesktopStructuredOpenError::WindowBudgetExhausted);
        }
        aggregate.pending = aggregate
            .pending
            .checked_add(1)
            .ok_or(DesktopStructuredOpenError::WindowBudgetExhausted)?;
        (
            Arc::clone(&aggregate.token),
            Arc::clone(&aggregate.queue_budget),
            aggregate.closed.clone(),
        )
    };
    Ok(PendingWindowOpen {
        active: Arc::clone(active),
        window,
        token,
        queue_budget,
        closed,
        settled: false,
    })
}

fn release_pending_open(
    active: &Mutex<ActiveSubscriptions>,
    window: &WindowLabel,
    token: &Arc<()>,
) {
    let mut active = active
        .lock()
        .expect("structured subscription registry lock must not be poisoned");
    let remove_window = if let Some(aggregate) = active.get_mut(window) {
        if !Arc::ptr_eq(&aggregate.token, token) {
            false
        } else {
            aggregate.pending = aggregate
                .pending
                .checked_sub(1)
                .expect("pending structured open guard must own one slot");
            aggregate.pending == 0 && aggregate.registrations.is_empty()
        }
    } else {
        false
    };
    if remove_window {
        active.remove(window);
    }
}

fn remove_registration(
    active: &Mutex<ActiveSubscriptions>,
    window: &WindowLabel,
    subscription_id: u64,
) -> Option<WindowLabel> {
    let mut active = active
        .lock()
        .expect("structured subscription registry lock must not be poisoned");
    let aggregate = active.get_mut(window)?;
    let internal_label = aggregate.registrations.remove(&subscription_id)?;
    if aggregate.registrations.is_empty() && aggregate.pending == 0 {
        active.remove(window);
    }
    Some(internal_label)
}

/// Pump one typed subscription into an actual Tauri IPC Channel.
pub async fn pump_tauri_structured_events(
    mut subscription: DesktopStructuredSubscription,
    channel: Channel<String>,
) -> DesktopStructuredPumpExit {
    loop {
        let frame = match subscription.next_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) => return DesktopStructuredPumpExit::MissingTerminal,
            Err(DesktopStructuredFrameError::Sequence(_)) => {
                return DesktopStructuredPumpExit::IntegrityViolation;
            }
            Err(DesktopStructuredFrameError::EventMismatch) => {
                return DesktopStructuredPumpExit::IntegrityViolation;
            }
            Err(DesktopStructuredFrameError::MissingTerminal) => {
                return DesktopStructuredPumpExit::MissingTerminal;
            }
        };
        let terminal = frame.terminal_reason();
        let Ok(frame) = serde_json::to_string(&frame) else {
            return DesktopStructuredPumpExit::IntegrityViolation;
        };
        if channel.send(frame).is_err() {
            return DesktopStructuredPumpExit::SinkClosed;
        }
        if let Some(reason) = terminal {
            return DesktopStructuredPumpExit::Terminal(reason);
        }
    }
}

fn project_frame(
    subscription_id: u64,
    stream: DesktopStructuredStreamKind,
    frame: &AppEventRef,
) -> DesktopStructuredEventFrame {
    let skipped = frame.skipped().map(project_gap);
    if let Some(event) = frame.event() {
        return DesktopStructuredEventFrame::Event {
            subscription_id,
            stream,
            sequence: frame.seq(),
            skipped,
            event: event.clone(),
        };
    }
    let reason = frame
        .terminal_reason()
        .expect("non-event Desktop frame must be terminal");
    let (reason, overflow_class) = match reason {
        DisconnectReason::QueueOverflow { class } => (
            DesktopStructuredTerminalReason::QueueOverflow,
            Some(project_delivery_class(class)),
        ),
        DisconnectReason::Shutdown => (DesktopStructuredTerminalReason::Shutdown, None),
        DisconnectReason::UpstreamEnded => (DesktopStructuredTerminalReason::UpstreamEnded, None),
        DisconnectReason::SubscriptionClosed => {
            (DesktopStructuredTerminalReason::SubscriptionClosed, None)
        }
    };
    DesktopStructuredEventFrame::Terminal {
        subscription_id,
        stream,
        sequence: frame.seq(),
        skipped,
        reason,
        overflow_class,
    }
}

fn project_gap(gap: SequenceGap) -> DesktopStructuredSequenceGap {
    DesktopStructuredSequenceGap {
        from_sequence: gap.from_seq,
        through_sequence: gap.through_seq,
        cause: match gap.cause {
            GapCause::Superseded => DesktopStructuredGapCause::Superseded,
            GapCause::Dropped => DesktopStructuredGapCause::Dropped,
        },
    }
}

fn project_delivery_class(class: DeliveryClass) -> DesktopStructuredDeliveryClass {
    match class {
        DeliveryClass::Critical => DesktopStructuredDeliveryClass::Critical,
        DeliveryClass::Coalescable => DesktopStructuredDeliveryClass::Coalescable,
        DeliveryClass::LatestValue => DesktopStructuredDeliveryClass::LatestValue,
        DeliveryClass::Screen => DesktopStructuredDeliveryClass::Screen,
    }
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicUsizeOrdering};

    use async_trait::async_trait;
    use openbot_application::{AppEventStream, ApplicationService};
    use openbot_contracts::command::{
        AppCommand, AppEvent, AppReply, ChannelActivityEvent, HealthReport, ThreadRunEvent,
        ThreadRunEventKind,
    };
    use openbot_contracts::error::AppError;
    use openbot_contracts::ids::{BotId, ChannelId, RunId, ThreadId};
    use tauri::ipc::InvokeResponseBody;

    use super::*;
    use crate::testing::auth_for;

    struct FiniteStream(VecDeque<AppEvent>);

    impl futures_core::Stream for FiniteStream {
        type Item = AppEvent;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct ScriptedService;

    #[async_trait]
    impl ApplicationService for ScriptedService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            let event = match request {
                SubscriptionRequest::ThreadEvents { thread_id, .. } => {
                    AppEvent::ThreadRunEvent(ThreadRunEvent {
                        thread_id,
                        run_id: RunId::new("run-1"),
                        event_sequence: 1,
                        event_type: ThreadRunEventKind::Started,
                        payload: serde_json::json!({}),
                        terminal: false,
                        created_at: time::OffsetDateTime::UNIX_EPOCH,
                    })
                }
                SubscriptionRequest::ChannelActivity => {
                    AppEvent::ChannelActivity(ChannelActivityEvent {
                        channel_id: ChannelId::new("channel-1"),
                        last_message: Some("updated".to_owned()),
                        last_message_at: Some(time::OffsetDateTime::UNIX_EPOCH),
                        last_message_agent_id: Some(BotId::new("agent-1")),
                    })
                }
                SubscriptionRequest::Health => AppEvent::Heartbeat { seq: 1 },
                SubscriptionRequest::ToolApprovalActivity => AppEvent::ToolApprovalActivity(
                    openbot_contracts::tool::ToolApprovalActivityEvent { pending_count: 1 },
                ),
            };
            Ok(Box::pin(FiniteStream(VecDeque::from([event]))))
        }
    }

    struct PendingStream;

    impl futures_core::Stream for PendingStream {
        type Item = AppEvent;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    struct PendingService;

    #[async_trait]
    impl ApplicationService for PendingService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(Box::pin(PendingStream))
        }
    }

    struct BlockingPendingService {
        entered: Arc<AtomicUsize>,
        release: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait]
    impl ApplicationService for BlockingPendingService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            self.entered.fetch_add(1, AtomicUsizeOrdering::SeqCst);
            self.release
                .acquire()
                .await
                .expect("test gate remains open")
                .forget();
            Ok(Box::pin(PendingStream))
        }
    }

    const BURST_EVENTS_PER_STREAM: usize = 200;

    struct BurstService;

    #[async_trait]
    impl ApplicationService for BurstService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            let events = (0..BURST_EVENTS_PER_STREAM)
                .map(|index| match &request {
                    SubscriptionRequest::ChannelActivity => {
                        AppEvent::ChannelActivity(ChannelActivityEvent {
                            channel_id: ChannelId::new("channel-burst"),
                            last_message: Some(index.to_string()),
                            last_message_at: Some(time::OffsetDateTime::UNIX_EPOCH),
                            last_message_agent_id: None,
                        })
                    }
                    SubscriptionRequest::ToolApprovalActivity => AppEvent::ToolApprovalActivity(
                        openbot_contracts::tool::ToolApprovalActivityEvent {
                            pending_count: u32::try_from(index).expect("bounded test count"),
                        },
                    ),
                    SubscriptionRequest::Health | SubscriptionRequest::ThreadEvents { .. } => {
                        AppEvent::Heartbeat {
                            seq: u64::try_from(index).expect("bounded test count"),
                        }
                    }
                })
                .collect();
            Ok(Box::pin(FiniteStream(events)))
        }
    }

    struct MismatchedService;

    #[async_trait]
    impl ApplicationService for MismatchedService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            let event = match request {
                SubscriptionRequest::ThreadEvents { .. } => {
                    AppEvent::ThreadRunEvent(ThreadRunEvent {
                        thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440099"),
                        run_id: RunId::new("run-mismatch"),
                        event_sequence: 1,
                        event_type: ThreadRunEventKind::Started,
                        payload: serde_json::json!({}),
                        terminal: false,
                        created_at: time::OffsetDateTime::UNIX_EPOCH,
                    })
                }
                SubscriptionRequest::Health
                | SubscriptionRequest::ChannelActivity
                | SubscriptionRequest::ToolApprovalActivity => {
                    AppEvent::ChannelActivity(ChannelActivityEvent {
                        channel_id: ChannelId::new("channel-mismatch"),
                        last_message: None,
                        last_message_at: None,
                        last_message_agent_id: None,
                    })
                }
            };
            Ok(Box::pin(FiniteStream(VecDeque::from([event]))))
        }
    }

    fn collecting_channel(frames: Arc<Mutex<Vec<DesktopStructuredEventFrame>>>) -> Channel<String> {
        Channel::new(move |body| {
            let InvokeResponseBody::Json(json) = body else {
                panic!("structured frame must use the JSON IPC lane");
            };
            let frame_json = serde_json::from_str::<String>(&json)?;
            frames
                .lock()
                .unwrap()
                .push(serde_json::from_str(&frame_json)?);
            Ok(())
        })
    }

    async fn drain_subscription(
        subscription: &mut DesktopStructuredSubscription,
    ) -> (usize, DesktopStructuredTerminalReason) {
        let mut events = 0;
        loop {
            let frame = subscription
                .next_frame()
                .await
                .expect("valid structured frame")
                .expect("terminal must precede EOF");
            if let Some(reason) = frame.terminal_reason() {
                return (events, reason);
            }
            events += 1;
        }
    }

    #[tokio::test]
    async fn subscription_identity_exhaustion_fails_before_opening_a_route() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(PendingService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        bridge.next_subscription_id.store(
            DESKTOP_STRUCTURED_SUBSCRIPTION_ID_EXCLUSIVE_LIMIT,
            Ordering::SeqCst,
        );

        assert!(matches!(
            bridge
                .open(
                    WindowLabel::new("main"),
                    &auth_for("actor-1"),
                    SubscriptionRequest::Health,
                )
                .await,
            Err(DesktopStructuredOpenError::CounterExhausted)
        ));
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);
        assert_eq!(
            bridge.remaining_window_event_capacity(&WindowLabel::new("main")),
            None
        );
    }

    #[tokio::test]
    async fn one_actual_webview_shares_exactly_256_queued_event_refs_across_streams() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(BurstService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let main = WindowLabel::new("main");
        let mut channels = bridge
            .open(main.clone(), &auth, SubscriptionRequest::ChannelActivity)
            .await
            .unwrap();
        let mut approvals = bridge
            .open(
                main.clone(),
                &auth,
                SubscriptionRequest::ToolApprovalActivity,
            )
            .await
            .unwrap();

        tokio::time::timeout(core::time::Duration::from_secs(2), async {
            while transport.broker().window_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both finite pumps must terminate");
        assert_eq!(
            bridge.remaining_window_event_capacity(&main),
            Some(0),
            "two internal routes must share one actual-window budget"
        );

        let (channel_result, approval_result) = tokio::join!(
            drain_subscription(&mut channels),
            drain_subscription(&mut approvals),
        );
        assert_eq!(
            channel_result.0 + approval_result.0,
            CRITICAL_EVENT_QUEUE_CAPACITY
        );
        assert!(
            [channel_result.1, approval_result.1]
                .contains(&DesktopStructuredTerminalReason::QueueOverflow),
            "the 257th aggregate critical event must force an explicit terminal"
        );
        assert_eq!(
            bridge.remaining_window_event_capacity(&main),
            Some(CRITICAL_EVENT_QUEUE_CAPACITY),
            "consuming every queued frame releases every shared permit"
        );

        drop(channels);
        drop(approvals);
        assert_eq!(bridge.remaining_window_event_capacity(&main), None);
        assert_eq!(bridge.active_subscription_count(), 0);
    }

    #[tokio::test]
    async fn the_257th_subscription_is_rejected_per_webview_without_starving_another_window() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(PendingService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let main = WindowLabel::new("main");
        let mut main_subscriptions = Vec::with_capacity(MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW);
        for _ in 0..MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW {
            main_subscriptions.push(
                bridge
                    .open(main.clone(), &auth, SubscriptionRequest::Health)
                    .await
                    .expect("first 256 subscriptions fit"),
            );
        }
        assert!(matches!(
            bridge
                .open(main.clone(), &auth, SubscriptionRequest::Health)
                .await,
            Err(DesktopStructuredOpenError::WindowBudgetExhausted)
        ));

        let auxiliary = WindowLabel::new("auxiliary");
        let auxiliary_subscription = bridge
            .open(auxiliary.clone(), &auth, SubscriptionRequest::Health)
            .await
            .expect("another actual Webview owns an independent budget");
        assert_eq!(
            bridge.active_subscription_count(),
            MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW + 1
        );
        assert_eq!(
            bridge.remaining_window_event_capacity(&main),
            Some(CRITICAL_EVENT_QUEUE_CAPACITY)
        );
        assert_eq!(
            bridge.remaining_window_event_capacity(&auxiliary),
            Some(CRITICAL_EVENT_QUEUE_CAPACITY)
        );

        drop(main_subscriptions);
        drop(auxiliary_subscription);
        assert_eq!(bridge.active_subscription_count(), 0);
        assert_eq!(transport.broker().window_count(), 0);
    }

    #[tokio::test]
    async fn pending_opens_count_toward_the_limit_and_window_close_cannot_resurrect_them() {
        let entered = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let transport = Arc::new(InProcessTransport::new(Arc::new(BlockingPendingService {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        })));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let main = WindowLabel::new("main");
        let mut opens = Vec::with_capacity(MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW);
        for _ in 0..MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW {
            let opening = bridge.clone();
            let window = main.clone();
            opens.push(tokio::spawn(async move {
                opening
                    .open(window, &auth_for("actor-1"), SubscriptionRequest::Health)
                    .await
            }));
        }
        tokio::time::timeout(core::time::Duration::from_secs(2), async {
            while entered.load(AtomicUsizeOrdering::SeqCst)
                != MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all permitted opens must reach ApplicationService");

        assert!(matches!(
            bridge
                .open(
                    main.clone(),
                    &auth_for("actor-1"),
                    SubscriptionRequest::Health
                )
                .await,
            Err(DesktopStructuredOpenError::WindowBudgetExhausted)
        ));
        assert_eq!(
            entered.load(AtomicUsizeOrdering::SeqCst),
            MAX_STRUCTURED_SUBSCRIPTIONS_PER_WINDOW,
            "the rejected open must not call ApplicationService"
        );
        assert_eq!(bridge.close_window(&main), 0, "all opens are still pending");
        assert_eq!(bridge.remaining_window_event_capacity(&main), None);

        tokio::time::timeout(core::time::Duration::from_secs(2), async {
            for open in opens {
                assert!(matches!(
                    open.await.expect("open task must finish"),
                    Err(DesktopStructuredOpenError::WindowClosed)
                ));
            }
        })
        .await
        .expect("window close must cancel every in-flight application subscribe");
        assert_eq!(bridge.active_subscription_count(), 0);
        assert_eq!(bridge.remaining_window_event_capacity(&main), None);
        assert_eq!(transport.broker().window_count(), 0);
    }

    #[tokio::test]
    async fn one_window_can_hold_multiple_host_owned_tauri_channels() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(ScriptedService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let actual_window = WindowLabel::new("main");
        let thread = ThreadId::new("550e8400-e29b-81d4-a716-446655440000");
        let thread_subscription = bridge
            .open(
                actual_window.clone(),
                &auth,
                SubscriptionRequest::ThreadEvents {
                    thread_id: thread.clone(),
                    after_event_sequence: None,
                },
            )
            .await
            .unwrap();
        let channel_subscription = bridge
            .open(
                actual_window.clone(),
                &auth,
                SubscriptionRequest::ChannelActivity,
            )
            .await
            .unwrap();
        assert_eq!(thread_subscription.window(), &actual_window);
        assert_eq!(channel_subscription.window(), &actual_window);
        assert_ne!(
            thread_subscription.subscription_id(),
            channel_subscription.subscription_id()
        );
        assert_eq!(transport.broker().window_count(), 2);
        assert_eq!(bridge.active_subscription_count(), 2);

        let thread_frames = Arc::new(Mutex::new(Vec::new()));
        let channel_frames = Arc::new(Mutex::new(Vec::new()));
        let (thread_exit, channel_exit) = tokio::join!(
            pump_tauri_structured_events(
                thread_subscription,
                collecting_channel(Arc::clone(&thread_frames)),
            ),
            pump_tauri_structured_events(
                channel_subscription,
                collecting_channel(Arc::clone(&channel_frames)),
            ),
        );
        assert_eq!(
            thread_exit,
            DesktopStructuredPumpExit::Terminal(DesktopStructuredTerminalReason::UpstreamEnded)
        );
        assert_eq!(
            channel_exit,
            DesktopStructuredPumpExit::Terminal(DesktopStructuredTerminalReason::UpstreamEnded)
        );
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);

        let thread_frames = thread_frames.lock().unwrap();
        let channel_frames = channel_frames.lock().unwrap();
        assert_eq!(thread_frames.len(), 2);
        assert_eq!(channel_frames.len(), 2);
        assert!(matches!(
            &thread_frames[0],
            DesktopStructuredEventFrame::Event {
                stream: DesktopStructuredStreamKind::ThreadEvents,
                event: AppEvent::ThreadRunEvent(event),
                ..
            } if event.thread_id == thread
        ));
        assert!(matches!(
            &channel_frames[0],
            DesktopStructuredEventFrame::Event {
                stream: DesktopStructuredStreamKind::ChannelActivity,
                event: AppEvent::ChannelActivity(_),
                ..
            }
        ));
        assert!(matches!(
            thread_frames[1],
            DesktopStructuredEventFrame::Terminal {
                reason: DesktopStructuredTerminalReason::UpstreamEnded,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dropping_one_subscription_cancels_only_its_internal_route() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(PendingService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let main = WindowLabel::new("main");
        let mut first = bridge
            .open(main.clone(), &auth, SubscriptionRequest::ChannelActivity)
            .await
            .unwrap();
        let second = bridge
            .open(
                main.clone(),
                &auth,
                SubscriptionRequest::ToolApprovalActivity,
            )
            .await
            .unwrap();
        assert_eq!(transport.broker().window_count(), 2);
        assert_eq!(bridge.active_subscription_count(), 2);
        assert!(
            !bridge
                .close_subscription(&WindowLabel::new("another-window"), first.subscription_id())
        );
        assert!(bridge.close_subscription(&main, first.subscription_id()));
        assert!(!bridge.close_subscription(&main, first.subscription_id()));
        let terminal = first.next_frame().await.unwrap().unwrap();
        assert_eq!(
            terminal.terminal_reason(),
            Some(DesktopStructuredTerminalReason::SubscriptionClosed)
        );
        assert_eq!(transport.broker().window_count(), 1);
        assert_eq!(bridge.active_subscription_count(), 1);
        drop(first);
        assert_eq!(transport.broker().window_count(), 1);
        assert_eq!(bridge.active_subscription_count(), 1);
        drop(second);
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);
    }

    #[tokio::test]
    async fn closing_one_actual_window_cancels_all_and_only_its_subscriptions() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(PendingService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let main = WindowLabel::new("main");
        let auxiliary = WindowLabel::new("auxiliary");
        let mut main_channels = bridge
            .open(main.clone(), &auth, SubscriptionRequest::ChannelActivity)
            .await
            .unwrap();
        let mut main_approvals = bridge
            .open(
                main.clone(),
                &auth,
                SubscriptionRequest::ToolApprovalActivity,
            )
            .await
            .unwrap();
        let auxiliary_health = bridge
            .open(auxiliary.clone(), &auth, SubscriptionRequest::Health)
            .await
            .unwrap();
        assert_eq!(transport.broker().window_count(), 3);
        assert_eq!(bridge.active_subscription_count(), 3);

        assert_eq!(bridge.close_window(&main), 2);
        assert_eq!(bridge.close_window(&main), 0, "window close is idempotent");
        assert_eq!(transport.broker().window_count(), 1);
        assert_eq!(bridge.active_subscription_count(), 1);
        for subscription in [&mut main_channels, &mut main_approvals] {
            let terminal = subscription.next_frame().await.unwrap().unwrap();
            assert_eq!(
                terminal.terminal_reason(),
                Some(DesktopStructuredTerminalReason::SubscriptionClosed)
            );
            assert!(subscription.next_frame().await.unwrap().is_none());
        }

        drop(auxiliary_health);
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);
    }

    #[tokio::test]
    async fn stream_family_and_exact_thread_are_checked_before_ipc_projection() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(MismatchedService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let auth = auth_for("actor-1");
        let requests = [
            SubscriptionRequest::Health,
            SubscriptionRequest::ThreadEvents {
                thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                after_event_sequence: None,
            },
        ];

        for (index, request) in requests.into_iter().enumerate() {
            let mut subscription = bridge
                .open(WindowLabel::new(format!("window-{index}")), &auth, request)
                .await
                .unwrap();
            assert!(matches!(
                subscription.next_frame().await,
                Err(DesktopStructuredFrameError::EventMismatch)
            ));
            drop(subscription);
        }
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);
    }

    #[tokio::test]
    async fn a_closed_tauri_sink_cancels_the_host_subscription() {
        let transport = Arc::new(InProcessTransport::new(Arc::new(ScriptedService)));
        let bridge = DesktopStructuredEventBridge::new(Arc::clone(&transport));
        let subscription = bridge
            .open(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
            )
            .await
            .unwrap();
        let channel = Channel::new(|_| Err(tauri::Error::FailedToReceiveMessage));

        assert_eq!(
            pump_tauri_structured_events(subscription, channel).await,
            DesktopStructuredPumpExit::SinkClosed
        );
        assert_eq!(transport.broker().window_count(), 0);
        assert_eq!(bridge.active_subscription_count(), 0);
    }

    #[test]
    fn non_overflow_terminal_wire_omits_the_overflow_class() {
        let frame = DesktopStructuredEventFrame::Terminal {
            subscription_id: 7,
            stream: DesktopStructuredStreamKind::Health,
            sequence: 3,
            skipped: None,
            reason: DesktopStructuredTerminalReason::UpstreamEnded,
            overflow_class: None,
        };
        let json = serde_json::to_value(frame).unwrap();
        assert_eq!(json["subscriptionId"], 7);
        assert_eq!(json["reason"], "upstream_ended");
        assert!(json.get("overflowClass").is_none());
        for forbidden in ["window", "actor", "tenant", "authGeneration"] {
            assert!(
                json.get(forbidden).is_none(),
                "authority field leaked: {forbidden}"
            );
        }
    }
}
