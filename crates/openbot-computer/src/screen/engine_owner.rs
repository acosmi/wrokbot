//! Sole owner of a live Engine session and its ScreenHub demand lifecycle.

use std::sync::Arc;
use std::time::Duration;

use openbot_contracts::auth::AuthContext;

use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::browser::BrowserInput;
use crate::control::{ControlService, HumanInputTicket};
use crate::engine::{EngineProcess, EngineProcessError, ScreenIngressStats, ScreenStreamKey};

use super::{ScreenDemandObserver, ScreenHub};

/// One in-flight input plus one capture transition fit within the first-source two-second bound.
const OPERATION_DEADLINE: Duration = Duration::from_millis(750);
const SHUTDOWN_DEADLINE: Duration = Duration::from_millis(1500);
const COMMAND_CAPACITY: usize = 16;

/// Rust-owned observation state. No external frame or renderer can set these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenEngineState {
    /// Source attached; the owner has not yet reconciled initial demand.
    Starting,
    /// At least one viewer is attached and capture is enabled.
    Running,
    /// Capture is stopped and all frames ACKed; the document and renderer are retained.
    Paused,
    /// Explicit shutdown/source invalidation completed.
    Closed,
    /// An operation failed or timed out; the process is retired, never reused.
    Failed,
}

/// Closed errors without engine prose, paths, user input, or scope identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScreenEngineError {
    /// Bounded command queue is full; nothing was enqueued.
    #[error("screen_engine_busy")]
    Busy,
    /// Owner or source is no longer available.
    #[error("screen_engine_closed")]
    Closed,
    /// Input was rejected by Rust authority before writing to the engine.
    #[error("screen_engine_input_refused")]
    InputRefused,
    /// Engine operation failed or exceeded its bound. Commit must not be inferred.
    #[error("screen_engine_unavailable")]
    Unavailable,
}

enum Command {
    Input {
        auth: Box<AuthContext>,
        ticket: HumanInputTicket,
        input: BrowserInput,
        reply: oneshot::Sender<Result<(), ScreenEngineError>>,
        _activity: Box<dyn Send>,
    },
    #[cfg(target_os = "macos")]
    Take {
        auth: Box<AuthContext>,
        expires_at: time::OffsetDateTime,
        reply: oneshot::Sender<Result<HumanInputTicket, ScreenEngineError>>,
        activity: Box<dyn Send>,
    },
    #[cfg(target_os = "macos")]
    Release {
        auth: Box<AuthContext>,
        ticket: HumanInputTicket,
        reply: oneshot::Sender<Result<(), ScreenEngineError>>,
        _activity: Box<dyn Send>,
    },
    Stats(oneshot::Sender<Result<ScreenIngressStats, ScreenEngineError>>),
}

/// Non-Clone supervisor handle. Drop requests bounded retirement on the owned task.
/// The source may be started by either Browser or Component role, but only one owner consumes it.
pub struct ScreenEngineOwner {
    client: ScreenEngineClient,
    state: watch::Receiver<ScreenEngineState>,
    task: Option<JoinHandle<Result<(), ScreenEngineError>>>,
}

impl ScreenEngineOwner {
    /// Consume an already started, authenticated EngineProcess and attach its unique source.
    /// Production ComputerManager must supply that process; this does not manufacture scope.
    pub async fn attach(
        engine: EngineProcess,
        hub: ScreenHub,
        control: Arc<Mutex<ControlService>>,
    ) -> Result<Self, ScreenEngineError> {
        Self::attach_with_lifetime(engine, hub, control, Box::new(()), None).await
    }

    /// Keep the profile lock with the actual task, including when its caller drops the owner.
    pub(crate) async fn attach_with_lifetime(
        engine: EngineProcess,
        hub: ScreenHub,
        control: Arc<Mutex<ControlService>>,
        lifetime: Box<dyn Send>,
        parent_stop: Option<watch::Receiver<bool>>,
    ) -> Result<Self, ScreenEngineError> {
        let mut process = EngineLifetime {
            engine: Some(engine),
            _guard: lifetime,
        };
        let source = process
            .engine
            .as_mut()
            .expect("owned engine")
            .take_screen_source()
            .map_err(|_| ScreenEngineError::Unavailable)?;
        let key = source.stream_key().clone();
        let demand = hub
            .attach(source)
            .await
            .map_err(|_| ScreenEngineError::Unavailable)?;
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (state, observer) = watch::channel(ScreenEngineState::Starting);
        let (stop, stop_receiver) = watch::channel(false);
        let task = tokio::spawn(own_engine(OwnerTask {
            process,
            hub,
            key,
            demand,
            commands: receiver,
            state,
            control,
            stop: stop_receiver,
            parent_stop,
        }));
        Ok(Self {
            client: ScreenEngineClient { commands, stop },
            state: observer,
            task: Some(task),
        })
    }

    /// Read-only lifecycle observer for the Rust host. It carries no frame or authority payload.
    #[must_use]
    pub fn observe(&self) -> watch::Receiver<ScreenEngineState> {
        self.state.clone()
    }

    /// Submit one fresh typed input. Queue saturation and caller abandonment before execution
    /// produce zero engine effect. Once an input has started, failure remains an unknown outcome.
    pub async fn apply_input(
        &self,
        auth: AuthContext,
        ticket: HumanInputTicket,
        input: BrowserInput,
    ) -> Result<(), ScreenEngineError> {
        self.client
            .apply_input(auth, ticket, input, Box::new(()))
            .await
    }

    /// Internal command handle; keeping it never keeps a retired engine alive.
    #[cfg(target_os = "macos")]
    pub(crate) fn client(&self) -> ScreenEngineClient {
        self.client.clone()
    }

    /// Read counters from the owned real ingress, including while capture is paused.
    pub async fn stats(&self) -> Result<ScreenIngressStats, ScreenEngineError> {
        let (reply, result) = oneshot::channel();
        self.client.enqueue(Command::Stats(reply))?;
        result.await.map_err(|_| ScreenEngineError::Closed)?
    }

    /// Retire the owner and its source. A saturated queue fails closed via this handle's Drop.
    pub async fn shutdown(mut self) -> Result<(), ScreenEngineError> {
        self.client.request_shutdown();
        self.task
            .as_mut()
            .ok_or(ScreenEngineError::Closed)?
            .await
            .map_err(|_| ScreenEngineError::Unavailable)?
    }
}

/// A non-owning command endpoint. Shutdown has its own watch signal, never waits behind a full
/// input queue, and prevents new admission synchronously. Only the owner owns the JoinHandle.
#[derive(Clone)]
pub(crate) struct ScreenEngineClient {
    commands: mpsc::Sender<Command>,
    stop: watch::Sender<bool>,
}

impl ScreenEngineClient {
    pub(crate) async fn apply_input(
        &self,
        auth: AuthContext,
        ticket: HumanInputTicket,
        input: BrowserInput,
        activity: Box<dyn Send>,
    ) -> Result<(), ScreenEngineError> {
        let (reply, result) = oneshot::channel();
        self.enqueue(Command::Input {
            auth: Box::new(auth),
            ticket,
            input,
            reply,
            _activity: activity,
        })?;
        result.await.map_err(|_| ScreenEngineError::Closed)?
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn take_control(
        &self,
        auth: AuthContext,
        expires_at: time::OffsetDateTime,
        activity: Box<dyn Send>,
    ) -> Result<HumanInputTicket, ScreenEngineError> {
        let (reply, result) = oneshot::channel();
        self.enqueue(Command::Take {
            auth: Box::new(auth),
            expires_at,
            reply,
            activity,
        })?;
        result.await.map_err(|_| ScreenEngineError::Closed)?
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn release_control(
        &self,
        auth: AuthContext,
        ticket: HumanInputTicket,
        activity: Box<dyn Send>,
    ) -> Result<(), ScreenEngineError> {
        let (reply, result) = oneshot::channel();
        self.enqueue(Command::Release {
            auth: Box::new(auth),
            ticket,
            reply,
            _activity: activity,
        })?;
        result.await.map_err(|_| ScreenEngineError::Closed)?
    }

    pub(crate) fn request_shutdown(&self) {
        self.stop.send_replace(true);
    }

    fn enqueue(&self, command: Command) -> Result<(), ScreenEngineError> {
        if *self.stop.borrow() {
            return Err(ScreenEngineError::Closed);
        }
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ScreenEngineError::Busy,
                mpsc::error::TrySendError::Closed(_) => ScreenEngineError::Closed,
            })
    }
}

impl Drop for ScreenEngineOwner {
    fn drop(&mut self) {
        // Do not release a profile lock before the Engine task has actually retired. Detach the
        // bounded cleanup task; runtime teardown remains the final EngineProcess Drop fallback.
        self.client.request_shutdown();
    }
}

async fn parent_stopped(parent: &mut Option<watch::Receiver<bool>>) {
    match parent {
        Some(receiver) => {
            while !*receiver.borrow_and_update() {
                if receiver.changed().await.is_err() {
                    return;
                }
            }
        }
        None => std::future::pending::<()>().await,
    }
}

// Struct field order ensures the process is dropped before its profile lock on task cancellation.
struct EngineLifetime {
    engine: Option<EngineProcess>,
    _guard: Box<dyn Send>,
}

struct OwnerTask {
    process: EngineLifetime,
    hub: ScreenHub,
    key: ScreenStreamKey,
    demand: ScreenDemandObserver,
    commands: mpsc::Receiver<Command>,
    state: watch::Sender<ScreenEngineState>,
    control: Arc<Mutex<ControlService>>,
    stop: watch::Receiver<bool>,
    parent_stop: Option<watch::Receiver<bool>>,
}

async fn own_engine(task: OwnerTask) -> Result<(), ScreenEngineError> {
    let OwnerTask {
        mut process,
        hub,
        key,
        mut demand,
        mut commands,
        state,
        control,
        mut stop,
        mut parent_stop,
    } = task;
    let engine = process.engine.as_mut().expect("owned engine");
    let mut human_activity: Option<Box<dyn Send>> = None;
    let mut human_deadline: Option<tokio::time::Instant> = None;
    let mut current = demand.current();
    let mut casting = None;
    let healthy = loop {
        if current.is_closed()
            || *stop.borrow()
            || parent_stop.as_ref().is_some_and(|s| *s.borrow())
        {
            break true;
        }
        let enabled = current.has_viewers();
        if casting != Some(enabled) {
            if !matches!(
                tokio::time::timeout(
                    OPERATION_DEADLINE,
                    engine.set_screencast(key.tab_id(), enabled)
                )
                .await,
                Ok(Ok(()))
            ) {
                break false;
            }
            casting = Some(enabled);
            state.send_replace(if enabled {
                ScreenEngineState::Running
            } else {
                ScreenEngineState::Paused
            });
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break true,
            () = parent_stopped(&mut parent_stop) => break true,
            () = async {
                match human_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Ok(mut control) = tokio::time::timeout(OPERATION_DEADLINE, control.lock()).await else { break false; };
                // Monotonic expiry must also retire the lease if the wall clock moved backwards.
                if control.release(time::OffsetDateTime::now_utc()).is_err() { break false; }
                human_activity.take();
                human_deadline = None;
            },
            next = demand.changed() => current = next,
            command = commands.recv() => match command {
                Some(Command::Input { auth, ticket, input, reply, _activity }) => {
                    if reply.is_closed() { continue; }
                    // Queue only a non-authority ticket. Revalidate the current lease at execution
                    // and hold its guard through the bounded write/ACK, so release/transfer cannot
                    // race between receipt minting and engine dispatch.
                    let outcome = tokio::time::timeout(OPERATION_DEADLINE, async {
                        let mut control = control.lock().await;
                        if reply.is_closed() { return Ok(()); }
                        if demand.is_closed() || *stop.borrow() || parent_stop.as_ref().is_some_and(|s| *s.borrow()) { return Err(ScreenEngineError::Closed); }
                        let now = time::OffsetDateTime::now_utc();
                        let authority = control.authorize_human_input_receipt(&auth, &ticket, now)
                            .map_err(|_| ScreenEngineError::InputRefused)?;
                        engine.apply_human_input(authority, &input, now).await.map_err(|error| match error {
                            EngineProcessError::InputAuthority | EngineProcessError::InputPlan(_) => ScreenEngineError::InputRefused,
                            _ => ScreenEngineError::Unavailable,
                        })
                    }).await;
                    match outcome {
                        Ok(Ok(())) => { let _ = reply.send(Ok(())); }
                        Ok(Err(ScreenEngineError::InputRefused)) => {
                            let _ = reply.send(Err(ScreenEngineError::InputRefused));
                        }
                        _ => {
                            let _ = reply.send(Err(ScreenEngineError::Unavailable));
                            break false;
                        }
                    }
                }
                #[cfg(target_os = "macos")]
                Some(Command::Take { auth, expires_at, reply, activity }) => {
                    if reply.is_closed() { continue; }
                    let outcome = tokio::time::timeout(OPERATION_DEADLINE, async {
                        let mut control = control.lock().await;
                        let now = time::OffsetDateTime::now_utc();
                        if reply.is_closed() || *stop.borrow() || demand.is_closed() || parent_stop.as_ref().is_some_and(|s| *s.borrow()) {
                            return Err(ScreenEngineError::Closed);
                        }
                        control.take(&auth, expires_at, now).map_err(|_| ScreenEngineError::InputRefused)?;
                        control.issue_human_input_ticket(now).map_err(|_| ScreenEngineError::InputRefused)
                    }).await;
                    match outcome {
                        Ok(Ok(ticket)) => {
                            let delay = std::time::Duration::try_from(expires_at - time::OffsetDateTime::now_utc()).ok();
                            human_deadline = delay.and_then(|delay| tokio::time::Instant::now().checked_add(delay));
                            if human_deadline.is_none() { break false; }
                            human_activity = Some(activity);
                            if reply.send(Ok(ticket)).is_err() {
                                let Ok(mut control) = tokio::time::timeout(OPERATION_DEADLINE, control.lock()).await else { break false; };
                                if control.release(time::OffsetDateTime::now_utc()).is_err() { break false; }
                                human_activity.take();
                                human_deadline = None;
                            }
                        }
                        Ok(Err(error)) => { let _ = reply.send(Err(error)); }
                        Err(_) => { let _ = reply.send(Err(ScreenEngineError::Unavailable)); break false; }
                    }
                }
                #[cfg(target_os = "macos")]
                Some(Command::Release { auth, ticket, reply, _activity }) => {
                    if reply.is_closed() { continue; }
                    let outcome = tokio::time::timeout(OPERATION_DEADLINE, async {
                        let mut control = control.lock().await;
                        let now = time::OffsetDateTime::now_utc();
                        if *stop.borrow() || demand.is_closed() || parent_stop.as_ref().is_some_and(|s| *s.borrow()) { return Err(ScreenEngineError::Closed); }
                        control.authorize_human_input(&auth, &ticket, now).map_err(|_| ScreenEngineError::InputRefused)?;
                        control.release(now).map_err(|_| ScreenEngineError::InputRefused)?;
                        Ok(())
                    }).await;
                    match outcome {
                        Ok(result) => {
                            if result.is_ok() { human_activity.take(); human_deadline = None; }
                            let _ = reply.send(result);
                        }
                        Err(_) => { let _ = reply.send(Err(ScreenEngineError::Unavailable)); break false; }
                    }
                }
                Some(Command::Stats(reply)) => {
                    if reply.is_closed() { continue; }
                    let stats = engine.screen_stats().await.map_err(|_| ScreenEngineError::Unavailable);
                    let failed = stats.is_err();
                    let _ = reply.send(stats);
                    if failed { break false; }
                }
                None => break true,
            }
        }
    };
    commands.close();
    drop(commands); // Drop queued activity leases before the manager awaits drain.
    drop(human_activity);
    hub.detach_registered(&key, &demand).await;
    // A timed-out wire operation is never followed by another command: its late response could
    // be mistaken for that command's response. Drop retires the process instead.
    let result = if healthy {
        match tokio::time::timeout(
            SHUTDOWN_DEADLINE,
            process.engine.take().expect("owned engine").shutdown(),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(ScreenEngineError::Unavailable),
        }
    } else {
        drop(process.engine.take());
        Err(ScreenEngineError::Unavailable)
    };
    state.send_replace(if result.is_ok() {
        ScreenEngineState::Closed
    } else {
        ScreenEngineState::Failed
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(target_os = "macos")]
    struct Activity(Arc<AtomicUsize>);
    #[cfg(target_os = "macos")]
    impl Drop for Activity {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_signal_bypasses_saturated_queue_and_closes_admission() {
        let (commands, mut receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (stop, mut stopped) = watch::channel(false);
        let client = ScreenEngineClient { commands, stop };
        for _ in 0..COMMAND_CAPACITY {
            let (reply, _result) = oneshot::channel();
            client.enqueue(Command::Stats(reply)).unwrap();
        }
        let (reply, _result) = oneshot::channel();
        assert_eq!(
            client.enqueue(Command::Stats(reply)).unwrap_err(),
            ScreenEngineError::Busy
        );
        client.request_shutdown();
        tokio::time::timeout(Duration::from_millis(100), stopped.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*stopped.borrow());
        let (reply, _result) = oneshot::channel();
        assert_eq!(
            client.enqueue(Command::Stats(reply)).unwrap_err(),
            ScreenEngineError::Closed
        );
        receiver.close();
        drop(receiver);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn queued_take_owns_activity_even_when_the_awaiting_caller_disappears() {
        use openbot_contracts::auth::{AuthGeneration, Role};
        use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (stop, _stopped) = watch::channel(false);
        let client = ScreenEngineClient { commands, stop };
        let released = Arc::new(AtomicUsize::new(0));
        let auth = AuthContext::for_test(
            DeploymentId::new("d"),
            TenantId::new("t"),
            ActorId::new("a"),
            [Role::User],
            AuthGeneration::new(1),
            true,
        );
        let caller = tokio::spawn({
            let released = released.clone();
            let client = client.clone();
            async move {
                client
                    .take_control(
                        auth,
                        time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
                        Box::new(Activity(released)),
                    )
                    .await
            }
        });
        while receiver.is_empty() {
            tokio::task::yield_now().await;
        }
        caller.abort();
        let _ = caller.await;
        assert_eq!(released.load(Ordering::SeqCst), 0);
        client.request_shutdown();
        drop(receiver);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
}
