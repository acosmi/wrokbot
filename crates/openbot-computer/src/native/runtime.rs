//! Native owner, revocation and checked effect boundary. No production OS adapter is installed here.
use super::control::{
    ActionCapability, InjectedInputState, NativeActionStatus, NativeControlError,
    NativeControlHolder, NativeReceipt, NativeSessionEpoch,
};
use super::identity::{
    MouseButton, NativeAction, NativeKey, NativeTarget, NativeTargetHandle, ObservationGeneration,
    OsSessionId,
};
use async_trait::async_trait;
use openbot_contracts::ids::CapabilityId;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::timeout;

pub const MAX_PENDING_ACTIONS: usize = 16;
pub const ACTION_TIMEOUT: StdDuration = StdDuration::from_secs(5);
pub const STOP_CLEANUP_TIMEOUT: StdDuration = StdDuration::from_secs(5);
pub const MAX_OBSERVATION_AGE: Duration = Duration::seconds(1);
pub const MAX_CONSUMED_CAPABILITIES: usize = 1024;
pub const MAX_REGISTERED_TARGETS: usize = 64;
pub const MAX_REGISTERED_SESSIONS: usize = 64;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
fn next_id() -> Result<u64, NativeControlError> {
    NEXT_ID
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
        .map_err(|_| NativeControlError::EpochStale)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeInjectionOutcome {
    Success,
    Unknown { reason: String },
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native_platform_failed")]
pub struct NativePlatformError(pub String);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSessionState {
    Active,
    Locked,
    Sleeping,
    Terminated,
}

/// Trusted adapter contract: all input must occur inside gate.dispatch, synchronously.
/// Async preparation/confirmation may surround dispatch; background work must never retain a
/// raw unguarded effect. Current authority/target/fidelity locks must cover the supplied callback.
/// Defaults deny: metadata constructors and a session query alone grant no execution authority.
#[async_trait]
pub trait NativePlatformPort: Send + Sync {
    async fn inject_action(
        &self,
        target: &NativeTarget,
        action: &NativeAction,
        gate: &NativeActionGate<'_>,
    ) -> Result<NativeInjectionOutcome, NativePlatformError>;
    async fn release_inputs(
        &self,
        target: &NativeTarget,
        keys: &[NativeKey],
        buttons: &[MouseButton],
        gate: &NativeCleanupGate<'_>,
    ) -> Result<(), NativePlatformError>;
    async fn query_session_state(
        &self,
        session: &OsSessionId,
    ) -> Result<NativeSessionState, NativePlatformError>;
    /// Verify current actor/run/auth generation, durable decision+attempt, exact action, current
    /// full target identity, OS permissions and supported fidelity while holding authority locks.
    /// The callback must be invoked exactly once only when all proofs remain current.
    fn with_current_action(
        &self,
        _capability: &ActionCapability,
        _target: &NativeTarget,
        _action: &NativeAction,
        _effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        Err(NativePlatformError("native_authority_unavailable".into()))
    }
    /// Independently verify the ORIGINAL target and scoped owned inputs at the actual release.
    fn with_current_cleanup(
        &self,
        _target: &NativeTarget,
        _effect: &mut dyn FnMut() -> Result<(), NativePlatformError>,
    ) -> Result<(), NativePlatformError> {
        Err(NativePlatformError(
            "native_cleanup_authority_unavailable".into(),
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeEnvironmentChange {
    LockScreen,
    Sleep,
    SessionSwitch,
    DisplayChange,
    ProcessTerminated,
}
struct Observation {
    generation: ObservationGeneration,
    wall: OffsetDateTime,
    recorded: Instant,
}
struct NativeSessionInner {
    epoch: NativeSessionEpoch,
    acting_owner: Option<(String, u64)>,
    holder: NativeControlHolder,
    injected_state: InjectedInputState,
    targets: HashMap<NativeTargetHandle, NativeTarget>,
    observations: HashMap<NativeTargetHandle, Observation>,
    consumed: HashSet<CapabilityId>,
    unknown_effect: bool,
    cleanup_failed: bool,
    stopped: bool,
}
pub struct NativeSessionCoordinator {
    session_id: OsSessionId,
    platform: Arc<dyn NativePlatformPort>,
    pending: AtomicUsize,
    drained: Notify,
    execution: Mutex<()>,
    cleanup: Mutex<()>,
    revoke: watch::Sender<()>,
    inner: StdMutex<NativeSessionInner>,
}
impl NativeSessionCoordinator {
    fn new(session_id: OsSessionId, platform: Arc<dyn NativePlatformPort>) -> Self {
        Self {
            session_id,
            platform,
            pending: AtomicUsize::new(0),
            drained: Notify::new(),
            execution: Mutex::new(()),
            cleanup: Mutex::new(()),
            revoke: watch::channel(()).0,
            inner: StdMutex::new(NativeSessionInner {
                epoch: NativeSessionEpoch::new(1),
                acting_owner: None,
                holder: NativeControlHolder::Bot,
                injected_state: InjectedInputState::default(),
                targets: HashMap::new(),
                observations: HashMap::new(),
                consumed: HashSet::new(),
                unknown_effect: false,
                cleanup_failed: false,
                stopped: false,
            }),
        }
    }
    pub fn session_id(&self) -> &OsSessionId {
        &self.session_id
    }
}
// Strong ownership retains unresolved obligations even if every caller disappears. Reclaim only
// quiescent clean entries; capacity exhaustion denies acquisition instead of evicting obligations.
static SESSIONS: LazyLock<StdMutex<HashMap<OsSessionId, Arc<NativeSessionCoordinator>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[derive(Clone, Default)]
pub struct NativeSessionRegistry;
impl NativeSessionRegistry {
    pub fn new() -> Self {
        Self
    }
    pub async fn get_or_create(
        &self,
        session_id: OsSessionId,
        owner_id: impl Into<String>,
        platform: Arc<dyn NativePlatformPort>,
    ) -> Result<NativeSessionHandle, NativeControlError> {
        let owner_id = owner_id.into();
        if session_id.as_str().is_empty()
            || session_id.as_str().len() > 256
            || owner_id.is_empty()
            || owner_id.len() > 256
        {
            return Err(NativeControlError::InvalidAction("invalid_owner"));
        }
        let mut map = SESSIONS.lock().map_err(|_| NativeControlError::Stopped)?;
        map.retain(|_, c| {
            if Arc::strong_count(c) != 1 || c.pending.load(Ordering::SeqCst) != 0 {
                return true;
            }
            c.inner.lock().map_or(true, |s| {
                !s.injected_state.is_clean() || s.unknown_effect || s.cleanup_failed
            })
        });
        if !map.contains_key(&session_id) {
            if map.len() >= MAX_REGISTERED_SESSIONS {
                return Err(NativeControlError::BoundedQueueFull);
            }
            map.insert(
                session_id.clone(),
                Arc::new(NativeSessionCoordinator::new(
                    session_id.clone(),
                    platform.clone(),
                )),
            );
        }
        let c = map.get(&session_id).expect("inserted").clone();
        if !Arc::ptr_eq(&c.platform, &platform) {
            return Err(NativeControlError::OwnerConflict);
        }
        Ok(NativeSessionHandle {
            owner_id,
            handle_id: next_id()?,
            coordinator: c,
        })
    }
}
struct PendingGuard<'a>(&'a NativeSessionCoordinator);
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
        self.0.drained.notify_waiters();
    }
}
/// Exactly one dispatch, with cancellation-safe ownership recorded BEFORE the actual effect.
pub struct NativeActionGate<'a> {
    handle: &'a NativeSessionHandle,
    capability: &'a ActionCapability,
    target: &'a NativeTarget,
    action: &'a NativeAction,
    sent: AtomicBool,
    settled: AtomicBool,
}
impl NativeActionGate<'_> {
    pub fn dispatch(&self, effect: impl FnOnce()) -> Result<(), NativePlatformError> {
        let mut s = self
            .handle
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativePlatformError("state_unavailable".into()))?;
        self.handle
            .validate(&s, self.capability, self.action)
            .map_err(|_| NativePlatformError("dispatch_revoked".into()))?;
        if self.sent.load(Ordering::SeqCst) {
            return Err(NativePlatformError("dispatch_already_used".into()));
        }
        let mut effect = Some(effect);
        let result = self.handle.coordinator.platform.with_current_action(
            self.capability,
            self.target,
            self.action,
            &mut || {
                let effect = effect
                    .take()
                    .ok_or_else(|| NativePlatformError("dispatch_already_used".into()))?;
                self.sent.store(true, Ordering::SeqCst);
                s.injected_state
                    .record_action_for_target(self.target, self.action, false);
                effect();
                Ok(())
            },
        );
        if result.is_err() || !self.sent.load(Ordering::SeqCst) {
            return Err(NativePlatformError("current_authority_refused".into()));
        }
        Ok(())
    }
}
impl Drop for NativeActionGate<'_> {
    fn drop(&mut self) {
        if self.sent.load(Ordering::SeqCst)
            && !self.settled.load(Ordering::SeqCst)
            && let Ok(mut s) = self.handle.coordinator.inner.lock()
        {
            s.unknown_effect = true;
        }
    }
}
/// Release uses the original target; no new process or arbitrary first registry entry may receive it.
pub struct NativeCleanupGate<'a> {
    coordinator: &'a NativeSessionCoordinator,
    target: &'a NativeTarget,
    dispatched: AtomicBool,
}
impl NativeCleanupGate<'_> {
    pub fn dispatch(&self, effect: impl FnOnce()) -> Result<(), NativePlatformError> {
        let s = self
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativePlatformError("state_unavailable".into()))?;
        if s.targets.values().any(|t| {
            t.os_session() == self.target.os_session()
                && t.pid() == self.target.pid()
                && t.window_id() == self.target.window_id()
                && !t.matches_environment(self.target)
        }) {
            return Err(NativePlatformError("cleanup_target_replaced".into()));
        }
        let mut effect = Some(effect);
        self.coordinator
            .platform
            .with_current_cleanup(self.target, &mut || {
                if self.dispatched.swap(true, Ordering::SeqCst) {
                    return Err(NativePlatformError("cleanup_already_used".into()));
                }
                effect
                    .take()
                    .ok_or_else(|| NativePlatformError("cleanup_already_used".into()))?(
                );
                Ok(())
            })?;
        if !self.dispatched.load(Ordering::SeqCst) {
            return Err(NativePlatformError("cleanup_unconfirmed".into()));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct NativeSessionHandle {
    owner_id: String,
    handle_id: u64,
    coordinator: Arc<NativeSessionCoordinator>,
}
impl NativeSessionHandle {
    pub fn session_id(&self) -> &OsSessionId {
        &self.coordinator.session_id
    }
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
    pub fn pending_actions(&self) -> usize {
        self.coordinator.pending.load(Ordering::SeqCst)
    }
    pub async fn register_target(&self, target: NativeTarget) -> NativeTargetHandle {
        let mut s = self
            .coordinator
            .inner
            .lock()
            .expect("native state poisoned");
        let handle = NativeTargetHandle::new(format!("native-target-{}", next_id().unwrap_or(0)));
        if s.stopped
            || handle.as_str() == "native-target-0"
            || !target.matches_session(self.session_id())
            || !target.valid_identity()
        {
            return handle;
        }
        s.targets.retain(|_, t| {
            !(t.os_session() == target.os_session()
                && t.pid() == target.pid()
                && t.window_id() == target.window_id())
        });
        if s.targets.len() >= MAX_REGISTERED_TARGETS {
            return handle;
        }
        let active: HashSet<_> = s.targets.keys().cloned().collect();
        s.observations.retain(|h, _| active.contains(h));
        s.observations.insert(
            handle.clone(),
            Observation {
                generation: target.observation_generation(),
                wall: OffsetDateTime::now_utc(),
                recorded: Instant::now(),
            },
        );
        s.targets.insert(handle.clone(), target);
        handle
    }
    pub async fn update_observation(
        &self,
        handle: &NativeTargetHandle,
        generation: ObservationGeneration,
        timestamp: OffsetDateTime,
    ) -> Result<(), NativeControlError> {
        let mut s = self
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativeControlError::Stopped)?;
        if !s.targets.contains_key(handle) {
            return Err(NativeControlError::TargetMismatch);
        }
        if timestamp > OffsetDateTime::now_utc()
            || s.observations
                .get(handle)
                .is_some_and(|o| generation < o.generation)
        {
            return Err(NativeControlError::ObservationExpired);
        }
        s.observations.insert(
            handle.clone(),
            Observation {
                generation,
                wall: timestamp,
                recorded: Instant::now(),
            },
        );
        Ok(())
    }
    pub async fn acquire_acting(&self) -> Result<(), NativeControlError> {
        let mut s = self
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativeControlError::Stopped)?;
        if s.unknown_effect || s.cleanup_failed {
            return Err(NativeControlError::ReconciliationRequired(
                "native_unresolved".into(),
            ));
        }
        if s.stopped {
            return Err(NativeControlError::Stopped);
        }
        if s.holder == NativeControlHolder::Human {
            return Err(NativeControlError::HumanLeaseActive);
        }
        if let Some((_, id)) = &s.acting_owner {
            return if *id == self.handle_id {
                Ok(())
            } else {
                Err(NativeControlError::SessionBusy)
            };
        }
        if self.coordinator.pending.load(Ordering::SeqCst) > 0 || !s.injected_state.is_clean() {
            return Err(NativeControlError::SessionBusy);
        }
        s.acting_owner = Some((self.owner_id.clone(), self.handle_id));
        Ok(())
    }
    pub async fn release_acting(&self) -> Result<(), NativeControlError> {
        let mut s = self
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativeControlError::Stopped)?;
        if s.acting_owner
            .as_ref()
            .is_some_and(|(_, id)| *id != self.handle_id)
        {
            return Err(NativeControlError::OwnerConflict);
        }
        if self.coordinator.pending.load(Ordering::SeqCst) > 0
            || !s.injected_state.is_clean()
            || s.unknown_effect
            || s.cleanup_failed
        {
            return Err(NativeControlError::SessionBusy);
        }
        s.epoch = s.epoch.next();
        s.consumed.clear();
        s.acting_owner = None;
        Ok(())
    }
    pub async fn current_epoch(&self) -> NativeSessionEpoch {
        self.coordinator
            .inner
            .lock()
            .expect("native state poisoned")
            .epoch
    }
    fn validate(
        &self,
        s: &NativeSessionInner,
        cap: &ActionCapability,
        action: &NativeAction,
    ) -> Result<NativeTarget, NativeControlError> {
        if s.stopped {
            return Err(NativeControlError::Stopped);
        }
        if s.holder == NativeControlHolder::Human {
            return Err(NativeControlError::HumanLeaseActive);
        }
        if s.epoch.is_exhausted() || s.epoch != cap.epoch() {
            return Err(NativeControlError::EpochStale);
        }
        if s.acting_owner
            .as_ref()
            .is_none_or(|(_, id)| *id != self.handle_id)
        {
            return Err(NativeControlError::OwnerConflict);
        }
        if s.unknown_effect || s.cleanup_failed {
            return Err(NativeControlError::ReconciliationRequired(
                "native_unresolved".into(),
            ));
        }
        let target = s
            .targets
            .get(cap.target_handle())
            .ok_or(NativeControlError::TargetMismatch)?;
        let o = s
            .observations
            .get(cap.target_handle())
            .ok_or(NativeControlError::ObservationExpired)?;
        let now = OffsetDateTime::now_utc();
        if o.generation != cap.observation_generation()
            || now < o.wall
            || now - o.wall > MAX_OBSERVATION_AGE
            || o.recorded.elapsed() > StdDuration::from_secs(1)
        {
            return Err(NativeControlError::ObservationExpired);
        }
        action
            .validate(Some(&target.coordinate_transform().bounds))
            .map_err(|_| NativeControlError::InvalidAction("invalid_action"))?;
        if cap.bound_action() != Some(action) {
            return Err(NativeControlError::InvalidAction("action_binding_required"));
        }
        for id in [
            cap.capability_id().as_str(),
            cap.actor().as_str(),
            cap.run_id().as_str(),
            cap.decision_id().as_str(),
        ] {
            if id.is_empty() || id.len() > 256 {
                return Err(NativeControlError::InvalidAction("invalid_capability"));
            }
        }
        Ok(target.clone())
    }
    pub async fn perform_action(
        &self,
        cap: ActionCapability,
        action: NativeAction,
        observation_time: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<NativeReceipt, NativeControlError> {
        let mut revoked = self.coordinator.revoke.subscribe();
        if now < observation_time || now - observation_time > MAX_OBSERVATION_AGE {
            return Err(NativeControlError::ObservationExpired);
        }
        // Admission is atomic and human/owner validation happens before waiting for execution.
        {
            let s = self
                .coordinator
                .inner
                .lock()
                .map_err(|_| NativeControlError::Stopped)?;
            self.validate(&s, &cap, &action)?;
        }
        self.coordinator
            .pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_PENDING_ACTIONS).then_some(n + 1)
            })
            .map_err(|_| NativeControlError::BoundedQueueFull)?;
        let _pending = PendingGuard(&self.coordinator);
        let result = timeout(ACTION_TIMEOUT, async {
            tokio::select! {
                biased;
                _=revoked.changed()=>Err(NativeControlError::EpochStale),
                result=self.perform_reserved(cap,action)=>result
            }
        })
        .await;
        result.map_err(|_| NativeControlError::ActionTimeout)?
    }
    async fn perform_reserved(
        &self,
        mut cap: ActionCapability,
        action: NativeAction,
    ) -> Result<NativeReceipt, NativeControlError> {
        let _execution = self.coordinator.execution.lock().await;
        let target = {
            let mut s = self
                .coordinator
                .inner
                .lock()
                .map_err(|_| NativeControlError::Stopped)?;
            let t = self.validate(&s, &cap, &action)?;
            if s.consumed.contains(cap.capability_id()) || !cap.consume() {
                return Err(NativeControlError::CapabilityConsumed);
            }
            if s.consumed.len() >= MAX_CONSUMED_CAPABILITIES {
                return Err(NativeControlError::BoundedQueueFull);
            }
            s.consumed.insert(cap.capability_id().clone());
            t
        };
        let state = self
            .coordinator
            .platform
            .query_session_state(self.session_id())
            .await
            .map_err(|_| NativeControlError::PlatformError("session_query_failed".into()))?;
        if state != NativeSessionState::Active {
            return Err(NativeControlError::SessionLocked);
        }
        let gate = NativeActionGate {
            handle: self,
            capability: &cap,
            target: &target,
            action: &action,
            sent: AtomicBool::new(false),
            settled: AtomicBool::new(false),
        };
        let result = self
            .coordinator
            .platform
            .inject_action(&target, &action, &gate)
            .await;
        let sent = gate.sent.load(Ordering::SeqCst);
        let status = {
            let mut s = self
                .coordinator
                .inner
                .lock()
                .map_err(|_| NativeControlError::Stopped)?;
            match result {
                Ok(NativeInjectionOutcome::Success)
                    if sent
                        && s.epoch == cap.epoch()
                        && s.targets.get(cap.target_handle()) == Some(&target) =>
                {
                    s.injected_state
                        .record_action_for_target(&target, &action, true);
                    NativeActionStatus::Confirmed
                }
                _ if sent => {
                    s.unknown_effect = true;
                    NativeActionStatus::Unknown {
                        reason: "native_injection_unconfirmed".into(),
                    }
                }
                _ => {
                    gate.settled.store(true, Ordering::SeqCst);
                    return Err(NativeControlError::PlatformError(
                        "native_dispatch_refused".into(),
                    ));
                }
            }
        };
        gate.settled.store(true, Ordering::SeqCst);
        Ok(NativeReceipt::new(
            format!("op-{}", cap.capability_id().as_str()),
            cap.target_handle().clone(),
            cap.epoch(),
            action.category(),
            status,
            Some(format!("obs-gen-{}", cap.observation_generation())),
            None,
        ))
    }
    async fn revoke_and_cleanup(&self, stop: bool, human: bool) -> Result<(), NativeControlError> {
        {
            let mut s = self
                .coordinator
                .inner
                .lock()
                .map_err(|_| NativeControlError::Stopped)?;
            s.epoch = s.epoch.next();
            s.stopped |= stop;
            if human {
                s.holder = NativeControlHolder::Human;
            }
            self.coordinator.revoke.send_replace(());
        }
        timeout(STOP_CLEANUP_TIMEOUT, async {
            let _cleanup = self.coordinator.cleanup.lock().await;
            loop {
                let notified = self.coordinator.drained.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.coordinator.pending.load(Ordering::SeqCst) == 0 {
                    break;
                }
                notified.await;
            }
            let obligations = {
                let s = self
                    .coordinator
                    .inner
                    .lock()
                    .map_err(|_| NativeControlError::Stopped)?;
                s.injected_state.cleanup_obligations()
            };
            for (target, keys, buttons) in obligations {
                let gate = NativeCleanupGate {
                    coordinator: &self.coordinator,
                    target: &target,
                    dispatched: AtomicBool::new(false),
                };
                // Failure/cancellation retains the obligation. Mark BEFORE await for Drop safety.
                self.coordinator
                    .inner
                    .lock()
                    .map_err(|_| NativeControlError::Stopped)?
                    .cleanup_failed = true;
                let result = self
                    .coordinator
                    .platform
                    .release_inputs(&target, &keys, &buttons, &gate)
                    .await;
                if result.is_err() || !gate.dispatched.load(Ordering::SeqCst) {
                    return Err(NativeControlError::PlatformError(
                        "native_cleanup_unconfirmed".into(),
                    ));
                }
                self.coordinator
                    .inner
                    .lock()
                    .map_err(|_| NativeControlError::Stopped)?
                    .injected_state
                    .confirm_release(&target, &keys, &buttons);
            }
            let mut s = self
                .coordinator
                .inner
                .lock()
                .map_err(|_| NativeControlError::Stopped)?;
            s.cleanup_failed = !s.injected_state.is_clean();
            if s.unknown_effect || s.cleanup_failed {
                return Err(NativeControlError::ReconciliationRequired(
                    "native_unresolved".into(),
                ));
            }
            s.acting_owner = None;
            Ok(())
        })
        .await
        .map_err(|_| NativeControlError::ActionTimeout)?
    }
    pub async fn stop(&self) -> Result<(), NativeControlError> {
        self.revoke_and_cleanup(true, false).await
    }
    pub async fn notify_human_takeover(&self) -> Result<(), NativeControlError> {
        self.revoke_and_cleanup(false, true).await
    }
    pub async fn release_human_takeover(&self) -> Result<(), NativeControlError> {
        let mut s = self
            .coordinator
            .inner
            .lock()
            .map_err(|_| NativeControlError::Stopped)?;
        if s.unknown_effect
            || s.cleanup_failed
            || !s.injected_state.is_clean()
            || self.coordinator.pending.load(Ordering::SeqCst) > 0
        {
            return Err(NativeControlError::ReconciliationRequired(
                "native_unresolved".into(),
            ));
        }
        s.holder = NativeControlHolder::Bot;
        s.epoch = s.epoch.next();
        s.acting_owner = None;
        s.targets.clear();
        s.observations.clear();
        Ok(())
    }
    pub async fn notify_environment_change(
        &self,
        _change: NativeEnvironmentChange,
    ) -> Result<(), NativeControlError> {
        // Terminal until a new trusted lifecycle is established; no implicit unlock/resume.
        self.revoke_and_cleanup(true, false).await
    }
}
