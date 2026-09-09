//! Native session epochs, one-shot capabilities, injected state tracking, and receipts (v5 §10.7).

use core::fmt;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, CapabilityId, PolicyDecisionId, RunId};

use super::identity::{
    MouseButton, NativeAction, NativeActionCategory, NativeKey, NativeTarget, NativeTargetHandle,
    ObservationGeneration,
};

/// Monotonic native session epoch per OS session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeSessionEpoch(u64);

impl NativeSessionEpoch {
    /// Construct epoch from numeric value.
    #[must_use]
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return raw counter.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance epoch monotonically without wrapping.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Check if epoch counter has reached saturation (poisoned).
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == u64::MAX
    }
}

impl fmt::Display for NativeSessionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One-shot action capability binding actor, run, decision, target, and epoch.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionCapability {
    capability_id: CapabilityId,
    actor: ActorId,
    run_id: RunId,
    decision_id: PolicyDecisionId,
    target_handle: NativeTargetHandle,
    observation_generation: ObservationGeneration,
    auth_generation: AuthGeneration,
    epoch: NativeSessionEpoch,
    consumed: bool,
    bound_action: Option<NativeAction>,
}

impl Eq for ActionCapability {}

impl ActionCapability {
    /// Construct a fresh action capability from authoritative Application/domain decision.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: CapabilityId,
        actor: ActorId,
        run_id: RunId,
        decision_id: PolicyDecisionId,
        target_handle: NativeTargetHandle,
        observation_generation: ObservationGeneration,
        auth_generation: AuthGeneration,
        epoch: NativeSessionEpoch,
    ) -> Self {
        Self {
            capability_id,
            actor,
            run_id,
            decision_id,
            target_handle,
            observation_generation,
            auth_generation,
            epoch,
            consumed: false,
            bound_action: None,
        }
    }

    /// Capability ID accessor.
    #[must_use]
    pub fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    /// Actor accessor.
    #[must_use]
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// Run ID accessor.
    #[must_use]
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Policy decision ID accessor.
    #[must_use]
    pub fn decision_id(&self) -> &PolicyDecisionId {
        &self.decision_id
    }

    /// Target handle accessor.
    #[must_use]
    pub fn target_handle(&self) -> &NativeTargetHandle {
        &self.target_handle
    }

    /// Observation generation accessor.
    #[must_use]
    pub fn observation_generation(&self) -> ObservationGeneration {
        self.observation_generation
    }

    /// Auth generation accessor.
    #[must_use]
    pub fn auth_generation(&self) -> AuthGeneration {
        self.auth_generation
    }

    /// Epoch accessor.
    #[must_use]
    pub fn epoch(&self) -> NativeSessionEpoch {
        self.epoch
    }

    /// Bound action accessor.
    #[must_use]
    pub fn bound_action(&self) -> Option<&NativeAction> {
        self.bound_action.as_ref()
    }

    /// Bind specific action to this capability.
    #[must_use]
    pub fn with_action(mut self, action: NativeAction) -> Self {
        self.bound_action = Some(action);
        self
    }

    /// Whether this capability has already been consumed.
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Consume the capability. Returns false if already consumed.
    pub fn consume(&mut self) -> bool {
        if self.consumed {
            false
        } else {
            self.consumed = true;
            true
        }
    }
}

/// Execution status of an injected native action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeActionStatus {
    NotSent,
    Sent,
    Confirmed,
    Unknown { reason: String },
}

/// Bounded, redacted execution receipt.
///
/// Plaintext keystrokes, secret payloads, and raw images never enter receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeReceipt {
    operation_id: String,
    target_handle: NativeTargetHandle,
    epoch: NativeSessionEpoch,
    category: NativeActionCategory,
    status: NativeActionStatus,
    pre_observation_ref: Option<String>,
    post_observation_ref: Option<String>,
}

impl NativeReceipt {
    /// Construct a redacted receipt.
    #[must_use]
    pub fn new(
        operation_id: impl Into<String>,
        target_handle: NativeTargetHandle,
        epoch: NativeSessionEpoch,
        category: NativeActionCategory,
        status: NativeActionStatus,
        pre_observation_ref: Option<String>,
        post_observation_ref: Option<String>,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            target_handle,
            epoch,
            category,
            status,
            pre_observation_ref,
            post_observation_ref,
        }
    }

    /// Operation ID accessor.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Target handle accessor.
    #[must_use]
    pub fn target_handle(&self) -> &NativeTargetHandle {
        &self.target_handle
    }

    /// Epoch accessor.
    #[must_use]
    pub fn epoch(&self) -> NativeSessionEpoch {
        self.epoch
    }

    /// Category accessor.
    #[must_use]
    pub fn category(&self) -> NativeActionCategory {
        self.category
    }

    /// Status accessor.
    #[must_use]
    pub fn status(&self) -> &NativeActionStatus {
        &self.status
    }

    /// Pre-observation reference.
    #[must_use]
    pub fn pre_observation_ref(&self) -> Option<&str> {
        self.pre_observation_ref.as_deref()
    }

    /// Post-observation reference.
    #[must_use]
    pub fn post_observation_ref(&self) -> Option<&str> {
        self.post_observation_ref.as_deref()
    }
}

impl fmt::Debug for NativeReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeReceipt")
            .field("operation_id", &self.operation_id)
            .field("target_handle", &self.target_handle)
            .field("epoch", &self.epoch)
            .field("category", &self.category)
            .field("status", &self.status)
            .field("pre_observation_ref", &self.pre_observation_ref)
            .field("post_observation_ref", &self.post_observation_ref)
            .finish()
    }
}

/// Injected inputs bound to a specific verified target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetInjectedObligation {
    pub target: NativeTarget,
    pub pressed_keys: BTreeSet<NativeKey>,
    pub pressed_buttons: BTreeSet<MouseButton>,
}

/// Tracks keys and mouse buttons strictly injected by THIS owner, bound to original targets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InjectedInputState {
    obligations: Vec<TargetInjectedObligation>,
}

impl InjectedInputState {
    /// Update tracking based on action for a specific target.
    pub fn record_action_for_target(
        &mut self,
        target: &NativeTarget,
        action: &NativeAction,
        confirmed: bool,
    ) {
        let idx = if let Some(i) = self
            .obligations
            .iter()
            .position(|o| o.target.matches_environment(target))
        {
            i
        } else {
            self.obligations.push(TargetInjectedObligation {
                target: target.clone(),
                pressed_keys: BTreeSet::new(),
                pressed_buttons: BTreeSet::new(),
            });
            self.obligations.len() - 1
        };

        let ob = &mut self.obligations[idx];
        match action {
            NativeAction::KeyDown { key } => {
                ob.pressed_keys.insert(key.clone());
            }
            NativeAction::KeyUp { key } => {
                if confirmed {
                    ob.pressed_keys.remove(key);
                }
            }
            NativeAction::MouseDown { button, .. } => {
                ob.pressed_buttons.insert(*button);
            }
            NativeAction::MouseUp { button, .. } => {
                if confirmed {
                    ob.pressed_buttons.remove(button);
                }
            }
            NativeAction::MouseMove { .. }
            | NativeAction::MouseWheel { .. }
            | NativeAction::InsertText { .. }
            | NativeAction::AxAction { .. } => {}
        }
        self.cleanup_empty();
    }

    /// Legacy record_action for callers without target identity.
    pub fn record_action(&mut self, action: &NativeAction) {
        if let Some(ob) = self.obligations.first_mut() {
            match action {
                NativeAction::KeyDown { key } => {
                    ob.pressed_keys.insert(key.clone());
                }
                NativeAction::KeyUp { key } => {
                    ob.pressed_keys.remove(key);
                }
                NativeAction::MouseDown { button, .. } => {
                    ob.pressed_buttons.insert(*button);
                }
                NativeAction::MouseUp { button, .. } => {
                    ob.pressed_buttons.remove(button);
                }
                _ => {}
            }
        }
        self.cleanup_empty();
    }

    /// Prune empty target obligations.
    fn cleanup_empty(&mut self) {
        self.obligations
            .retain(|o| !o.pressed_keys.is_empty() || !o.pressed_buttons.is_empty());
    }

    /// Return snapshot of active obligations to release.
    #[must_use]
    pub fn cleanup_obligations(&self) -> Vec<(NativeTarget, Vec<NativeKey>, Vec<MouseButton>)> {
        self.obligations
            .iter()
            .filter(|o| !o.pressed_keys.is_empty() || !o.pressed_buttons.is_empty())
            .map(|o| {
                (
                    o.target.clone(),
                    o.pressed_keys.iter().cloned().collect(),
                    o.pressed_buttons.iter().copied().collect(),
                )
            })
            .collect()
    }

    /// Confirm that release succeeded for this target and remove the confirmed obligations.
    pub fn confirm_release(
        &mut self,
        target: &NativeTarget,
        keys: &[NativeKey],
        buttons: &[MouseButton],
    ) {
        if let Some(ob) = self
            .obligations
            .iter_mut()
            .find(|o| o.target.matches_environment(target))
        {
            for k in keys {
                ob.pressed_keys.remove(k);
            }
            for b in buttons {
                ob.pressed_buttons.remove(b);
            }
        }
        self.cleanup_empty();
    }

    /// Return copies of currently pressed keys.
    #[must_use]
    pub fn pressed_keys(&self) -> Vec<NativeKey> {
        let mut set = BTreeSet::new();
        for ob in &self.obligations {
            for k in &ob.pressed_keys {
                set.insert(k.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Return copies of currently pressed mouse buttons.
    #[must_use]
    pub fn pressed_buttons(&self) -> Vec<MouseButton> {
        let mut set = BTreeSet::new();
        for ob in &self.obligations {
            for b in &ob.pressed_buttons {
                set.insert(*b);
            }
        }
        set.into_iter().collect()
    }

    /// Drain and return all pressed keys and buttons for scoped cleanup.
    pub fn take_cleanup(&mut self) -> (Vec<NativeKey>, Vec<MouseButton>) {
        let keys = self.pressed_keys();
        let buttons = self.pressed_buttons();
        self.obligations.clear();
        (keys, buttons)
    }

    /// Check if all injected state has been cleared.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.obligations
            .iter()
            .all(|o| o.pressed_keys.is_empty() && o.pressed_buttons.is_empty())
    }
}

/// RAII in-flight counter guard to guarantee cleanup even on abort, timeout, or panic.
pub struct InFlightGuard {
    in_flight: Arc<AtomicUsize>,
    pending_count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    active: bool,
}

impl InFlightGuard {
    /// Construct a new guard.
    #[must_use]
    pub fn new(
        in_flight: Arc<AtomicUsize>,
        pending_count: Arc<AtomicUsize>,
        notify: Arc<Notify>,
    ) -> Self {
        pending_count.fetch_add(1, Ordering::SeqCst);
        in_flight.fetch_add(1, Ordering::SeqCst);
        Self {
            in_flight,
            pending_count,
            notify,
            active: true,
        }
    }

    /// Disarm the guard without decrementing counters.
    pub fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.active {
            self.pending_count.fetch_sub(1, Ordering::SeqCst);
            if self.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
                self.notify.notify_waiters();
            }
        }
    }
}

/// Native input wheel holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeControlHolder {
    Bot,
    Human,
}

/// Closed native control errors without secret leaks.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeControlError {
    #[error("native_queue_full")]
    BoundedQueueFull,
    #[error("native_action_timeout")]
    ActionTimeout,
    #[error("native_human_lease_active")]
    HumanLeaseActive,
    #[error("native_observation_expired")]
    ObservationExpired,
    #[error("native_target_mismatch")]
    TargetMismatch,
    #[error("native_capability_already_consumed")]
    CapabilityConsumed,
    #[error("native_session_busy")]
    SessionBusy,
    #[error("native_owner_conflict")]
    OwnerConflict,
    #[error("native_epoch_stale")]
    EpochStale,
    #[error("native_session_locked")]
    SessionLocked,
    #[error("native_invalid_action: {0}")]
    InvalidAction(&'static str),
    #[error("native_reconciliation_required: {0}")]
    ReconciliationRequired(String),
    #[error("native_platform_error: {0}")]
    PlatformError(String),
    #[error("native_session_stopped")]
    Stopped,
}
