//! Browser control handover and the authority-owned HumanLease fence.
//!
//! The fixed upstream keeps the wheel state beside the browser and deliberately has no Playwright
//! dependency in that state machine. This module preserves that split, then adds the v3 §12.5
//! epoch/generation fence. Every clock value is supplied by the caller: policy/configuration owns
//! lease duration, and this crate must not invent a default that the first source never specified.

use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::ids::{ActorId, ComputerGeneration, ComputerId, DocumentGeneration, TabId};
use openbot_contracts::text::trim_ecmascript;
use time::{Duration, OffsetDateTime};

/// Fixed-upstream unanswered help-request lifetime.
pub const HELP_REQUEST_TTL: Duration = Duration::minutes(10);

/// Fixed-upstream default reason when the Bot supplied no meaningful text.
pub const DEFAULT_HELP_REASON: &str = "The assistant needs a person to continue.";

/// Fixed-upstream default label for a scoped secret request.
pub const DEFAULT_SECRET_LABEL: &str = "the value this page is asking for";

/// Who currently has the wheel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlHolder {
    /// Agent/browser operations may proceed.
    Bot,
    /// A person holds the wheel; Agent acting must be refused rather than queued.
    Human,
}

/// Monotonic HumanLease epoch within one computer generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanLeaseEpoch(u64);

impl HumanLeaseEpoch {
    /// Construct an epoch from authority-owned state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw counter.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// The exact field authorized for one pending secret insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSecretTarget {
    field_ref: String,
    document_generation: DocumentGeneration,
}

impl PendingSecretTarget {
    /// Element reference named by the Bot's snapshot.
    #[must_use]
    pub fn field_ref(&self) -> &str {
        self.field_ref.as_str()
    }

    /// Authority-owned document generation bound to that reference.
    #[must_use]
    pub const fn document_generation(&self) -> DocumentGeneration {
        self.document_generation
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlState {
    holder: ControlHolder,
    since: OffsetDateTime,
    requested: bool,
    requested_at: Option<OffsetDateTime>,
    reason: Option<String>,
    secret_wanted: Option<String>,
    pending_secret: Option<PendingSecretTarget>,
}

/// Read-only state exposed to the control surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlSnapshot {
    state: ControlState,
    epoch: HumanLeaseEpoch,
    poisoned: bool,
    lease_expires_at: Option<OffsetDateTime>,
}

impl ControlSnapshot {
    /// Current wheel holder.
    #[must_use]
    pub const fn holder(&self) -> ControlHolder {
        self.state.holder
    }

    /// When the current holder took effect.
    #[must_use]
    pub const fn since(&self) -> OffsetDateTime {
        self.state.since
    }

    /// Whether the Bot has an unanswered request for full control handover.
    #[must_use]
    pub const fn requested(&self) -> bool {
        self.state.requested
    }

    /// Time of the unanswered request; absent after expiry/take/release.
    #[must_use]
    pub const fn requested_at(&self) -> Option<OffsetDateTime> {
        self.state.requested_at
    }

    /// Bot-supplied reason. It survives take and disappears on release.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.state.reason.as_deref()
    }

    /// Label only; the secret value is never stored in control state.
    #[must_use]
    pub fn secret_wanted(&self) -> Option<&str> {
        self.state.secret_wanted.as_deref()
    }

    /// Current scoped secret target.
    #[must_use]
    pub fn pending_secret(&self) -> Option<&PendingSecretTarget> {
        self.state.pending_secret.as_ref()
    }

    /// Current HumanLease epoch.
    #[must_use]
    pub const fn epoch(&self) -> HumanLeaseEpoch {
        self.epoch
    }

    /// Epoch exhaustion poisoned this generation; only a newer ComputerGeneration can recover it.
    #[must_use]
    pub const fn poisoned(&self) -> bool {
        self.poisoned
    }

    /// Human lease expiry; absent while the Bot holds the wheel.
    #[must_use]
    pub const fn lease_expires_at(&self) -> Option<OffsetDateTime> {
        self.lease_expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HumanLease {
    owner: ActorId,
    computer_id: ComputerId,
    tab_id: TabId,
    computer_generation: ComputerGeneration,
    auth_generation: AuthGeneration,
    epoch: HumanLeaseEpoch,
    expires_at: OffsetDateTime,
}

/// Non-authority ticket echoed by a viewer with each input frame.
///
/// The ticket deliberately contains no actor or role. The current [`AuthContext`] supplies those at
/// authorization time, and every field below is compared with the Rust-owned lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanInputTicket {
    computer_id: ComputerId,
    tab_id: TabId,
    computer_generation: ComputerGeneration,
    epoch: HumanLeaseEpoch,
    expires_at: OffsetDateTime,
}

/// Single-use, non-serializable proof that fresh Rust authority accepted one queued human input.
///
/// Fields are private and the type is not `Clone`, so transport/renderer code cannot mint or replay
/// it. The engine consumes it immediately before writing the input command.
pub struct AuthorizedHumanInput {
    computer_id: ComputerId,
    tab_id: TabId,
    computer_generation: ComputerGeneration,
    epoch: HumanLeaseEpoch,
    expires_at: OffsetDateTime,
}

impl AuthorizedHumanInput {
    /// Exact computer accepted by the current lease.
    #[must_use]
    pub fn computer_id(&self) -> &ComputerId {
        &self.computer_id
    }

    /// Exact active tab accepted by the current lease.
    #[must_use]
    pub fn tab_id(&self) -> &TabId {
        &self.tab_id
    }

    /// Computer generation accepted by the current lease.
    #[must_use]
    pub const fn computer_generation(&self) -> ComputerGeneration {
        self.computer_generation
    }

    /// HumanLease epoch checked immediately before engine dispatch.
    #[must_use]
    pub const fn epoch(&self) -> HumanLeaseEpoch {
        self.epoch
    }

    /// Absolute lease expiry checked by the authority layer.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl HumanInputTicket {
    /// Computer bound to the ticket.
    #[must_use]
    pub fn computer_id(&self) -> &ComputerId {
        &self.computer_id
    }

    /// Tab bound to the ticket.
    #[must_use]
    pub fn tab_id(&self) -> &TabId {
        &self.tab_id
    }

    /// Computer generation bound to the ticket.
    #[must_use]
    pub const fn computer_generation(&self) -> ComputerGeneration {
        self.computer_generation
    }

    /// Lease epoch bound to the ticket.
    #[must_use]
    pub const fn epoch(&self) -> HumanLeaseEpoch {
        self.epoch
    }

    /// Absolute expiry chosen by the authority layer.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// Stable control-plane failures; UI text is localized outside this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ControlError {
    /// A person is driving, so Agent acting is refused immediately.
    #[error("human_has_control")]
    HumanHasControl,
    /// Human input arrived without a current HumanLease.
    #[error("take_control_first")]
    TakeControlFirst,
    /// Authority supplied an expiry that was not in the future.
    #[error("human_lease_invalid_expiry")]
    InvalidLeaseExpiry,
    /// Lease expired before the input was authorized.
    #[error("human_lease_expired")]
    LeaseExpired,
    /// Actor/auth generation/resource/generation/epoch did not exactly match the current lease.
    #[error("human_input_stale_or_wrong_scope")]
    StaleOrWrongScope,
    /// A secret request did not name a field reference.
    #[error("secret_field_ref_required")]
    SecretFieldRefRequired,
    /// No secret request is currently pending.
    #[error("no_secret_pending")]
    NoSecretPending,
    /// The engine completed a different/stale secret target.
    #[error("secret_target_changed")]
    SecretTargetChanged,
    /// Computer restart generation did not advance.
    #[error("computer_generation_did_not_advance")]
    ComputerGenerationDidNotAdvance,
    /// The HumanLease epoch was exhausted; this generation refuses both human input and Bot acting.
    #[error("human_lease_epoch_poisoned")]
    HumanLeaseEpochPoisoned,
}

/// One computer/tab's wheel and HumanLease state machine.
#[derive(Debug)]
pub struct ControlService {
    computer_id: ComputerId,
    tab_id: TabId,
    computer_generation: ComputerGeneration,
    epoch: HumanLeaseEpoch,
    poisoned: bool,
    state: ControlState,
    lease: Option<HumanLease>,
}

impl ControlService {
    /// Start with the Bot holding the wheel.
    #[must_use]
    pub fn new(
        computer_id: ComputerId,
        tab_id: TabId,
        computer_generation: ComputerGeneration,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            computer_id,
            tab_id,
            computer_generation,
            epoch: HumanLeaseEpoch::default(),
            poisoned: false,
            state: ControlState {
                holder: ControlHolder::Bot,
                since: now,
                requested: false,
                requested_at: None,
                reason: None,
                secret_wanted: None,
                pending_secret: None,
            },
            lease: None,
        }
    }

    /// Read current state, lazily retiring expired asks/leases exactly when somebody observes them.
    pub fn state(&mut self, now: OffsetDateTime) -> ControlSnapshot {
        let _ = self.expire_human_lease(now);
        self.expire_help_request(now);
        self.snapshot()
    }

    /// Bot asks for help but does not hand over control.
    pub fn request_help(&mut self, reason: Option<&str>, now: OffsetDateTime) -> ControlSnapshot {
        let reason = reason
            .map(trim_ecmascript)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_HELP_REASON)
            .to_owned();
        self.state.requested = true;
        self.state.requested_at = Some(now);
        self.state.reason = Some(reason);
        self.snapshot()
    }

    /// Bot asks for one value, binding the request to an authority-owned document generation.
    pub fn request_secret(
        &mut self,
        label: Option<&str>,
        field_ref: &str,
        document_generation: DocumentGeneration,
    ) -> Result<ControlSnapshot, ControlError> {
        let field_ref = trim_ecmascript(field_ref);
        if field_ref.is_empty() {
            return Err(ControlError::SecretFieldRefRequired);
        }
        let label = label
            .map(trim_ecmascript)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_SECRET_LABEL)
            .to_owned();
        self.state.secret_wanted = Some(label);
        self.state.pending_secret = Some(PendingSecretTarget {
            field_ref: field_ref.to_owned(),
            document_generation,
        });
        Ok(self.snapshot())
    }

    /// Return the current target before constructing a typed SecretInsert command.
    pub fn pending_secret(&self) -> Result<PendingSecretTarget, ControlError> {
        self.state
            .pending_secret
            .clone()
            .ok_or(ControlError::NoSecretPending)
    }

    /// Clear a secret request only after that exact target received the value.
    pub fn secret_supplied(&mut self, completed: &PendingSecretTarget) -> Result<(), ControlError> {
        let Some(current) = self.state.pending_secret.as_ref() else {
            return Err(ControlError::NoSecretPending);
        };
        if current != completed {
            return Err(ControlError::SecretTargetChanged);
        }
        self.state.secret_wanted = None;
        self.state.pending_secret = None;
        Ok(())
    }

    /// A verified actor takes (or transfers) control until the authority-selected expiry.
    pub fn take(
        &mut self,
        auth: &AuthContext,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<ControlSnapshot, ControlError> {
        self.ensure_not_poisoned()?;
        if expires_at <= now {
            return Err(ControlError::InvalidLeaseExpiry);
        }
        self.bump_epoch()?;
        self.state = ControlState {
            holder: ControlHolder::Human,
            since: now,
            requested: false,
            requested_at: None,
            reason: self.state.reason.take(),
            secret_wanted: None,
            pending_secret: None,
        };
        self.lease = Some(HumanLease {
            owner: auth.actor().clone(),
            computer_id: self.computer_id.clone(),
            tab_id: self.tab_id.clone(),
            computer_generation: self.computer_generation,
            auth_generation: auth.auth_generation(),
            epoch: self.epoch,
            expires_at,
        });
        Ok(self.snapshot())
    }

    /// Hand control back to the Bot and invalidate every queued human input.
    pub fn release(&mut self, now: OffsetDateTime) -> Result<ControlSnapshot, ControlError> {
        self.ensure_not_poisoned()?;
        self.bump_epoch()?;
        self.release_without_bump(now);
        Ok(self.snapshot())
    }

    /// Refuse Agent acting while a current human lease exists. Nothing is queued.
    pub fn assert_bot_may_act(&mut self, now: OffsetDateTime) -> Result<(), ControlError> {
        self.ensure_not_poisoned()?;
        self.expire_human_lease(now)?;
        if self.state.holder == ControlHolder::Human {
            return Err(ControlError::HumanHasControl);
        }
        Ok(())
    }

    /// Mint the exact non-authority ticket the viewer must echo with input.
    pub fn issue_human_input_ticket(
        &mut self,
        now: OffsetDateTime,
    ) -> Result<HumanInputTicket, ControlError> {
        self.ensure_not_poisoned()?;
        if self.expire_human_lease(now)? {
            return Err(ControlError::LeaseExpired);
        }
        let lease = self.lease.as_ref().ok_or(ControlError::TakeControlFirst)?;
        Ok(HumanInputTicket {
            computer_id: lease.computer_id.clone(),
            tab_id: lease.tab_id.clone(),
            computer_generation: lease.computer_generation,
            epoch: lease.epoch,
            expires_at: lease.expires_at,
        })
    }

    /// Re-authorize one queued input against fresh AuthContext and current lease state.
    pub fn authorize_human_input(
        &mut self,
        auth: &AuthContext,
        ticket: &HumanInputTicket,
        now: OffsetDateTime,
    ) -> Result<(), ControlError> {
        self.ensure_not_poisoned()?;
        if self.expire_human_lease(now)? {
            return Err(ControlError::LeaseExpired);
        }
        let lease = self.lease.as_ref().ok_or(ControlError::TakeControlFirst)?;
        if lease.owner != *auth.actor()
            || lease.auth_generation != auth.auth_generation()
            || lease.computer_id != ticket.computer_id
            || lease.tab_id != ticket.tab_id
            || lease.computer_generation != ticket.computer_generation
            || lease.epoch != ticket.epoch
            || lease.expires_at != ticket.expires_at
        {
            return Err(ControlError::StaleOrWrongScope);
        }
        Ok(())
    }

    /// Re-authorize and mint a non-forgeable receipt consumed by the engine input boundary.
    pub fn authorize_human_input_receipt(
        &mut self,
        auth: &AuthContext,
        ticket: &HumanInputTicket,
        now: OffsetDateTime,
    ) -> Result<AuthorizedHumanInput, ControlError> {
        self.authorize_human_input(auth, ticket, now)?;
        Ok(AuthorizedHumanInput {
            computer_id: ticket.computer_id.clone(),
            tab_id: ticket.tab_id.clone(),
            computer_generation: ticket.computer_generation,
            epoch: ticket.epoch,
            expires_at: ticket.expires_at,
        })
    }

    /// Navigation invalidates already queued input while preserving a current person's handover.
    pub fn document_navigated(&mut self) -> Result<ControlSnapshot, ControlError> {
        self.ensure_not_poisoned()?;
        self.bump_epoch()?;
        if let Some(lease) = &mut self.lease {
            lease.epoch = self.epoch;
        }
        Ok(self.snapshot())
    }

    /// Restart/reset advances computer generation, releases control and clears pending requests.
    pub fn computer_restarted(
        &mut self,
        new_generation: ComputerGeneration,
        now: OffsetDateTime,
    ) -> Result<ControlSnapshot, ControlError> {
        if new_generation <= self.computer_generation {
            return Err(ControlError::ComputerGenerationDidNotAdvance);
        }
        self.computer_generation = new_generation;
        // ComputerGeneration is the outer fence. Once it advances, resetting an exhausted epoch
        // cannot revive an old ticket because every ticket also binds the former generation.
        self.epoch = self.epoch.next().unwrap_or_default();
        self.poisoned = false;
        self.release_without_bump(now);
        Ok(self.snapshot())
    }

    fn snapshot(&self) -> ControlSnapshot {
        ControlSnapshot {
            state: self.state.clone(),
            epoch: self.epoch,
            poisoned: self.poisoned,
            lease_expires_at: self.lease.as_ref().map(|lease| lease.expires_at),
        }
    }

    fn bump_epoch(&mut self) -> Result<(), ControlError> {
        let Some(next) = self.epoch.next() else {
            self.enter_poisoned();
            return Err(ControlError::HumanLeaseEpochPoisoned);
        };
        self.epoch = next;
        Ok(())
    }

    fn ensure_not_poisoned(&self) -> Result<(), ControlError> {
        if self.poisoned {
            Err(ControlError::HumanLeaseEpochPoisoned)
        } else {
            Ok(())
        }
    }

    fn enter_poisoned(&mut self) {
        self.poisoned = true;
        self.lease = None;
        self.state.holder = ControlHolder::Bot;
        self.state.requested = false;
        self.state.requested_at = None;
        self.state.reason = None;
        self.state.secret_wanted = None;
        self.state.pending_secret = None;
    }

    fn release_without_bump(&mut self, now: OffsetDateTime) {
        self.state = ControlState {
            holder: ControlHolder::Bot,
            since: now,
            requested: false,
            requested_at: None,
            reason: None,
            secret_wanted: None,
            pending_secret: None,
        };
        self.lease = None;
    }

    fn expire_human_lease(&mut self, now: OffsetDateTime) -> Result<bool, ControlError> {
        let expired = self
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.expires_at);
        if expired {
            self.bump_epoch()?;
            self.release_without_bump(now);
        }
        Ok(expired)
    }

    fn expire_help_request(&mut self, now: OffsetDateTime) {
        let expired = self.state.holder == ControlHolder::Bot
            && self.state.requested
            && self
                .state
                .requested_at
                .is_some_and(|requested_at| now - requested_at > HELP_REQUEST_TTL);
        if expired {
            self.state.requested = false;
            self.state.requested_at = None;
            self.state.reason = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{
        ActorId, ComputerGeneration, ComputerId, DeploymentId, DocumentGeneration, TabId, TenantId,
    };
    use time::{Duration, OffsetDateTime, macros::datetime};

    use super::{
        ControlError, ControlHolder, ControlService, DEFAULT_HELP_REASON, DEFAULT_SECRET_LABEL,
        HELP_REQUEST_TTL, HumanLeaseEpoch,
    };

    const START: OffsetDateTime = datetime!(2026-08-28 12:00 UTC);

    fn auth(actor: &str, generation: u64) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("deployment-0"),
            TenantId::new("tenant-0"),
            ActorId::new(actor),
            [Role::User],
            AuthGeneration::new(generation),
            false,
        )
    }

    fn service() -> ControlService {
        ControlService::new(
            ComputerId::new("computer-0"),
            TabId::new("tab-0"),
            ComputerGeneration::new(7),
            START,
        )
    }

    #[test]
    fn unanswered_help_expires_only_after_the_exact_upstream_ttl() {
        let mut service = service();
        let requested = service.request_help(Some("\u{feff}   "), START);
        assert_eq!(requested.holder(), ControlHolder::Bot);
        assert!(requested.requested());
        assert_eq!(requested.reason(), Some(DEFAULT_HELP_REASON));
        assert_eq!(requested.requested_at(), Some(START));

        let exact = service.state(START + HELP_REQUEST_TTL);
        assert!(
            exact.requested(),
            "upstream expires only when age is greater than TTL"
        );

        let expired = service.state(START + HELP_REQUEST_TTL + Duration::nanoseconds(1));
        assert!(!expired.requested());
        assert_eq!(expired.reason(), None);
        assert_eq!(expired.requested_at(), None);
        assert_eq!(expired.epoch(), HumanLeaseEpoch::new(0));
    }

    #[test]
    fn scoped_secret_stores_only_label_ref_and_authoritative_document_generation() {
        let mut service = service();
        assert_eq!(service.pending_secret(), Err(ControlError::NoSecretPending));
        assert_eq!(
            service.request_secret(None, "\u{feff}   ", DocumentGeneration::new(3)),
            Err(ControlError::SecretFieldRefRequired)
        );

        let snapshot = service
            .request_secret(None, "\u{feff}field-9\u{00a0}", DocumentGeneration::new(3))
            .expect("valid field ref");
        assert_eq!(snapshot.secret_wanted(), Some(DEFAULT_SECRET_LABEL));
        let target = service.pending_secret().expect("pending target");
        assert_eq!(target.field_ref(), "field-9");
        assert_eq!(target.document_generation(), DocumentGeneration::new(3));

        let stale = service
            .request_secret(Some(" Password "), "field-10", DocumentGeneration::new(4))
            .expect("second request")
            .pending_secret()
            .expect("target")
            .clone();
        assert_eq!(stale.field_ref(), "field-10");
        assert_eq!(
            service.secret_supplied(&target),
            Err(ControlError::SecretTargetChanged)
        );
        service
            .secret_supplied(&stale)
            .expect("exact target completes");
        assert_eq!(service.pending_secret(), Err(ControlError::NoSecretPending));
    }

    #[test]
    fn take_release_and_transfer_fence_actor_auth_generation_and_queued_input() {
        let mut service = service();
        service.request_help(Some(" Finish sign-in "), START);
        service
            .request_secret(Some("OTP"), "field-1", DocumentGeneration::new(1))
            .expect("secret request");

        let actor_a = auth("actor-a", 5);
        let taken = service
            .take(&actor_a, START + Duration::minutes(5), START)
            .expect("take");
        assert_eq!(taken.holder(), ControlHolder::Human);
        assert_eq!(taken.reason(), Some("Finish sign-in"));
        assert!(!taken.requested());
        assert_eq!(taken.secret_wanted(), None);
        assert_eq!(taken.epoch(), HumanLeaseEpoch::new(1));
        assert_eq!(
            service.assert_bot_may_act(START),
            Err(ControlError::HumanHasControl)
        );

        let ticket_a = service
            .issue_human_input_ticket(START)
            .expect("current ticket");
        service
            .authorize_human_input(&actor_a, &ticket_a, START)
            .expect("owner can drive");
        let receipt = service
            .authorize_human_input_receipt(&actor_a, &ticket_a, START)
            .expect("fresh engine receipt");
        assert_eq!(receipt.computer_id(), ticket_a.computer_id());
        assert_eq!(receipt.tab_id(), ticket_a.tab_id());
        assert_eq!(
            receipt.computer_generation(),
            ticket_a.computer_generation()
        );
        assert_eq!(receipt.epoch(), ticket_a.epoch());
        assert_eq!(receipt.expires_at(), ticket_a.expires_at());
        assert_eq!(
            service.authorize_human_input(&auth("actor-b", 5), &ticket_a, START),
            Err(ControlError::StaleOrWrongScope)
        );
        assert_eq!(
            service.authorize_human_input(&auth("actor-a", 6), &ticket_a, START),
            Err(ControlError::StaleOrWrongScope)
        );

        let actor_b = auth("actor-b", 9);
        let transferred = service
            .take(
                &actor_b,
                START + Duration::minutes(6),
                START + Duration::seconds(1),
            )
            .expect("transfer");
        assert_eq!(transferred.epoch(), HumanLeaseEpoch::new(2));
        assert_eq!(
            service.authorize_human_input(&actor_a, &ticket_a, START + Duration::seconds(1)),
            Err(ControlError::StaleOrWrongScope)
        );

        let ticket_b = service
            .issue_human_input_ticket(START + Duration::seconds(1))
            .expect("transferred ticket");
        service
            .authorize_human_input(&actor_b, &ticket_b, START + Duration::seconds(1))
            .expect("new owner can drive");

        let released = service
            .release(START + Duration::seconds(2))
            .expect("release");
        assert_eq!(released.holder(), ControlHolder::Bot);
        assert_eq!(released.reason(), None);
        assert_eq!(released.epoch(), HumanLeaseEpoch::new(3));
        assert_eq!(
            service.authorize_human_input(&actor_b, &ticket_b, START + Duration::seconds(2)),
            Err(ControlError::TakeControlFirst)
        );
        service
            .assert_bot_may_act(START + Duration::seconds(2))
            .expect("Bot acts after release");
    }

    #[test]
    fn expiry_navigation_and_restart_each_invalidate_old_input_with_checked_epoch() {
        let mut service = service();
        let actor = auth("actor-a", 1);
        service
            .take(&actor, START + Duration::minutes(1), START)
            .expect("take");
        let before_navigation = service.issue_human_input_ticket(START).expect("ticket");

        let after_navigation = service.document_navigated().expect("navigation");
        assert_eq!(after_navigation.epoch(), HumanLeaseEpoch::new(2));
        assert_eq!(
            service.authorize_human_input(&actor, &before_navigation, START),
            Err(ControlError::StaleOrWrongScope)
        );
        let current = service.issue_human_input_ticket(START).expect("new ticket");
        service
            .authorize_human_input(&actor, &current, START)
            .expect("new epoch accepted");

        assert_eq!(
            service.issue_human_input_ticket(START + Duration::minutes(1)),
            Err(ControlError::LeaseExpired)
        );
        let expired = service.state(START + Duration::minutes(1));
        assert_eq!(expired.holder(), ControlHolder::Bot);
        assert_eq!(expired.epoch(), HumanLeaseEpoch::new(3));

        assert_eq!(
            service.computer_restarted(ComputerGeneration::new(7), START + Duration::minutes(2)),
            Err(ControlError::ComputerGenerationDidNotAdvance)
        );
        let restarted = service
            .computer_restarted(ComputerGeneration::new(8), START + Duration::minutes(2))
            .expect("generation advances");
        assert_eq!(restarted.epoch(), HumanLeaseEpoch::new(4));
        assert_eq!(restarted.holder(), ControlHolder::Bot);

        assert_eq!(
            HumanLeaseEpoch::new(u64::MAX - 1).next(),
            Some(HumanLeaseEpoch::new(u64::MAX))
        );
        assert_eq!(HumanLeaseEpoch::new(u64::MAX).next(), None);
    }

    #[test]
    fn epoch_exhaustion_clears_lease_and_poison_fails_closed_until_generation_advances() {
        let mut service = service();
        let actor = auth("actor-a", 1);
        service
            .take(&actor, START + Duration::minutes(5), START)
            .expect("take");
        let old_ticket = service.issue_human_input_ticket(START).expect("ticket");

        // Same-module test injection reaches the otherwise infeasible boundary without billions of
        // transitions. The next real invalidation must poison rather than saturate or wrap.
        service.epoch = HumanLeaseEpoch::new(u64::MAX);
        assert_eq!(
            service.document_navigated(),
            Err(ControlError::HumanLeaseEpochPoisoned)
        );
        let poisoned = service.state(START + Duration::seconds(1));
        assert!(poisoned.poisoned());
        assert_eq!(poisoned.holder(), ControlHolder::Bot);
        assert_eq!(poisoned.lease_expires_at(), None, "poison clears lease");
        assert_eq!(
            service.issue_human_input_ticket(START + Duration::seconds(1)),
            Err(ControlError::HumanLeaseEpochPoisoned)
        );
        assert_eq!(
            service.authorize_human_input(&actor, &old_ticket, START + Duration::seconds(1)),
            Err(ControlError::HumanLeaseEpochPoisoned)
        );
        assert_eq!(
            service.assert_bot_may_act(START + Duration::seconds(1)),
            Err(ControlError::HumanLeaseEpochPoisoned)
        );
        assert_eq!(
            service.take(
                &actor,
                START + Duration::minutes(6),
                START + Duration::seconds(1)
            ),
            Err(ControlError::HumanLeaseEpochPoisoned)
        );

        assert_eq!(
            service.computer_restarted(ComputerGeneration::new(7), START + Duration::seconds(2)),
            Err(ControlError::ComputerGenerationDidNotAdvance)
        );
        assert!(service.state(START + Duration::seconds(2)).poisoned());

        let recovered = service
            .computer_restarted(ComputerGeneration::new(8), START + Duration::seconds(2))
            .expect("new generation recovers poison");
        assert!(!recovered.poisoned());
        assert_eq!(recovered.epoch(), HumanLeaseEpoch::default());
        service
            .assert_bot_may_act(START + Duration::seconds(2))
            .expect("Bot may act only after generation advances");
        assert_eq!(
            service.authorize_human_input(&actor, &old_ticket, START + Duration::seconds(2)),
            Err(ControlError::TakeControlFirst),
            "old-generation input remains unusable after recovery"
        );
    }

    #[test]
    fn lease_expiry_is_explicit_and_never_guessed_by_the_computer_crate() {
        let mut service = service();
        let actor = auth("actor-a", 1);
        assert_eq!(
            service.take(&actor, START, START),
            Err(ControlError::InvalidLeaseExpiry)
        );
        assert_eq!(
            service.take(&actor, START - Duration::nanoseconds(1), START),
            Err(ControlError::InvalidLeaseExpiry)
        );
        service
            .take(&actor, START + Duration::nanoseconds(1), START)
            .expect("caller-supplied future expiry");
    }
}
