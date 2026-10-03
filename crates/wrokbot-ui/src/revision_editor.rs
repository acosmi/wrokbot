//! Payload-free R415 editing state. Typed drafts and authenticated write ownership stay outside.

pub(crate) const DEBOUNCE_MS: u64 = 800;
pub(crate) const SAVE_WAIT_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Saved,
    Dirty,
    Saving,
    Error,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    Unbound,
    Absent,
    Existing(i64),
}

impl Binding {
    const fn revision(self) -> Option<i64> {
        match self {
            Self::Existing(revision) => Some(revision),
            Self::Unbound | Self::Absent => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttemptToken {
    generation: u64,
    edit_serial: u64,
    attempt_serial: u64,
    expected_revision: Option<i64>,
    start_ms: u64,
}

impl AttemptToken {
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
    pub(crate) const fn edit_serial(self) -> u64 {
        self.edit_serial
    }
    #[cfg(test)]
    pub(crate) const fn attempt_serial(self) -> u64 {
        self.attempt_serial
    }
    pub(crate) const fn expected_revision(self) -> Option<i64> {
        self.expected_revision
    }
    pub(crate) const fn start_ms(self) -> u64 {
        self.start_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DebounceToken {
    generation: u64,
    edit_serial: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadToken {
    generation: u64,
    read_serial: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryToken {
    generation: u64,
    read_serial: u64,
    current_revision: Option<i64>,
}

impl RecoveryToken {
    pub(crate) const fn current_revision(self) -> Option<i64> {
        self.current_revision
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Definite,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Apply {
    Applied,
    Ignored,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoreError {
    InvalidRevision,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Blocked {
    Unbound,
    InFlight,
    Paused,
    NotDirty,
    NotDue,
    Composing,
    Ineligible,
    Stale,
    NeedRecovery,
    HigherRemote,
    RevisionRegression,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attempt {
    token: AttemptToken,
    recovery: bool,
    timed_out: bool,
}

/// Correlation and timing only; no token here grants permission or unlocks a write barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EditorCore {
    binding: Binding,
    phase: Phase,
    generation: u64,
    edit_serial: u64,
    attempt_serial: u64,
    read_serial: u64,
    deadline: Option<u64>,
    semantic_dirty: bool,
    composing: bool,
    paused: bool,
    exhausted: bool,
    current: Option<Attempt>,
    failed: Option<AttemptToken>,
    uncertain: Option<AttemptToken>,
    historical_uncertainty: bool,
    latest_revision: Option<i64>,
    recovery: Option<RecoveryToken>,
}

impl Default for EditorCore {
    fn default() -> Self {
        Self::new()
    }
}

impl EditorCore {
    pub(crate) const fn new() -> Self {
        Self {
            binding: Binding::Unbound,
            phase: Phase::Saved,
            generation: 0,
            edit_serial: 0,
            attempt_serial: 0,
            read_serial: 0,
            deadline: None,
            semantic_dirty: false,
            composing: false,
            paused: false,
            exhausted: false,
            current: None,
            failed: None,
            uncertain: None,
            historical_uncertainty: false,
            latest_revision: None,
            recovery: None,
        }
    }

    pub(crate) fn bind_existing(&mut self, revision: i64) -> Result<u64, CoreError> {
        if revision <= 0 {
            return Err(CoreError::InvalidRevision);
        }
        self.rebind(Binding::Existing(revision))
    }

    /// Only the preference consumer uses this after an authorized, exact four-null read.
    pub(crate) fn bind_absent(&mut self) -> Result<u64, CoreError> {
        self.rebind(Binding::Absent)
    }

    fn rebind(&mut self, binding: Binding) -> Result<u64, CoreError> {
        self.invalidate()?;
        self.binding = binding;
        Ok(self.generation)
    }

    pub(crate) const fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) const fn known_revision(&self) -> Option<i64> {
        self.binding.revision()
    }
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) const fn edit_serial(&self) -> u64 {
        self.edit_serial
    }
    pub(crate) const fn is_bound(&self) -> bool {
        !matches!(self.binding, Binding::Unbound)
    }
    #[cfg(test)]
    pub(crate) const fn is_bound_absent(&self) -> bool {
        matches!(self.binding, Binding::Absent)
    }
    pub(crate) fn current_attempt(&self) -> Option<AttemptToken> {
        self.current.map(|a| a.token)
    }
    pub(crate) const fn auto_paused(&self) -> bool {
        self.paused
    }
    #[cfg(test)]
    pub(crate) const fn last_uncertain_attempt(&self) -> Option<AttemptToken> {
        self.uncertain
    }
    pub(crate) const fn historical_uncertainty(&self) -> bool {
        self.historical_uncertainty
    }

    /// Import only a payload-free authenticated hold, never a server version or draft.
    pub(crate) fn restore_pause(&mut self, phase: Phase, uncertain: bool) {
        if matches!(phase, Phase::Error | Phase::Conflict) {
            self.phase = phase;
            self.paused = true;
            self.historical_uncertainty |= uncertain;
            self.deadline = None;
        }
    }

    pub(crate) fn edit(&mut self, now_ms: u64) -> Result<DebounceToken, CoreError> {
        self.edit_serial = self.increment(self.edit_serial)?;
        self.deadline = Some(
            now_ms
                .checked_add(DEBOUNCE_MS)
                .ok_or_else(|| self.exhaust())?,
        );
        self.semantic_dirty = true;
        if self.current.is_none() && !self.paused {
            self.phase = Phase::Dirty;
        }
        Ok(DebounceToken {
            generation: self.generation,
            edit_serial: self.edit_serial,
        })
    }

    pub(crate) fn set_local_matches_known(&mut self, matches: bool) {
        self.semantic_dirty = !matches;
        if self.current.is_none() && !self.paused {
            self.phase = if matches { Phase::Saved } else { Phase::Dirty };
            if matches {
                self.deadline = None;
            }
        }
    }

    pub(crate) fn set_composing(&mut self, active: bool, now_ms: u64) -> Result<(), CoreError> {
        if self.composing == active {
            return Ok(());
        }
        self.composing = active;
        self.edit_serial = self.increment(self.edit_serial)?;
        self.deadline = if !active && self.semantic_dirty {
            Some(
                now_ms
                    .checked_add(DEBOUNCE_MS)
                    .ok_or_else(|| self.exhaust())?,
            )
        } else {
            None
        };
        Ok(())
    }

    pub(crate) fn debounce_token(&self) -> DebounceToken {
        DebounceToken {
            generation: self.generation,
            edit_serial: self.edit_serial,
        }
    }

    pub(crate) fn next_auto_deadline(&self) -> Option<u64> {
        if !self.is_bound()
            || self.paused
            || self.composing
            || self.current.is_some()
            || !self.semantic_dirty
            || self.phase != Phase::Dirty
        {
            return None;
        }
        self.deadline
    }

    pub(crate) fn begin_auto(
        &mut self,
        ticket: DebounceToken,
        now_ms: u64,
        eligible: bool,
    ) -> Result<AttemptToken, Blocked> {
        self.dispatch_gate(eligible)?;
        if self.paused {
            return Err(Blocked::Paused);
        }
        if ticket != self.debounce_token() {
            return Err(Blocked::Stale);
        }
        if !self.semantic_dirty || self.phase != Phase::Dirty {
            return Err(Blocked::NotDirty);
        }
        if !self.deadline.is_some_and(|deadline| now_ms >= deadline) {
            return Err(Blocked::NotDue);
        }
        self.start(self.binding.revision(), self.edit_serial, now_ms, false)
    }

    /// Normal explicit Save retains its action; paused edits still require recovery choices.
    pub(crate) fn begin_explicit(
        &mut self,
        now_ms: u64,
        eligible: bool,
    ) -> Result<AttemptToken, Blocked> {
        self.dispatch_gate(eligible)?;
        if self.paused {
            return Err(Blocked::Paused);
        }
        if !self.semantic_dirty {
            return Err(Blocked::NotDirty);
        }
        self.start(self.binding.revision(), self.edit_serial, now_ms, false)
    }

    pub(crate) fn mark_timeout(&mut self, token: AttemptToken, now_ms: u64) -> Apply {
        let Some(attempt) = self.current.as_mut().filter(|a| a.token == token) else {
            return Apply::Ignored;
        };
        if !now_ms
            .checked_sub(token.start_ms())
            .is_some_and(|elapsed| elapsed >= SAVE_WAIT_MS)
        {
            return Apply::Ignored;
        }
        attempt.timed_out = true;
        self.uncertain = Some(token);
        self.failed = Some(token);
        self.historical_uncertainty = true;
        self.paused = true;
        if self.phase != Phase::Conflict {
            self.phase = Phase::Error;
        }
        Apply::Applied
    }

    pub(crate) fn finish_ack(
        &mut self,
        token: AttemptToken,
        revision: i64,
        local_semantically_matches_ack: bool,
    ) -> Apply {
        if token.generation != self.generation {
            return Apply::Ignored;
        }
        let current = self.current.filter(|a| a.token == token);
        if current.is_none() && (self.current.is_some() || self.uncertain != Some(token)) {
            return Apply::Ignored;
        }
        let expected = token
            .expected_revision
            .map_or(Some(1), |r| r.checked_add(1));
        if expected != Some(revision) || revision <= 0 {
            self.current = None;
            self.uncertain = Some(token);
            self.failed = Some(token);
            self.historical_uncertainty = true;
            self.restore_pause(Phase::Error, true);
            return Apply::Invalid;
        }
        if self.known_revision().is_some_and(|known| known > revision) {
            return Apply::Ignored;
        }
        self.binding = Binding::Existing(revision);
        self.current = None;
        self.semantic_dirty = !local_semantically_matches_ack;
        if self.uncertain == Some(token) {
            self.uncertain = None;
            self.historical_uncertainty = false;
        }
        let remote_conflict = self.latest_revision.is_some_and(|remote| remote > revision);
        if current.is_some_and(|a| a.recovery && !a.timed_out) && !remote_conflict {
            self.paused = false;
            self.historical_uncertainty = false;
            self.uncertain = None;
            self.failed = None;
        }
        if remote_conflict {
            self.restore_pause(Phase::Conflict, self.historical_uncertainty);
        }
        if !self.paused {
            self.phase = if local_semantically_matches_ack {
                Phase::Saved
            } else {
                Phase::Dirty
            };
            if local_semantically_matches_ack {
                self.deadline = None;
            }
        }
        Apply::Applied
    }

    pub(crate) fn finish_closed_conflict(
        &mut self,
        token: AttemptToken,
        current_revision: i64,
    ) -> Apply {
        if self.current_attempt() != Some(token) {
            return Apply::Ignored;
        }
        if current_revision <= 0 || self.known_revision().is_some_and(|r| current_revision < r) {
            return self.finish_invalid(token);
        }
        self.current = None;
        self.failed = Some(token);
        self.latest_revision = Some(
            self.latest_revision
                .map_or(current_revision, |r| r.max(current_revision)),
        );
        self.restore_pause(Phase::Conflict, self.historical_uncertainty);
        Apply::Applied
    }

    pub(crate) fn finish_failure(&mut self, token: AttemptToken, class: FailureClass) -> Apply {
        if self.current_attempt() != Some(token) {
            return Apply::Ignored;
        }
        self.current = None;
        self.failed = Some(token);
        if class == FailureClass::Unknown {
            self.uncertain = Some(token);
            self.historical_uncertainty = true;
        }
        self.restore_pause(
            if self.phase == Phase::Conflict {
                Phase::Conflict
            } else {
                Phase::Error
            },
            self.historical_uncertainty,
        );
        Apply::Applied
    }

    fn finish_invalid(&mut self, token: AttemptToken) -> Apply {
        self.finish_failure(token, FailureClass::Unknown);
        Apply::Invalid
    }

    pub(crate) fn observe_remote(&mut self, revision: i64) -> Apply {
        if !self.is_bound() {
            return Apply::Ignored;
        }
        if revision <= 0 || self.known_revision().is_some_and(|known| revision < known) {
            self.restore_pause(Phase::Error, self.historical_uncertainty);
            return Apply::Invalid;
        }
        if self.known_revision().is_none_or(|known| revision > known) {
            self.latest_revision = Some(self.latest_revision.map_or(revision, |r| r.max(revision)));
            self.restore_pause(Phase::Conflict, self.historical_uncertainty);
        }
        Apply::Applied
    }

    /// Correlate a user-requested authorized recovery read; GET itself never resumes automation.
    pub(crate) fn begin_read(&mut self) -> Result<ReadToken, CoreError> {
        self.read_serial = self.increment(self.read_serial)?;
        self.recovery = None;
        Ok(ReadToken {
            generation: self.generation,
            read_serial: self.read_serial,
        })
    }

    pub(crate) fn accept_recovery_read(
        &mut self,
        token: ReadToken,
        revision: i64,
    ) -> Result<RecoveryToken, Blocked> {
        if revision <= 0 {
            return Err(Blocked::RevisionRegression);
        }
        self.accept_read(token, Some(revision))
    }

    pub(crate) fn accept_recovery_absent(
        &mut self,
        token: ReadToken,
    ) -> Result<RecoveryToken, Blocked> {
        self.accept_read(token, None)
    }

    fn accept_read(
        &mut self,
        token: ReadToken,
        revision: Option<i64>,
    ) -> Result<RecoveryToken, Blocked> {
        if !self.is_bound() {
            return Err(Blocked::Unbound);
        }
        if token.generation != self.generation || token.read_serial != self.read_serial {
            return Err(Blocked::Stale);
        }
        if self
            .known_revision()
            .is_some_and(|known| revision.is_none_or(|read| read < known))
        {
            self.restore_pause(Phase::Error, self.historical_uncertainty);
            return Err(Blocked::RevisionRegression);
        }
        if let Some(revision) = revision {
            self.observe_remote(revision);
        }
        let recovered = RecoveryToken {
            generation: self.generation,
            read_serial: self.read_serial,
            current_revision: revision,
        };
        self.recovery = Some(recovered);
        Ok(recovered)
    }

    pub(crate) fn choose_load(&mut self, token: RecoveryToken, user_confirmed: bool) -> Apply {
        if !user_confirmed || self.recovery != Some(token) || self.current.is_some() {
            return Apply::Ignored;
        }
        self.binding = token
            .current_revision()
            .map_or(Binding::Absent, Binding::Existing);
        self.semantic_dirty = false;
        self.deadline = None;
        self.latest_revision = None;
        self.recovery = None;
        self.paused = self.historical_uncertainty;
        self.phase = if self.paused {
            Phase::Error
        } else {
            Phase::Saved
        };
        Apply::Applied
    }

    pub(crate) fn begin_retry_original(
        &mut self,
        token: RecoveryToken,
        original: AttemptToken,
        now_ms: u64,
        eligible: bool,
    ) -> Result<AttemptToken, Blocked> {
        self.recovery_gate(token, eligible)?;
        if original.generation != self.generation
            || (self.failed != Some(original) && self.uncertain != Some(original))
        {
            return Err(Blocked::Stale);
        }
        if token.current_revision() != original.expected_revision {
            return Err(Blocked::HigherRemote);
        }
        self.recovery = None;
        self.start(
            original.expected_revision,
            original.edit_serial,
            now_ms,
            true,
        )
    }

    pub(crate) fn begin_reapply(
        &mut self,
        token: RecoveryToken,
        user_confirmed: bool,
        now_ms: u64,
        eligible: bool,
    ) -> Result<AttemptToken, Blocked> {
        self.recovery_gate(token, eligible)?;
        if !user_confirmed {
            return Err(Blocked::NeedRecovery);
        }
        self.recovery = None;
        self.start(token.current_revision(), self.edit_serial, now_ms, true)
    }

    fn recovery_gate(&self, token: RecoveryToken, eligible: bool) -> Result<(), Blocked> {
        self.dispatch_gate(eligible)?;
        if self.recovery != Some(token) {
            return Err(Blocked::NeedRecovery);
        }
        if self
            .latest_revision
            .is_some_and(|latest| token.current_revision.is_none_or(|read| latest > read))
        {
            return Err(Blocked::HigherRemote);
        }
        Ok(())
    }

    fn dispatch_gate(&self, eligible: bool) -> Result<(), Blocked> {
        if self.exhausted {
            return Err(Blocked::Exhausted);
        }
        if !self.is_bound() {
            return Err(Blocked::Unbound);
        }
        if self.current.is_some() {
            return Err(Blocked::InFlight);
        }
        if self.composing {
            return Err(Blocked::Composing);
        }
        if !eligible {
            return Err(Blocked::Ineligible);
        }
        Ok(())
    }

    fn start(
        &mut self,
        expected_revision: Option<i64>,
        edit_serial: u64,
        now_ms: u64,
        recovery: bool,
    ) -> Result<AttemptToken, Blocked> {
        if expected_revision.is_some_and(|revision| revision.checked_add(1).is_none()) {
            self.exhaust();
            return Err(Blocked::Exhausted);
        }
        self.attempt_serial = self
            .increment(self.attempt_serial)
            .map_err(|_| Blocked::Exhausted)?;
        let token = AttemptToken {
            generation: self.generation,
            edit_serial,
            attempt_serial: self.attempt_serial,
            expected_revision,
            start_ms: now_ms,
        };
        self.current = Some(Attempt {
            token,
            recovery,
            timed_out: false,
        });
        self.phase = Phase::Saving;
        Ok(token)
    }

    pub(crate) fn invalidate(&mut self) -> Result<u64, CoreError> {
        let generation = self.increment(self.generation)?;
        *self = Self {
            generation,
            edit_serial: self.edit_serial,
            attempt_serial: self.attempt_serial,
            read_serial: self.read_serial,
            ..Self::new()
        };
        Ok(generation)
    }

    fn increment(&mut self, value: u64) -> Result<u64, CoreError> {
        if self.exhausted {
            return Err(CoreError::Exhausted);
        }
        value.checked_add(1).ok_or_else(|| self.exhaust())
    }

    fn exhaust(&mut self) -> CoreError {
        self.exhausted = true;
        self.restore_pause(Phase::Error, self.historical_uncertainty);
        CoreError::Exhausted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing() -> EditorCore {
        let mut core = EditorCore::new();
        core.bind_existing(4).unwrap();
        core
    }

    #[test]
    fn unread_none_is_closed_but_authorized_absence_creates_revision_one() {
        let mut core = EditorCore::default();
        let ticket = core.edit(0).unwrap();
        assert_eq!(core.begin_auto(ticket, 800, true), Err(Blocked::Unbound));
        core.bind_absent().unwrap();
        let ticket = core.edit(100).unwrap();
        let attempt = core.begin_auto(ticket, 900, true).unwrap();
        assert_eq!(attempt.expected_revision(), None);
        assert_eq!(core.finish_ack(attempt, 1, true), Apply::Applied);
        assert_eq!(core.known_revision(), Some(1));
        assert!(!core.is_bound_absent());
        assert_eq!(core.phase(), Phase::Saved);
    }

    #[test]
    fn rapid_input_and_ime_wait_for_the_latest_complete_input() {
        let mut core = existing();
        let old = core.edit(0).unwrap();
        let newer = core.edit(600).unwrap();
        assert_eq!(core.begin_auto(old, 1400, true), Err(Blocked::Stale));
        assert_eq!(core.begin_auto(newer, 1399, true), Err(Blocked::NotDue));
        core.set_composing(true, 1400).unwrap();
        assert_eq!(core.begin_auto(newer, 2000, true), Err(Blocked::Composing));
        core.set_composing(false, 2100).unwrap();
        assert_eq!(core.next_auto_deadline(), Some(2900));
        assert_eq!(
            core.begin_auto(core.debounce_token(), 2899, true),
            Err(Blocked::NotDue)
        );
        assert!(core.begin_auto(core.debounce_token(), 2900, true).is_ok());
    }

    #[test]
    fn explicit_save_keeps_cas_but_cannot_bypass_an_error_or_composition() {
        let mut core = existing();
        core.edit(0).unwrap();
        core.set_composing(true, 100).unwrap();
        assert_eq!(core.begin_explicit(200, true), Err(Blocked::Composing));
        core.set_composing(false, 300).unwrap();
        let attempt = core.begin_explicit(301, true).unwrap();
        assert_eq!(attempt.expected_revision(), Some(4));
        assert_eq!(core.begin_explicit(302, true), Err(Blocked::InFlight));
        core.finish_failure(attempt, FailureClass::Unknown);
        assert_eq!(core.begin_explicit(303, true), Err(Blocked::Paused));
        assert_eq!(core.phase(), Phase::Error);
    }

    #[test]
    fn a_receipt_advances_the_base_for_later_b_without_starting_two_writes() {
        let mut core = existing();
        let a = core.edit(0).unwrap();
        let sent = core.begin_auto(a, 800, true).unwrap();
        let b = core.edit(900).unwrap();
        assert_eq!(core.begin_auto(b, 1700, true), Err(Blocked::InFlight));
        assert_eq!(core.finish_ack(sent, 5, false), Apply::Applied);
        assert_eq!(core.phase(), Phase::Dirty);
        assert_eq!(core.next_auto_deadline(), Some(1700));
        let next = core.begin_auto(b, 1700, true).unwrap();
        assert_eq!(next.expected_revision(), Some(5));
        assert_ne!(sent.attempt_serial(), next.attempt_serial());
    }

    #[test]
    fn returning_to_known_content_cancels_unsent_business_write_only() {
        let mut core = existing();
        core.edit(0).unwrap();
        core.set_local_matches_known(true);
        assert_eq!(core.phase(), Phase::Saved);
        assert_eq!(core.next_auto_deadline(), None);
        core.restore_pause(Phase::Error, true);
        core.edit(100).unwrap();
        core.set_local_matches_known(true);
        assert_eq!(core.phase(), Phase::Error);
        assert!(core.auto_paused());
        assert!(core.historical_uncertainty());
    }

    #[test]
    fn timeout_retains_live_attempt_and_late_ack_does_not_resume_automatic_save() {
        let mut core = existing();
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        core.edit(900).unwrap();
        assert_eq!(core.mark_timeout(sent, 10_799), Apply::Ignored);
        assert_eq!(core.mark_timeout(sent, 10_800), Apply::Applied);
        assert_eq!(core.current_attempt(), Some(sent));
        let read = core.begin_read().unwrap();
        let remote = core.accept_recovery_read(read, 4).unwrap();
        assert_eq!(
            core.begin_retry_original(remote, sent, 10_900, true),
            Err(Blocked::InFlight)
        );
        assert_eq!(core.finish_ack(sent, 5, false), Apply::Applied);
        assert_eq!(core.known_revision(), Some(5));
        assert_eq!(core.phase(), Phase::Error);
        assert!(core.auto_paused());
        assert_eq!(core.next_auto_deadline(), None);
    }

    #[test]
    fn unknown_retry_preserves_original_cas_and_closed_rejection_does_not_erase_history() {
        let mut core = existing();
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        core.finish_failure(sent, FailureClass::Unknown);
        core.observe_remote(4);
        assert!(core.auto_paused());
        let read = core.begin_read().unwrap();
        let recovered = core.accept_recovery_read(read, 4).unwrap();
        let retry = core
            .begin_retry_original(recovered, sent, 12_000, true)
            .unwrap();
        assert_eq!(retry.expected_revision(), sent.expected_revision());
        assert_eq!(retry.edit_serial(), sent.edit_serial());
        assert_eq!(core.finish_closed_conflict(retry, 5), Apply::Applied);
        assert!(core.historical_uncertainty());
        assert_eq!(core.last_uncertain_attempt(), Some(sent));
        assert_eq!(core.phase(), Phase::Conflict);
        let read = core.begin_read().unwrap();
        let recovered = core.accept_recovery_read(read, 5).unwrap();
        assert_eq!(
            core.begin_retry_original(recovered, retry, 13_000, true),
            Err(Blocked::HigherRemote)
        );
        let reapplied = core.begin_reapply(recovered, true, 13_100, true).unwrap();
        assert_eq!(reapplied.expected_revision(), Some(5));
        assert_eq!(core.finish_ack(reapplied, 6, true), Apply::Applied);
        assert!(!core.auto_paused());
    }

    #[test]
    fn absent_timeout_and_recovery_never_substitute_a_fake_revision() {
        let mut core = EditorCore::new();
        core.bind_absent().unwrap();
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        core.finish_failure(sent, FailureClass::Unknown);
        let read = core.begin_read().unwrap();
        let recovered = core.accept_recovery_absent(read).unwrap();
        let retry = core
            .begin_retry_original(recovered, sent, 11_000, true)
            .unwrap();
        assert_eq!(retry.expected_revision(), None);
        core.finish_closed_conflict(retry, 1);
        let read = core.begin_read().unwrap();
        let recovered = core.accept_recovery_read(read, 1).unwrap();
        assert_eq!(
            core.begin_retry_original(recovered, retry, 12_000, true),
            Err(Blocked::HigherRemote)
        );
        let next = core.begin_reapply(recovered, true, 12_100, true).unwrap();
        assert_eq!(next.expected_revision(), Some(1));
    }

    #[test]
    fn higher_remote_and_explicit_discard_never_turn_unknown_into_not_committed() {
        let mut core = existing();
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        core.finish_failure(sent, FailureClass::Unknown);
        let read = core.begin_read().unwrap();
        let recovered = core.accept_recovery_read(read, 7).unwrap();
        assert_eq!(core.known_revision(), Some(4));
        assert_eq!(core.phase(), Phase::Conflict);
        assert_eq!(core.choose_load(recovered, false), Apply::Ignored);
        assert_eq!(core.choose_load(recovered, true), Apply::Applied);
        assert_eq!(core.known_revision(), Some(7));
        assert!(core.historical_uncertainty());
        assert!(core.auto_paused());
        assert_eq!(core.phase(), Phase::Error);
    }

    #[test]
    fn changed_binding_and_newer_read_discard_old_tokens() {
        let mut core = existing();
        let old_read = core.begin_read().unwrap();
        let new_read = core.begin_read().unwrap();
        assert_eq!(core.accept_recovery_read(old_read, 4), Err(Blocked::Stale));
        assert!(core.accept_recovery_read(new_read, 4).is_ok());
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        core.bind_existing(10).unwrap();
        assert_eq!(core.finish_ack(sent, 5, true), Apply::Ignored);
        assert_eq!(core.known_revision(), Some(10));
        assert_eq!(core.accept_recovery_read(new_read, 4), Err(Blocked::Stale));
    }

    #[test]
    fn wrong_positive_revision_and_exhausted_counters_fail_closed() {
        let mut core = existing();
        let ticket = core.edit(0).unwrap();
        let sent = core.begin_auto(ticket, 800, true).unwrap();
        assert_eq!(core.finish_ack(sent, 6, true), Apply::Invalid);
        assert_eq!(core.known_revision(), Some(4));
        assert!(core.historical_uncertainty());
        core.generation = u64::MAX;
        assert_eq!(core.invalidate(), Err(CoreError::Exhausted));
        assert_eq!(core.begin_auto(ticket, 900, true), Err(Blocked::Exhausted));
    }
}
