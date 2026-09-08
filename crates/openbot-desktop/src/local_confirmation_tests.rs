use super::*;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

struct Fixture {
    coordinator: LocalConfirmationCoordinator,
    grant: GrantHandle,
    auth: AuthContext,
    base: ClockSample,
}

impl Fixture {
    fn new() -> Self {
        let auth = auth(
            "deployment-private",
            "tenant-private",
            "actor-private",
            1,
            true,
            [Role::Admin],
        );
        let coordinator = LocalConfirmationCoordinator::new("installation-private", true).unwrap();
        let grant = coordinator.register_binding(91, &auth).unwrap();
        Self {
            coordinator,
            grant,
            auth,
            base: ClockSample::new(
                Instant::now(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
            ),
        }
    }

    fn at(&self, seconds: u64) -> ClockSample {
        self.clocks(Duration::from_secs(seconds), Duration::from_secs(seconds))
    }

    fn clocks(&self, monotonic: Duration, wall: Duration) -> ClockSample {
        ClockSample::new(self.base.monotonic + monotonic, self.base.wall + wall)
    }

    fn begin(&self, seconds: u64) -> ConfirmationAttempt {
        self.coordinator
            .begin(&self.grant, &self.auth, self.at(seconds))
            .unwrap()
    }

    fn success(&self, began: u64, succeeded: u64, installed: u64) -> LocalConfirmationReceipt {
        let mut attempt = self.begin(began);
        let native = attempt.start_native(self.at(began)).unwrap();
        assert_eq!(
            native.record_outcome(
                NativeOutcome::Succeeded {
                    at: self.at(succeeded)
                },
                self.at(succeeded)
            ),
            Ok(NativeDisposition::NeedsPostcheck)
        );
        native.native_stopped();
        attempt
            .install(&self.grant, &self.auth, self.at(installed))
            .unwrap()
    }
}

fn auth<const N: usize>(
    deployment: &str,
    tenant: &str,
    actor: &str,
    generation: u64,
    single: bool,
    roles: [Role; N],
) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        ActorId::new(actor),
        roles,
        AuthGeneration::new(generation),
        single,
    )
}

#[test]
fn native_success_requires_postcheck_and_uses_callback_time() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(1)).unwrap();
    assert!(!fixture.grant.is_fresh(fixture.at(2)));
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(10) },
            fixture.at(12)
        ),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    assert!(!fixture.grant.is_fresh(fixture.at(13)));
    native.native_stopped();
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(14)),
        Err(ConfirmationError::Busy)
    ));
    let receipt = attempt
        .install(&fixture.grant, &fixture.auth, fixture.at(20))
        .unwrap();
    assert_eq!(receipt.outcome, LocalConfirmationOutcome::Confirmed);
    assert_eq!(receipt.remaining_seconds, 890);
    assert!(fixture.grant.is_fresh(fixture.at(909)));
    assert!(!fixture.grant.is_fresh(fixture.at(910)));
    assert_eq!(
        fixture.grant.status(fixture.at(911)).unwrap().state,
        LocalConfirmationState::Required
    );
}

#[test]
fn strict_900_boundary_and_positive_fractional_display() {
    let fixture = Fixture::new();
    assert_eq!(fixture.success(0, 0, 0).remaining_seconds, 900);
    let almost = Duration::from_secs(900) - Duration::from_nanos(1);
    let status = fixture
        .grant
        .status(fixture.clocks(almost, almost))
        .unwrap();
    assert_eq!(status.state, LocalConfirmationState::Fresh);
    assert_eq!(status.remaining_seconds, 1);
    assert!(!fixture.grant.is_fresh(fixture.at(900)));
}

#[test]
fn singleflight_applies_across_bindings_without_status_leak() {
    let fixture = Fixture::new();
    let other = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    let attempt = fixture.begin(0);
    assert_eq!(
        fixture.grant.status(fixture.at(1)).unwrap().state,
        LocalConfirmationState::Pending
    );
    assert_eq!(
        other.status(fixture.at(1)).unwrap().state,
        LocalConfirmationState::Required
    );
    assert!(matches!(
        fixture
            .coordinator
            .begin(&other, &fixture.auth, fixture.at(1)),
        Err(ConfirmationError::Busy)
    ));
    drop(attempt);
    assert!(
        fixture
            .coordinator
            .begin(&other, &fixture.auth, fixture.at(2))
            .is_ok()
    );
}

#[test]
fn concurrent_begin_has_exactly_one_winner() {
    let fixture = Fixture::new();
    let barrier = std::sync::Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    fixture
                        .coordinator
                        .begin(&fixture.grant, &fixture.auth, fixture.at(0))
                })
            })
            .collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ConfirmationError::Busy)))
            .count(),
        7
    );
    drop(results);
    assert!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(1))
            .is_ok()
    );
}

#[test]
fn cancelled_post_retains_native_slot_until_independent_stop() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    let cancellation = native.cancellation();
    drop(attempt);
    assert!(cancellation.is_cancelled());
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(1)),
        Err(ConfirmationError::Busy)
    ));
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(1) },
            fixture.at(1)
        ),
        Ok(NativeDisposition::Rejected)
    );
    assert!(!fixture.grant.is_fresh(fixture.at(1)));
    native.native_stopped();
    assert!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(2))
            .is_ok()
    );
}

#[test]
fn dropped_native_token_cannot_claim_native_stopped() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    drop(native);
    drop(attempt);
    fixture.coordinator.expire(fixture.at(1000)).unwrap();
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(1000)),
        Err(ConfirmationError::Busy)
    ));
}

#[test]
fn native_stop_without_outcome_never_grants_and_old_ticket_cannot_cancel_new_one() {
    let fixture = Fixture::new();
    let mut old_attempt = fixture.begin(0);
    let native = old_attempt.start_native(fixture.at(0)).unwrap();
    native.native_stopped();
    let new_attempt = fixture.begin(1);
    drop(old_attempt);
    assert_eq!(
        fixture.grant.status(fixture.at(1)).unwrap().state,
        LocalConfirmationState::Pending
    );
    assert!(!fixture.grant.is_fresh(fixture.at(1)));
    drop(new_attempt);
}

#[test]
fn timeout_rejects_late_success_but_does_not_free_native() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    fixture.coordinator.expire(fixture.at(120)).unwrap();
    assert!(native.cancellation().is_cancelled());
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded {
                at: fixture.at(119)
            },
            fixture.at(120)
        ),
        Ok(NativeDisposition::Rejected)
    );
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(120))
            .is_err()
    );
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(121)),
        Err(ConfirmationError::Busy)
    ));
    native.native_stopped();
    assert!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(121))
            .is_ok()
    );
}

#[test]
fn final_cas_must_fit_120_seconds_even_after_native_success() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded {
                at: fixture.at(119)
            },
            fixture.at(119)
        ),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    native.native_stopped();
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(120))
            .is_err()
    );
    assert!(!fixture.grant.is_fresh(fixture.at(120)));
}

#[test]
fn confirmation_is_allowed_one_nanosecond_before_wait_deadline() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    let elapsed = WAIT - Duration::from_nanos(1);
    let now = fixture.clocks(elapsed, elapsed);
    assert_eq!(
        native.record_outcome(NativeOutcome::Succeeded { at: now }, now),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    native.native_stopped();
    assert_eq!(
        attempt
            .install(&fixture.grant, &fixture.auth, now)
            .unwrap()
            .remaining_seconds,
        900
    );
}

#[test]
fn callback_cannot_be_replaced_replayed_or_fabricated_in_the_future() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    assert!(matches!(
        attempt.start_native(fixture.at(0)),
        Err(ConfirmationError::InvalidState)
    ));
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(1) },
            fixture.at(1)
        ),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2)
        ),
        Ok(NativeDisposition::Rejected)
    );
    let result = attempt
        .install(&fixture.grant, &fixture.auth, fixture.at(3))
        .unwrap();
    assert_eq!(result.remaining_seconds, 898);
    // A completed grant still does not declare the original OS owner stopped.
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(3)),
        Err(ConfirmationError::Busy)
    ));
    native.native_stopped();
    let mut another = fixture.begin(4);
    let native = another.start_native(fixture.at(4)).unwrap();
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(6) },
            fixture.at(5)
        ),
        Err(ConfirmationError::ClockRegression)
    );
    assert!(
        another
            .install(&fixture.grant, &fixture.auth, fixture.at(5))
            .is_err()
    );
    native.native_stopped();
}

#[test]
fn cancelling_reconfirmation_preserves_only_the_old_deadline() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let mut attempt = fixture.begin(100);
    let native = attempt.start_native(fixture.at(100)).unwrap();
    assert_eq!(
        fixture.grant.status(fixture.at(100)).unwrap().state,
        LocalConfirmationState::Pending
    );
    assert!(fixture.grant.is_fresh(fixture.at(101)));
    assert_eq!(
        native.record_outcome(NativeOutcome::Cancelled, fixture.at(102)),
        Ok(NativeDisposition::Cancelled)
    );
    native.native_stopped();
    let receipt = attempt.cancel(fixture.at(103)).unwrap();
    assert_eq!(receipt.outcome, LocalConfirmationOutcome::Cancelled);
    assert_eq!(receipt.remaining_seconds, 797);
    assert!(!fixture.grant.is_fresh(fixture.at(900)));
}

#[test]
fn old_clones_share_revocation_and_rebind_does_not_transfer_grant() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let old_clone = fixture.grant.clone();
    fixture.grant.revoke();
    assert!(!old_clone.is_fresh(fixture.at(1)));
    assert_eq!(
        old_clone.status(fixture.at(1)),
        Err(ConfirmationError::NotCurrent)
    );
    let replacement = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    assert!(!replacement.is_fresh(fixture.at(1)));
    let mut attempt = fixture
        .coordinator
        .begin(&replacement, &fixture.auth, fixture.at(1))
        .unwrap();
    let native = attempt.start_native(fixture.at(1)).unwrap();
    native
        .record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2),
        )
        .unwrap();
    // Even reusing the same numeric binding does not replace Arc authority identity.
    let forged_replacement = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    assert_eq!(
        attempt.install(&forged_replacement, &fixture.auth, fixture.at(3)),
        Err(ConfirmationError::NotCurrent)
    );
    assert!(!replacement.is_fresh(fixture.at(3)));
    assert!(!forged_replacement.is_fresh(fixture.at(3)));
    native.native_stopped();
}

#[test]
fn clearing_existing_grant_is_shared_per_binding_and_never_revives_on_read() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let old_clone = fixture.grant.clone();
    let other = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    let mut attempt = fixture
        .coordinator
        .begin(&other, &fixture.auth, fixture.at(1))
        .unwrap();
    let native = attempt.start_native(fixture.at(1)).unwrap();
    native
        .record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2),
        )
        .unwrap();
    native.native_stopped();
    attempt
        .install(&other, &fixture.auth, fixture.at(3))
        .unwrap();

    fixture.grant.clear_existing_grant();
    old_clone.clear_existing_grant(); // Idempotent; no new authority on a repeated blur.
    for seconds in [4, 100, 899] {
        assert!(!old_clone.is_fresh(fixture.at(seconds)));
        assert_eq!(
            fixture.grant.status(fixture.at(seconds)).unwrap().state,
            LocalConfirmationState::Required
        );
        assert!(other.is_fresh(fixture.at(seconds)));
    }
    // Clearing an already revoked binding cannot turn it back into an admitted binding.
    fixture.grant.revoke();
    fixture.grant.clear_existing_grant();
    assert_eq!(
        old_clone.status(fixture.at(900)),
        Err(ConfirmationError::NotCurrent)
    );
}

#[test]
fn same_binding_requires_both_arc_identities_and_is_not_an_authority_check() {
    let fixture = Fixture::new();
    let clone = fixture.grant.clone();
    assert!(fixture.grant.is_same_binding(&clone));
    assert!(clone.is_same_binding(&fixture.grant));

    let registered_again = fixture
        .coordinator
        .register_binding(91, &fixture.auth)
        .unwrap();
    assert!(!fixture.grant.is_same_binding(&registered_again));
    let other_coordinator =
        LocalConfirmationCoordinator::new("installation-private", true).unwrap();
    let other = other_coordinator
        .register_binding(91, &fixture.auth)
        .unwrap();
    assert!(!fixture.grant.is_same_binding(&other));

    fixture.grant.revoke();
    assert!(fixture.grant.is_same_binding(&clone));
    assert_eq!(
        clone.status(fixture.at(0)),
        Err(ConfirmationError::NotCurrent)
    );
}

#[test]
fn independent_attempt_cancellation_rejects_queued_install_without_claiming_native_stop() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let cancellation = attempt.cancellation_handle();
    let native = attempt.start_native(fixture.at(0)).unwrap();
    native
        .record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(1) },
            fixture.at(1),
        )
        .unwrap();
    cancellation.clone().cancel();
    assert!(native.cancellation().is_cancelled());
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(2))
            .is_err()
    );
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(2)),
        Err(ConfirmationError::Busy)
    ));
    native.native_stopped();
    assert!(!fixture.grant.is_fresh(fixture.at(2)));
    assert!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(3))
            .is_ok()
    );
}

#[test]
fn old_attempt_cancellation_cannot_abort_a_replacement_attempt() {
    let fixture = Fixture::new();
    let old = fixture.begin(0);
    let cancellation = old.cancellation_handle();
    drop(old);
    let current = fixture.begin(1);
    cancellation.cancel();
    assert_eq!(
        fixture.grant.status(fixture.at(1)).unwrap().state,
        LocalConfirmationState::Pending
    );
    drop(current);
}

#[test]
fn instance_grant_clear_reaches_all_clones_but_preserves_pending_proof_and_deadline() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let first_clone = fixture.grant.clone();
    let second = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    let second_clone = second.clone();
    let mut other_attempt = fixture
        .coordinator
        .begin(&second, &fixture.auth, fixture.at(1))
        .unwrap();
    let other_native = other_attempt.start_native(fixture.at(1)).unwrap();
    other_native
        .record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2),
        )
        .unwrap();
    other_native.native_stopped();
    other_attempt
        .install(&second, &fixture.auth, fixture.at(3))
        .unwrap();

    let mut attempt = fixture.begin(4);
    let native = attempt.start_native(fixture.at(4)).unwrap();
    fixture.coordinator.clear_existing_grants();
    assert!(!first_clone.is_fresh(fixture.at(5)));
    assert!(!second_clone.is_fresh(fixture.at(5)));
    assert!(!native.cancellation().is_cancelled());
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(10) },
            fixture.at(10)
        ),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    fixture.coordinator.clear_existing_grants();
    assert!(!native.cancellation().is_cancelled());
    native.native_stopped();
    assert_eq!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(20))
            .unwrap()
            .remaining_seconds,
        890
    );
    assert!(!second_clone.is_fresh(fixture.at(20)));
    assert!(first_clone.is_fresh(fixture.at(909)));
    assert!(!first_clone.is_fresh(fixture.at(910)));
}

#[test]
fn full_invalidation_still_cancels_after_instance_grant_clear() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let mut attempt = fixture.begin(1);
    let native = attempt.start_native(fixture.at(1)).unwrap();
    fixture.coordinator.clear_existing_grants();
    assert!(!native.cancellation().is_cancelled());
    fixture.coordinator.invalidate_all();
    assert!(native.cancellation().is_cancelled());
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2)
        ),
        Ok(NativeDisposition::Rejected)
    );
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(2))
            .is_err()
    );
    native.native_stopped();
    assert!(!fixture.grant.is_fresh(fixture.at(3)));
}

#[test]
fn instance_grant_epoch_exhaustion_shuts_down_and_cancels_pending() {
    let fixture = Fixture::new();
    fixture.coordinator.shared.state.lock().unwrap().grant_epoch = u64::MAX;
    fixture.success(0, 0, 0);
    assert!(fixture.grant.is_fresh(fixture.at(1)));
    let mut attempt = fixture.begin(1);
    let native = attempt.start_native(fixture.at(1)).unwrap();
    fixture.coordinator.clear_existing_grants();
    assert!(native.cancellation().is_cancelled());
    assert!(!fixture.grant.is_fresh(fixture.at(2)));
    assert!(matches!(
        fixture.coordinator.register_binding(92, &fixture.auth),
        Err(ConfirmationError::NotCurrent)
    ));
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(2))
            .is_err()
    );
    native.native_stopped();
}

#[test]
fn clearing_existing_grant_preserves_pending_and_original_native_proof_deadline() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let mut attempt = fixture.begin(100);
    let native = attempt.start_native(fixture.at(100)).unwrap();
    let cancellation = native.cancellation();
    let old_clone = fixture.grant.clone();
    fixture.grant.clear_existing_grant();
    assert!(!old_clone.is_fresh(fixture.at(101)));
    assert!(!cancellation.is_cancelled());
    assert_eq!(
        fixture.grant.status(fixture.at(101)).unwrap().state,
        LocalConfirmationState::Pending
    );
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded {
                at: fixture.at(110)
            },
            fixture.at(110)
        ),
        Ok(NativeDisposition::NeedsPostcheck)
    );
    // Also preserve a success still awaiting host postchecks, without rewriting its time.
    fixture.grant.clear_existing_grant();
    assert!(!cancellation.is_cancelled());
    native.native_stopped();
    let receipt = attempt
        .install(&fixture.grant, &fixture.auth, fixture.at(115))
        .unwrap();
    assert_eq!(receipt.outcome, LocalConfirmationOutcome::Confirmed);
    assert_eq!(receipt.remaining_seconds, 895);
    assert!(old_clone.is_fresh(fixture.at(1009)));
    assert!(!old_clone.is_fresh(fixture.at(1010)));
}

#[test]
fn clearing_existing_grant_does_not_restart_the_attempt_budget() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    native
        .record_outcome(
            NativeOutcome::Succeeded {
                at: fixture.at(119),
            },
            fixture.at(119),
        )
        .unwrap();
    fixture.grant.clear_existing_grant();
    native.native_stopped();
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(120))
            .is_err()
    );
    assert!(!fixture.grant.is_fresh(fixture.at(120)));
}

#[test]
fn clearing_existing_grant_cannot_override_global_invalidation_of_pending() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let mut attempt = fixture.begin(1);
    let native = attempt.start_native(fixture.at(1)).unwrap();
    fixture.grant.clear_existing_grant();
    assert!(!native.cancellation().is_cancelled());
    fixture.coordinator.invalidate_all();
    fixture.grant.clear_existing_grant();
    assert!(native.cancellation().is_cancelled());
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2)
        ),
        Ok(NativeDisposition::Rejected)
    );
    assert!(
        attempt
            .install(&fixture.grant, &fixture.auth, fixture.at(3))
            .is_err()
    );
    native.native_stopped();
    assert!(!fixture.grant.is_fresh(fixture.at(4)));
}

#[test]
fn every_scope_field_and_role_set_is_checked_before_and_after_native() {
    let variants = [
        auth(
            "other",
            "tenant-private",
            "actor-private",
            1,
            true,
            [Role::Admin],
        ),
        auth(
            "deployment-private",
            "other",
            "actor-private",
            1,
            true,
            [Role::Admin],
        ),
        auth(
            "deployment-private",
            "tenant-private",
            "other",
            1,
            true,
            [Role::Admin],
        ),
        auth(
            "deployment-private",
            "tenant-private",
            "actor-private",
            2,
            true,
            [Role::Admin],
        ),
        auth(
            "deployment-private",
            "tenant-private",
            "actor-private",
            1,
            false,
            [Role::Admin],
        ),
        auth(
            "deployment-private",
            "tenant-private",
            "actor-private",
            1,
            true,
            [Role::User],
        ),
        auth(
            "deployment-private",
            "tenant-private",
            "actor-private",
            1,
            true,
            [Role::Admin, Role::User],
        ),
    ];
    for changed in variants {
        let fixture = Fixture::new();
        fixture.success(0, 0, 0);
        assert!(matches!(
            fixture
                .coordinator
                .begin(&fixture.grant, &changed, fixture.at(1)),
            Err(ConfirmationError::NotCurrent)
        ));
        assert!(!fixture.grant.is_fresh(fixture.at(1)));
        let fixture = Fixture::new();
        let mut attempt = fixture.begin(0);
        let native = attempt.start_native(fixture.at(0)).unwrap();
        native
            .record_outcome(
                NativeOutcome::Succeeded { at: fixture.at(1) },
                fixture.at(1),
            )
            .unwrap();
        assert_eq!(
            attempt.install(&fixture.grant, &changed, fixture.at(2)),
            Err(ConfirmationError::NotCurrent)
        );
        assert!(!fixture.grant.is_fresh(fixture.at(2)));
        native.native_stopped();
    }
}

#[test]
fn independent_coordinator_with_same_name_cannot_accept_handles_or_attempts() {
    let fixture = Fixture::new();
    let other = LocalConfirmationCoordinator::new("installation-private", true).unwrap();
    assert!(matches!(
        other.begin(&fixture.grant, &fixture.auth, fixture.at(0)),
        Err(ConfirmationError::NotCurrent)
    ));
    let other_grant = other.register_binding(91, &fixture.auth).unwrap();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    native
        .record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(1) },
            fixture.at(1),
        )
        .unwrap();
    assert_eq!(
        attempt.install(&other_grant, &fixture.auth, fixture.at(1)),
        Err(ConfirmationError::NotCurrent)
    );
    native.native_stopped();
    assert!(!other_grant.is_fresh(fixture.at(1)));
}

#[test]
fn global_epoch_revokes_all_clones_and_obsolete_native_callbacks() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let clone = fixture.grant.clone();
    let other = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    let mut attempt = fixture
        .coordinator
        .begin(&other, &fixture.auth, fixture.at(1))
        .unwrap();
    let native = attempt.start_native(fixture.at(1)).unwrap();
    fixture.coordinator.invalidate_all();
    assert!(!clone.is_fresh(fixture.at(2)));
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2)
        ),
        Ok(NativeDisposition::Rejected)
    );
    assert!(
        attempt
            .install(&other, &fixture.auth, fixture.at(2))
            .is_err()
    );
    native.native_stopped();
    assert!(
        fixture
            .coordinator
            .begin(&other, &fixture.auth, fixture.at(3))
            .is_ok()
    );
}

#[test]
fn either_clock_expiring_denies_and_clock_regression_never_revives_grant() {
    for (monotonic, wall) in [(900, 1), (1, 900)] {
        let fixture = Fixture::new();
        fixture.success(0, 0, 0);
        assert!(
            !fixture.grant.is_fresh(
                fixture.clocks(Duration::from_secs(monotonic), Duration::from_secs(wall))
            )
        );
        assert!(!fixture.grant.is_fresh(fixture.at(2)));
    }
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    assert!(fixture.grant.is_fresh(fixture.at(10)));
    assert_eq!(
        fixture
            .grant
            .status(fixture.clocks(Duration::from_secs(11), Duration::from_secs(9))),
        Err(ConfirmationError::ClockRegression)
    );
    assert!(!fixture.grant.is_fresh(fixture.at(12)));
}

#[test]
fn samples_arriving_t2_before_t1_reject_only_the_stale_operation() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let other = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    assert!(fixture.grant.is_fresh(fixture.at(2)));
    assert_eq!(
        other.status(fixture.at(1)),
        Err(ConfirmationError::StaleClockSample)
    );
    assert!(matches!(
        fixture
            .coordinator
            .begin(&other, &fixture.auth, fixture.at(1)),
        Err(ConfirmationError::StaleClockSample)
    ));
    assert_eq!(
        fixture
            .grant
            .status(fixture.at(2))
            .unwrap()
            .remaining_seconds,
        898
    );
    assert!(fixture.grant.is_fresh(fixture.at(3)));
    // A regressed monotonic component alone cannot prove wall-clock rollback either.
    assert_eq!(
        other.status(fixture.clocks(Duration::from_secs(2), Duration::from_secs(4))),
        Err(ConfirmationError::StaleClockSample)
    );
    assert!(fixture.grant.is_fresh(fixture.at(4)));
}

#[test]
fn stale_callback_cancels_only_its_attempt_and_keeps_native_budget() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let other = fixture
        .coordinator
        .register_binding(92, &fixture.auth)
        .unwrap();
    let mut attempt = fixture
        .coordinator
        .begin(&other, &fixture.auth, fixture.at(1))
        .unwrap();
    let native = attempt.start_native(fixture.at(1)).unwrap();
    assert!(fixture.grant.is_fresh(fixture.at(3)));
    assert_eq!(
        native.record_outcome(
            NativeOutcome::Succeeded { at: fixture.at(2) },
            fixture.at(2)
        ),
        Err(ConfirmationError::StaleClockSample)
    );
    assert!(native.cancellation().is_cancelled());
    assert!(fixture.grant.is_fresh(fixture.at(3)));
    assert!(!other.is_fresh(fixture.at(3)));
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(3)),
        Err(ConfirmationError::Busy)
    ));
    native.native_stopped();
    assert!(
        attempt
            .install(&other, &fixture.auth, fixture.at(4))
            .is_err()
    );
    assert!(fixture.grant.is_fresh(fixture.at(4)));
}

#[test]
fn cancelled_native_without_previous_grant_returns_zero() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    assert_eq!(
        native.record_outcome(NativeOutcome::Cancelled, fixture.at(1)),
        Ok(NativeDisposition::Cancelled)
    );
    native.native_stopped();
    assert_eq!(
        attempt.cancel(fixture.at(2)).unwrap(),
        LocalConfirmationReceipt {
            outcome: LocalConfirmationOutcome::Cancelled,
            remaining_seconds: 0,
        }
    );
}

#[test]
fn either_clock_wait_timeout_cancels_native_without_early_slot_release() {
    for (monotonic, wall) in [(120, 1), (1, 120)] {
        let fixture = Fixture::new();
        let mut attempt = fixture.begin(0);
        let native = attempt.start_native(fixture.at(0)).unwrap();
        fixture
            .coordinator
            .expire(fixture.clocks(Duration::from_secs(monotonic), Duration::from_secs(wall)))
            .unwrap();
        assert!(native.cancellation().is_cancelled());
        assert!(matches!(
            fixture
                .coordinator
                .begin(&fixture.grant, &fixture.auth, fixture.at(121)),
            Err(ConfirmationError::Busy)
        ));
        native.native_stopped();
        assert!(
            attempt
                .install(&fixture.grant, &fixture.auth, fixture.at(121))
                .is_err()
        );
    }
}

#[test]
fn unavailable_recovery_and_owner_drop_do_not_restore_authority() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    fixture.coordinator.set_available(false);
    assert_eq!(
        fixture.grant.status(fixture.at(1)).unwrap().state,
        LocalConfirmationState::Unavailable
    );
    fixture.coordinator.set_available(true);
    assert!(!fixture.grant.is_fresh(fixture.at(2)));
    let mut attempt = fixture.begin(3);
    let native = attempt.start_native(fixture.at(3)).unwrap();
    assert_eq!(
        native.record_outcome(NativeOutcome::Unavailable, fixture.at(4)),
        Ok(NativeDisposition::Unavailable)
    );
    assert_eq!(
        attempt.install(&fixture.grant, &fixture.auth, fixture.at(4)),
        Err(ConfirmationError::Unavailable)
    );
    native.native_stopped();
    fixture.success(5, 6, 7);
    let clone = fixture.grant.clone();
    drop(fixture.coordinator);
    assert!(!clone.is_fresh(ClockSample::new(
        fixture.base.monotonic + Duration::from_secs(8),
        fixture.base.wall + Duration::from_secs(8)
    )));
}

#[test]
fn invalid_scope_and_internal_counter_exhaustion_fail_closed() {
    let fixture = Fixture::new();
    assert!(matches!(
        LocalConfirmationCoordinator::new("", true),
        Err(ConfirmationError::InvalidScope)
    ));
    assert!(matches!(
        fixture.coordinator.register_binding(0, &fixture.auth),
        Err(ConfirmationError::InvalidScope)
    ));
    let user = auth("d", "t", "a", 1, true, [Role::User]);
    assert!(matches!(
        fixture.coordinator.register_binding(1, &user),
        Err(ConfirmationError::InvalidScope)
    ));
    fixture
        .coordinator
        .shared
        .state
        .lock()
        .unwrap()
        .next_attempt = u64::MAX;
    assert!(matches!(
        fixture
            .coordinator
            .begin(&fixture.grant, &fixture.auth, fixture.at(0)),
        Err(ConfirmationError::Exhausted)
    ));
    fixture.coordinator.shared.state.lock().unwrap().epoch = u64::MAX;
    fixture.coordinator.invalidate_all();
    assert!(matches!(
        fixture.coordinator.register_binding(2, &fixture.auth),
        Err(ConfirmationError::NotCurrent)
    ));
}

#[test]
fn concurrent_revocation_is_visible_to_preexisting_clone() {
    let fixture = Fixture::new();
    fixture.success(0, 0, 0);
    let clone = fixture.grant.clone();
    let revoked = fixture.grant.clone();
    std::thread::spawn(move || revoked.revoke()).join().unwrap();
    assert!(!clone.is_fresh(fixture.at(1)));
}

#[test]
fn poisoned_mutex_cannot_grant_and_cleanup_still_cancels_native() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    let shared = Arc::clone(&fixture.coordinator.shared);
    let _ = std::thread::spawn(move || {
        let _guard = shared.state.lock().unwrap();
        panic!("synthetic coordinator poison");
    })
    .join();
    assert!(!fixture.grant.is_fresh(fixture.at(1)));
    assert_eq!(
        fixture.grant.status(fixture.at(1)),
        Err(ConfirmationError::Poisoned)
    );
    drop(attempt);
    assert!(native.cancellation().is_cancelled());
    native.native_stopped();
}

#[test]
fn debug_excludes_installation_auth_binding_and_clock_values() {
    let fixture = Fixture::new();
    let mut attempt = fixture.begin(0);
    let native = attempt.start_native(fixture.at(0)).unwrap();
    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        fixture.coordinator, fixture.grant, attempt, native, fixture.base
    );
    for private in [
        "installation-private",
        "deployment-private",
        "tenant-private",
        "actor-private",
        "91",
        "10000",
    ] {
        assert!(!debug.contains(private));
    }
    native.native_stopped();
}
