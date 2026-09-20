//! Combined-only health API tests. No real LAContext or native observer is constructed.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, Sender};

struct HealthBackend {
    started: Sender<Completion>,
    panic_on_start: bool,
}
struct HealthEvaluation;
impl Evaluation for HealthEvaluation {
    fn invalidate(&mut self) {}
}
impl Backend for HealthBackend {
    fn start(
        &mut self,
        _locale: ConfirmationLocale,
        completion: Completion,
    ) -> Result<Box<dyn Evaluation>, NativeResult> {
        self.started.send(completion).unwrap();
        assert!(!self.panic_on_start, "fixed health-test worker failure");
        Ok(Box::new(HealthEvaluation))
    }
}
fn owner(panic_on_start: bool) -> (MacLocalAuthOwner, Receiver<Completion>) {
    let (started, receiver) = mpsc::channel();
    (
        MacLocalAuthOwner::spawn(
            HealthBackend {
                started,
                panic_on_start,
            },
            Duration::from_secs(2),
            None,
        )
        .unwrap(),
        receiver,
    )
}
fn worker_ended(owner: &MacLocalAuthOwner) {
    // Test-only recovery to observe cleanup after intentional poison, never to grant authority.
    let guard = lock(&owner.shared.state);
    let (guard, _) = owner
        .shared
        .changed
        .wait_timeout_while(guard, Duration::from_secs(1), |state| !state.worker_done)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(guard.worker_done);
}

#[test]
fn is_running_accepts_idle_and_normal_pending_without_requiring_an_empty_slot() {
    let (owner, started) = owner(false);
    assert!(owner.is_running());
    let attempt = owner.begin(ConfirmationLocale::English).unwrap();
    let completion = started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(owner.is_running());
    assert!(!attempt.is_stopped());
    completion.finish(NativeResult::Cancelled, Instant::now(), SystemTime::now());
    owner.stop();
    assert!(owner.wait_stopped(Duration::from_secs(1)));
}

#[test]
fn stop_disables_health_before_native_ack_and_stays_false_after_normal_worker_exit() {
    let (owner, started) = owner(false);
    let attempt = owner.begin(ConfirmationLocale::English).unwrap();
    let completion = started.recv_timeout(Duration::from_secs(1)).unwrap();
    owner.stop();
    assert!(!owner.is_running());
    assert!(!attempt.is_stopped());
    assert!(!owner.wait_stopped(Duration::ZERO));
    completion.finish(NativeResult::Cancelled, Instant::now(), SystemTime::now());
    assert!(owner.wait_stopped(Duration::from_secs(1)));
    assert!(!owner.is_running());
}

#[test]
fn owner_mutex_poison_is_not_recovered_as_healthy() {
    let (owner, _started) = owner(false);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = owner.shared.state.lock().unwrap();
        panic!("fixed health-test owner poison");
    }));
    assert!(!owner.is_running());
    assert!(owner.shared.state.is_poisoned());
    owner.stop();
    worker_ended(&owner);
    assert!(!owner.is_running());
}

#[test]
fn unexpected_worker_panic_is_unhealthy_without_faking_native_retirement() {
    let (owner, started) = owner(true);
    let attempt = owner.begin(ConfirmationLocale::English).unwrap();
    let _completion = started.recv_timeout(Duration::from_secs(1)).unwrap();
    worker_ended(&owner);
    assert!(!owner.is_running());
    assert!(!attempt.is_stopped());
    assert!(!owner.wait_stopped(Duration::ZERO));
}

#[test]
fn pending_poison_worker_exit_is_unhealthy_even_though_native_stop_is_unknown() {
    let (owner, started) = owner(false);
    let attempt = owner.begin(ConfirmationLocale::English).unwrap();
    let _completion = started.recv_timeout(Duration::from_secs(1)).unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = attempt.inner.state.lock().unwrap();
        panic!("fixed health-test attempt poison");
    }));
    attempt.inner.changed.notify_all();
    worker_ended(&owner);
    assert!(!owner.is_running());
    assert!(!attempt.is_stopped());
    assert!(!owner.wait_stopped(Duration::ZERO));
}
