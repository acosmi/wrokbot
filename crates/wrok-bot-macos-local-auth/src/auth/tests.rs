use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::ThreadId;

#[derive(Default)]
struct Observed {
    starts: AtomicUsize,
    invalidates: AtomicUsize,
    drops: AtomicUsize,
    threads: Mutex<Vec<ThreadId>>,
}

struct FakeBackend {
    observed: Arc<Observed>,
    started: Sender<Completion>,
    fail: bool,
    preflight: Option<Arc<(Mutex<bool>, Condvar)>>,
}

struct FakeEvaluation {
    observed: Arc<Observed>,
}

impl Backend for FakeBackend {
    fn start(
        &mut self,
        _locale: ConfirmationLocale,
        completion: Completion,
    ) -> Result<Box<dyn Evaluation>, NativeResult> {
        self.observed.starts.fetch_add(1, Ordering::SeqCst);
        lock(&self.observed.threads).push(std::thread::current().id());
        self.started.send(completion.clone()).unwrap();
        if let Some(preflight) = &self.preflight {
            let mut released = lock(&preflight.0);
            while !*released {
                released = preflight.1.wait(released).unwrap();
            }
        }
        if !completion.is_live() {
            return Err(NativeResult::Cancelled);
        }
        if self.fail {
            return Err(NativeResult::Unavailable);
        }
        Ok(Box::new(FakeEvaluation {
            observed: self.observed.clone(),
        }))
    }
}

impl Evaluation for FakeEvaluation {
    fn invalidate(&mut self) {
        self.observed.invalidates.fetch_add(1, Ordering::SeqCst);
        lock(&self.observed.threads).push(std::thread::current().id());
    }
}

impl Drop for FakeEvaluation {
    fn drop(&mut self) {
        self.observed.drops.fetch_add(1, Ordering::SeqCst);
        lock(&self.observed.threads).push(std::thread::current().id());
    }
}

struct Rig {
    owner: MacLocalAuthOwner,
    started: Receiver<Completion>,
    observed: Arc<Observed>,
}

fn rig(timeout: Duration, fail: bool, preflight: Option<Arc<(Mutex<bool>, Condvar)>>) -> Rig {
    let (tx, rx) = mpsc::channel();
    let observed = Arc::new(Observed::default());
    let owner = MacLocalAuthOwner::spawn(
        FakeBackend {
            observed: observed.clone(),
            started: tx,
            fail,
            preflight,
        },
        timeout,
        None,
    )
    .unwrap();
    Rig {
        owner,
        started: rx,
        observed,
    }
}

fn begin(rig: &Rig) -> (LocalAuthAttempt, Completion) {
    let attempt = rig.owner.begin(ConfirmationLocale::English).unwrap();
    let completion = rig.started.recv_timeout(Duration::from_secs(1)).unwrap();
    (attempt, completion)
}

fn complete(completion: &Completion, result: NativeResult) {
    completion.finish(result, Instant::now(), SystemTime::now());
}

fn stopped(attempt: &LocalAuthAttempt) {
    let state = lock(&attempt.inner.state);
    let (state, _) = attempt
        .inner
        .changed
        .wait_timeout_while(state, Duration::from_secs(1), |state| !state.native_stopped)
        .unwrap();
    assert!(state.native_stopped);
}

fn finish(rig: &Rig) {
    rig.owner.stop();
    assert!(rig.owner.wait_stopped(Duration::from_secs(1)));
}

#[test]
fn success_records_both_callback_clocks_and_is_delivered_once() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    let monotonic = Instant::now();
    let wall = SystemTime::now();
    completion.finish(NativeResult::Confirmed, monotonic, wall);
    let LocalAuthOutcome::Confirmed(proof) = attempt.wait_timeout(Duration::from_secs(1)).unwrap()
    else {
        panic!()
    };
    assert_eq!(proof.attempt_id(), attempt.id());
    assert_eq!(proof.confirmed_at(), monotonic);
    assert_eq!(proof.confirmed_at_wall(), wall);
    assert!(attempt.try_take_outcome().is_none());
    stopped(&attempt);
    assert_eq!(rig.observed.drops.load(Ordering::SeqCst), 1);
    let threads = lock(&rig.observed.threads);
    assert!(threads.iter().all(|id| *id == threads[0]));
    assert_ne!(threads[0], std::thread::current().id());
    drop(threads);
    finish(&rig);
}

#[test]
fn cancel_does_not_release_native_slot_until_late_callback_retires() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    attempt.cancel();
    assert!(matches!(
        attempt.try_take_outcome(),
        Some(LocalAuthOutcome::Cancelled)
    ));
    assert!(attempt.is_cancelled());
    assert!(!attempt.is_stopped());
    assert!(matches!(
        rig.owner.begin(ConfirmationLocale::English),
        Err(LocalAuthStartError::Busy)
    ));
    complete(&completion, NativeResult::Confirmed);
    stopped(&attempt);
    assert!(attempt.try_take_outcome().is_none());
    finish(&rig);
}

#[test]
fn timeout_is_not_native_completion_and_late_success_cannot_grant() {
    let rig = rig(Duration::from_millis(20), false, None);
    let (attempt, completion) = begin(&rig);
    assert!(matches!(
        attempt.wait_timeout(Duration::from_secs(1)),
        Some(LocalAuthOutcome::TimedOut)
    ));
    assert!(!attempt.is_stopped());
    assert!(matches!(
        rig.owner.begin(ConfirmationLocale::English),
        Err(LocalAuthStartError::Busy)
    ));
    complete(&completion, NativeResult::Confirmed);
    stopped(&attempt);
    assert!(attempt.try_take_outcome().is_none());
    finish(&rig);
}

#[test]
fn stop_wait_is_bounded_and_does_not_report_unacknowledged_native_as_stopped() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    rig.owner.stop();
    rig.owner.stop();
    assert!(matches!(
        attempt.try_take_outcome(),
        Some(LocalAuthOutcome::Stopped)
    ));
    assert!(!rig.owner.wait_stopped(Duration::from_millis(5)));
    assert!(!rig.owner.is_stopped());
    assert!(!attempt.is_stopped());
    assert!(matches!(
        rig.owner.begin(ConfirmationLocale::English),
        Err(LocalAuthStartError::Stopped)
    ));
    complete(&completion, NativeResult::Confirmed);
    assert!(rig.owner.wait_stopped(Duration::from_secs(1)));
    assert!(attempt.is_stopped());
    assert!(attempt.try_take_outcome().is_none());
}

#[test]
fn dropped_attempt_cancels_but_preserves_native_pending_capacity() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    drop(attempt);
    assert!(lock(&completion.0.state).cancel_requested);
    assert!(matches!(
        rig.owner.begin(ConfirmationLocale::English),
        Err(LocalAuthStartError::Busy)
    ));
    complete(&completion, NativeResult::Cancelled);
    finish(&rig);
}

#[test]
fn duplicate_callback_does_not_overwrite_first_result_or_mint_another_proof() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    complete(&completion, NativeResult::Cancelled);
    complete(&completion, NativeResult::Confirmed);
    assert!(matches!(
        attempt.wait_timeout(Duration::from_secs(1)),
        Some(LocalAuthOutcome::Cancelled)
    ));
    assert!(attempt.try_take_outcome().is_none());
    stopped(&attempt);
    finish(&rig);
}

#[test]
fn cancel_before_success_consumption_discards_unconsumed_proof() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    complete(&completion, NativeResult::Confirmed);
    attempt.cancel();
    assert!(matches!(
        attempt.try_take_outcome(),
        Some(LocalAuthOutcome::Cancelled)
    ));
    stopped(&attempt);
    finish(&rig);
}

#[test]
fn preflight_failure_is_unavailable_and_cleans_up_without_claiming_authentication() {
    let rig = rig(Duration::from_secs(2), true, None);
    let (attempt, _) = begin(&rig);
    assert!(matches!(
        attempt.wait_timeout(Duration::from_secs(1)),
        Some(LocalAuthOutcome::Unavailable)
    ));
    stopped(&attempt);
    assert_eq!(rig.observed.drops.load(Ordering::SeqCst), 0);
    finish(&rig);
}

#[test]
fn timeout_during_blocking_preflight_rejects_start_without_faking_hard_cancellation() {
    let barrier = Arc::new((Mutex::new(false), Condvar::new()));
    let rig = rig(Duration::from_millis(20), false, Some(barrier.clone()));
    let (attempt, _) = begin(&rig);
    assert!(matches!(
        attempt.wait_timeout(Duration::from_secs(1)),
        Some(LocalAuthOutcome::TimedOut)
    ));
    assert!(!attempt.is_stopped());
    rig.owner.stop();
    assert!(!rig.owner.wait_stopped(Duration::from_millis(5)));
    *lock(&barrier.0) = true;
    barrier.1.notify_all();
    assert!(rig.owner.wait_stopped(Duration::from_secs(1)));
    assert!(attempt.is_stopped());
    assert_eq!(rig.observed.drops.load(Ordering::SeqCst), 0);
}

#[test]
fn late_old_callback_cannot_complete_a_later_attempt() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (first, old_callback) = begin(&rig);
    complete(&old_callback, NativeResult::Cancelled);
    stopped(&first);
    // Retirement and releasing the owner slot are ordered but separately observed; wait on it.
    let state = lock(&rig.owner.shared.state);
    let (state, _) = rig
        .owner
        .shared
        .changed
        .wait_timeout_while(state, Duration::from_secs(1), |state| {
            state.pending.is_some()
        })
        .unwrap();
    assert!(state.pending.is_none());
    drop(state);
    let (second, new_callback) = begin(&rig);
    assert_ne!(first.id(), second.id());
    complete(&old_callback, NativeResult::Confirmed);
    assert!(second.try_take_outcome().is_none());
    complete(&new_callback, NativeResult::Cancelled);
    stopped(&second);
    finish(&rig);
}

#[test]
fn idle_owner_stop_and_drop_are_prompt_without_native_start() {
    let rig = rig(Duration::from_secs(2), false, None);
    finish(&rig);
    assert_eq!(rig.observed.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn dropping_owner_signals_stop_but_does_not_claim_native_cleanup_before_callback() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    let shared = rig.owner.shared.clone();
    drop(rig.owner);
    assert!(matches!(
        attempt.try_take_outcome(),
        Some(LocalAuthOutcome::Stopped)
    ));
    assert!(!attempt.is_stopped());
    complete(&completion, NativeResult::Confirmed);
    let state = lock(&shared.state);
    let (state, _) = shared
        .changed
        .wait_timeout_while(state, Duration::from_secs(1), |state| {
            !state.worker_done || state.pending.is_some()
        })
        .unwrap();
    assert!(state.worker_done && state.pending.is_none());
    drop(state);
    assert!(attempt.is_stopped());
    assert!(attempt.try_take_outcome().is_none());
}

#[test]
fn replacing_owner_cannot_reuse_an_old_native_attempt_identity() {
    let first_rig = rig(Duration::from_secs(2), false, None);
    let (first, old_callback) = begin(&first_rig);
    complete(&old_callback, NativeResult::Cancelled);
    stopped(&first);
    finish(&first_rig);
    let next_rig = rig(Duration::from_secs(2), false, None);
    let (next, next_callback) = begin(&next_rig);
    assert_ne!(first.id(), next.id());
    complete(&old_callback, NativeResult::Confirmed);
    assert!(next.try_take_outcome().is_none());
    complete(&next_callback, NativeResult::Cancelled);
    stopped(&next);
    finish(&next_rig);
}

fn poison<T>(mutex: &Mutex<T>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("QA poison injection");
    }));
    assert!(result.is_err() && mutex.is_poisoned());
}

fn observe_worker_cleanup_without_claiming_poisoned_public_state(rig: &Rig) {
    rig.owner.stop();
    let state = lock(&rig.owner.shared.state);
    let (state, _) = rig
        .owner
        .shared
        .changed
        .wait_timeout_while(state, Duration::from_secs(1), |state| !state.worker_done)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        state.worker_done,
        "fixture worker must terminate; this is not public native_stopped"
    );
}

fn poisoned_success_is_not_delivered(owner_poison: bool, use_wait: bool) {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, callback) = begin(&rig);
    complete(&callback, NativeResult::Confirmed);
    stopped(&attempt);
    if owner_poison {
        poison(&rig.owner.shared.state);
    } else {
        poison(&attempt.inner.state);
    }
    let outcome = if use_wait {
        attempt.wait_timeout(Duration::from_millis(20))
    } else {
        attempt.try_take_outcome()
    };
    assert!(matches!(outcome, Some(LocalAuthOutcome::Unavailable)));
    assert!(attempt.try_take_outcome().is_none());
    assert!(attempt.is_cancelled());
    assert!(!attempt.is_stopped());
    if owner_poison {
        assert!(matches!(
            rig.owner.begin(ConfirmationLocale::English),
            Err(LocalAuthStartError::Unavailable)
        ));
        assert!(!rig.owner.is_stopped());
        assert!(!rig.owner.wait_stopped(Duration::from_millis(1)));
    }
    observe_worker_cleanup_without_claiming_poisoned_public_state(&rig);
}

#[test]
fn owner_poison_after_success_blocks_try_take() {
    poisoned_success_is_not_delivered(true, false);
}

#[test]
fn owner_poison_after_success_blocks_wait() {
    poisoned_success_is_not_delivered(true, true);
}

#[test]
fn attempt_poison_after_success_blocks_try_take() {
    poisoned_success_is_not_delivered(false, false);
}

#[test]
fn attempt_poison_after_success_blocks_wait() {
    poisoned_success_is_not_delivered(false, true);
}

#[test]
fn poisoned_pending_attempt_never_reports_native_retired_or_reopens_slot() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, callback) = begin(&rig);
    poison(&attempt.inner.state);
    assert!(matches!(
        attempt.try_take_outcome(),
        Some(LocalAuthOutcome::Unavailable)
    ));
    observe_worker_cleanup_without_claiming_poisoned_public_state(&rig);
    assert!(!attempt.is_stopped());
    assert!(!rig.owner.is_stopped());
    assert!(matches!(
        rig.owner.begin(ConfirmationLocale::English),
        Err(LocalAuthStartError::Stopped)
    ));
    complete(&callback, NativeResult::Confirmed);
    assert!(attempt.try_take_outcome().is_none());
}

#[test]
fn native_stop_receipt_does_not_wait_for_callback_stack_tail() {
    let rig = rig(Duration::from_secs(2), false, None);
    let (attempt, completion) = begin(&rig);
    let (tail_tx, tail_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let callback = std::thread::spawn(move || {
        complete(&completion, NativeResult::Confirmed);
        tail_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    });
    tail_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    stopped(&attempt);
    assert!(attempt.is_stopped());
    assert!(!callback.is_finished());
    release_tx.send(()).unwrap();
    callback.join().unwrap();
    finish(&rig);
}
