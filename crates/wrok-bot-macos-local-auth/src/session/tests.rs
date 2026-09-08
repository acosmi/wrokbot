use super::*;
use std::sync::{Barrier, atomic::AtomicUsize};

struct FakeOwner {
    remaining: Vec<usize>,
    removed: Arc<Mutex<Vec<usize>>>,
    fail: Arc<AtomicBool>,
}
impl ObserverOwner for FakeOwner {
    fn remove_all(&mut self) -> Result<(), MonitorError> {
        while let Some(id) = self.remaining.first().copied() {
            if id == 3 && self.fail.load(Ordering::SeqCst) {
                return Err(MonitorError::Failed);
            }
            self.remaining.remove(0);
            self.removed.lock().unwrap().push(id);
        }
        Ok(())
    }
}
struct Fixture {
    handle: MonitorHandle,
    removed: Arc<Mutex<Vec<usize>>>,
    fail: Arc<AtomicBool>,
}
impl Fixture {
    fn new(callback: impl Fn(SessionEvent) + Send + Sync + 'static) -> Self {
        let removed = Arc::new(Mutex::new(Vec::new()));
        let fail = Arc::new(AtomicBool::new(false));
        let handle = start_inner(Arc::new(callback), |_| {
            Box::new(FakeOwner {
                remaining: (0..7).collect(),
                removed: Arc::clone(&removed),
                fail: Arc::clone(&fail),
            })
        })
        .unwrap();
        Self {
            handle,
            removed,
            fail,
        }
    }
    fn cleanup(&self) -> Result<CleanupReceipt, MonitorError> {
        cleanup_inner(&self.handle.shared)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.close_callbacks();
        self.fail.store(false, Ordering::SeqCst);
        let _ = self.cleanup();
        // A poisoned/failed production slot is deliberately not reusable. Only this private
        // fake fixture resets its thread's leftover slot so it cannot affect another test.
        SLOT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[test]
fn fixed_events_have_only_the_two_authorized_invalidation_actions() {
    assert_eq!(
        SessionEvent::AppResignedActive.invalidation(),
        Invalidation::ClearExistingGrant
    );
    for event in [
        SessionEvent::SystemWillSleep,
        SessionEvent::SystemDidWake,
        SessionEvent::ScreensDidSleep,
        SessionEvent::ScreensDidWake,
        SessionEvent::SessionResignedActive,
        SessionEvent::SessionBecameActive,
    ] {
        assert_eq!(event.invalidation(), Invalidation::InvalidateAll);
    }
}

#[test]
fn only_opaque_rust_handles_cross_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<MonitorHandle>();
    send_sync::<CleanupTicket>();
}

#[test]
fn close_blocks_late_callbacks_but_is_not_native_removal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let f = Fixture::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    assert!(f.handle.is_live());
    callback_boundary(&f.handle.shared, SessionEvent::SystemDidWake);
    f.handle.close_callbacks();
    callback_boundary(&f.handle.shared, SessionEvent::SystemWillSleep);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.handle.status(), MonitorStatus::Closing);
    assert!(!f.handle.is_removed());
    assert!(f.removed.lock().unwrap().is_empty());
    f.cleanup().unwrap();
    assert_eq!(*f.removed.lock().unwrap(), (0..7).collect::<Vec<_>>());
    assert!(f.handle.is_removed());
    assert!(!f.handle.is_live());
}

#[test]
fn owner_drop_preserves_exact_cleanup_ticket_and_does_not_remove_observers() {
    let removed = Arc::new(Mutex::new(Vec::new()));
    let r = Arc::clone(&removed);
    let handle = start_inner(Arc::new(|_| {}), |_| {
        Box::new(FakeOwner {
            remaining: (0..7).collect(),
            removed: r,
            fail: Arc::new(AtomicBool::new(false)),
        })
    })
    .unwrap();
    let ticket = handle.cleanup_ticket();
    drop(handle);
    assert_eq!(ticket.shared.status(), MonitorStatus::Closing);
    assert!(removed.lock().unwrap().is_empty());
    cleanup_inner(&ticket.shared).unwrap();
    assert!(ticket.is_removed());
}

#[test]
fn old_ticket_and_late_callback_never_close_a_replacement() {
    let f = Fixture::new(|_| {});
    let old = f.handle.cleanup_ticket();
    f.cleanup().unwrap();
    let replacement = Fixture::new(|_| {});
    cleanup_inner(&old.shared).unwrap();
    callback_boundary(&old.shared, SessionEvent::SystemWillSleep);
    assert!(replacement.handle.is_live());
    assert!(replacement.removed.lock().unwrap().is_empty());
    replacement.cleanup().unwrap();
}

#[test]
fn closed_but_unremoved_slot_stays_busy_without_building_more_observers() {
    let f = Fixture::new(|_| {});
    f.handle.close_callbacks();
    let called = AtomicBool::new(false);
    let result = start_inner(Arc::new(|_| {}), |_| {
        called.store(true, Ordering::SeqCst);
        unreachable!()
    });
    assert!(matches!(result, Err(MonitorError::Busy)));
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn callback_can_reenter_close_without_mutex_or_tls_deadlock() {
    let shared = Arc::new(Mutex::new(None::<std::sync::Weak<Shared>>));
    let shared_in = Arc::clone(&shared);
    let f = Fixture::new(move |_| {
        assert!(SLOT.with(|slot| slot.try_borrow_mut().is_ok()));
        shared_in
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap()
            .close();
    });
    *shared.lock().unwrap() = Some(Arc::downgrade(&f.handle.shared));
    callback_boundary(&f.handle.shared, SessionEvent::AppResignedActive);
    assert_eq!(f.handle.status(), MonitorStatus::Closing);
}

#[test]
fn reentrant_cleanup_removes_native_but_waits_for_the_callback_flight() {
    let shared = Arc::new(Mutex::new(None::<std::sync::Weak<Shared>>));
    let weak = Arc::clone(&shared);
    let f = Fixture::new(move |_| {
        let state = weak.lock().unwrap().as_ref().unwrap().upgrade().unwrap();
        assert_eq!(cleanup_inner(&state), Err(MonitorError::Busy));
        assert_ne!(state.status(), MonitorStatus::Removed);
    });
    *shared.lock().unwrap() = Some(Arc::downgrade(&f.handle.shared));
    callback_boundary(&f.handle.shared, SessionEvent::AppResignedActive);
    assert_eq!(f.removed.lock().unwrap().len(), 7);
    assert!(!f.handle.is_removed());
    f.cleanup().unwrap();
    assert!(f.handle.is_removed());
}

#[test]
fn an_admitted_callback_tail_delays_removal_receipt_without_blocking_cleanup() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let a = Arc::clone(&entered);
    let b = Arc::clone(&release);
    let f = Fixture::new(move |_| {
        a.wait();
        b.wait();
    });
    let state = Arc::clone(&f.handle.shared);
    let thread =
        std::thread::spawn(move || callback_boundary(&state, SessionEvent::SystemWillSleep));
    entered.wait();
    assert_eq!(f.cleanup(), Err(MonitorError::Busy));
    assert_eq!(f.removed.lock().unwrap().len(), 7);
    assert!(!f.handle.is_live());
    assert!(!f.handle.is_removed());
    release.wait();
    thread.join().unwrap();
    f.cleanup().unwrap();
}

#[test]
fn rust_callback_panic_is_contained_and_never_reports_live_or_removed() {
    let f = Fixture::new(|_| panic!("fixed test callback panic"));
    assert!(
        catch_unwind(AssertUnwindSafe(|| callback_boundary(
            &f.handle.shared,
            SessionEvent::SystemWillSleep
        )))
        .is_ok()
    );
    assert_eq!(f.handle.status(), MonitorStatus::Failed);
    assert_eq!(f.cleanup(), Err(MonitorError::Failed));
    assert_eq!(f.removed.lock().unwrap().len(), 7);
    assert!(!f.handle.is_removed());
}

#[test]
fn a_panicking_payload_destructor_cannot_unwind_across_the_callback_boundary() {
    struct BadPayload;
    impl Drop for BadPayload {
        fn drop(&mut self) {
            panic!("payload must not be dropped");
        }
    }
    let f = Fixture::new(|_| std::panic::panic_any(BadPayload));
    assert!(
        catch_unwind(AssertUnwindSafe(|| callback_boundary(
            &f.handle.shared,
            SessionEvent::SystemWillSleep
        )))
        .is_ok()
    );
    assert_eq!(f.handle.status(), MonitorStatus::Failed);
}

#[test]
fn poisoned_status_and_callback_admission_fail_closed_but_remove_every_token() {
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    let f = Fixture::new(move |_| {
        c.fetch_add(1, Ordering::SeqCst);
    });
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _g = f.handle.shared.state.lock().unwrap();
        panic!("fixed poison");
    }));
    callback_boundary(&f.handle.shared, SessionEvent::SystemWillSleep);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(f.handle.status(), MonitorStatus::Failed);
    assert_eq!(f.cleanup(), Err(MonitorError::Failed));
    assert_eq!(f.removed.lock().unwrap().len(), 7);
    assert!(!f.handle.is_removed());
}

#[test]
fn partial_remove_failure_keeps_the_slot_and_never_claims_retirement() {
    let f = Fixture::new(|_| {});
    f.fail.store(true, Ordering::SeqCst);
    assert_eq!(f.cleanup(), Err(MonitorError::Failed));
    assert_eq!(*f.removed.lock().unwrap(), vec![0, 1, 2]);
    assert!(!f.handle.is_removed());
    assert!(!f.handle.is_live());
    f.fail.store(false, Ordering::SeqCst);
    assert_eq!(f.cleanup(), Err(MonitorError::Failed));
    assert_eq!(*f.removed.lock().unwrap(), (0..7).collect::<Vec<_>>());
    assert!(!f.handle.is_removed());
}

#[test]
fn registration_callbacks_run_outside_tls_and_cannot_reenter_install() {
    let removed = Arc::new(Mutex::new(Vec::new()));
    let r = Arc::clone(&removed);
    let handle = start_inner(
        Arc::new(|_| {
            assert!(SLOT.with(|slot| slot.try_borrow_mut().is_ok()));
            assert!(matches!(
                start_inner(Arc::new(|_| {}), |_| unreachable!()),
                Err(MonitorError::Busy)
            ));
        }),
        |shared| {
            callback_boundary(&shared, SessionEvent::SystemWillSleep);
            Box::new(FakeOwner {
                remaining: (0..7).collect(),
                removed: r,
                fail: Arc::new(AtomicBool::new(false)),
            })
        },
    )
    .unwrap();
    assert!(handle.is_live());
    cleanup_inner(&handle.shared).unwrap();
}

#[test]
fn startup_callback_failure_removes_tokens_and_does_not_publish_a_handle() {
    let removed = Arc::new(Mutex::new(Vec::new()));
    let r = Arc::clone(&removed);
    let result = start_inner(
        Arc::new(|_| panic!("fixed startup callback panic")),
        |shared| {
            callback_boundary(&shared, SessionEvent::SystemWillSleep);
            Box::new(FakeOwner {
                remaining: (0..7).collect(),
                removed: r,
                fail: Arc::new(AtomicBool::new(false)),
            })
        },
    );
    assert!(matches!(result, Err(MonitorError::Failed)));
    assert_eq!(removed.lock().unwrap().len(), 7);
    SLOT.with(|slot| {
        slot.borrow_mut().take();
    });
}

#[cfg(target_os = "macos")]
#[test]
fn wrong_thread_rejects_before_native_app_or_observer_calls() {
    std::thread::spawn(|| {
        assert!(matches!(start(|_| {}), Err(MonitorError::WrongThread)));
        assert_eq!(current_app_is_active(), Err(MonitorError::WrongThread));
    })
    .join()
    .unwrap();
}
