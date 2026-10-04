//! Real finite-inventory primitives; this component case does not claim artifact IO.
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::{Context, Poll, Waker};

use super::*;

#[tokio::test]
async fn close_between_admission_and_worker_entry_does_not_false_ack() {
    // Fact 1: an actual admitted blocking job remains inventory before its entry runs.
    let lifecycle = ArtifactReadLifecycle::new();
    let operation_stopped = AtomicBool::new(false);
    let permit = lifecycle.admit(&operation_stopped).unwrap();
    let (enter, entered) = std::sync::mpsc::channel();
    let actual_worker_lifecycle = lifecycle.clone();
    let did_work = Arc::new(AtomicBool::new(false));
    let actual_did_work = did_work.clone();
    let worker = tokio::task::spawn_blocking(move || {
        entered.recv().unwrap();
        if !actual_worker_lifecycle.closed.load(Ordering::SeqCst) {
            actual_did_work.store(true, Ordering::SeqCst);
        }
        drop(permit);
    });
    lifecycle.close();
    assert_eq!(lifecycle.jobs.load(Ordering::SeqCst), 1);
    assert!(matches!(
        lifecycle
            .drain_before(Instant::now() + Duration::from_millis(30))
            .await,
        Err(ArtifactReadDrainError::Elapsed)
    ));
    assert!(lifecycle.admit(&operation_stopped).is_err());
    enter.send(()).unwrap();
    worker.await.unwrap();
    assert!(!did_work.load(Ordering::SeqCst));
    assert_eq!(lifecycle.jobs.load(Ordering::SeqCst), 0);
    assert!(
        lifecycle
            .drain_before(Instant::now() + Duration::from_secs(1))
            .await
            .is_ok()
    );
    // Fact 2: poisoning the actual inventory mutex cannot mint a drain ACK.
    let poisoned = ArtifactReadLifecycle::new();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _guard = poisoned.gate.lock().unwrap();
            panic!("owned finite-inventory poison fixture");
        }))
        .is_err()
    );
    poisoned.close();
    assert!(matches!(
        poisoned
            .drain_before(Instant::now() + Duration::from_secs(1))
            .await,
        Err(ArtifactReadDrainError::Unavailable)
    ));
    assert!(poisoned.admit(&operation_stopped).is_err());
    // Fact 3: a short, actual gate collision is pending, never an empty-inventory proof.
    let contended = ArtifactReadLifecycle::new();
    contended.close();
    let mut waiter = Box::pin(contended.drain_before(Instant::now() + Duration::from_secs(1)));
    {
        let _guard = contended.gate.lock().unwrap();
        assert!(matches!(
            waiter
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    assert!(waiter.await.is_ok());
}
