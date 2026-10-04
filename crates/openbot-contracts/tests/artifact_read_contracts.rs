//! Contract seams only: these synthetic guards/targets are not live host acceptance.
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use openbot_contracts::artifact_read::PendingArtifactReadBuffer;
use openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::*;
use time::OffsetDateTime;

fn plain(role: Role) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("read-contract-deployment"),
        TenantId::new("read-contract-tenant"),
        ActorId::new("read-contract-actor"),
        AuthGeneration::new(0),
        false,
    )
    .with_role(role)
    .build()
}
fn bound(
    issuer: &RequestBindingIssuer,
    guard: Arc<dyn HostRequestBindingGuard>,
    role: Role,
) -> AuthContext {
    let auth = plain(role);
    let key = ServerSessionBindingIdentity::from_verified_row(
        "read-contract-session".to_owned(),
        auth.actor().clone(),
        "synthetic-test-column".to_owned(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    auth.clone()
        .with_verified_request_binding(
            issuer
                .bind_server_session(&auth, key, guard)
                .expect("contract epoch"),
        )
        .expect("contract attachment")
}
struct Target {
    physical: AtomicBool,
}
impl ArtifactReadCurrentTarget for Target {
    fn lookup_id(&self) -> &str {
        "01900000-0000-7000-8000-000000000001"
    }
    fn matches_authority(&self, _: &Arc<()>) -> bool {
        true
    }
    fn matches_auth(&self, _: &AuthContext) -> bool {
        true
    }
    fn matches_current_record(&self, _: ArtifactReadRecordFacts<'_>) -> bool {
        true
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        if self.physical.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ArtifactReadCurrentError::Unavailable)
        }
    }
}
struct Tail(AtomicBool);
impl ArtifactReadTailWitness for Tail {
    fn verify_current(&self, _: &AuthContext, _: Instant) -> Result<(), ArtifactReadCurrentError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))
        }
    }
}
struct Guard {
    calls: Arc<AtomicUsize>,
    gate: Option<Arc<AtomicBool>>,
}
impl HostRequestBindingGuard for Guard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        _: &'a AuthContext,
        _: &'a dyn ArtifactReadCurrentTarget,
        _: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                poll_fn(|_| {
                    if gate.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                return Err(ArtifactReadCurrentError::NotVisible);
            }
            Ok(Box::new(Tail(AtomicBool::new(true))) as Box<dyn ArtifactReadTailWitness>)
        })
    }
}
struct Legacy;
impl HostRequestBindingGuard for Legacy {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn fixture() -> (RequestBindingOwnerLease, AuthContext, Target, Tail) {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = bound(
        &issuer,
        Arc::new(Guard {
            calls: Arc::new(AtomicUsize::new(0)),
            gate: None,
        }),
        Role::User,
    );
    (
        lease,
        auth,
        Target {
            physical: AtomicBool::new(true),
        },
        Tail(AtomicBool::new(true)),
    )
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("contract seam unexpectedly awaited"),
    }
}

#[test]
fn pending_full_initialization_and_whole_wipe() {
    let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
    assert_eq!(
        pending.initialized_mut().len(),
        MAX_ARTIFACT_READ_CHUNK_BYTES
    );
    assert!(pending.initialized_mut().iter().all(|byte| *byte == 0));
    pending.initialized_mut().fill(0xa5);
    pending.record_actual_length(3).unwrap();
    pending.wipe();
    assert!(pending.initialized_mut().iter().all(|byte| *byte == 0));
    assert_eq!(pending.actual_length(), None);
    assert!(pending.record_actual_length(3).is_err());
}

#[test]
fn pending_repeated_or_oversized_actual_length_wipes() {
    for repeated in [false, true] {
        let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
        pending.initialized_mut().fill(0xa5);
        if repeated {
            pending.record_actual_length(1).unwrap();
        }
        assert!(
            pending
                .record_actual_length(if repeated {
                    1
                } else {
                    MAX_ARTIFACT_READ_CHUNK_BYTES + 1
                })
                .is_err()
        );
        assert_eq!(pending.actual_length(), None);
        assert!(pending.initialized_mut().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn pending_handoff_suffix_cleared_and_only_actual_bytes() {
    let (_lease, auth, target, tail) = fixture();
    let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
    pending.initialized_mut().fill(0xa5);
    pending.initialized_mut()[..3].copy_from_slice(b"abc");
    pending.record_actual_length(3).unwrap();
    let original = auth.request_binding().unwrap();
    assert_eq!(
        pending
            .handoff(&auth, original, &target, &tail, deadline())
            .unwrap(),
        b"abc"
    );
    // The returned Vec's capacity is not read outside its initialized len. Internal suffix
    // clearing and Zeroizing Drop are verified by source; no freed-memory reading occurs.
}

#[test]
fn pending_handoff_rejects_owner_drop() {
    let (lease, auth, target, tail) = fixture();
    let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
    pending.initialized_mut()[0] = 0xa5;
    pending.record_actual_length(1).unwrap();
    drop(lease);
    assert_eq!(
        pending
            .handoff(
                &auth,
                auth.request_binding().unwrap(),
                &target,
                &tail,
                deadline()
            )
            .err(),
        Some(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent
        ))
    );
}

#[test]
fn pending_handoff_rejects_changed_physical_or_tail() {
    for physical in [false, true] {
        let (_lease, auth, target, tail) = fixture();
        target.physical.store(physical, Ordering::SeqCst);
        tail.0.store(false, Ordering::SeqCst);
        let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
        pending.record_actual_length(0).unwrap();
        let error = pending
            .handoff(
                &auth,
                auth.request_binding().unwrap(),
                &target,
                &tail,
                deadline(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error,
            if physical {
                ArtifactReadCurrentError::Host(HostRequestBindingError::NotCurrent)
            } else {
                ArtifactReadCurrentError::Unavailable
            }
        );
    }
}

#[test]
fn joint_default_guard_is_unavailable() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = bound(&issuer, Arc::new(Legacy), Role::User);
    let target = Target {
        physical: AtomicBool::new(true),
    };
    assert!(matches!(
        ready(
            auth.request_binding()
                .unwrap()
                .verify_artifact_read_current_before(&auth, &target, deadline())
        ),
        Err(ArtifactReadCurrentError::Host(
            HostRequestBindingError::Unavailable
        ))
    ));
}

#[test]
fn joint_foreign_binding_and_six_facts_zero_guard() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let a = bound(
        &issuer,
        Arc::new(Guard {
            calls: Arc::clone(&calls),
            gate: None,
        }),
        Role::User,
    );
    let (_other_lease, other_issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let b = bound(&other_issuer, Arc::new(Legacy), Role::User);
    let other_role = bound(&issuer, Arc::new(Legacy), Role::Admin);
    let target = Target {
        physical: AtomicBool::new(true),
    };
    for changed in [&b, &other_role] {
        assert!(matches!(
            ready(
                a.request_binding()
                    .unwrap()
                    .verify_artifact_read_current_before(changed, &target, deadline())
            ),
            Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent
            ))
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn joint_owner_close_during_await_wins_source_error() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(AtomicBool::new(false));
    let auth = bound(
        &issuer,
        Arc::new(Guard {
            calls: Arc::clone(&calls),
            gate: Some(Arc::clone(&gate)),
        }),
        Role::User,
    );
    let original = auth.request_binding().unwrap().clone();
    let target = Target {
        physical: AtomicBool::new(true),
    };
    let mut future =
        Box::pin(original.verify_artifact_read_current_before(&auth, &target, deadline()));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    lease.close();
    gate.store(true, Ordering::SeqCst);
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent
        )))
    ));
}

#[test]
fn joint_original_deadline_is_not_extended() {
    let (_lease, auth, target, _) = fixture();
    assert!(matches!(
        ready(
            auth.request_binding()
                .unwrap()
                .verify_artifact_read_current_before(&auth, &target, Instant::now())
        ),
        Err(ArtifactReadCurrentError::Host(
            HostRequestBindingError::Unavailable
        ))
    ));
}
