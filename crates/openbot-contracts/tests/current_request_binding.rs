//! R425 carrier-only semantics. These trusted test guards are synthetic: no session, native
//! window, Local installation, PostgreSQL authority or product acceptance is proved here.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingIdentity,
    HostRequestBindingKind, RequestBindingAttachError, RequestBindingIssuer,
    RequestBindingOwnerLease, ServerSessionBindingIdentity, VerifiedHostRequestBinding,
};
use time::OffsetDateTime;

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match poll_once(future.as_mut()) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("carrier-only fixture unexpectedly awaited an external event"),
    }
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("carrier-deployment"),
        TenantId::new("carrier-tenant"),
        ActorId::new("carrier-actor"),
        AuthGeneration::new(7),
        false,
    )
    .with_role(Role::User)
    .build()
}

struct CountingGuard(Arc<AtomicUsize>);
impl HostRequestBindingGuard for CountingGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn session_key(id: &str, token: &str, created: OffsetDateTime) -> ServerSessionBindingIdentity {
    ServerSessionBindingIdentity::from_verified_row(
        id.to_owned(),
        auth().actor().clone(),
        token.to_owned(),
        created,
        auth().auth_generation(),
    )
}

fn bind(
    issuer: &RequestBindingIssuer,
    key: ServerSessionBindingIdentity,
    calls: Arc<AtomicUsize>,
) -> VerifiedHostRequestBinding {
    issuer
        .bind_server_session(&auth(), key, Arc::new(CountingGuard(calls)))
        .unwrap()
}

#[test]
fn repeated_same_epoch_uses_exact_owner_identity_and_auth_eq_keeps_original_six_facts() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let key = session_key(
        "private-row-a",
        "private-token-column-a",
        OffsetDateTime::UNIX_EPOCH,
    );
    let first = bind(&issuer, key.clone(), Arc::clone(&calls));
    let repeated = bind(&issuer, key, Arc::clone(&calls));
    assert!(first.identity().same_binding(repeated.identity()));
    let (_other_lease, other_issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let foreign = bind(
        &other_issuer,
        session_key(
            "private-row-a",
            "private-token-column-a",
            OffsetDateTime::UNIX_EPOCH,
        ),
        Arc::clone(&calls),
    );
    assert!(!first.identity().same_binding(foreign.identity()));
    let first_auth = auth().with_verified_request_binding(first).unwrap();
    let other_auth = auth().with_verified_request_binding(foreign).unwrap();
    assert_eq!(first_auth, other_auth);
    assert_eq!(first_auth, auth());
    let clone = first_auth.clone();
    assert!(
        first_auth
            .request_binding()
            .unwrap()
            .identity()
            .same_binding(clone.request_binding().unwrap().identity())
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "comparison must not imply a current guard ran"
    );
}

#[test]
fn each_session_epoch_component_is_distinct_even_when_original_auth_is_equal() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let original = bind(
        &issuer,
        session_key("row-a", "hash-a", OffsetDateTime::UNIX_EPOCH),
        Arc::clone(&calls),
    );
    for key in [
        session_key("row-b", "hash-a", OffsetDateTime::UNIX_EPOCH),
        session_key("row-a", "hash-b", OffsetDateTime::UNIX_EPOCH),
        session_key(
            "row-a",
            "hash-a",
            OffsetDateTime::UNIX_EPOCH + time::Duration::milliseconds(1),
        ),
    ] {
        let different = bind(&issuer, key, Arc::clone(&calls));
        assert!(!original.identity().same_binding(different.identity()));
    }
}

#[test]
fn consuming_attachment_checks_each_original_fact_after_builder_completion() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let binding = bind(
        &issuer,
        session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
        Arc::new(AtomicUsize::new(0)),
    );
    for index in 0..6 {
        let changed = AuthContextBuilder::from_verified_session(
            DeploymentId::new(if index == 0 {
                "changed"
            } else {
                "carrier-deployment"
            }),
            TenantId::new(if index == 1 {
                "changed"
            } else {
                "carrier-tenant"
            }),
            ActorId::new(if index == 2 {
                "changed"
            } else {
                "carrier-actor"
            }),
            AuthGeneration::new(if index == 3 { 8 } else { 7 }),
            index == 4,
        )
        .with_role(if index == 5 { Role::Admin } else { Role::User })
        .build();
        assert_eq!(
            changed
                .with_verified_request_binding(binding.clone())
                .unwrap_err(),
            RequestBindingAttachError::IdentityMismatch
        );
    }
}

#[test]
fn identity_and_debug_do_not_replace_an_actual_guard_call_or_leak_epoch_fields() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let key = session_key(
        "ROW_SECRET_CANARY",
        "HASH_SECRET_CANARY",
        OffsetDateTime::UNIX_EPOCH,
    );
    let binding = bind(&issuer, key.clone(), Arc::clone(&calls));
    let attached = auth()
        .with_verified_request_binding(binding.clone())
        .unwrap();
    for _ in 0..2 {
        assert_eq!(ready(binding.verify_current(&attached)), Ok(()));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let debug = format!(
        "{attached:?} {binding:?} {:?} {issuer:?} {lease:?} {key:?}",
        binding.identity()
    );
    assert!(!debug.contains("ROW_SECRET_CANARY"));
    assert!(!debug.contains("HASH_SECRET_CANARY"));
    lease.close();
    assert!(binding.identity().same_binding(binding.clone().identity()));
    assert_eq!(
        ready(binding.verify_current(&attached)),
        Err(HostRequestBindingError::NotCurrent)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn dropping_proof_or_issuer_clones_does_not_close_the_real_lease_but_lease_drop_does() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let observation = issuer.observation();
    let binding = bind(
        &issuer,
        session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
        Arc::new(AtomicUsize::new(0)),
    );
    drop(binding.clone());
    drop(issuer.clone());
    let attached = auth()
        .with_verified_request_binding(binding.clone())
        .unwrap();
    assert!(observation.is_current());
    assert_eq!(ready(binding.verify_current(&attached)), Ok(()));
    drop(lease);
    assert!(!observation.is_current());
    assert_eq!(
        ready(binding.verify_current(&attached)),
        Err(HostRequestBindingError::NotCurrent)
    );
    assert_eq!(
        issuer
            .bind_server_session(
                &auth(),
                session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
                Arc::new(CountingGuard(Arc::new(AtomicUsize::new(0))))
            )
            .unwrap_err(),
        RequestBindingAttachError::NotCurrent
    );
}

struct SuspendedGuard {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}
impl HostRequestBindingGuard for SuspendedGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::SeqCst);
            poll_fn(|_| {
                if self.release.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            Ok(())
        })
    }
}

#[test]
fn lease_drop_during_pending_guard_withholds_its_later_success_and_new_owner_cannot_revive_it() {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let binding = issuer
        .bind_server_session(
            &auth(),
            session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
            Arc::new(SuspendedGuard {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        )
        .unwrap();
    let attached = auth()
        .with_verified_request_binding(binding.clone())
        .unwrap();
    let mut current = Box::pin(binding.verify_current(&attached));
    assert!(poll_once(current.as_mut()).is_pending());
    assert!(entered.load(Ordering::SeqCst));
    drop(lease);
    let (_new_lease, new_issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let new = bind(
        &new_issuer,
        session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
        Arc::new(AtomicUsize::new(0)),
    );
    assert!(!binding.identity().same_binding(new.identity()));
    release.store(true, Ordering::SeqCst);
    assert_eq!(
        poll_once(current.as_mut()),
        Poll::Ready(Err(HostRequestBindingError::NotCurrent))
    );
    let new_auth = auth().with_verified_request_binding(new.clone()).unwrap();
    assert_eq!(ready(new.verify_current(&new_auth)), Ok(()));
}

#[test]
fn verifying_a_proof_requires_that_same_proof_on_the_supplied_context() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let first = bind(
        &issuer,
        session_key("row-a", "hash-a", OffsetDateTime::UNIX_EPOCH),
        Arc::clone(&calls),
    );
    let second = bind(
        &issuer,
        session_key("row-b", "hash-b", OffsetDateTime::UNIX_EPOCH),
        Arc::clone(&calls),
    );
    let other_auth = auth().with_verified_request_binding(second).unwrap();
    assert_eq!(
        ready(first.verify_current(&auth())),
        Err(HostRequestBindingError::NotCurrent)
    );
    assert_eq!(
        ready(first.verify_current(&other_auth)),
        Err(HostRequestBindingError::NotCurrent)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn closed_owner_kinds_and_invalid_window_epochs_are_refused() {
    let (_lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
    let guard: Arc<dyn HostRequestBindingGuard> =
        Arc::new(CountingGuard(Arc::new(AtomicUsize::new(0))));
    assert_eq!(
        issuer
            .bind_server_session(
                &auth(),
                session_key("row", "hash", OffsetDateTime::UNIX_EPOCH),
                Arc::clone(&guard)
            )
            .unwrap_err(),
        RequestBindingAttachError::WrongOwnerKind
    );
    for (label, id) in [("window", 0), ("", 1)] {
        assert_eq!(
            issuer
                .bind_desktop_window(&auth(), label.to_owned(), id, Arc::clone(&guard))
                .unwrap_err(),
            RequestBindingAttachError::InvalidEpoch
        );
    }
    let (_other_lease, other) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
    let first = issuer
        .bind_desktop_window(&auth(), "window".to_owned(), 1, Arc::clone(&guard))
        .unwrap();
    let second = other
        .bind_desktop_window(&auth(), "window".to_owned(), 1, guard)
        .unwrap();
    assert!(!first.identity().same_binding(second.identity()));
}

#[test]
fn binding_carriers_remain_nonserde_and_the_unique_lease_is_not_clone() {
    trait AmbiguousSerialize<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousSerialize<()> for T {}
    impl<T: ?Sized + serde::Serialize> AmbiguousSerialize<u8> for T {}
    let _ = <AuthContext as AmbiguousSerialize<_>>::item;
    let _ = <VerifiedHostRequestBinding as AmbiguousSerialize<_>>::item;
    let _ = <HostRequestBindingIdentity as AmbiguousSerialize<_>>::item;
    trait AmbiguousDeserialize<A> {
        fn item() {}
    }
    impl<T> AmbiguousDeserialize<()> for T {}
    impl<T: serde::de::DeserializeOwned> AmbiguousDeserialize<u8> for T {}
    let _ = <AuthContext as AmbiguousDeserialize<_>>::item;
    let _ = <VerifiedHostRequestBinding as AmbiguousDeserialize<_>>::item;
    trait AmbiguousClone<A> {
        fn item() {}
    }
    impl<T> AmbiguousClone<()> for T {}
    impl<T: Clone> AmbiguousClone<u8> for T {}
    let _ = <RequestBindingOwnerLease as AmbiguousClone<_>>::item;
}
