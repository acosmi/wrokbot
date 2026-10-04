//! Application seams only. Synthetic guards/leases do not prove physical IO or real hosts.
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::*;

use super::*;
use crate::fakes::FakeChannelReader;
use crate::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, OpenBotApplication,
};

struct Guard;
impl HostRequestBindingGuard for Guard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn bound() -> (RequestBindingOwnerLease, AuthContext) {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new("app-lifecycle"),
        TenantId::new("app-lifecycle"),
        ActorId::new("app-lifecycle"),
        AuthGeneration::new(0),
        false,
    )
    .with_role(Role::User)
    .build();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "synthetic-lifecycle-session".into(),
        auth.actor().clone(),
        "synthetic-test-column".into(),
        time::OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(Guard))
        .unwrap();
    (owner, auth.with_verified_request_binding(binding).unwrap())
}
struct Target;
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
        Ok(())
    }
}
struct Tail(bool);
impl ArtifactReadTailWitness for Tail {
    fn verify_current(&self, _: &AuthContext, _: Instant) -> Result<(), ArtifactReadCurrentError> {
        if self.0 {
            Ok(())
        } else {
            Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))
        }
    }
}
struct Lease {
    closed: Arc<AtomicBool>,
    handed: AtomicBool,
    eof: bool,
}
impl ArtifactReadAllocationLease for Lease {
    fn mark_handed_off(&self) -> Result<(), ArtifactReadCurrentError> {
        self.handed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.handed.load(Ordering::SeqCst) || self.eof {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
}
#[derive(Clone, Copy)]
enum Mode {
    FailedTail,
    Pending,
    Await,
    Eof,
}
struct Port {
    mode: Mode,
    closed: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl ArtifactReadOperation for Port {
    async fn next_block(
        &mut self,
        auth: &AuthContext,
    ) -> Result<CurrentArtifactReadBlock, AppError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(artifacts_unavailable());
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, Mode::Await) {
            pending::<()>().await;
        }
        let mut allocation = PendingArtifactReadBuffer::new_initialized().unwrap();
        allocation.initialized_mut().fill(0xa5);
        allocation.initialized_mut()[0] = b'x';
        let eof = matches!(self.mode, Mode::Eof);
        allocation.record_actual_length(usize::from(!eof)).unwrap();
        CurrentArtifactReadBlock::from_trusted_observation(
            allocation,
            auth.clone(),
            Arc::new(Target),
            Box::new(Tail(!matches!(self.mode, Mode::FailedTail))),
            Instant::now() + Duration::from_secs(5),
            Box::new(Lease {
                closed: self.closed.clone(),
                handed: AtomicBool::new(false),
                eof,
            }),
        )
    }
    fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}
fn operation(
    auth: AuthContext,
    mode: Mode,
) -> (
    CurrentArtifactReadOperation,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
) {
    let closed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let port = Port {
        mode,
        closed: closed.clone(),
        calls: calls.clone(),
    };
    (
        CurrentArtifactReadOperation::from_trusted_operation(auth, Box::new(port)).unwrap(),
        closed,
        calls,
    )
}
struct DefaultAdministration;
#[async_trait]
impl ArtifactAdministration for DefaultAdministration {
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        Err(ArtifactAdministrationError::Unavailable)
    }
}

#[tokio::test]
async fn pending_failure_or_drop_permanently_closes_original_operation() {
    let (_owner, auth) = bound();
    // Fact 1: existing unimplemented/default administration remains the closed static503.
    let app = OpenBotApplication::new(FakeChannelReader::empty())
        .with_artifacts(Arc::new(DefaultAdministration));
    assert!(matches!(
        app.open_current_artifact_read(auth.clone(), Target.lookup_id().into())
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts"
        })
    ));
    // Fact 2: same six auth fields on a replacement issuer do not replace the original binding.
    let (_replacement_owner, replacement) = bound();
    assert_eq!(auth, replacement);
    let (mut op, closed, calls) = operation(auth.clone(), Mode::Pending);
    assert!(matches!(
        op.next_block(&replacement).await,
        Err(AppError::Unauthenticated)
    ));
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Fact 3: an accepted pending-construction tail failure permanently closes its producer.
    let (mut op, closed, calls) = operation(auth.clone(), Mode::FailedTail);
    assert!(matches!(
        op.next_block(&auth).await,
        Err(AppError::Unauthenticated)
    ));
    assert!(closed.load(Ordering::SeqCst));
    assert!(op.next_block(&auth).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Fact 4: dropping an unhanded pending block destroys its lease and closes the producer.
    let (mut op, closed, calls) = operation(auth.clone(), Mode::Pending);
    drop(op.next_block(&auth).await.unwrap());
    assert!(closed.load(Ordering::SeqCst));
    assert!(op.next_block(&auth).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Fact 5: cancellation polls the actual application operation before dropping its waiter.
    let (mut op, closed, calls) = operation(auth.clone(), Mode::Await);
    let mut waiter = Box::pin(op.next_block(&auth));
    assert!(matches!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(waiter);
    assert!(closed.load(Ordering::SeqCst));
    assert!(op.next_block(&auth).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Fact 6: verified zero EOF handoff ends the original producer and cannot reopen it.
    let (mut op, closed, calls) = operation(auth.clone(), Mode::Eof);
    assert!(
        op.next_block(&auth)
            .await
            .unwrap()
            .handoff(&auth)
            .unwrap()
            .is_none()
    );
    assert!(closed.load(Ordering::SeqCst));
    assert!(op.next_block(&auth).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
