//! Pure allocation seams. Synthetic host witnesses do not certify a real host or FD.
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES;
use crate::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use crate::ids::{ActorId, DeploymentId, TenantId};
use crate::request_binding::*;

use super::*;

struct Observation {
    address: usize,
    wiped: Arc<AtomicBool>,
}
thread_local! {
    static LIVE_OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}
pub(super) fn observe_live_wiped(bytes: &[u8]) {
    LIVE_OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow().as_ref()
            && bytes.as_ptr() as usize == observation.address
        {
            assert_eq!(bytes.len(), MAX_ARTIFACT_READ_CHUNK_BYTES);
            assert!(bytes.iter().all(|byte| *byte == 0));
            observation.wiped.store(true, Ordering::SeqCst);
        }
    });
}
struct Lease {
    wiped: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    handed: Arc<AtomicBool>,
}
impl ArtifactReadAllocationLease for Lease {
    fn mark_handed_off(&self) -> Result<(), ArtifactReadCurrentError> {
        self.handed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert!(
            self.wiped.load(Ordering::SeqCst),
            "lease release preceded the live full-allocation wipe"
        );
        self.released.store(true, Ordering::SeqCst);
    }
}
struct Guard;
impl HostRequestBindingGuard for Guard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
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
fn auth() -> (RequestBindingOwnerLease, AuthContext) {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new("lifecycle-contract"),
        TenantId::new("lifecycle-contract"),
        ActorId::new("lifecycle-contract"),
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
type LeaseFixture = (
    PendingArtifactReadBuffer,
    Box<dyn ArtifactReadAllocationLease>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
);
fn allocation() -> LeaseFixture {
    let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
    pending.initialized_mut().fill(0xa5);
    pending.initialized_mut()[..3].copy_from_slice(b"abc");
    pending.record_actual_length(3).unwrap();
    let wiped = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));
    let handed = Arc::new(AtomicBool::new(false));
    LIVE_OBSERVATION.with(|slot| {
        *slot.borrow_mut() = Some(Observation {
            address: pending.bytes.as_ptr() as usize,
            wiped: wiped.clone(),
        })
    });
    let lease = Box::new(Lease {
        wiped,
        released: released.clone(),
        handed: handed.clone(),
    });
    (pending, lease, released, handed)
}

#[test]
fn allocation_handoff_retains_full_initialized_owner_and_wipes_before_release() {
    let (_owner, auth) = auth();
    let original = auth.request_binding().unwrap();
    let deadline = || Instant::now() + Duration::from_secs(5);
    // Fact 1: the original full allocation survives the sole successful handoff.
    let (pending, lease, released, handed) = allocation();
    let original_address = pending.bytes.as_ptr();
    let block = pending
        .handoff_leased(&auth, original, &Target, &Tail(true), deadline(), lease)
        .unwrap();
    assert_eq!(block.as_bytes(), b"abc");
    assert_eq!(block.bytes.len(), MAX_ARTIFACT_READ_CHUNK_BYTES);
    assert_eq!(block.bytes.as_ptr(), original_address);
    assert!(block.bytes[3..].iter().all(|byte| *byte == 0));
    assert!(handed.load(Ordering::SeqCst));
    assert!(!released.load(Ordering::SeqCst));
    drop(block);
    assert!(released.load(Ordering::SeqCst));
    // Fact 2: a failing synchronous tail also wipes the complete original allocation first.
    let (pending, lease, released, handed) = allocation();
    assert!(
        pending
            .handoff_leased(&auth, original, &Target, &Tail(false), deadline(), lease)
            .is_err()
    );
    assert!(!handed.load(Ordering::SeqCst));
    assert!(released.load(Ordering::SeqCst));
    // Fact 3: direct destruction of the coupled RAII owner has the same ordering.
    let (mut pending, lease, released, handed) = allocation();
    let block = LeasedArtifactReadBlock {
        bytes: Zeroizing::new(std::mem::take(&mut *pending.bytes)),
        actual_length: 3,
        lease: Some(lease),
    };
    drop(block);
    assert!(released.load(Ordering::SeqCst));
    assert!(!handed.load(Ordering::SeqCst));
    LIVE_OBSERVATION.with(|slot| *slot.borrow_mut() = None);
}
