//! Application contract seams; synthetic witnesses do not certify a live host consumer.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use openbot_contracts::artifact_read::PendingArtifactReadBuffer;
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::*;
use time::OffsetDateTime;

use super::*;
use crate::fakes::FakeChannelReader;
use crate::{ApplicationService, OpenBotApplication};

const ID: &str = "01900000-0000-7000-8000-000000000001";
fn plain(role: bool) -> AuthContext {
    let builder = AuthContextBuilder::from_verified_session(
        DeploymentId::new("app-read-deployment"),
        TenantId::new("app-read-tenant"),
        ActorId::new("app-read-user"),
        AuthGeneration::new(0),
        false,
    );
    if role {
        builder.with_role(Role::User).build()
    } else {
        builder.build()
    }
}
struct SyntheticGuard;
impl HostRequestBindingGuard for SyntheticGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn bound(role: bool) -> (RequestBindingOwnerLease, AuthContext) {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = plain(role);
    let key = ServerSessionBindingIdentity::from_verified_row(
        "app-read-original-session".into(),
        auth.actor().clone(),
        "synthetic-test-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, key, Arc::new(SyntheticGuard))
        .unwrap();
    (lease, auth.with_verified_request_binding(binding).unwrap())
}
#[derive(Default)]
struct CountingPort(AtomicUsize);
#[async_trait]
impl ArtifactAdministration for CountingPort {
    async fn read_host_bound_chunk(
        &self,
        _: &AuthContext,
        id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        assert_eq!(id, ID);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(AppError::NotVisible)
    }
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
struct SyntheticTarget;
impl ArtifactReadCurrentTarget for SyntheticTarget {
    fn lookup_id(&self) -> &str {
        ID
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
struct SyntheticTail;
impl ArtifactReadTailWitness for SyntheticTail {
    fn verify_current(&self, _: &AuthContext, _: Instant) -> Result<(), ArtifactReadCurrentError> {
        Ok(())
    }
}

#[tokio::test]
async fn application_invalid_selector_zero_read_port() {
    let (_lease, auth) = bound(true);
    let port = Arc::new(CountingPort::default());
    let app = OpenBotApplication::new(FakeChannelReader::empty()).with_artifacts(port.clone());
    assert!(matches!(
        app.read_current_artifact_chunk(auth, "../invalid".into())
            .await,
        Err(AppError::MalformedPayload {
            field: "artifactId"
        })
    ));
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn application_missing_binding_zero_read_port() {
    let port = Arc::new(CountingPort::default());
    let app = OpenBotApplication::new(FakeChannelReader::empty()).with_artifacts(port.clone());
    assert!(matches!(
        app.read_current_artifact_chunk(plain(true), ID.into())
            .await,
        Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding"
        })
    ));
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn application_bound_current_role_reaches_actual_read_port() {
    for role in [false, true] {
        let (_lease, auth) = bound(role);
        let port = Arc::new(CountingPort::default());
        let app = OpenBotApplication::new(FakeChannelReader::empty()).with_artifacts(port.clone());
        assert!(matches!(
            app.read_current_artifact_chunk(auth, ID.to_uppercase())
                .await,
            Err(AppError::NotVisible)
        ));
        assert_eq!(port.0.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn sealed_chunk_refuses_binding_swap_at_handoff() {
    let (_a_lease, a) = bound(true);
    let (_b_lease, b) = bound(true);
    assert_eq!(a, b);
    let mut pending = PendingArtifactReadBuffer::new_initialized().unwrap();
    pending.initialized_mut()[..3].copy_from_slice(b"abc");
    pending.record_actual_length(3).unwrap();
    let chunk = CurrentArtifactReadChunk::from_trusted_observation(
        pending,
        a,
        Arc::new(SyntheticTarget),
        Box::new(SyntheticTail),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(chunk.handoff(&b), Err(AppError::Unauthenticated)));
}
