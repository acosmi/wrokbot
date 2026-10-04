//! Controlled contract seams only; genuine Session and Local producers have separate PG cases.
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{GetSourceRunArtifactIds, SourceRunArtifactIds};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::request_binding::*;
use time::OffsetDateTime;

use super::*;

const ID: &str = "019a0000-0000-7000-8000-000000000010";
fn selector() -> GetSourceRunArtifactIds {
    GetSourceRunArtifactIds { source_thread_id: ThreadId::new("source/thread%成果"), source_run_id: RunId::new("source/run ") }
}
fn plain() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("source-ids-contract"), TenantId::new("source-ids-tenant"),
        ActorId::new("source-ids-user"), AuthGeneration::new(0), false,
    ).with_role(Role::User).build()
}
struct DefaultGuard(Arc<AtomicUsize>);
impl HostRequestBindingGuard for DefaultGuard {
    fn verify_current<'a>(&'a self, _: &'a AuthContext) -> Pin<Box<dyn Future<Output=Result<(), HostRequestBindingError>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}
fn bound() -> (Arc<RequestBindingOwnerLease>, AuthContext, Arc<AtomicUsize>) {
    let (lease, issuer) = RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = plain();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "controlled-original-session".into(), auth.actor().clone(), "controlled-column".into(),
        OffsetDateTime::UNIX_EPOCH, auth.auth_generation(),
    );
    let binding = issuer.bind_server_session(&auth, epoch, Arc::new(DefaultGuard(calls.clone()))).unwrap();
    (Arc::new(lease), auth.with_verified_request_binding(binding).unwrap(), calls)
}
struct Tail {
    auth: AuthContext,
    calls: Arc<AtomicUsize>,
    deadline: Instant,
}
impl ArtifactReadTailWitness for Tail {
    fn verify_current(&self, auth: &AuthContext, deadline: Instant) -> Result<(), ArtifactReadCurrentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(deadline, self.deadline);
        if !auth.request_binding().zip(self.auth.request_binding())
            .is_some_and(|(a,b)| a.identity().same_binding(b.identity()))
        { return Err(ArtifactReadCurrentError::Host(HostRequestBindingError::NotCurrent)); }
        Ok(())
    }
}
struct Port {
    result: Result<SourceRunArtifactIds, ArtifactReadCurrentError>,
    witness_auth: AuthContext,
    close: Option<Arc<RequestBindingOwnerLease>>,
    calls: AtomicUsize,
    tail_calls: Arc<AtomicUsize>,
    observed: Mutex<Option<Instant>>,
}
#[async_trait]
impl ArtifactAdministration for Port {
    async fn observe_source_run_artifact_ids_current(&self, _: &AuthContext, input: &GetSourceRunArtifactIds, deadline: Instant) -> SourceRunArtifactIdsCurrentOutcome {
        assert_eq!(input, &selector());
        assert!(deadline > Instant::now() && deadline <= Instant::now()+Duration::from_secs(5));
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.observed.lock().unwrap() = Some(deadline);
        if let Some(owner) = &self.close { owner.close(); }
        Ok((Box::new(Tail { auth: self.witness_auth.clone(), calls: self.tail_calls.clone(), deadline }), self.result.clone()))
    }
    async fn save_run_message_text(&self, _: &AuthContext, _: SaveRunMessageTextArtifact) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        panic!("IDs-only consumer must not save or fallback")
    }
    async fn get_metadata(&self, _: &AuthContext, _: &str) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        panic!("IDs-only consumer must not call005 or enumerate metadata")
    }
}
fn port(auth: AuthContext, result: Result<SourceRunArtifactIds, ArtifactReadCurrentError>) -> Port {
    Port { result, witness_auth: auth, close: None, calls: AtomicUsize::new(0), tail_calls: Arc::new(AtomicUsize::new(0)), observed: Mutex::new(None) }
}
fn ids(values: Vec<String>) -> SourceRunArtifactIds {
    SourceRunArtifactIds { source_thread_id: selector().source_thread_id, source_run_id: selector().source_run_id, artifact_ids: values }
}
struct DefaultTarget;
impl SourceRunArtifactIdsCurrentTarget for DefaultTarget {
    fn source_thread_id(&self) -> &str { "source/thread%成果" }
    fn source_run_id(&self) -> &str { "source/run " }
    fn matches_authority(&self, _: &Arc<()>) -> bool { true }
    fn matches_auth(&self, _: &AuthContext) -> bool { true }
}

#[tokio::test]
async fn source_run_joint_outcome_handoff_is_host_first_and_default_closed() {
    let (_owner, auth, old_calls) = bound();
    let p = port(auth.clone(), Ok(ids(vec![ID.into()])));
    assert_eq!(get_source_run_artifact_ids(&p, &plain(), selector()).await.err(), Some(AppError::DependencyUnavailable { dependency:"host_request_binding" }));
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    for (thread, run, field) in [("", "ok", "sourceThreadId"), ("ok", "\u{85}", "sourceRunId"), ("ok", &"é".repeat(257), "sourceRunId")] {
        assert_eq!(get_source_run_artifact_ids(&p, &auth, GetSourceRunArtifactIds { source_thread_id:ThreadId::new(thread), source_run_id:RunId::new(run) }).await.err(), Some(AppError::MalformedPayload{field}));
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    assert_eq!(get_source_run_artifact_ids(&NoArtifactAdministration, &auth, selector()).await.err(), Some(AppError::DependencyUnavailable { dependency:"artifacts" }));
    assert_eq!(auth.request_binding().unwrap().verify_source_run_artifact_ids_current_before(&auth, &DefaultTarget, Instant::now()+Duration::from_secs(5)).await.err(), Some(ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable)));
    assert_eq!(old_calls.load(Ordering::SeqCst), 0);
    for result in [Ok(ids(Vec::new())), Ok(ids(vec![ID.into()])), Err(ArtifactReadCurrentError::NotVisible), Err(ArtifactReadCurrentError::Unavailable)] {
        let p = port(auth.clone(), result.clone());
        let actual = get_source_run_artifact_ids(&p, &auth, selector()).await;
        assert_eq!(actual, result.map_err(current_read_error));
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
        assert!(p.observed.lock().unwrap().is_some());
    }
    for status in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
        let p = port(auth.clone(), Err(ArtifactReadCurrentError::Gone(status)));
        assert_eq!(get_source_run_artifact_ids(&p, &auth, selector()).await.err(), Some(AppError::DependencyUnavailable { dependency:"artifacts" }));
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
    }
    let mut mismatch = ids(vec![ID.into()]); mismatch.source_run_id = RunId::new("other");
    let mut mismatch_thread = ids(vec![ID.into()]); mismatch_thread.source_thread_id = ThreadId::new("other");
    for bad in [mismatch, mismatch_thread, ids(vec![ID.into(), ID.into()]), ids(vec![ID.into();33]), ids(vec![ID.to_uppercase()]), ids(vec!["019a0000-0000-7000-8000-000000000011".into(), ID.into()]), ids(vec!["not-an-id".into()])] {
        let p = port(auth.clone(), Ok(bad));
        assert_eq!(get_source_run_artifact_ids(&p, &auth, selector()).await.err(), Some(AppError::DependencyUnavailable { dependency:"artifacts" }));
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
    }
    let (_foreign_owner, foreign, _) = bound();
    let p = port(foreign, Ok(ids(vec![ID.into()])));
    assert_eq!(get_source_run_artifact_ids(&p, &auth, selector()).await.err(), Some(AppError::Unauthenticated));
    for result in [Ok(ids(vec![ID.into()])), Err(ArtifactReadCurrentError::NotVisible), Err(ArtifactReadCurrentError::Unavailable)] {
        let (owner, current, _) = bound();
        let mut p = port(current.clone(), result); p.close = Some(owner);
        assert_eq!(get_source_run_artifact_ids(&p, &current, selector()).await.err(), Some(AppError::Unauthenticated));
    }
}
