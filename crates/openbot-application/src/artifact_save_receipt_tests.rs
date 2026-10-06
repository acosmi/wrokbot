//! Core port tests only. These manually minted attachments are not genuine host acceptance.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactMetadata, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::request_binding::*;
use time::OffsetDateTime;

use super::*;
use crate::{ArtifactAdministrationError, NoArtifactAdministration};

const REQUEST: &str = "019a7777-abcd-7abc-8abc-0123456789ab";
fn input() -> GetArtifactSaveReceipt {
    GetArtifactSaveReceipt {
        request_id: REQUEST.into(),
    }
}
fn plain() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("receipt-core"),
        TenantId::new("receipt-tenant"),
        ActorId::new("receipt-owner"),
        AuthGeneration::new(0),
        false,
    )
    .with_role(Role::User)
    .build()
}
struct Legacy;
impl HostRequestBindingGuard for Legacy {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        panic!("receipt consumer must not substitute old current guard")
    }
}
fn bound() -> (Arc<RequestBindingOwnerLease>, AuthContext) {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = plain();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "receipt-core-session".into(),
        auth.actor().clone(),
        "receipt-core-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(Legacy))
        .unwrap();
    (
        Arc::new(owner),
        auth.with_verified_request_binding(binding).unwrap(),
    )
}
fn receipt() -> ArtifactRegistrationReceipt {
    ArtifactRegistrationReceipt {
        operation_id: "019a7778-abcd-7abc-8abc-0123456789ab".into(),
        artifact_id: "019a7779-abcd-7abc-8abc-0123456789ab".into(),
        request_id: REQUEST.into(),
        owner_actor_id: plain().actor().clone(),
        source_thread_id: ThreadId::new("source/thread%成果"),
        source_run_id: RunId::new(" source/run "),
        source_message_id: "source-message/成果".into(),
        source_call_seq: None,
        source_attempt_seq: None,
    }
}
struct Tail {
    auth: AuthContext,
    deadline: Instant,
    calls: Arc<AtomicUsize>,
}
impl ArtifactReadTailWitness for Tail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(deadline, self.deadline);
        if !auth
            .request_binding()
            .zip(self.auth.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        Ok(())
    }
}
struct Port {
    result: Result<ArtifactRegistrationReceipt, ArtifactReadCurrentError>,
    witness_auth: AuthContext,
    close: Option<Arc<RequestBindingOwnerLease>>,
    calls: AtomicUsize,
    tail_calls: Arc<AtomicUsize>,
    observed_deadline: Mutex<Option<Instant>>,
}
#[async_trait]
impl ArtifactAdministration for Port {
    async fn observe_artifact_save_receipt_current(
        &self,
        _: &AuthContext,
        request: &GetArtifactSaveReceipt,
        deadline: Instant,
    ) -> ArtifactSaveReceiptCurrentOutcome {
        assert_eq!(request, &input());
        assert!(deadline > Instant::now() && deadline <= Instant::now() + Duration::from_secs(5));
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.observed_deadline.lock().unwrap() = Some(deadline);
        tokio::task::yield_now().await;
        if let Some(owner) = &self.close {
            owner.close();
        }
        Ok((
            Box::new(Tail {
                auth: self.witness_auth.clone(),
                deadline,
                calls: self.tail_calls.clone(),
            }),
            self.result.clone(),
        ))
    }
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        panic!("receipt observation cannot save or replay")
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        panic!("receipt observation cannot substitute metadata")
    }
    async fn observe_source_run_artifact_ids_current(
        &self,
        _: &AuthContext,
        _: &openbot_contracts::artifacts::GetSourceRunArtifactIds,
        _: Instant,
    ) -> SourceRunArtifactIdsCurrentOutcome {
        panic!("receipt observation cannot enumerate source IDs")
    }
}
fn port(
    auth: &AuthContext,
    result: Result<ArtifactRegistrationReceipt, ArtifactReadCurrentError>,
) -> Port {
    Port {
        result,
        witness_auth: auth.clone(),
        close: None,
        calls: AtomicUsize::new(0),
        tail_calls: Arc::new(AtomicUsize::new(0)),
        observed_deadline: Mutex::new(None),
    }
}

#[tokio::test]
async fn receipt_consumer_preserves_original_binding_and_checks_tail_before_all_outcomes() {
    let (_owner, auth) = bound();
    let p = port(&auth, Ok(receipt()));
    assert_eq!(
        get_artifact_save_receipt(&p, &plain(), input()).await.err(),
        Some(AppError::DependencyUnavailable {
            dependency: "host_request_binding"
        })
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    for outcome in [
        Ok(receipt()),
        Err(ArtifactReadCurrentError::NotVisible),
        Err(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Deleted)),
        Err(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Expired)),
        Err(ArtifactReadCurrentError::Unavailable),
    ] {
        let p = port(&auth, outcome.clone());
        assert_eq!(
            get_artifact_save_receipt(&p, &auth, input()).await,
            outcome.map_err(AppError::from)
        );
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
        assert!(p.observed_deadline.lock().unwrap().is_some());
    }
    for invalid in [false, true] {
        let mut bad = receipt();
        if invalid {
            bad.request_id = "019a8888-abcd-7abc-8abc-0123456789ab".into();
        }
        let (_foreign_owner, foreign) = bound();
        let mut p = port(
            &auth,
            if invalid {
                Ok(bad)
            } else {
                Err(ArtifactReadCurrentError::NotVisible)
            },
        );
        p.witness_auth = foreign;
        assert_eq!(
            get_artifact_save_receipt(&p, &auth, input()).await.err(),
            Some(AppError::Unauthenticated)
        );
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
    }
    for outcome in [
        Ok(receipt()),
        Err(ArtifactReadCurrentError::NotVisible),
        Err(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Deleted)),
        Err(ArtifactReadCurrentError::Unavailable),
    ] {
        let (owner, auth) = bound();
        let mut p = port(&auth, outcome);
        p.close = Some(owner);
        assert_eq!(
            get_artifact_save_receipt(&p, &auth, input()).await.err(),
            Some(AppError::Unauthenticated)
        );
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn receipt_consumer_canonicalizes_request_without_save_or_negative_commit_claim() {
    let (_owner, auth) = bound();
    let p = port(&auth, Ok(receipt()));
    assert_eq!(
        get_artifact_save_receipt(
            &p,
            &auth,
            GetArtifactSaveReceipt {
                request_id: REQUEST.to_uppercase()
            }
        )
        .await,
        Ok(receipt())
    );
    for bad in [
        "",
        "bad",
        &format!(" {REQUEST}"),
        "019a7777-abcd-4abc-8abc-0123456789ab",
    ] {
        assert_eq!(
            get_artifact_save_receipt(
                &p,
                &auth,
                GetArtifactSaveReceipt {
                    request_id: bad.into()
                }
            )
            .await
            .err(),
            Some(AppError::MalformedPayload { field: "requestId" })
        );
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        get_artifact_save_receipt(&NoArtifactAdministration, &auth, input())
            .await
            .err(),
        Some(AppError::DependencyUnavailable {
            dependency: "artifacts"
        })
    );
    let mut cases = Vec::new();
    let mut bad = receipt();
    bad.operation_id = bad.operation_id.to_uppercase();
    cases.push(bad);
    let mut bad = receipt();
    bad.artifact_id = "not-a-uuid".into();
    cases.push(bad);
    let mut bad = receipt();
    bad.owner_actor_id = ActorId::new("different-owner");
    cases.push(bad);
    let mut bad = receipt();
    bad.source_thread_id = ThreadId::new("x".repeat(513));
    cases.push(bad);
    let mut bad = receipt();
    bad.source_run_id = RunId::new("\u{85}");
    cases.push(bad);
    let mut bad = receipt();
    bad.source_message_id = String::new();
    cases.push(bad);
    let mut bad = receipt();
    bad.source_call_seq = Some(1);
    cases.push(bad);
    let mut bad = receipt();
    bad.source_attempt_seq = Some(1);
    cases.push(bad);
    for bad in cases {
        let p = port(&auth, Ok(bad));
        assert_eq!(
            get_artifact_save_receipt(&p, &auth, input()).await.err(),
            Some(AppError::DependencyUnavailable {
                dependency: "artifacts"
            })
        );
        assert_eq!(p.tail_calls.load(Ordering::SeqCst), 1);
    }
    let mut boundary = receipt();
    boundary.source_thread_id = ThreadId::new("x".repeat(512));
    boundary.source_run_id = RunId::new("é".repeat(256));
    boundary.source_message_id = "y".repeat(512);
    assert_eq!(
        get_artifact_save_receipt(&port(&auth, Ok(boundary.clone())), &auth, input()).await,
        Ok(boundary)
    );
}
