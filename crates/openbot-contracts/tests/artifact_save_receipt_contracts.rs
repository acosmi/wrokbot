//! Pure contract seams. Trusted test guards do not prove a real Session or Local producer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetArtifactSaveReceipt, canonical_artifact_uuid_v7,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::request_binding::*;
use serde_json::json;
use time::OffsetDateTime;

const ID: &str = "019a7777-abcd-7abc-8abc-0123456789ab";

#[test]
fn save_receipt_request_and_reused_reply_preserve_closed_canonical_wire() {
    let input = GetArtifactSaveReceipt {
        request_id: ID.to_uppercase(),
    };
    let wire = json!({"requestId": ID.to_uppercase()});
    assert_eq!(serde_json::to_value(&input).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<GetArtifactSaveReceipt>(wire.clone()).unwrap(),
        input
    );
    assert_eq!(
        canonical_artifact_uuid_v7(&input.request_id).as_deref(),
        Some(ID)
    );
    for selector in [
        "",
        "not-a-uuid",
        &format!(" {ID}"),
        "019a7777-abcd-4abc-8abc-0123456789ab",
    ] {
        assert!(canonical_artifact_uuid_v7(selector).is_none());
    }
    for field in [
        "sourceThreadId",
        "ownerActorId",
        "dataset",
        "pool",
        "authority",
        "body",
        "retry",
    ] {
        let mut bad = wire.clone();
        bad[field] = json!("untrusted");
        assert!(serde_json::from_value::<GetArtifactSaveReceipt>(bad).is_err());
    }
    let command = AppCommand::GetArtifactSaveReceipt(input);
    let command_wire = serde_json::to_value(&command).unwrap();
    assert_eq!(command_wire["kind"], "get_artifact_save_receipt");
    assert_eq!(
        serde_json::from_value::<AppCommand>(command_wire).unwrap(),
        command
    );
    let receipt = ArtifactRegistrationReceipt {
        operation_id: ID.into(),
        artifact_id: ID.into(),
        request_id: ID.into(),
        owner_actor_id: ActorId::new("\\\"".repeat(256)),
        source_thread_id: ThreadId::new("\\\"".repeat(256)),
        source_run_id: RunId::new("\\\"".repeat(256)),
        source_message_id: "\\\"".repeat(256),
        source_call_seq: None,
        source_attempt_seq: None,
    };
    let value = serde_json::to_value(&receipt).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 9);
    assert!(value["sourceCallSeq"].is_null() && value["sourceAttemptSeq"].is_null());
    assert!(serde_json::to_vec(&receipt).unwrap().len() <= 4374);
    for field in [
        "status",
        "bytes",
        "byteLength",
        "sha256",
        "path",
        "retry",
        "committed",
    ] {
        let mut bad = value.clone();
        bad[field] = json!("untrusted");
        assert!(serde_json::from_value::<ArtifactRegistrationReceipt>(bad).is_err());
    }
    let reply = AppReply::ArtifactRegistrationReceipt(receipt);
    assert_eq!(
        serde_json::from_value::<AppReply>(serde_json::to_value(&reply).unwrap()).unwrap(),
        reply
    );
}

fn plain() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("receipt-contract"),
        TenantId::new("receipt-tenant"),
        ActorId::new("receipt-user"),
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
        Box::pin(async { Ok(()) })
    }
}
struct Target;
impl ArtifactSaveReceiptCurrentTarget for Target {
    fn request_id(&self) -> &str {
        ID
    }
    fn matches_authority(&self, _: &Arc<()>) -> bool {
        true
    }
    fn matches_auth(&self, _: &AuthContext) -> bool {
        true
    }
}
struct Tail {
    auth: AuthContext,
    calls: Arc<AtomicUsize>,
    result: Result<(), ArtifactReadCurrentError>,
}
impl ArtifactReadTailWitness for Tail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        _: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !auth
            .request_binding()
            .zip(self.auth.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        self.result
    }
}
fn bound(issuer: &RequestBindingIssuer) -> AuthContext {
    let auth = plain();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "receipt-synthetic-session".into(),
        auth.actor().clone(),
        "receipt-synthetic-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(Legacy))
        .unwrap();
    auth.with_verified_request_binding(binding).unwrap()
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("contract seam unexpectedly waited"),
    }
}

#[test]
fn save_receipt_guard_defaults_refuse_and_original_tail_retains_errors() {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = bound(&issuer);
    let (_other_owner, other_issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let other = bound(&other_issuer);
    assert_eq!(auth, other);
    assert!(
        !auth
            .request_binding()
            .unwrap()
            .identity()
            .same_binding(other.request_binding().unwrap().identity())
    );
    let original = auth.request_binding().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        ready(original.verify_artifact_save_receipt_current_before(&auth, &Target, deadline)).err(),
        Some(ArtifactReadCurrentError::Host(
            HostRequestBindingError::Unavailable
        ))
    );
    assert_eq!(
        original.check_artifact_save_receipt_attachment(&other, deadline),
        Err(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent
        ))
    );
    for result in [
        Ok(()),
        Err(ArtifactReadCurrentError::NotVisible),
        Err(ArtifactReadCurrentError::Unavailable),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = Tail {
            auth: auth.clone(),
            calls: calls.clone(),
            result,
        };
        assert_eq!(
            original.verify_artifact_save_receipt_tail(&auth, &tail, deadline),
            result
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    owner.close();
    let calls = Arc::new(AtomicUsize::new(0));
    let tail = Tail {
        auth: auth.clone(),
        calls: calls.clone(),
        result: Ok(()),
    };
    assert_eq!(
        original.verify_artifact_save_receipt_tail(&auth, &tail, deadline),
        Err(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent
        ))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
