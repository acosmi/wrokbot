//! Read-only observation of an original positive save receipt, retaining the original host tail.

use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetArtifactSaveReceipt, canonical_artifact_uuid_v7,
    is_valid_artifact_identity,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::ArtifactReadCurrentError;

use crate::ArtifactAdministration;

/// Observe an existing original registration fact without saving, replaying or reading bytes.
/// An absent or refused observation never establishes a negative commit result.
pub async fn get_artifact_save_receipt(
    port: &dyn ArtifactAdministration,
    auth: &AuthContext,
    mut input: GetArtifactSaveReceipt,
) -> Result<ArtifactRegistrationReceipt, AppError> {
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).ok_or(
        AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        },
    )?;
    input.request_id = canonical_artifact_uuid_v7(&input.request_id)
        .ok_or(AppError::MalformedPayload { field: "requestId" })?;
    let original = auth
        .request_binding()
        .cloned()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    original
        .check_artifact_save_receipt_attachment(auth, deadline)
        .map_err(AppError::from)?;
    let outcome = port
        .observe_artifact_save_receipt_current(auth, &input, deadline)
        .await;
    original
        .check_artifact_save_receipt_attachment(auth, deadline)
        .map_err(AppError::from)?;
    let (witness, receipt) = outcome.map_err(AppError::from)?;
    // Preserve both the actual source result and any shape refusal until the original tail.
    let receipt = receipt.and_then(|receipt| {
        if canonical_artifact_uuid_v7(&receipt.operation_id).as_deref()
            != Some(receipt.operation_id.as_str())
            || canonical_artifact_uuid_v7(&receipt.artifact_id).as_deref()
                != Some(receipt.artifact_id.as_str())
            || receipt.request_id != input.request_id
            || &receipt.owner_actor_id != auth.actor()
            || !is_valid_artifact_identity(receipt.owner_actor_id.as_str())
            || !is_valid_artifact_identity(receipt.source_thread_id.as_str())
            || !is_valid_artifact_identity(receipt.source_run_id.as_str())
            || !is_valid_artifact_identity(&receipt.source_message_id)
            || receipt.source_call_seq.is_some()
            || receipt.source_attempt_seq.is_some()
        {
            Err(ArtifactReadCurrentError::Unavailable)
        } else {
            Ok(receipt)
        }
    });
    original
        .verify_artifact_save_receipt_tail(auth, witness.as_ref(), deadline)
        .map_err(AppError::from)?;
    receipt.map_err(AppError::from)
}

#[cfg(test)]
#[path = "artifact_save_receipt_tests.rs"]
mod tests;
