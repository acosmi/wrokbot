//! Selected native USER saves and current metadata. A registration ACK is not a byte reader.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use openbot_contracts::{
    artifacts::{
        ArtifactGoneStatus, ArtifactMetadata, ArtifactRegistrationReceipt, ArtifactRetentionClass,
        ArtifactWorkspace, MAX_ARTIFACT_BYTES, SaveRunMessageTextArtifact,
        canonical_artifact_uuid_v7, is_valid_artifact_identity, is_valid_artifact_sha256,
    },
    command::ThreadRunAnchor,
    ids::{ActorId, thread::ThreadIdentity},
};

use super::ApiError;

const SAVE_PATH: &str = "/api/artifacts/save-run-message-text";
// All strings in this closed DTO are bounded identities, a fixed media type or an RFC3339 time.
// This also rejects an oversized response instead of presenting a partial metadata object.
const MAX_METADATA_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveError {
    NotSubmitted,
    // Every dispatched failure, including a refusal, leaves the original operation unresolved.
    Unknown(ApiError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptReadError {
    // A refused, absent, cancelled or timed-out observation is never NotSubmitted.
    Unconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetadataError {
    Unauthorized,
    Forbidden,
    NotFound,
    Gone(ArtifactGoneStatus),
    Unavailable,
    InvalidResponse,
}

fn canonical_id(id: &str) -> bool {
    canonical_artifact_uuid_v7(id).as_deref() == Some(id)
}

fn valid_packet(input: &SaveRunMessageTextArtifact, actor: &ActorId) -> bool {
    canonical_id(&input.request_id)
        && ThreadIdentity::is_plausible(&input.source_thread_id)
        && is_valid_artifact_identity(input.source_run_id.as_str())
        && is_valid_artifact_identity(&input.source_message_id)
        && is_valid_artifact_identity(actor.as_str())
        && is_valid_artifact_sha256(&input.expected_sha256)
}

pub(crate) fn receipt_matches(
    receipt: &ArtifactRegistrationReceipt,
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> bool {
    valid_packet(input, actor)
        && canonical_id(&receipt.operation_id)
        && canonical_id(&receipt.artifact_id)
        && receipt.request_id == input.request_id
        && receipt.owner_actor_id == *actor
        && receipt.source_thread_id == input.source_thread_id
        && receipt.source_run_id == input.source_run_id
        && receipt.source_message_id == input.source_message_id
        && receipt.source_call_seq.is_none()
        && receipt.source_attempt_seq.is_none()
}

// Explicit null fields must be present. Serde's Option fallback alone also accepts missing keys.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserProvenance {
    source_call_seq: (),
    source_attempt_seq: (),
}

fn has_complete_user_provenance(body: &str) -> bool {
    let Ok(UserProvenance {
        source_call_seq: (),
        source_attempt_seq: (),
    }) = serde_json::from_str::<UserProvenance>(body)
    else {
        return false;
    };
    true
}

#[cfg(any(target_arch = "wasm32", test))]
fn decode_save(
    status: u16,
    no_store: bool,
    body: &str,
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> Result<ArtifactRegistrationReceipt, SaveError> {
    if status != 200 {
        return Err(SaveError::Unknown(super::status_error(status)));
    }
    if !no_store || body.len() > MAX_METADATA_RESPONSE_BYTES || !has_complete_user_provenance(body)
    {
        return Err(SaveError::Unknown(ApiError::InvalidResponse));
    }
    let receipt: ArtifactRegistrationReceipt =
        serde_json::from_str(body).map_err(|_| SaveError::Unknown(ApiError::InvalidResponse))?;
    if !receipt_matches(&receipt, input, actor) {
        return Err(SaveError::Unknown(ApiError::InvalidResponse));
    }
    Ok(receipt)
}

#[cfg(any(target_arch = "wasm32", test))]
fn decode_save_receipt(
    status: u16,
    no_store: bool,
    body: &str,
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> Result<ArtifactRegistrationReceipt, ReceiptReadError> {
    // Same closed positive receipt as Save; no status is a negative commit proof.
    decode_save(status, no_store, body, input, actor).map_err(|_| ReceiptReadError::Unconfirmed)
}

fn save_receipt_path(
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> Result<String, ReceiptReadError> {
    if !valid_packet(input, actor) {
        return Err(ReceiptReadError::Unconfirmed);
    }
    Ok(format!("/api/artifacts/save-requests/{}", input.request_id))
}

#[cfg(target_arch = "wasm32")]
struct ReceiptWaitGuard {
    window: web_sys::Window,
    timer: i32,
    _callback: wasm_bindgen::closure::Closure<dyn FnMut()>,
    controller: wasm_bindgen::JsValue,
    abort: js_sys::Function,
    abort_pending: bool,
    deadline_resolve: js_sys::Function,
}

#[cfg(target_arch = "wasm32")]
impl Drop for ReceiptWaitGuard {
    fn drop(&mut self) {
        self.window.clear_timeout_with_handle(self.timer);
        // Release the losing deadline future on success and owner cancellation as well.
        let _ = self
            .deadline_resolve
            .call0(&wasm_bindgen::JsValue::UNDEFINED);
        if self.abort_pending {
            let _ = self.abort.call0(&self.controller);
        }
    }
}

/// Explicit read of the original request. Never POST, replay, mint or replace a locator.
pub(crate) async fn save_receipt(
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> Result<ArtifactRegistrationReceipt, ReceiptReadError> {
    let path = save_receipt_path(input, actor)?;
    #[cfg(target_arch = "wasm32")]
    {
        use futures_util::future::{Either, select};
        use wasm_bindgen::{JsCast, JsValue, closure::Closure};

        use super::request::Request;

        let unconfirmed = |_| ReceiptReadError::Unconfirmed;
        let constructor = js_sys::Reflect::get(&js_sys::global(), &"AbortController".into())
            .map_err(unconfirmed)?
            .dyn_into::<js_sys::Function>()
            .map_err(unconfirmed)?;
        let controller: JsValue = js_sys::Reflect::construct(&constructor, &js_sys::Array::new())
            .map_err(unconfirmed)?
            .into();
        let signal = js_sys::Reflect::get(&controller, &"signal".into()).map_err(unconfirmed)?;
        let abort = js_sys::Reflect::get(&controller, &"abort".into())
            .map_err(unconfirmed)?
            .dyn_into::<js_sys::Function>()
            .map_err(unconfirmed)?;
        let window = web_sys::window().ok_or(ReceiptReadError::Unconfirmed)?;
        let mut timer = None;
        let mut callback = None;
        let mut deadline_resolve = None;
        let deadline = js_sys::Promise::new(&mut |resolve, _| {
            deadline_resolve = Some(resolve.clone());
            let ready = Closure::wrap(Box::new(move || {
                let _ = resolve.call0(&JsValue::UNDEFINED);
            }) as Box<dyn FnMut()>);
            timer = window
                .set_timeout_with_callback_and_timeout_and_arguments_0(
                    ready.as_ref().unchecked_ref(),
                    15_000,
                )
                .ok();
            callback = Some(ready);
        });
        let mut guard = ReceiptWaitGuard {
            window,
            timer: timer.ok_or(ReceiptReadError::Unconfirmed)?,
            _callback: callback.ok_or(ReceiptReadError::Unconfirmed)?,
            controller,
            abort,
            abort_pending: true,
            deadline_resolve: deadline_resolve.ok_or(ReceiptReadError::Unconfirmed)?,
        };
        let body_finished = std::cell::Cell::new(false);
        let read = Box::pin(async {
            // Shared SameOrigin/NoStore/redirect-error builder, empty body and query.
            let response =
                Request::send(Request::get(&path).abort_signal(Some(signal.unchecked_ref())))
                    .await
                    .map_err(|_| ReceiptReadError::Unconfirmed)?;
            let status = response.status();
            if status != 200 {
                return Err(ReceiptReadError::Unconfirmed);
            }
            let no_store = has_no_store(&response);
            let text = response
                .text()
                .await
                .map_err(|_| ReceiptReadError::Unconfirmed)?;
            body_finished.set(true);
            let body = zeroize::Zeroizing::new(text);
            decode_save_receipt(status, no_store, &body, input, actor)
        });
        let timeout = Box::pin(wasm_bindgen_futures::JsFuture::from(deadline));
        match select(read, timeout).await {
            Either::Left((result, _)) => {
                guard.abort_pending = !body_finished.get();
                result
            }
            Either::Right(_) => Err(ReceiptReadError::Unconfirmed),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = path;
        Err(ReceiptReadError::Unconfirmed)
    }
}

fn metadata_matches(
    metadata: &ArtifactMetadata,
    receipt: &ArtifactRegistrationReceipt,
    actor: &ActorId,
    anchor: &ThreadRunAnchor,
) -> bool {
    let record = match metadata {
        ArtifactMetadata::Available(record) | ArtifactMetadata::FailedPartial(record) => record,
        ArtifactMetadata::Deleted(_) | ArtifactMetadata::Expired(_) => return false,
    };
    let workspace_matches = match (&record.workspace, anchor) {
        (ArtifactWorkspace::Channel { id }, ThreadRunAnchor::Channel { channel_id }) => {
            id == channel_id.as_str()
        }
        (ArtifactWorkspace::Thread { id }, ThreadRunAnchor::DirectBot) => {
            id == record.source_thread_id.as_str()
        }
        _ => false,
    };
    record.artifact_id == receipt.artifact_id
        && canonical_id(&record.artifact_id)
        && receipt.owner_actor_id == *actor
        && record.owner_actor_id == *actor
        && record.source_thread_id == receipt.source_thread_id
        && record.source_run_id == receipt.source_run_id
        && is_valid_artifact_identity(record.deployment_id.as_str())
        && is_valid_artifact_identity(record.tenant_id.as_str())
        && is_valid_artifact_identity(&record.dataset_id)
        && is_valid_artifact_identity(record.owner_actor_id.as_str())
        && workspace_matches
        && record.source_call_seq.is_none()
        && record.source_attempt_seq.is_none()
        && record.media_type == "text/plain; charset=utf-8"
        && record.byte_length <= MAX_ARTIFACT_BYTES
        && is_valid_artifact_sha256(&record.sha256)
        && record.retention_class == ArtifactRetentionClass::ExplicitSaved
        && record.saved_by.as_ref() == Some(actor)
        && record.saved_at.is_some()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GoneReply {
    code: String,
    status: ArtifactGoneStatus,
}

fn decode_metadata(
    status: u16,
    no_store: bool,
    body: &str,
    receipt: &ArtifactRegistrationReceipt,
    actor: &ActorId,
    anchor: &ThreadRunAnchor,
) -> Result<ArtifactMetadata, MetadataError> {
    if body.len() > MAX_METADATA_RESPONSE_BYTES || !no_store {
        return Err(MetadataError::InvalidResponse);
    }
    match status {
        200 => {
            if !has_complete_user_provenance(body) {
                return Err(MetadataError::InvalidResponse);
            }
            let metadata = serde_json::from_str::<ArtifactMetadata>(body)
                .map_err(|_| MetadataError::InvalidResponse)?;
            if !metadata_matches(&metadata, receipt, actor, anchor) {
                return Err(MetadataError::InvalidResponse);
            }
            Ok(metadata)
        }
        410 => {
            let gone = serde_json::from_str::<GoneReply>(body)
                .map_err(|_| MetadataError::InvalidResponse)?;
            if gone.code != "artifact_gone" {
                return Err(MetadataError::InvalidResponse);
            }
            Err(MetadataError::Gone(gone.status))
        }
        401 => Err(MetadataError::Unauthorized),
        403 => Err(MetadataError::Forbidden),
        404 => Err(MetadataError::NotFound),
        503 => Err(MetadataError::Unavailable),
        _ => Err(MetadataError::InvalidResponse),
    }
}

fn metadata_path(id: &str) -> Result<String, MetadataError> {
    if !canonical_id(id) {
        return Err(MetadataError::InvalidResponse);
    }
    // A canonical UUIDv7 needs no path/query encoding or renderer-supplied URL.
    Ok(format!("/api/artifacts/{id}"))
}

#[cfg(target_arch = "wasm32")]
fn has_no_store(response: &gloo_net::http::Response) -> bool {
    response
        .headers()
        .get("Cache-Control")
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("no-store"))
        })
}

pub(crate) async fn save(
    input: &SaveRunMessageTextArtifact,
    actor: &ActorId,
) -> Result<ArtifactRegistrationReceipt, SaveError> {
    if !valid_packet(input, actor) {
        return Err(SaveError::NotSubmitted);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use super::request::Request;
        let request = super::secret_json(Request::post(SAVE_PATH), input)
            .map_err(|_| SaveError::NotSubmitted)?;
        // No branch after this boundary turns a dispatched result into NotSubmitted.
        let response = Request::send(request).await.map_err(SaveError::Unknown)?;
        let status = response.status();
        let no_store = has_no_store(&response);
        if status != 200 {
            return Err(SaveError::Unknown(super::status_error(status)));
        }
        let body = zeroize::Zeroizing::new(
            response
                .text()
                .await
                .map_err(|_| SaveError::Unknown(ApiError::InvalidResponse))?,
        );
        decode_save(status, no_store, &body, input, actor)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(SaveError::NotSubmitted)
    }
}

pub(crate) async fn metadata(
    receipt: &ArtifactRegistrationReceipt,
    actor: &ActorId,
    anchor: &ThreadRunAnchor,
) -> Result<ArtifactMetadata, MetadataError> {
    let path = metadata_path(&receipt.artifact_id)?;
    if receipt.owner_actor_id != *actor {
        return Err(MetadataError::InvalidResponse);
    }
    #[cfg(target_arch = "wasm32")]
    {
        use super::request::Request;
        // Intentionally no body or query; the one request builder retains SameOrigin/NoStore.
        let response = Request::send(Request::get(&path))
            .await
            .map_err(|_| MetadataError::Unavailable)?;
        let status = response.status();
        let no_store = has_no_store(&response);
        let body = zeroize::Zeroizing::new(
            response
                .text()
                .await
                .map_err(|_| MetadataError::InvalidResponse)?,
        );
        decode_metadata(status, no_store, &body, receipt, actor, anchor)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, anchor);
        Err(MetadataError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::{
        artifacts::ArtifactRecordMetadata,
        ids::{DeploymentId, RunId, TenantId, ThreadId},
    };

    const REQUEST: &str = "019a7778-abcd-7abc-8abc-0123456789ab";
    const ARTIFACT: &str = "019a7778-abcd-7abc-8abc-0123456789ac";
    const OPERATION: &str = "019a7778-abcd-7abc-8abc-0123456789ad";

    fn packet() -> SaveRunMessageTextArtifact {
        SaveRunMessageTextArtifact {
            request_id: REQUEST.into(),
            source_thread_id: ThreadId::new("019a7778-abcd-8abc-8abc-0123456789ab"),
            source_run_id: RunId::new("opaque run"),
            source_message_id: "exact-message".into(),
            expected_sha256: "1".repeat(64),
        }
    }

    fn receipt() -> ArtifactRegistrationReceipt {
        let input = packet();
        ArtifactRegistrationReceipt {
            operation_id: OPERATION.into(),
            artifact_id: ARTIFACT.into(),
            request_id: input.request_id,
            owner_actor_id: ActorId::new("actor"),
            source_thread_id: input.source_thread_id,
            source_run_id: input.source_run_id,
            source_message_id: input.source_message_id,
            source_call_seq: None,
            source_attempt_seq: None,
        }
    }

    fn record() -> ArtifactRecordMetadata {
        let ack = receipt();
        ArtifactRecordMetadata {
            artifact_id: ack.artifact_id,
            deployment_id: DeploymentId::new("deployment"),
            tenant_id: TenantId::new("tenant"),
            dataset_id: "dataset".into(),
            owner_actor_id: ack.owner_actor_id.clone(),
            workspace: ArtifactWorkspace::Thread {
                id: ack.source_thread_id.as_str().into(),
            },
            source_thread_id: ack.source_thread_id,
            source_run_id: ack.source_run_id,
            source_call_seq: None,
            source_attempt_seq: None,
            media_type: "text/plain; charset=utf-8".into(),
            byte_length: 7,
            sha256: "2".repeat(64),
            retention_class: ArtifactRetentionClass::ExplicitSaved,
            saved_by: Some(ack.owner_actor_id),
            saved_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn save_has_only_five_selectors_and_only_matched_200_is_acknowledged() {
        let input = packet();
        let wire = serde_json::to_value(&input).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 5);
        let body = serde_json::to_string(&receipt()).unwrap();
        assert!(decode_save(200, true, &body, &input, &ActorId::new("actor")).is_ok());
        for status in [201, 202, 400, 401, 403, 404, 409, 503] {
            assert!(matches!(
                decode_save(status, true, &body, &input, &ActorId::new("actor")),
                Err(SaveError::Unknown(_))
            ));
        }
        assert!(decode_save(200, false, &body, &input, &ActorId::new("actor")).is_err());
    }

    #[test]
    fn save_receipt_get_has_original_locator_only_and_refusals_stay_unconfirmed() {
        let input = packet();
        let actor = ActorId::new("actor");
        assert_eq!(
            save_receipt_path(&input, &actor).unwrap(),
            format!("/api/artifacts/save-requests/{REQUEST}")
        );
        let body = serde_json::to_string(&receipt()).unwrap();
        assert_eq!(
            decode_save_receipt(200, true, &body, &input, &actor),
            Ok(receipt())
        );
        for status in [201, 202, 204, 400, 401, 403, 404, 409, 410, 500, 503] {
            assert_eq!(
                decode_save_receipt(status, true, &body, &input, &actor),
                Err(ReceiptReadError::Unconfirmed),
                "{status}"
            );
        }
        for request in [
            REQUEST.to_uppercase(),
            format!("{REQUEST}?actor=other"),
            format!("{REQUEST}/receipt"),
            "".into(),
        ] {
            let mut bad = input.clone();
            bad.request_id = request;
            assert_eq!(
                save_receipt_path(&bad, &actor),
                Err(ReceiptReadError::Unconfirmed)
            );
        }
    }

    #[test]
    fn save_receipt_get_does_not_trust_foreign_extra_missing_or_cacheable_receipts() {
        let input = packet();
        let actor = ActorId::new("actor");
        let good = serde_json::to_value(receipt()).unwrap();
        for field in [
            "operationId",
            "artifactId",
            "requestId",
            "ownerActorId",
            "sourceThreadId",
            "sourceRunId",
            "sourceMessageId",
            "sourceCallSeq",
            "sourceAttemptSeq",
            "authGeneration",
            "windowBinding",
            "expectedSha256",
        ] {
            let mut bad = good.clone();
            bad[field] = if field.ends_with("Seq") {
                serde_json::json!(1)
            } else {
                serde_json::json!("foreign")
            };
            assert_eq!(
                decode_save_receipt(200, true, &bad.to_string(), &input, &actor),
                Err(ReceiptReadError::Unconfirmed),
                "{field}"
            );
        }
        for field in ["sourceCallSeq", "sourceAttemptSeq"] {
            let mut bad = good.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert_eq!(
                decode_save_receipt(200, true, &bad.to_string(), &input, &actor),
                Err(ReceiptReadError::Unconfirmed)
            );
        }
        for (no_store, body) in [
            (false, good.to_string()),
            (true, " ".repeat(MAX_METADATA_RESPONSE_BYTES + 1)),
            (true, "{}".into()),
        ] {
            assert_eq!(
                decode_save_receipt(200, no_store, &body, &input, &actor),
                Err(ReceiptReadError::Unconfirmed)
            );
        }
    }

    #[test]
    fn every_receipt_identity_and_tool_provenance_is_checked() {
        for field in [
            "requestId",
            "operationId",
            "artifactId",
            "ownerActorId",
            "sourceThreadId",
            "sourceRunId",
            "sourceMessageId",
            "sourceCallSeq",
            "sourceAttemptSeq",
            "replayed",
        ] {
            let mut wire = serde_json::to_value(receipt()).unwrap();
            wire[field] = if field.ends_with("Seq") {
                serde_json::json!(1)
            } else {
                serde_json::json!("wrong")
            };
            assert!(
                decode_save(
                    200,
                    true,
                    &wire.to_string(),
                    &packet(),
                    &ActorId::new("actor")
                )
                .is_err(),
                "{field}"
            );
        }
        for field in ["sourceCallSeq", "sourceAttemptSeq"] {
            let mut wire = serde_json::to_value(receipt()).unwrap();
            wire.as_object_mut().unwrap().remove(field);
            assert!(
                decode_save(
                    200,
                    true,
                    &wire.to_string(),
                    &packet(),
                    &ActorId::new("actor")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn failed_partial_keeps_actual_zero_length_and_actual_digest() {
        let mut actual = record();
        actual.byte_length = 0;
        let body = serde_json::to_string(&ArtifactMetadata::FailedPartial(actual.clone())).unwrap();
        let decoded = decode_metadata(
            200,
            true,
            &body,
            &receipt(),
            &ActorId::new("actor"),
            &ThreadRunAnchor::DirectBot,
        )
        .unwrap();
        assert_eq!(decoded, ArtifactMetadata::FailedPartial(actual));
        assert_ne!(record().sha256, packet().expected_sha256);
    }

    #[test]
    fn metadata_rejects_wrong_scope_extra_fields_and_unregistered_status() {
        let good = serde_json::to_value(ArtifactMetadata::Available(record())).unwrap();
        for (field, value) in [
            ("ownerActorId", serde_json::json!("other")),
            ("artifactId", serde_json::json!(REQUEST)),
            ("sourceRunId", serde_json::json!("other")),
            ("sourceCallSeq", serde_json::json!(1)),
            ("byteLength", serde_json::json!(MAX_ARTIFACT_BYTES + 1)),
            ("status", serde_json::json!("ready")),
            ("downloadUrl", serde_json::json!("file:///private")),
            (
                "workspace",
                serde_json::json!({"kind":"thread","id":"other"}),
            ),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert_eq!(
                decode_metadata(
                    200,
                    true,
                    &bad.to_string(),
                    &receipt(),
                    &ActorId::new("actor"),
                    &ThreadRunAnchor::DirectBot,
                ),
                Err(MetadataError::InvalidResponse),
                "{field}"
            );
        }
        assert_eq!(
            decode_metadata(
                200,
                false,
                &good.to_string(),
                &receipt(),
                &ActorId::new("actor"),
                &ThreadRunAnchor::DirectBot,
            ),
            Err(MetadataError::InvalidResponse)
        );
        for field in ["sourceCallSeq", "sourceAttemptSeq", "savedBy", "savedAt"] {
            let mut bad = good.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert_eq!(
                decode_metadata(
                    200,
                    true,
                    &bad.to_string(),
                    &receipt(),
                    &ActorId::new("actor"),
                    &ThreadRunAnchor::DirectBot
                ),
                Err(MetadataError::InvalidResponse)
            );
        }
    }

    #[test]
    fn gone_is_closed_and_never_generic_conflict_or_live_metadata() {
        for (status, body, expected) in [
            (
                410,
                r#"{"code":"artifact_gone","status":"deleted"}"#,
                MetadataError::Gone(ArtifactGoneStatus::Deleted),
            ),
            (
                410,
                r#"{"code":"artifact_gone","status":"expired"}"#,
                MetadataError::Gone(ArtifactGoneStatus::Expired),
            ),
            (
                410,
                r#"{"code":"artifact_gone","status":"available"}"#,
                MetadataError::InvalidResponse,
            ),
            (
                410,
                r#"{"code":"artifact_gone","status":"deleted","sha256":"private"}"#,
                MetadataError::InvalidResponse,
            ),
            (
                401,
                r#"{"code":"unauthenticated"}"#,
                MetadataError::Unauthorized,
            ),
            (404, r#"{"code":"not_found"}"#, MetadataError::NotFound),
            (
                503,
                r#"{"code":"dependency_unavailable"}"#,
                MetadataError::Unavailable,
            ),
        ] {
            assert_eq!(
                decode_metadata(
                    status,
                    true,
                    body,
                    &receipt(),
                    &ActorId::new("actor"),
                    &ThreadRunAnchor::DirectBot,
                ),
                Err(expected)
            );
        }
        assert!(metadata_path(ARTIFACT).unwrap().ends_with(ARTIFACT));
        for id in [
            REQUEST.to_uppercase(),
            format!("{ARTIFACT}?x=1"),
            "request".into(),
        ] {
            assert!(metadata_path(&id).is_err());
        }
    }
}
