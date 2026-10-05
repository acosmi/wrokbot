//! Original positive-receipt observation. The locator never authorizes Save or byte IO.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactRegistrationReceipt, GetArtifactSaveReceipt,
    canonical_artifact_uuid_v7, is_valid_artifact_identity,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::{ActorId, RunId, ThreadId};
use openbot_contracts::request_binding::{
    ArtifactReadCurrentError, ArtifactReadTailWitness, ArtifactSaveReceiptCurrentOutcome,
    ArtifactSaveReceiptCurrentTarget, HostRequestBindingKind,
};
use tokio_postgres::{IsolationLevel, Row};

use super::{
    CurrentHost, PostgresArtifactAdministration, PostgresArtifactReadAuthority, decode_host,
    host_not_current, host_unavailable, remaining, same_original_auth,
};

struct RequestedArtifactSaveReceiptTarget {
    identity: Arc<()>,
    auth: AuthContext,
    input: GetArtifactSaveReceipt,
}
impl ArtifactSaveReceiptCurrentTarget for RequestedArtifactSaveReceiptTarget {
    fn request_id(&self) -> &str {
        &self.input.request_id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
}

pub(super) async fn current(
    authority: &Arc<PostgresArtifactReadAuthority>,
    auth: &AuthContext,
    input: &GetArtifactSaveReceipt,
    deadline: Instant,
) -> ArtifactSaveReceiptCurrentOutcome {
    let original = auth.request_binding().ok_or_else(host_unavailable)?;
    if !matches!(
        original.kind(),
        HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
    ) {
        return Err(host_unavailable());
    }
    let target = RequestedArtifactSaveReceiptTarget {
        identity: Arc::clone(&authority.identity),
        auth: auth.clone(),
        input: input.clone(),
    };
    original
        .verify_artifact_save_receipt_current_before(auth, &target, deadline)
        .await
}

pub(super) async fn observe(
    authority: &PostgresArtifactReadAuthority,
    auth: &AuthContext,
    target: &dyn ArtifactSaveReceiptCurrentTarget,
    host: CurrentHost<'_>,
    deadline: Instant,
) -> ArtifactSaveReceiptCurrentOutcome {
    remaining(deadline)?;
    if !target.matches_authority(&authority.identity) || !target.matches_auth(auth) {
        return Err(host_not_current());
    }
    if canonical_artifact_uuid_v7(target.request_id()).as_deref() != Some(target.request_id()) {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    let administration = authority
        .administration
        .upgrade()
        .ok_or_else(host_unavailable)?;
    administration
        .check_namespace(auth)
        .map_err(|_| host_not_current())?;
    if let CurrentHost::Desktop(installation) = &host
        && !administration
            .registry
            .matches_desktop_read_installation(installation)
    {
        return Err(host_unavailable());
    }
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        observe_inner(authority, &administration, auth, target, host, deadline),
    )
    .await
    .map_err(|_| host_unavailable())?
}

async fn observe_inner(
    authority: &PostgresArtifactReadAuthority,
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    target: &dyn ArtifactSaveReceiptCurrentTarget,
    host: CurrentHost<'_>,
    deadline: Instant,
) -> ArtifactSaveReceiptCurrentOutcome {
    super::super::verify_artifact_registration_schema(administration.registry.pool())
        .await
        .map_err(|_| host_unavailable())?;
    remaining(deadline)?;
    let mut client = administration
        .registry
        .pool()
        .get()
        .await
        .map_err(|_| host_unavailable())?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .await
        .map_err(|_| host_unavailable())?;
    let outcome = async {
        let millis = remaining(deadline)?.as_millis().clamp(1, 5000);
        tx.batch_execute(&format!(
            "SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"
        ))
        .await
        .map_err(|_| host_unavailable())?;
        let binding = administration.registry.binding();
        let physical = administration.store.physical_binding();
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| host_not_current())?;
        let session_id = match &host {
            CurrentHost::Session { epoch, .. } => Some(epoch.lookup_id()),
            CurrentHost::Desktop(_) => None,
        };
        remaining(deadline)?;
        tracing::trace!(
            save_receipt_phase = "joint_statement_ready",
            "artifact_save_receipt_current_phase"
        );
        let row = tx
            .query_one(
                current_sql(matches!(&host, CurrentHost::Desktop(_))),
                &[
                    &target.request_id(),
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                    &binding.dataset_id(),
                    &binding.binding_schema(),
                    &binding.initial_origin(),
                    &binding.created_at(),
                    &administration.store.store_id().to_string(),
                    &physical.device(),
                    &physical.inode(),
                    &physical.uid(),
                    &session_id,
                ],
            )
            .await
            .map_err(|_| host_unavailable())?;
        // The independent host anchor survives absent/corrupt receipt and source joins.
        let witness = decode_host(administration, auth, &row, &host)?;
        let receipt = decode_receipt(administration, auth, target, &row);
        tracing::trace!(
            save_receipt_phase = "joint_result_observed_before_rollback",
            "artifact_save_receipt_current_phase"
        );
        Ok::<_, ArtifactReadCurrentError>((witness, receipt))
    }
    .await;
    #[cfg(test)]
    let rollback = rollback_with_reviewed_pending_gate(authority, tx, deadline).await;
    #[cfg(not(test))]
    let rollback = {
        let _ = authority;
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), tx.rollback())
            .await
            .map_err(|_| host_unavailable())?
            .map_err(|_| host_unavailable())
    };
    // No inner result escapes before the actual original rollback future returns its ACK.
    if rollback.is_ok() {
        tracing::trace!(
            save_receipt_phase = "rollback_acknowledged_before_tail",
            "artifact_save_receipt_current_phase"
        );
    }
    if let Ok((witness, _)) = &outcome {
        witness.verify_current(auth, deadline)?;
    }
    remaining(deadline)?;
    rollback?;
    let (witness, receipt) = outcome?;
    Ok((Box::new(witness), receipt))
}

fn decode_receipt(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    target: &dyn ArtifactSaveReceiptCurrentTarget,
    row: &Row,
) -> Result<ArtifactRegistrationReceipt, ArtifactReadCurrentError> {
    let field = |_| ArtifactReadCurrentError::Unavailable;
    if !row.try_get::<_, bool>("operation_present").map_err(field)?
        || !row.try_get::<_, bool>("owner_matches").map_err(field)?
        || !row.try_get::<_, bool>("source_visible").map_err(field)?
    {
        return Err(ArtifactReadCurrentError::NotVisible);
    }
    if !row
        .try_get::<_, bool>("current_store_binding")
        .map_err(field)?
        || !administration
            .store
            .matches_registry_owner(&administration.registry)
        || !row.try_get::<_, bool>("operation_valid").map_err(field)?
        || !row.try_get::<_, bool>("record_valid").map_err(field)?
    {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    match row
        .try_get::<_, Option<String>>("record_status")
        .map_err(field)?
        .as_deref()
    {
        Some("deleted") => return Err(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Deleted)),
        Some("expired") => return Err(ArtifactReadCurrentError::Gone(ArtifactGoneStatus::Expired)),
        Some("available") => {}
        _ => return Err(ArtifactReadCurrentError::Unavailable),
    }
    if !row.try_get::<_, bool>("receipt_valid").map_err(field)? {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    fn id(row: &Row, name: &'static str) -> Result<String, ArtifactReadCurrentError> {
        let id: Option<String> = row
            .try_get(name)
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        id.filter(|value| is_valid_artifact_identity(value))
            .ok_or(ArtifactReadCurrentError::Unavailable)
    }
    // Every output field comes from the actual persisted receipt, never from the operation/input.
    let receipt = ArtifactRegistrationReceipt {
        operation_id: id(row, "receipt_operation")?,
        artifact_id: id(row, "receipt_artifact")?,
        request_id: id(row, "receipt_request")?,
        owner_actor_id: ActorId::new(id(row, "receipt_owner")?),
        source_thread_id: ThreadId::new(id(row, "receipt_thread")?),
        source_run_id: RunId::new(id(row, "receipt_run")?),
        source_message_id: id(row, "receipt_message")?,
        source_call_seq: row
            .try_get::<_, Option<i64>>("receipt_call")
            .map_err(field)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?,
        source_attempt_seq: row
            .try_get::<_, Option<i64>>("receipt_attempt")
            .map_err(field)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?,
    };
    if [
        &receipt.operation_id,
        &receipt.artifact_id,
        &receipt.request_id,
    ]
    .into_iter()
    .any(|value| canonical_artifact_uuid_v7(value).as_deref() != Some(value.as_str()))
        || receipt.request_id != target.request_id()
        || &receipt.owner_actor_id != auth.actor()
        || receipt.source_call_seq.is_some()
        || receipt.source_attempt_seq.is_some()
    {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    Ok(receipt)
}

fn current_sql(desktop: bool) -> &'static str {
    static SESSION: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let sql = if desktop { &DESKTOP } else { &SESSION };
    sql.get_or_init(|| {
        // Keep the original R398 predicate intact; only its fixed placeholders are rebound
        // to the original operation's source and this statement's own auth parameters.
        let visible = crate::thread_directory::reconciliation_visibility::VISIBLE_RUN
            .trim().strip_prefix("WITH ").expect("static visibility CTE")
            .replace("$1", "(SELECT source_thread_id FROM requested_operation)")
            .replace("$2", "(SELECT source_run_id FROM requested_operation)")
            .replace("$3", "$2").replace("$4", "$3").replace("$5", "$4").replace("$6", "$5");
        let (canary_columns, canary_joins) = if desktop { (
            ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
             CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
             CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
             CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
             CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
             c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
             CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
            " LEFT JOIN pg_control_system() pcs ON true \
              LEFT JOIN pg_database d ON d.datname=current_database() \
              LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$3 AND c.tenant_id=$4 AND c.key_version=1"
        ) } else { ("", "") };
        format!(r#"/* artifact_save_receipt_joint_current */ WITH requested_operation AS (
          SELECT o.deployment_id,o.tenant_id,o.dataset_id,o.request_id,o.operation_id,o.artifact_id,
            o.owner_actor_id,o.source_thread_id,o.source_run_id,o.source_message_id,
            o.source_call_seq,o.source_attempt_seq,o.state,o.store_id,o.workspace_kind,o.workspace_id,
            (o.request_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
             AND o.operation_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
             AND o.artifact_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
             AND o.source_call_seq IS NULL AND o.source_attempt_seq IS NULL
             AND octet_length(o.owner_actor_id) BETWEEN 1 AND 512
             AND octet_length(o.source_thread_id) BETWEEN 1 AND 512
             AND octet_length(o.source_run_id) BETWEEN 1 AND 512
             AND octet_length(o.source_message_id) BETWEEN 1 AND 512
             AND o.owner_actor_id !~ U&'[\0001-\001F\007F-\009F]'
             AND o.source_thread_id !~ U&'[\0001-\001F\007F-\009F]'
             AND o.source_run_id !~ U&'[\0001-\001F\007F-\009F]'
             AND o.source_message_id !~ U&'[\0001-\001F\007F-\009F]') AS identity_valid,
            (o.state IN ('deleted','expired') AND o.store_id IS NULL AND o.workspace_kind IS NULL
             AND o.workspace_id IS NULL AND o.expected_sha256 IS NULL AND o.expected_bytes IS NULL
             AND o.charged_bytes IS NULL AND o.actual_absent IS NULL AND o.actual_byte_length IS NULL
             AND o.actual_sha256 IS NULL AND o.actual_location IS NULL AND o.observation_phase IS NULL
             AND o.created_at IS NULL) AS terminal_valid,
            (o.state='available' AND o.store_id=$10 AND o.expected_bytes BETWEEN 1 AND 67108864
             AND o.expected_sha256 ~ '^[0-9a-f]{{64}}$' AND o.charged_bytes=o.expected_bytes
             AND o.actual_absent IS FALSE AND o.actual_byte_length=o.expected_bytes
             AND o.actual_sha256=o.expected_sha256 AND o.actual_location='object'
             AND o.observation_phase='installed' AND o.created_at IS NOT NULL
             AND EXISTS(SELECT 1 FROM openbot_internal.artifact_records ar
               WHERE ar.deployment_id=o.deployment_id AND ar.tenant_id=o.tenant_id
                 AND ar.dataset_id=o.dataset_id AND ar.artifact_id=o.artifact_id
                 AND ar.byte_length=o.actual_byte_length AND ar.sha256=o.actual_sha256)) AS available_valid
          FROM openbot_internal.artifact_save_operations o
          WHERE o.request_id=$1 AND o.deployment_id=$3 AND o.tenant_id=$4 AND o.dataset_id=$6
        ), {visible}, observed AS (
          SELECT o.operation_id IS NOT NULL AS operation_present,coalesce(o.owner_actor_id=$2,false) AS owner_matches,
            EXISTS(SELECT 1 FROM visible_run r JOIN public.messages m
              ON m.message_id=o.source_message_id AND m.thread_id=r.thread_id AND m.run_id=r.run_id
              AND m.actor_id=o.owner_actor_id AND m.role='user') AS source_visible,
            coalesce(o.identity_valid AND (o.terminal_valid OR o.available_valid),false) AS operation_valid,
            coalesce(a.operation_id=o.operation_id AND a.artifact_id=o.artifact_id AND a.request_id=o.request_id
              AND a.owner_actor_id=o.owner_actor_id AND a.source_thread_id=o.source_thread_id
              AND a.source_run_id=o.source_run_id AND a.source_message_id=o.source_message_id
              AND a.source_call_seq IS NOT DISTINCT FROM o.source_call_seq
              AND a.source_attempt_seq IS NOT DISTINCT FROM o.source_attempt_seq AND a.status=o.state
              AND ((o.terminal_valid AND a.workspace_kind IS NULL AND a.workspace_id IS NULL
                AND a.media_type IS NULL AND a.byte_length IS NULL AND a.sha256 IS NULL
                AND a.retention_class IS NULL AND a.saved_by IS NULL AND a.saved_at IS NULL)
              OR (o.available_valid AND a.workspace_kind=o.workspace_kind AND a.workspace_id=o.workspace_id
                AND a.workspace_kind=CASE t.anchor_kind WHEN 'channel' THEN 'channel' WHEN 'direct_bot' THEN 'thread' END
                AND a.workspace_id=CASE t.anchor_kind WHEN 'channel' THEN t.anchor_id WHEN 'direct_bot' THEN t.thread_id END
                AND a.media_type='text/plain; charset=utf-8' AND a.byte_length BETWEEN 1 AND 67108864
                AND a.sha256 ~ '^[0-9a-f]{{64}}$' AND a.retention_class='explicit_saved'
                AND a.saved_by=o.owner_actor_id AND a.saved_at IS NOT NULL)),false) AS record_valid,
            coalesce(p.operation_id=o.operation_id AND p.artifact_id=o.artifact_id AND p.request_id=o.request_id
              AND p.owner_actor_id=o.owner_actor_id AND p.source_thread_id=o.source_thread_id
              AND p.source_run_id=o.source_run_id AND p.source_message_id=o.source_message_id
              AND p.source_call_seq IS NOT DISTINCT FROM o.source_call_seq
              AND p.source_attempt_seq IS NOT DISTINCT FROM o.source_attempt_seq
              AND p.source_call_seq IS NULL AND p.source_attempt_seq IS NULL,false) AS receipt_valid,
            CASE WHEN octet_length(a.status) BETWEEN 1 AND 14 THEN a.status END AS record_status,
            CASE WHEN octet_length(p.operation_id)=36 THEN p.operation_id END AS receipt_operation,
            CASE WHEN octet_length(p.artifact_id)=36 THEN p.artifact_id END AS receipt_artifact,
            CASE WHEN octet_length(p.request_id)=36 THEN p.request_id END AS receipt_request,
            CASE WHEN octet_length(p.owner_actor_id) BETWEEN 1 AND 512 THEN p.owner_actor_id END AS receipt_owner,
            CASE WHEN octet_length(p.source_thread_id) BETWEEN 1 AND 512 THEN p.source_thread_id END AS receipt_thread,
            CASE WHEN octet_length(p.source_run_id) BETWEEN 1 AND 512 THEN p.source_run_id END AS receipt_run,
            CASE WHEN octet_length(p.source_message_id) BETWEEN 1 AND 512 THEN p.source_message_id END AS receipt_message,
            p.source_call_seq AS receipt_call,p.source_attempt_seq AS receipt_attempt
          FROM (SELECT 1) anchor LEFT JOIN requested_operation o ON true
          LEFT JOIN openbot_internal.artifact_records a ON a.deployment_id=o.deployment_id
            AND a.tenant_id=o.tenant_id AND a.dataset_id=o.dataset_id AND a.artifact_id=o.artifact_id
          LEFT JOIN public.threads t ON t.thread_id=o.source_thread_id
          LEFT JOIN openbot_internal.artifact_saved_receipts p ON p.deployment_id=o.deployment_id
            AND p.tenant_id=o.tenant_id AND p.dataset_id=o.dataset_id AND p.operation_id=o.operation_id
        ) SELECT observed.*,
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d
            JOIN openbot_internal.artifact_store_bindings b USING(deployment_id,tenant_id,dataset_id)
            WHERE d.deployment_id=$3 AND d.tenant_id=$4 AND d.dataset_id=$6 AND d.binding_schema=$7
              AND d.initial_origin=$8 AND d.created_at=$9 AND b.store_id=$10
              AND b.root_device=$11 AND b.root_inode=$12 AND b.root_uid=$13) AS current_store_binding,
          u.id AS read_host_user,u.auth_generation AS read_host_generation,
          CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS read_host_email,
          EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked,
          ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS read_host_roles,
          s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token,
          s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,
          s.auth_generation AS read_session_generation {canary_columns}
          FROM observed LEFT JOIN public.users u ON u.id=$2
          LEFT JOIN public.sessions s ON s.id=$14 AND s.user_id=u.id {canary_joins}"#)
    })
}

#[cfg(test)]
pub(super) struct SaveReceiptRollbackGate {
    first_pending: tokio::sync::oneshot::Sender<Instant>,
    resume: tokio::sync::oneshot::Receiver<()>,
    actual_ack: tokio::sync::oneshot::Sender<bool>,
}

#[cfg(test)]
async fn rollback_with_reviewed_pending_gate(
    authority: &PostgresArtifactReadAuthority,
    tx: deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), ArtifactReadCurrentError> {
    use std::future::{Future as _, poll_fn};
    use std::task::Poll;
    let gate = authority
        .save_receipt_rollback_gate
        .lock()
        .map_err(|_| host_unavailable())?
        .take();
    let mut original = Box::pin(tx.rollback());
    let limit = tokio::time::Instant::from_std(deadline);
    let Some(gate) = gate else {
        return tokio::time::timeout_at(limit, original)
            .await
            .map_err(|_| host_unavailable())?
            .map_err(|_| host_unavailable());
    };
    let first = poll_fn(|cx| match original.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(None),
        Poll::Ready(result) => Poll::Ready(Some(result)),
    })
    .await;
    let result = if let Some(result) = first {
        result
    } else {
        gate.first_pending
            .send(deadline)
            .map_err(|_| host_unavailable())?;
        tokio::time::timeout_at(limit, gate.resume)
            .await
            .map_err(|_| host_unavailable())?
            .map_err(|_| host_unavailable())?;
        tokio::time::timeout_at(limit, original)
            .await
            .map_err(|_| host_unavailable())?
    };
    let _ = gate.actual_ack.send(result.is_ok());
    result.map_err(|_| host_unavailable())
}

#[cfg(test)]
#[path = "save_receipt_tests.rs"]
mod tests;
