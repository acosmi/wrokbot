//! IDs-only final observation. This child never opens an artifact or manufactures a host proof.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use openbot_contracts::artifacts::{
    GetSourceRunArtifactIds, SourceRunArtifactIds, canonical_artifact_uuid_v7,
    is_valid_artifact_identity,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::{RunId, ThreadId};
use openbot_contracts::request_binding::{
    ArtifactReadCurrentError, ArtifactReadTailWitness, HostRequestBindingKind,
    SourceRunArtifactIdsCurrentOutcome, SourceRunArtifactIdsCurrentTarget,
};
use tokio_postgres::{IsolationLevel, Row};

use super::{
    CurrentHost, PostgresArtifactAdministration, PostgresArtifactReadAuthority, decode_host,
    host_not_current, host_unavailable, remaining, same_original_auth,
};

struct RequestedSourceRunArtifactIdsTarget {
    identity: Arc<()>,
    auth: AuthContext,
    input: GetSourceRunArtifactIds,
}
impl SourceRunArtifactIdsCurrentTarget for RequestedSourceRunArtifactIdsTarget {
    fn source_thread_id(&self) -> &str {
        self.input.source_thread_id.as_str()
    }
    fn source_run_id(&self) -> &str {
        self.input.source_run_id.as_str()
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
    input: &GetSourceRunArtifactIds,
    deadline: Instant,
) -> SourceRunArtifactIdsCurrentOutcome {
    let original = auth.request_binding().ok_or_else(host_unavailable)?;
    if !matches!(
        original.kind(),
        HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
    ) {
        return Err(host_unavailable());
    }
    let target = RequestedSourceRunArtifactIdsTarget {
        identity: Arc::clone(&authority.identity),
        auth: auth.clone(),
        input: input.clone(),
    };
    original
        .verify_source_run_artifact_ids_current_before(auth, &target, deadline)
        .await
}

pub(super) async fn observe(
    authority: &PostgresArtifactReadAuthority,
    auth: &AuthContext,
    target: &dyn SourceRunArtifactIdsCurrentTarget,
    host: CurrentHost<'_>,
    deadline: Instant,
) -> SourceRunArtifactIdsCurrentOutcome {
    remaining(deadline)?;
    if !target.matches_authority(&authority.identity) || !target.matches_auth(auth) {
        return Err(host_not_current());
    }
    if !is_valid_artifact_identity(target.source_thread_id())
        || !is_valid_artifact_identity(target.source_run_id())
    {
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
    target: &dyn SourceRunArtifactIdsCurrentTarget,
    host: CurrentHost<'_>,
    deadline: Instant,
) -> SourceRunArtifactIdsCurrentOutcome {
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
            source_run_ids_phase = "joint_statement_ready",
            "source_run_artifact_ids_current_phase"
        );
        let row = tx
            .query_one(
                current_sql(matches!(&host, CurrentHost::Desktop(_))),
                &[
                    &target.source_thread_id(),
                    &target.source_run_id(),
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
        // The host is classified first even for a missing source or corrupt materialized row.
        let witness = decode_host(administration, auth, &row, &host)?;
        let source = decode_source(administration, target, &row);
        tracing::trace!(
            source_run_ids_phase = "joint_result_observed_before_rollback",
            "source_run_artifact_ids_current_phase"
        );
        Ok::<_, ArtifactReadCurrentError>((witness, source))
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
    if rollback.is_ok() {
        tracing::trace!(
            source_run_ids_phase = "rollback_acknowledged_before_tail",
            "source_run_artifact_ids_current_phase"
        );
    }
    if let Ok((witness, _)) = &outcome {
        witness.verify_current(auth, deadline)?;
    }
    remaining(deadline)?;
    rollback?;
    let (witness, source) = outcome?;
    Ok((Box::new(witness), source))
}

fn decode_source(
    administration: &PostgresArtifactAdministration,
    target: &dyn SourceRunArtifactIdsCurrentTarget,
    row: &Row,
) -> Result<SourceRunArtifactIds, ArtifactReadCurrentError> {
    let field = |_| ArtifactReadCurrentError::Unavailable;
    if !row.try_get::<_, bool>("source_visible").map_err(field)? {
        return Err(ArtifactReadCurrentError::NotVisible);
    }
    if !row
        .try_get::<_, bool>("current_store_binding")
        .map_err(field)?
        || !administration
            .store
            .matches_registry_owner(&administration.registry)
        || !row.try_get::<_, bool>("records_valid").map_err(field)?
    {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    let artifact_ids: Vec<String> = row.try_get("artifact_ids").map_err(field)?;
    if artifact_ids.len() > 32
        || artifact_ids
            .iter()
            .any(|id| canonical_artifact_uuid_v7(id).as_deref() != Some(id.as_str()))
        || artifact_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    Ok(SourceRunArtifactIds {
        source_thread_id: ThreadId::new(target.source_thread_id()),
        source_run_id: RunId::new(target.source_run_id()),
        artifact_ids,
    })
}

fn current_sql(desktop: bool) -> &'static str {
    static SESSION: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let sql = if desktop { &DESKTOP } else { &SESSION };
    sql.get_or_init(|| {
        let visible = crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;
        let (canary_columns, canary_joins) = if desktop {
            (
                ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
                 CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
                 CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
                 CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
                 CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
                 c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
                 CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
                " LEFT JOIN pg_control_system() pcs ON true \
                  LEFT JOIN pg_database d ON d.datname=current_database() \
                  LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$4 AND c.tenant_id=$5 AND c.key_version=1",
            )
        } else { ("", "") };
        format!(r#"/* source_run_artifact_ids_joint_current */ {visible}, bounded_source_artifacts AS (
          SELECT a.artifact_id,
            coalesce(o.operation_id IS NOT NULL AND o.state=a.status
              AND a.artifact_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
              AND a.operation_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
              AND a.request_id ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
              AND ((a.source_call_seq IS NULL AND a.source_attempt_seq IS NULL)
                OR (a.source_call_seq>=0 AND a.source_attempt_seq>=0))
              AND (
                (a.status IN ('deleted','expired')
                  AND a.workspace_kind IS NULL AND a.workspace_id IS NULL AND a.media_type IS NULL
                  AND a.byte_length IS NULL AND a.sha256 IS NULL AND a.retention_class IS NULL
                  AND a.saved_by IS NULL AND a.saved_at IS NULL
                  AND o.store_id IS NULL AND o.workspace_kind IS NULL AND o.workspace_id IS NULL
                  AND o.expected_sha256 IS NULL AND o.expected_bytes IS NULL AND o.charged_bytes IS NULL
                  AND o.actual_absent IS NULL AND o.actual_byte_length IS NULL AND o.actual_sha256 IS NULL
                  AND o.actual_location IS NULL AND o.observation_phase IS NULL AND o.created_at IS NULL)
                OR (a.status IN ('available','failed_partial') AND o.store_id=$11
                  AND a.workspace_kind=CASE t.anchor_kind WHEN 'channel' THEN 'channel' WHEN 'direct_bot' THEN 'thread' END
                  AND a.workspace_id=CASE t.anchor_kind WHEN 'channel' THEN t.anchor_id WHEN 'direct_bot' THEN t.thread_id END
                  AND o.workspace_kind=a.workspace_kind AND o.workspace_id=a.workspace_id
                  AND a.media_type='text/plain; charset=utf-8' AND a.byte_length BETWEEN 0 AND 67108864
                  AND a.sha256 ~ '^[0-9a-f]{{64}}$' AND a.retention_class='explicit_saved'
                  AND a.saved_by=a.owner_actor_id AND a.saved_at IS NOT NULL AND o.created_at IS NOT NULL
                  AND o.expected_sha256 ~ '^[0-9a-f]{{64}}$' AND o.expected_bytes BETWEEN 1 AND 67108864
                  AND o.charged_bytes=a.byte_length AND o.actual_absent IS FALSE
                  AND o.actual_byte_length=a.byte_length AND o.actual_sha256=a.sha256
                  AND o.actual_location IN ('staging','object')
                  AND o.observation_phase IN ('before_write','staging','installing','installed')
                  AND (a.status='failed_partial' OR (a.byte_length>0 AND o.expected_bytes=a.byte_length
                    AND o.expected_sha256=a.sha256 AND o.actual_location='object' AND o.observation_phase='installed')))
              ),false) AS integrity
          FROM visible_run r JOIN openbot_internal.artifact_records a
            ON a.source_thread_id=r.thread_id AND a.source_run_id=r.run_id
          JOIN public.threads t ON t.thread_id=r.thread_id
          JOIN public.messages m ON m.message_id=a.source_message_id AND m.thread_id=a.source_thread_id
            AND m.run_id=a.source_run_id AND m.actor_id=a.owner_actor_id AND m.role='user'
          LEFT JOIN openbot_internal.artifact_save_operations o
            ON o.deployment_id=a.deployment_id AND o.tenant_id=a.tenant_id AND o.dataset_id=a.dataset_id
            AND o.operation_id=a.operation_id AND o.artifact_id=a.artifact_id AND o.request_id=a.request_id
            AND o.owner_actor_id=a.owner_actor_id AND o.source_thread_id=a.source_thread_id
            AND o.source_run_id=a.source_run_id AND o.source_message_id=a.source_message_id
            AND o.source_call_seq IS NOT DISTINCT FROM a.source_call_seq
            AND o.source_attempt_seq IS NOT DISTINCT FROM a.source_attempt_seq
          WHERE a.owner_actor_id=$3 AND a.deployment_id=$4 AND a.tenant_id=$5 AND a.dataset_id=$7
          ORDER BY a.artifact_id COLLATE "C" LIMIT 33
        ) SELECT
          EXISTS(SELECT 1 FROM visible_run) AS source_visible,
          ARRAY(SELECT artifact_id FROM bounded_source_artifacts ORDER BY artifact_id COLLATE "C") AS artifact_ids,
          NOT EXISTS(SELECT 1 FROM bounded_source_artifacts WHERE NOT integrity) AS records_valid,
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d
            JOIN openbot_internal.artifact_store_bindings b USING(deployment_id,tenant_id,dataset_id)
            WHERE d.deployment_id=$4 AND d.tenant_id=$5 AND d.dataset_id=$7 AND d.binding_schema=$8
              AND d.initial_origin=$9 AND d.created_at=$10 AND b.store_id=$11
              AND b.root_device=$12 AND b.root_inode=$13 AND b.root_uid=$14) AS current_store_binding,
          u.id AS read_host_user,u.auth_generation AS read_host_generation,
          CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS read_host_email,
          EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked,
          ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS read_host_roles,
          s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token,
          s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,
          s.auth_generation AS read_session_generation {canary_columns}
          FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$3
          LEFT JOIN public.sessions s ON s.id=$15 AND s.user_id=u.id {canary_joins}"#)
    })
}

#[cfg(test)]
pub(super) struct SourceRunIdsRollbackGate {
    first_pending: tokio::sync::oneshot::Sender<()>,
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
        .source_run_ids_rollback_gate
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
        // A Ready first poll is an actual result, never a fabricated Pending observation.
        result
    } else {
        gate.first_pending
            .send(())
            .map_err(|_| host_unavailable())?;
        tokio::time::timeout_at(limit, gate.resume)
            .await
            .map_err(|_| host_unavailable())?
            .map_err(|_| host_unavailable())?;
        tokio::time::timeout_at(limit, original)
            .await
            .map_err(|_| host_unavailable())?
    };
    // False qualifies an actually returned error. Timeout/Drop sends no presumed ACK.
    let _ = gate.actual_ack.send(result.is_ok());
    result.map_err(|_| host_unavailable())
}

#[cfg(test)]
#[path = "source_run_ids_tests.rs"]
mod tests;
