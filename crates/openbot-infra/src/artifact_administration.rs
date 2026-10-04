//! R424 real user-message registration. Every mutation owns its registry Pool and RC transaction.
//! Durable admission and IO_STARTED acknowledgements precede once-only physical IO. Unknown
//! outcomes retain the original operation/charge; observation never grants a retry or byte read.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use openbot_application::{ArtifactAdministration, ArtifactAdministrationError};
use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactMetadata, ArtifactRecordMetadata, ArtifactRegistrationReceipt,
    ArtifactRetentionClass, ArtifactTombstone, ArtifactWorkspace, SaveRunMessageTextArtifact,
    canonical_artifact_uuid_v7, is_valid_artifact_identity, is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::artifact::{ArtifactQuotaPolicy, ArtifactWorkspaceKey};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::secret::SecretBytes;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row, Transaction};
use uuid::Uuid;

use crate::artifact_bytes::ArtifactBlob;
use crate::artifact_registry::{ARTIFACT_REGISTRY_SCHEMA_SQL, ArtifactDatasetRegistry};
use crate::artifact_store::{
    ArtifactByteObservationState, DatasetBoundArtifactStore, VerifiedArtifactByteObservation,
};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;

#[path = "artifact_read_authority.rs"]
pub mod artifact_read_authority;
#[path = "artifact_read_lifecycle.rs"]
pub mod artifact_read_lifecycle;

const WAIT: Duration = Duration::from_secs(5);
const PG_PHASE: Duration = Duration::from_secs(30);
const MEDIA: &str = "text/plain; charset=utf-8";
const TABLES: [&str; 6] = [
    "artifact_store_bindings",
    "artifact_workspace_quotas",
    "artifact_run_quotas",
    "artifact_save_operations",
    "artifact_records",
    "artifact_saved_receipts",
];
// Independently captured from the owned actual native0042 PostgreSQL schema. Runtime compares
// every captured catalog field exactly; capture itself never depends on this oracle.
const REGISTERED_REGISTRATION_SCHEMA: &str =
    include_str!("../../../fixtures/db/artifact-registration-0042.json");

/// Real ordered catalog observations, independently frozen by the schema generation test.
pub type ArtifactRegistrationSchemaFacts = Value;

/// Capture the six real internal relations, including exact guards, collation and enabled hooks.
pub async fn capture_artifact_registration_schema(
    pool: &Pool,
) -> Result<ArtifactRegistrationSchemaFacts, ArtifactAdministrationError> {
    let client = tokio::time::timeout(WAIT, pool.get())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    let mut tables = Map::new();
    for name in TABLES {
        let sql = ARTIFACT_REGISTRY_SCHEMA_SQL.replace("artifact_dataset_bindings", name);
        let row = tokio::time::timeout(WAIT, client.query_one(&sql, &[]))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let raw: String = row.try_get(0).map_err(|_| corrupt("schema_facts"))?;
        tables.insert(
            name.to_owned(),
            serde_json::from_str(&raw).map_err(|_| corrupt("schema_facts"))?,
        );
    }
    let row = tokio::time::timeout(WAIT, client.query_one(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'definition',pg_get_functiondef(p.oid),         'arguments',pg_get_function_identity_arguments(p.oid),'securityDefiner',p.prosecdef,'configuration',p.proconfig)         ORDER BY p.proname),'[]'::jsonb)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace         WHERE n.nspname='openbot_internal' AND p.proname IN ('prevent_artifact_operation_misuse','prevent_artifact_record_misuse')", &[])).await
        .map_err(|_| unavailable())?.map_err(|_| unavailable())?;
    let raw: String = row.try_get(0).map_err(|_| corrupt("schema_guards"))?;
    tables.insert(
        "registration_guards".to_owned(),
        serde_json::from_str(&raw).map_err(|_| corrupt("schema_guards"))?,
    );
    Ok(Value::Object(tables))
}

/// Verify current native/public/registry facts and the independently captured registration oracle.
pub async fn verify_artifact_registration_schema(
    pool: &Pool,
) -> Result<(), ArtifactAdministrationError> {
    tokio::time::timeout(PG_PHASE, verify_registration_schema_inner(pool))
        .await
        .map_err(|_| unavailable())?
}

async fn verify_registration_schema_inner(pool: &Pool) -> Result<(), ArtifactAdministrationError> {
    crate::artifact_registry::verify_artifact_registry_schema(pool)
        .await
        .map_err(|_| corrupt("registry_schema"))?;
    let expected: Value = serde_json::from_str(REGISTERED_REGISTRATION_SCHEMA)
        .map_err(|_| corrupt("registration_oracle"))?;
    if capture_artifact_registration_schema(pool).await? != expected {
        return Err(corrupt("registration_schema"));
    }
    Ok(())
}

/// Shared authenticated save adapter, retaining the exact trusted dataset and live byte owner.
pub struct PostgresArtifactAdministration {
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    policy: ArtifactQuotaPolicy,
    audit_key: SecretBytes,
    read_authority: OnceLock<Arc<artifact_read_authority::PostgresArtifactReadAuthority>>,
}

/// A single owned-PG record/source snapshot bound to its exact actual byte-store owner.
///
/// Private construction prevents a metadata DTO or caller-provided digest from becoming a
/// descriptor. This value is deliberately not a current session/window ticket: authorization
/// can change after its final PostgreSQL statement. A future public byte handoff must recheck
/// its own current host and source authority. Move this value into the actual blocking job;
/// dropping a future waiting for that job does not stop IO or release the job's root owner.
pub struct ObservedArtifactReadRecord {
    store: Arc<DatasetBoundArtifactStore>,
    blob: ArtifactBlob,
    auth_snapshot: AuthContext,
    source_snapshot: ArtifactRegistrationReceipt,
    workspace_snapshot: ArtifactWorkspaceKey,
}

impl core::fmt::Debug for ObservedArtifactReadRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObservedArtifactReadRecord")
            .field("record_and_source", &"<redacted snapshot>")
            .finish()
    }
}

impl ObservedArtifactReadRecord {
    pub(crate) fn matches_store(&self, store: &Arc<DatasetBoundArtifactStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
            && self.source_snapshot.artifact_id == self.blob.id().to_string()
            && self.source_snapshot.owner_actor_id == *self.auth_snapshot.actor()
            && is_valid_artifact_identity(self.workspace_snapshot.id())
    }

    pub(crate) const fn blob(&self) -> &ArtifactBlob {
        &self.blob
    }
}

impl PostgresArtifactAdministration {
    /// Compose actual current owners; a second Pool or caller-created transaction is not accepted.
    pub fn new(
        registry: Arc<ArtifactDatasetRegistry>,
        store: Arc<DatasetBoundArtifactStore>,
        policy: ArtifactQuotaPolicy,
        audit_key: SecretBytes,
    ) -> Result<Self, ArtifactAdministrationError> {
        if !store.matches_registry_owner(&registry) || audit_key.is_empty() {
            return Err(unavailable());
        }
        Ok(Self {
            registry,
            store,
            policy,
            audit_key,
            read_authority: OnceLock::new(),
        })
    }

    /// Retain one actual reader authority; its weak administration link never forms a cycle.
    pub fn read_authority(
        self: &Arc<Self>,
    ) -> Arc<artifact_read_authority::PostgresArtifactReadAuthority> {
        Arc::clone(self.read_authority.get_or_init(|| {
            Arc::new(
                artifact_read_authority::PostgresArtifactReadAuthority::from_administration(self),
            )
        }))
    }

    /// Observe one currently visible available record using only this adapter's actual Pool.
    ///
    /// The final RC statement jointly observes the unchanged R398 source predicate, the exact
    /// saved message relationship, operation payload and current dataset/store tuple. The
    /// explicit read-only rollback completes before the snapshot is returned. No physical IO,
    /// session renewal, audit event or current byte-delivery authority is produced here.
    pub async fn observe_read_record(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        #[cfg(test)]
        return self
            .observe_read_record_inner(auth, artifact_id, None)
            .await;
        #[cfg(not(test))]
        self.observe_read_record_inner(auth, artifact_id).await
    }

    async fn observe_read_record_inner(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        #[cfg(test)] final_query_gate: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        tokio::time::timeout(PG_PHASE, async {
            let id = canonical_artifact_uuid_v7(artifact_id).ok_or(
                ArtifactAdministrationError::InvalidInput {
                    field: "artifactId",
                },
            )?;
            self.check_namespace(auth)?;
            verify_artifact_registration_schema(self.registry.pool()).await?;
            let mut client = self.connection().await?;
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .read_only(true)
                .start()
                .await
                .map_err(|_| unavailable())?;
            // Every statement outcome, including an error, is retained until rollback is
            // explicitly awaited. Timeout/drop does not prove the server worker has finished.
            let outcome = async {
                setup(&tx).await?;
                let b = self.registry.binding();
                let seed = tx.query_opt(
                    "SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
                     WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 \
                       AND artifact_id=$4 AND owner_actor_id=$5",
                    &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &id,
                      &auth.actor().as_str()],
                ).await.map_err(|_| unavailable())?
                    .ok_or(ArtifactAdministrationError::NotVisible)?;
                let thread: String = value(&seed, "source_thread_id")?;
                let run: String = value(&seed, "source_run_id")?;
                let generation = i64::try_from(auth.auth_generation().get())
                    .map_err(|_| ArtifactAdministrationError::NotVisible)?;
                let physical = self.store.physical_binding();
                // Tests coordinate after the actual preflight/seed, then still require the
                // final statement's real PG lock wait. No gate exists in release builds.
                #[cfg(test)]
                if let Some((reached, proceed)) = final_query_gate {
                    reached.send(()).map_err(|_| unavailable())?;
                    proceed.await.map_err(|_| unavailable())?;
                }
                let row = tx
                    .query_opt(
                        observed_read_sql(),
                        &[
                            &thread,
                            &run,
                            &auth.actor().as_str(),
                            &auth.deployment().as_str(),
                            &auth.tenant().as_str(),
                            &generation,
                            &id,
                            &b.dataset_id(),
                            &b.binding_schema(),
                            &b.initial_origin(),
                            &b.created_at(),
                            &self.store.store_id().to_string(),
                            &physical.device(),
                            &physical.inode(),
                            &physical.uid(),
                        ],
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .ok_or(ArtifactAdministrationError::NotVisible)?;
                self.decode_read_record(auth, &row)
            }
            .await;
            tx.rollback().await.map_err(|_| unavailable())?;
            outcome
        })
        .await
        .map_err(|_| unavailable())?
    }

    fn decode_read_record(
        &self,
        auth: &AuthContext,
        row: &Row,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        if !value::<bool>(row, "current_store_binding")?
            || !self.store.matches_registry_owner(&self.registry)
        {
            return Err(unavailable());
        }
        let status: String = value(row, "status")?;
        match status.as_str() {
            "deleted" => {
                return Err(ArtifactAdministrationError::Gone {
                    status: ArtifactGoneStatus::Deleted,
                });
            }
            "expired" => {
                return Err(ArtifactAdministrationError::Gone {
                    status: ArtifactGoneStatus::Expired,
                });
            }
            "failed_partial" => return Err(unavailable()),
            "available" => {}
            _ => return Err(corrupt("read_status")),
        }
        let source = decode_receipt(row)?; // Actual row IDs, never a historical receipt lookup.
        if source.owner_actor_id != *auth.actor()
            || canonical_artifact_uuid_v7(&source.artifact_id).as_deref()
                != Some(source.artifact_id.as_str())
            || canonical_artifact_uuid_v7(&source.operation_id).as_deref()
                != Some(source.operation_id.as_str())
            || canonical_artifact_uuid_v7(&source.request_id).as_deref()
                != Some(source.request_id.as_str())
            || !ThreadIdentity::is_plausible(&source.source_thread_id)
            || !is_valid_artifact_identity(source.source_run_id.as_str())
            || !is_valid_artifact_identity(&source.source_message_id)
            || source.source_call_seq.is_some()
            || source.source_attempt_seq.is_some()
        {
            return Err(corrupt("read_source_snapshot"));
        }
        let kind: String = value(row, "workspace_kind")?;
        let workspace_id: String = value(row, "workspace_id")?;
        let workspace = ArtifactWorkspaceKey::new(
            match kind.as_str() {
                "channel" => openbot_domain::artifact::ArtifactWorkspaceKind::Channel,
                "thread" => openbot_domain::artifact::ArtifactWorkspaceKind::Thread,
                _ => return Err(corrupt("read_workspace")),
            },
            &workspace_id,
        )
        .map_err(|_| corrupt("read_workspace"))?;
        let length = unsigned(value(row, "byte_length")?)?;
        let sha256: String = value(row, "sha256")?;
        if length == 0
            || !is_valid_artifact_sha256(&sha256)
            || value::<String>(row, "media_type")? != MEDIA
            || value::<String>(row, "retention_class")? != "explicit_saved"
            || value::<Option<String>>(row, "saved_by")?.as_deref() != Some(auth.actor().as_str())
            || value::<Option<OffsetDateTime>>(row, "saved_at")?.is_none()
            || value::<String>(row, "source_workspace_kind")? != kind
            || value::<String>(row, "source_workspace_id")? != workspace_id
        {
            return Err(corrupt("read_record_payload"));
        }
        // A current record alone cannot select another operation's bytes or invent installed
        // bytes for an unresolved/partial operation. All nullable actual fields must be real.
        if value::<Option<String>>(row, "op_state")?.as_deref() != Some("available")
            || value::<Option<String>>(row, "op_store_id")?.as_deref()
                != Some(self.store.store_id().to_string().as_str())
            || value::<Option<String>>(row, "op_workspace_kind")?.as_deref() != Some(kind.as_str())
            || value::<Option<String>>(row, "op_workspace_id")?.as_deref()
                != Some(workspace_id.as_str())
            || value::<Option<String>>(row, "op_expected_sha256")?.as_deref()
                != Some(sha256.as_str())
            || value::<Option<i64>>(row, "op_expected_bytes")? != Some(integer(length)?)
            || value::<Option<i64>>(row, "op_charged_bytes")? != Some(integer(length)?)
            || value::<Option<bool>>(row, "op_actual_absent")? != Some(false)
            || value::<Option<i64>>(row, "op_actual_byte_length")? != Some(integer(length)?)
            || value::<Option<String>>(row, "op_actual_sha256")?.as_deref() != Some(sha256.as_str())
            || value::<Option<String>>(row, "op_actual_location")?.as_deref() != Some("object")
            || value::<Option<String>>(row, "op_observation_phase")?.as_deref() != Some("installed")
        {
            return Err(corrupt("read_operation_payload"));
        }
        let blob = ArtifactBlob::from_record(
            Uuid::parse_str(&source.artifact_id).map_err(|_| corrupt("read_artifact_id"))?,
            length,
            parse_digest(&sha256)?,
        )
        .map_err(|_| corrupt("read_blob_binding"))?;
        Ok(ObservedArtifactReadRecord {
            store: Arc::clone(&self.store),
            blob,
            auth_snapshot: auth.clone(),
            source_snapshot: source,
            workspace_snapshot: workspace,
        })
    }

    async fn connection(&self) -> Result<deadpool_postgres::Object, ArtifactAdministrationError> {
        tokio::time::timeout(WAIT, self.registry.pool().get())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
    }

    async fn admit(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        disk_bytes: u64,
    ) -> Result<AdmissionOutcome, ArtifactAdministrationError> {
        let mut client = self.connection().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| unavailable())?;
        setup(&tx).await?;
        self.lock_actor(&tx, auth).await?;
        let source = self.lock_source(&tx, auth, input).await?;
        self.check_binding(&tx).await?;
        self.lock_quota(&tx, &source.workspace, input.source_run_id.as_str())
            .await?;
        let existing = tx.query_opt(
            "SELECT * FROM openbot_internal.artifact_save_operations \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND request_id=$4 FOR UPDATE",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &input.request_id],
        ).await.map_err(|_| unavailable())?;
        // Unique-key/quota waits occurred after the initial authority observation. Re-read all
        // current facts in a NEW RC statement; locks keep their positive entities stable.
        let fresh = self.fresh_source(&tx, auth, input).await?;
        source.ensure_same(&fresh)?;
        self.check_binding(&tx).await?;
        if let Some(row) = existing {
            ensure_intent(&row, auth, input, &fresh)?;
            let state: String = value(&row, "state")?;
            if state == "available" {
                let op: String = value(&row, "operation_id")?;
                let receipt = self.receipt(&tx, &op).await?;
                // Do not publish an observation after any later wait without current source facts.
                self.fresh_source(&tx, auth, input)
                    .await?
                    .ensure_same(&fresh)?;
                tx.rollback().await.map_err(|_| unavailable())?;
                return Ok(AdmissionOutcome::Observed(receipt));
            }
            return Err(unavailable());
        }
        if fresh.sha256 != input.expected_sha256 {
            return Err(ArtifactAdministrationError::InvalidInput {
                field: "expectedSha256",
            });
        }
        let len = fresh.length;
        if len > disk_bytes {
            return Err(ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_disk_space",
            });
        }
        let (count, charged) = self
            .usage(&tx, &fresh.workspace, input.source_run_id.as_str())
            .await?;
        let projected = self
            .policy
            .project_registration(count, charged, len)
            .map_err(|_| ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_quota",
            })?;
        let operation_id = Uuid::now_v7().to_string();
        let artifact_id = Uuid::now_v7();
        let store_id = self.store.store_id().to_string();
        let len_pg = integer(len)?;
        let inserted = tx.execute(
            "INSERT INTO openbot_internal.artifact_save_operations \
             (deployment_id,tenant_id,dataset_id,request_id,operation_id,artifact_id,owner_actor_id,\
              source_thread_id,source_run_id,source_message_id,state,store_id,workspace_kind,workspace_id,\
              expected_sha256,expected_bytes,charged_bytes,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'admitted',$11,$12,$13,$14,$15,$15,clock_timestamp()) ON CONFLICT(deployment_id,tenant_id,dataset_id,request_id) DO NOTHING",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &input.request_id, &operation_id,
              &artifact_id.to_string(), &auth.actor().as_str(), &input.source_thread_id.as_str(),
              &input.source_run_id.as_str(), &input.source_message_id.as_str(), &store_id,
              &fresh.workspace.kind().as_str(), &fresh.workspace.id(), &input.expected_sha256, &len_pg],
        ).await.map_err(|_| unavailable())?;
        if inserted != 1 {
            // Another namespace locator may win without sharing this actor or workspace lock.
            // A new statement after the unique-key wait sees that original intent; never mint IO.
            self.fresh_source(&tx, auth, input)
                .await?
                .ensure_same(&fresh)?;
            self.check_binding(&tx).await?;
            return Err(ArtifactAdministrationError::RequestConflict);
        }
        self.set_usage(
            &tx,
            &fresh.workspace,
            input.source_run_id.as_str(),
            projected.run_identities(),
            projected.workspace_charged_bytes(),
        )
        .await?;
        self.fresh_source(&tx, auth, input)
            .await?
            .ensure_same(&fresh)?;
        self.check_binding(&tx).await?;
        commit(tx).await?;
        Ok(AdmissionOutcome::Prepared(Admission {
            operation_id,
            artifact_id,
            source: fresh,
            length: len,
        }))
    }

    async fn start_io(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        admission: &Admission,
    ) -> Result<(), ArtifactAdministrationError> {
        let mut client = self.connection().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| unavailable())?;
        setup(&tx).await?;
        self.lock_actor(&tx, auth).await?;
        self.lock_source(&tx, auth, input)
            .await?
            .ensure_same(&admission.source)?;
        self.check_binding(&tx).await?;
        self.lock_quota(
            &tx,
            &admission.source.workspace,
            input.source_run_id.as_str(),
        )
        .await?;
        let row = self.operation(&tx, &admission.operation_id).await?;
        ensure_intent(&row, auth, input, &admission.source)?;
        if value::<String>(&row, "state")? != "admitted"
            || value::<String>(&row, "artifact_id")? != admission.artifact_id.to_string()
        {
            return Err(unavailable());
        }
        self.fresh_source(&tx, auth, input)
            .await?
            .ensure_same(&admission.source)?;
        self.check_binding(&tx).await?;
        tx.execute(
            "UPDATE openbot_internal.artifact_save_operations SET state='io_started' \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 AND state='admitted'",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.operation_id],
        ).await.map_err(|_| unavailable())?;
        commit(tx).await
    }

    async fn finalize(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        admission: &Admission,
        observation: &VerifiedArtifactByteObservation,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        if !observation.matches_store(&self.store)
            || observation.artifact_id() != admission.artifact_id
        {
            return Err(corrupt("byte_owner"));
        }
        let mut client = self.connection().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| unavailable())?;
        setup(&tx).await?;
        // A no-row authority result does not abort the transaction. Retain real failure facts
        // under the original private admission, without granting the revoked caller a read.
        let authorized = match self.lock_actor(&tx, auth).await {
            Ok(()) => match self.lock_source(&tx, auth, input).await {
                Ok(source) => source.ensure_same(&admission.source).is_ok(),
                Err(
                    ArtifactAdministrationError::NotVisible
                    | ArtifactAdministrationError::InvalidInput { .. },
                ) => false,
                Err(error) => return Err(error),
            },
            Err(ArtifactAdministrationError::NotVisible) => false,
            Err(error) => return Err(error),
        };
        self.check_binding(&tx).await?;
        self.lock_quota(
            &tx,
            &admission.source.workspace,
            input.source_run_id.as_str(),
        )
        .await?;
        let row = self.operation(&tx, &admission.operation_id).await?;
        ensure_intent(&row, auth, input, &admission.source)?;
        if value::<String>(&row, "state")? != "io_started"
            || value::<String>(&row, "artifact_id")? != admission.artifact_id.to_string()
        {
            return Err(unavailable());
        }
        let (audit_id, audit_time) = if authorized
            && matches!(
                observation.state(),
                ArtifactByteObservationState::DurableInstalled { .. }
            ) {
            let coordinates = next_event_coordinates(&tx)
                .await
                .map_err(|_| unavailable())?;
            (Some(coordinates.0), Some(coordinates.1))
        } else {
            (None, None)
        };
        let authorized = authorized
            && match self.fresh_source(&tx, auth, input).await {
                Ok(current) => current.ensure_same(&admission.source).is_ok(),
                Err(
                    ArtifactAdministrationError::NotVisible
                    | ArtifactAdministrationError::InvalidInput { .. },
                ) => false,
                Err(error) => return Err(error),
            };
        self.check_binding(&tx).await?;
        let state = *observation.state();
        let mut positive = false;
        let (actual_absent, actual_len, actual_sha, actual_location, charge) = match state {
            ArtifactByteObservationState::DurableInstalled {
                byte_length,
                sha256,
            } => {
                positive = authorized
                    && byte_length == admission.length
                    && digest_hex(&sha256) == input.expected_sha256;
                (
                    Some(false),
                    Some(integer(byte_length)?),
                    Some(digest_hex(&sha256)),
                    Some("object"),
                    byte_length,
                )
            }
            ArtifactByteObservationState::RetainedPartial {
                location,
                byte_length,
                sha256,
            } => (
                Some(false),
                Some(integer(byte_length)?),
                Some(digest_hex(&sha256)),
                Some(location.as_str()),
                byte_length,
            ),
            ArtifactByteObservationState::DurableAbsent => (Some(true), None, None, None, 0),
            ArtifactByteObservationState::Indeterminate => {
                (None, None, None, None, admission.length)
            }
        };
        if charge > admission.length {
            return Err(corrupt("unexpected_retained_length"));
        }
        let record_failed = authorized && !positive && actual_absent == Some(false);
        let next_state = if positive {
            "available"
        } else if record_failed {
            "failed_partial"
        } else {
            "unresolved"
        };
        if positive || record_failed {
            let actual_len = actual_len.ok_or_else(|| corrupt("actual_length"))?;
            let actual_sha = actual_sha
                .as_deref()
                .ok_or_else(|| corrupt("actual_digest"))?;
            tx.execute(
                "INSERT INTO openbot_internal.artifact_records \
                 (deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,owner_actor_id,\
                  source_thread_id,source_run_id,source_message_id,status,workspace_kind,workspace_id,\
                  media_type,byte_length,sha256,retention_class,saved_by,saved_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'explicit_saved',$7,clock_timestamp())",
                &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
                  &self.registry.binding().dataset_id(), &admission.artifact_id.to_string(), &admission.operation_id,
                  &input.request_id, &auth.actor().as_str(), &input.source_thread_id.as_str(),
                  &input.source_run_id.as_str(), &input.source_message_id.as_str(), &next_state,
                  &admission.source.workspace.kind().as_str(), &admission.source.workspace.id(),
                  &MEDIA, &actual_len, &actual_sha],
            ).await.map_err(|_| unavailable())?;
        }
        let (_, charged) = self
            .usage(
                &tx,
                &admission.source.workspace,
                input.source_run_id.as_str(),
            )
            .await?;
        let old_charge = unsigned(value(&row, "charged_bytes")?)?;
        let new_charged = charged
            .checked_sub(old_charge)
            .and_then(|n| n.checked_add(charge))
            .ok_or_else(|| corrupt("quota_charge"))?;
        tx.execute(
            "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$6 \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.source.workspace.kind().as_str(),
              &admission.source.workspace.id(), &integer(new_charged)?],
        ).await.map_err(|_| unavailable())?;
        tx.execute(
            "UPDATE openbot_internal.artifact_save_operations SET state=$5,charged_bytes=$6,\
             actual_absent=$7,actual_byte_length=$8,actual_sha256=$9,actual_location=$10,observation_phase=$11 \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 AND state='io_started'",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.operation_id, &next_state, &integer(charge)?,
              &actual_absent, &actual_len, &actual_sha, &actual_location, &observation.phase().as_str()],
        ).await.map_err(|_| unavailable())?;
        let receipt = receipt_from(admission, auth, input);
        if positive {
            tx.execute(
                "INSERT INTO openbot_internal.artifact_saved_receipts \
                 (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,request_id,owner_actor_id,\
                  source_thread_id,source_run_id,source_message_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
                  &self.registry.binding().dataset_id(), &receipt.operation_id, &receipt.artifact_id,
                  &receipt.request_id, &auth.actor().as_str(), &input.source_thread_id.as_str(),
                  &input.source_run_id.as_str(), &input.source_message_id.as_str()],
            ).await.map_err(|_| unavailable())?;
            let artifact = AuditIdentifier::new(&receipt.artifact_id)
                .map_err(|_| corrupt("audit_artifact_id"))?;
            let operation = AuditIdentifier::new(&receipt.operation_id)
                .map_err(|_| corrupt("audit_operation_id"))?;
            let event = AuditEvent {
                id: audit_id.ok_or_else(|| corrupt("audit_coordinate"))?,
                actor: Some(auth.actor().clone()),
                event_type: AuditEventType::ARTIFACT_SAVED,
                target_kind: AuditLabel::new("artifact"),
                target_id: Some(artifact.clone()),
                payload: AuditPayload::from_facts([
                    AuditFact::ArtifactId(artifact),
                    AuditFact::ArtifactOperationId(operation),
                ])
                .map_err(|_| corrupt("audit_payload"))?,
                created_at: audit_time.ok_or_else(|| corrupt("audit_coordinate"))?,
            };
            append_event_in_transaction(&tx, &event, self.audit_key.expose())
                .await
                .map_err(|_| unavailable())?;
            // Covers later FK/unique/audit waits. If any currently checked authority changed,
            // rollback the tentative record/receipt; the durable IO_STARTED remains charged.
            self.fresh_source(&tx, auth, input)
                .await?
                .ensure_same(&admission.source)?;
            self.check_binding(&tx).await?;
        }
        commit(tx).await?;
        if positive {
            Ok(receipt)
        } else {
            Err(unavailable())
        }
    }

    async fn lock_actor(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
    ) -> Result<(), ArtifactAdministrationError> {
        self.check_namespace(auth)?;
        tx.query_opt(
            "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
            &[&auth.actor().as_str()],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 \
             AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin')) \
             AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))",
            &[&auth.actor().as_str(), &generation],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        Ok(())
    }

    async fn lock_source(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
    ) -> Result<Source, ArtifactAdministrationError> {
        // A caller-supplied locator grants no right to lock its rows. Establish the current
        // R398/message tuple first so a foreign or mismatched source stays uniformly invisible.
        let source = self.fresh_source(tx, auth, input).await?;
        let roles = tx.query("SELECT role FROM public.user_roles WHERE user_id=$1 AND role IN ('user','admin') ORDER BY role FOR SHARE NOWAIT",
            &[&auth.actor().as_str()]).await.map_err(|_| unavailable())?;
        if roles.is_empty() {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        tx.query_opt(
            "SELECT run_id FROM public.runs WHERE run_id=$1 AND thread_id=$2 AND actor_id=$3 FOR SHARE NOWAIT",
            &[&input.source_run_id.as_str(), &input.source_thread_id.as_str(), &auth.actor().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT thread_id FROM public.threads WHERE thread_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND status<>'deleted' FOR SHARE NOWAIT",
            &[&input.source_thread_id.as_str(), &auth.deployment().as_str(), &auth.tenant().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT message_id FROM public.messages WHERE message_id=$1 AND thread_id=$2 AND run_id=$3 AND actor_id=$4 AND role='user' FOR SHARE NOWAIT",
            &[&input.source_message_id.as_str(), &input.source_thread_id.as_str(), &input.source_run_id.as_str(), &auth.actor().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT id FROM public.agents WHERE id=$1 FOR SHARE NOWAIT",
            &[&source.bot],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT agent_id FROM public.agent_profiles WHERE agent_id=$1 FOR SHARE NOWAIT",
            &[&source.bot],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        if let Some(package) = &source.bot_package {
            tx.query_opt(
                "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT",
                &[package],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        }
        if source.workspace.kind().as_str() == "channel" {
            let channel = source.workspace.id();
            tx.query_opt(
                "SELECT id FROM public.channels WHERE id=$1 FOR SHARE NOWAIT",
                &[&channel],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
            tx.query_opt("SELECT channel_id FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                &[&channel, &auth.actor().as_str()]).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
            tx.query_opt("SELECT channel_id FROM public.channel_agents WHERE channel_id=$1 AND agent_id=$2 FOR SHARE NOWAIT",
                &[&channel, &source.bot]).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
            if let Some(package) = &source.channel_package {
                tx.query_opt(
                    "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT",
                    &[package],
                )
                .await
                .map_err(|_| unavailable())?
                .ok_or(ArtifactAdministrationError::NotVisible)?;
            }
        } else {
            tx.query_opt("SELECT thread_id FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                &[&input.source_thread_id.as_str(), &auth.actor().as_str()]).await.map_err(|_| unavailable())?
                .ok_or(ArtifactAdministrationError::NotVisible)?;
        }
        let fresh = self.fresh_source(tx, auth, input).await?;
        source.ensure_same(&fresh)?;
        Ok(fresh)
    }

    async fn fresh_source(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
    ) -> Result<Source, ArtifactAdministrationError> {
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| ArtifactAdministrationError::NotVisible)?;
        let row = tx
            .query_opt(
                source_sql(),
                &[
                    &input.source_thread_id.as_str(),
                    &input.source_run_id.as_str(),
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                    &input.source_message_id.as_str(),
                    &integer(self.policy.max_artifact_bytes())?,
                ],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        let length = unsigned(value(&row, "text_byte_length")?)?;
        if length > self.policy.max_artifact_bytes() {
            return Err(ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_quota",
            });
        }
        let text: String = value(&row, "text")?;
        if u64::try_from(text.len()).map_err(|_| corrupt("message_length"))? != length {
            return Err(corrupt("message_length"));
        }
        let kind: String = value(&row, "anchor_kind")?;
        let anchor: String = value(&row, "anchor_id")?;
        let workspace = match kind.as_str() {
            "channel" => ArtifactWorkspaceKey::channel(&anchor),
            "direct_bot" => ArtifactWorkspaceKey::thread(input.source_thread_id.as_str()),
            _ => return Err(corrupt("workspace_kind")),
        }
        .map_err(|_| corrupt("workspace_id"))?;
        Ok(Source {
            length,
            sha256: Sha256Digest::of(text.as_bytes()).to_hex(),
            text,
            workspace,
            bot: value(&row, "bot_id")?,
            bot_package: value(&row, "bot_package")?,
            channel_package: value(&row, "channel_package")?,
        })
    }

    async fn check_binding(&self, tx: &Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        let physical = self.store.physical_binding();
        let exists: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d \
             JOIN openbot_internal.artifact_store_bindings s USING(deployment_id,tenant_id,dataset_id) \
             WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.dataset_id=$3 AND d.binding_schema=$4 \
              AND d.initial_origin=$5 AND d.created_at=$6 AND s.store_id=$7 \
              AND s.root_device=$8 AND s.root_inode=$9 AND s.root_uid=$10)",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &b.binding_schema(), &b.initial_origin(),
              &b.created_at(), &self.store.store_id().to_string(), &physical.device(), &physical.inode(), &physical.uid()],
        ).await.map_err(|_| unavailable())?.try_get(0).map_err(|_| corrupt("dataset_store_binding"))?;
        if !exists || !self.store.matches_registry_owner(&self.registry) {
            return Err(corrupt("dataset_store_binding"));
        }
        Ok(())
    }

    async fn lock_quota(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
    ) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.execute("INSERT INTO openbot_internal.artifact_workspace_quotas \
            (deployment_id,tenant_id,dataset_id,workspace_kind,workspace_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id()])
            .await.map_err(|_| unavailable())?;
        tx.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5 FOR UPDATE",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id()])
            .await.map_err(|_| unavailable())?;
        tx.execute("INSERT INTO openbot_internal.artifact_run_quotas \
            (deployment_id,tenant_id,dataset_id,source_run_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &run]).await.map_err(|_| unavailable())?;
        tx.query_one("SELECT identity_count FROM openbot_internal.artifact_run_quotas \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND source_run_id=$4 FOR UPDATE",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &run]).await.map_err(|_| unavailable())?;
        Ok(())
    }

    async fn usage(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
    ) -> Result<(u64, u64), ArtifactAdministrationError> {
        let b = self.registry.binding();
        let row = tx.query_one("SELECT q.charged_bytes,r.identity_count FROM openbot_internal.artifact_workspace_quotas q \
            JOIN openbot_internal.artifact_run_quotas r USING(deployment_id,tenant_id,dataset_id) \
            WHERE q.deployment_id=$1 AND q.tenant_id=$2 AND q.dataset_id=$3 AND q.workspace_kind=$4 AND q.workspace_id=$5 AND r.source_run_id=$6",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id(), &run])
            .await.map_err(|_| unavailable())?;
        Ok((
            unsigned(value(&row, "identity_count")?)?,
            unsigned(value(&row, "charged_bytes")?)?,
        ))
    }

    async fn set_usage(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
        count: u64,
        charged: u64,
    ) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.execute("UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$6 \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id(), &integer(charged)?])
            .await.map_err(|_| unavailable())?;
        tx.execute(
            "UPDATE openbot_internal.artifact_run_quotas SET identity_count=$5 \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND source_run_id=$4",
            &[
                &b.deployment_id(),
                &b.tenant_id(),
                &b.dataset_id(),
                &run,
                &integer(count)?,
            ],
        )
        .await
        .map_err(|_| unavailable())?;
        Ok(())
    }

    async fn operation(
        &self,
        tx: &Transaction<'_>,
        op: &str,
    ) -> Result<Row, ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.query_opt("SELECT * FROM openbot_internal.artifact_save_operations WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 FOR UPDATE",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&op]).await.map_err(|_| unavailable())?
            .ok_or_else(|| corrupt("operation_missing"))
    }

    async fn receipt(
        &self,
        tx: &Transaction<'_>,
        op: &str,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        let b = self.registry.binding();
        let row=tx.query_opt("SELECT * FROM openbot_internal.artifact_saved_receipts WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&op]).await.map_err(|_| unavailable())?
            .ok_or_else(|| corrupt("positive_receipt_missing"))?;
        decode_receipt(&row)
    }

    fn check_namespace(&self, auth: &AuthContext) -> Result<(), ArtifactAdministrationError> {
        if auth.deployment().as_str() != self.registry.binding().deployment_id()
            || auth.tenant().as_str() != self.registry.binding().tenant_id()
        {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        for id in [
            auth.actor().as_str(),
            auth.deployment().as_str(),
            auth.tenant().as_str(),
        ] {
            if !is_valid_artifact_identity(id) {
                return Err(ArtifactAdministrationError::NotVisible);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ArtifactAdministration for PostgresArtifactAdministration {
    async fn open_host_bound_read_operation(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, openbot_contracts::error::AppError>
    {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority
            .open_host_bound_read_operation(auth, artifact_id)
            .await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadChunk, openbot_contracts::error::AppError>
    {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority.read_host_bound_chunk(auth, artifact_id).await
    }
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        mut input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        input.request_id = canonical_artifact_uuid_v7(&input.request_id)
            .ok_or(ArtifactAdministrationError::InvalidInput { field: "requestId" })?;
        if !ThreadIdentity::is_plausible(&input.source_thread_id) {
            return Err(ArtifactAdministrationError::InvalidInput {
                field: "sourceThreadId",
            });
        }
        for (field, id) in [
            ("sourceRunId", input.source_run_id.as_str()),
            ("sourceMessageId", input.source_message_id.as_str()),
        ] {
            if !is_valid_artifact_identity(id) {
                return Err(ArtifactAdministrationError::InvalidInput { field });
            }
        }
        if !is_valid_artifact_sha256(&input.expected_sha256) {
            return Err(ArtifactAdministrationError::InvalidInput {
                field: "expectedSha256",
            });
        }
        self.check_namespace(auth)?;
        verify_artifact_registration_schema(self.registry.pool()).await?;
        let store = Arc::clone(&self.store);
        let disk = tokio::time::timeout(
            WAIT,
            tokio::task::spawn_blocking(move || store.available_bytes()),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        let outcome = tokio::time::timeout(PG_PHASE, self.admit(auth, &input, disk))
            .await
            .map_err(|_| ArtifactAdministrationError::CommitUnknown)??;
        let mut admission = match outcome {
            AdmissionOutcome::Observed(receipt) => return Ok(receipt),
            AdmissionOutcome::Prepared(value) => value,
        };
        tokio::time::timeout(PG_PHASE, self.start_io(auth, &input, &admission))
            .await
            .map_err(|_| ArtifactAdministrationError::CommitUnknown)??;
        let store = Arc::clone(&self.store);
        let id = admission.artifact_id;
        let expected = parse_digest(&input.expected_sha256)?;
        let text = std::mem::take(&mut admission.source.text);
        // Dropping/cancelling this waiter cannot cancel a worker; IO_STARTED and charge remain.
        let observation = tokio::time::timeout(
            PG_PHASE,
            tokio::task::spawn_blocking(move || {
                store.write_text_once(id, expected, text.as_bytes())
            }),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        tokio::time::timeout(
            PG_PHASE,
            self.finalize(auth, &input, &admission, &observation),
        )
        .await
        .map_err(|_| ArtifactAdministrationError::CommitUnknown)?
    }

    async fn get_metadata(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        tokio::time::timeout(PG_PHASE, async {
        let id=canonical_artifact_uuid_v7(artifact_id).ok_or(ArtifactAdministrationError::InvalidInput{field:"artifactId"})?;
        self.check_namespace(auth)?;
        verify_artifact_registration_schema(self.registry.pool()).await?;
        let mut client=self.connection().await?;
        let tx=client.build_transaction().isolation_level(IsolationLevel::ReadCommitted).start().await.map_err(|_| unavailable())?;
        setup(&tx).await?;
        self.check_binding(&tx).await?;
        let b=self.registry.binding();
        let raw=tx.query_opt("SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND owner_actor_id=$5",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&id,&auth.actor().as_str()]).await.map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        let thread:String=value(&raw,"source_thread_id")?;
        let run:String=value(&raw,"source_run_id")?;
        let generation=i64::try_from(auth.auth_generation().get()).map_err(|_| ArtifactAdministrationError::NotVisible)?;
        let sql=format!("{VISIBLE_RUN} SELECT a.* FROM visible_run r JOIN openbot_internal.artifact_records a \
            ON a.source_thread_id=r.thread_id AND a.source_run_id=r.run_id \
            JOIN public.messages m ON m.message_id=a.source_message_id \
              AND m.thread_id=a.source_thread_id AND m.run_id=a.source_run_id \
              AND m.actor_id=a.owner_actor_id AND m.role='user' \
            WHERE a.owner_actor_id=$3 AND a.deployment_id=$4 AND a.tenant_id=$5 AND a.artifact_id=$7 AND a.dataset_id=$8");
        let row=tx.query_opt(&sql,&[&thread,&run,&auth.actor().as_str(),&auth.deployment().as_str(),&auth.tenant().as_str(),&generation,&id,&b.dataset_id()])
            .await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        self.check_binding(&tx).await?;
        let metadata=decode_metadata(&row)?;
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(metadata)
        }).await.map_err(|_| unavailable())?
    }
}

struct Source {
    text: String,
    length: u64,
    sha256: String,
    workspace: ArtifactWorkspaceKey,
    bot: String,
    bot_package: Option<Uuid>,
    channel_package: Option<Uuid>,
}
impl Source {
    fn ensure_same(&self, other: &Self) -> Result<(), ArtifactAdministrationError> {
        if self.sha256 != other.sha256
            || self.length != other.length
            || self.workspace != other.workspace
            || self.bot != other.bot
            || self.bot_package != other.bot_package
            || self.channel_package != other.channel_package
        {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        Ok(())
    }
}
struct Admission {
    operation_id: String,
    artifact_id: Uuid,
    source: Source,
    length: u64,
}
enum AdmissionOutcome {
    Prepared(Admission),
    Observed(ArtifactRegistrationReceipt),
}

async fn setup(tx: &Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='5s'")
        .await
        .map_err(|_| unavailable())
}
async fn commit(tx: deadpool_postgres::Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
    tokio::time::timeout(WAIT, tx.commit())
        .await
        .map_err(|_| ArtifactAdministrationError::CommitUnknown)?
        .map_err(|_| ArtifactAdministrationError::CommitUnknown)
}
fn source_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        format!(
            "{VISIBLE_RUN} SELECT octet_length(m.content->>'text')::bigint AS text_byte_length,\
        CASE WHEN octet_length(m.content->>'text')::bigint <= $8 THEN m.content->>'text' ELSE NULL END AS text,\
        t.anchor_kind,t.anchor_id,r.bot_id,\
        b.package_id AS bot_package,ch.package_id AS channel_package FROM visible_run r \
        JOIN public.threads t ON t.thread_id=r.thread_id JOIN public.agents b ON b.id=r.bot_id \
        JOIN public.messages m ON m.thread_id=r.thread_id AND m.run_id=r.run_id \
        LEFT JOIN public.channels ch ON t.anchor_kind='channel' AND ch.id=t.anchor_id \
        WHERE m.message_id=$7 AND m.actor_id=$3 AND m.role='user' \
          AND jsonb_typeof(m.content)='object' AND jsonb_typeof(m.content->'text')='string' \
          AND octet_length(m.content->>'text') > 0"
        )
    })
    .as_str()
}
fn ensure_intent(
    row: &Row,
    auth: &AuthContext,
    input: &SaveRunMessageTextArtifact,
    source: &Source,
) -> Result<(), ArtifactAdministrationError> {
    let state: String = value(row, "state")?;
    if matches!(state.as_str(), "deleted" | "expired") {
        return Err(unavailable());
    }
    let expected: String = value(row, "expected_sha256")?;
    if value::<String>(row, "owner_actor_id")? != auth.actor().as_str()
        || value::<String>(row, "source_thread_id")? != input.source_thread_id.as_str()
        || value::<String>(row, "source_run_id")? != input.source_run_id.as_str()
        || value::<String>(row, "source_message_id")? != input.source_message_id.as_str()
        || expected != input.expected_sha256
        || unsigned(value(row, "expected_bytes")?)? != source.length
        || value::<String>(row, "workspace_kind")? != source.workspace.kind().as_str()
        || value::<String>(row, "workspace_id")? != source.workspace.id()
    {
        return Err(ArtifactAdministrationError::RequestConflict);
    }
    if source.sha256 != expected {
        return Err(ArtifactAdministrationError::NotVisible);
    }
    Ok(())
}
fn receipt_from(
    a: &Admission,
    auth: &AuthContext,
    input: &SaveRunMessageTextArtifact,
) -> ArtifactRegistrationReceipt {
    ArtifactRegistrationReceipt {
        operation_id: a.operation_id.clone(),
        artifact_id: a.artifact_id.to_string(),
        request_id: input.request_id.clone(),
        owner_actor_id: auth.actor().clone(),
        source_thread_id: input.source_thread_id.clone(),
        source_run_id: input.source_run_id.clone(),
        source_message_id: input.source_message_id.clone(),
        source_call_seq: None,
        source_attempt_seq: None,
    }
}
fn decode_receipt(row: &Row) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
    Ok(ArtifactRegistrationReceipt {
        operation_id: value(row, "operation_id")?,
        artifact_id: value(row, "artifact_id")?,
        request_id: value(row, "request_id")?,
        owner_actor_id: ActorId::new(value::<String>(row, "owner_actor_id")?),
        source_thread_id: ThreadId::new(value::<String>(row, "source_thread_id")?),
        source_run_id: RunId::new(value::<String>(row, "source_run_id")?),
        source_message_id: value(row, "source_message_id")?,
        source_call_seq: sequence(value(row, "source_call_seq")?)?,
        source_attempt_seq: sequence(value(row, "source_attempt_seq")?)?,
    })
}
fn decode_metadata(row: &Row) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
    let status: String = value(row, "status")?;
    if matches!(status.as_str(), "deleted" | "expired") {
        let r = decode_receipt(row)?;
        let tombstone = ArtifactTombstone {
            artifact_id: r.artifact_id,
            operation_id: r.operation_id,
            request_id: r.request_id,
            owner_actor_id: r.owner_actor_id,
            source_thread_id: r.source_thread_id,
            source_run_id: r.source_run_id,
            source_message_id: r.source_message_id,
            source_call_seq: r.source_call_seq,
            source_attempt_seq: r.source_attempt_seq,
        };
        return Ok(if status == "deleted" {
            ArtifactMetadata::Deleted(tombstone)
        } else {
            ArtifactMetadata::Expired(tombstone)
        });
    }
    let kind: String = value(row, "workspace_kind")?;
    let workspace_id: String = value(row, "workspace_id")?;
    let workspace = match kind.as_str() {
        "channel" => ArtifactWorkspace::Channel { id: workspace_id },
        "thread" => ArtifactWorkspace::Thread { id: workspace_id },
        _ => return Err(corrupt("workspace_kind")),
    };
    let record = ArtifactRecordMetadata {
        artifact_id: value(row, "artifact_id")?,
        deployment_id: DeploymentId::new(value::<String>(row, "deployment_id")?),
        tenant_id: TenantId::new(value::<String>(row, "tenant_id")?),
        dataset_id: value(row, "dataset_id")?,
        owner_actor_id: ActorId::new(value::<String>(row, "owner_actor_id")?),
        workspace,
        source_thread_id: ThreadId::new(value::<String>(row, "source_thread_id")?),
        source_run_id: RunId::new(value::<String>(row, "source_run_id")?),
        source_call_seq: sequence(value(row, "source_call_seq")?)?,
        source_attempt_seq: sequence(value(row, "source_attempt_seq")?)?,
        media_type: value(row, "media_type")?,
        byte_length: unsigned(value(row, "byte_length")?)?,
        sha256: value(row, "sha256")?,
        retention_class: ArtifactRetentionClass::ExplicitSaved,
        saved_by: value::<Option<String>>(row, "saved_by")?.map(ActorId::new),
        saved_at: value::<Option<OffsetDateTime>>(row, "saved_at")?,
    };
    match status.as_str() {
        "available" => Ok(ArtifactMetadata::Available(record)),
        "failed_partial" => Ok(ArtifactMetadata::FailedPartial(record)),
        _ => Err(corrupt("status")),
    }
}
fn value<T: for<'a> tokio_postgres::types::FromSql<'a>>(
    row: &Row,
    column: &'static str,
) -> Result<T, ArtifactAdministrationError> {
    row.try_get(column).map_err(|_| corrupt(column))
}
fn integer(value: u64) -> Result<i64, ArtifactAdministrationError> {
    i64::try_from(value).map_err(|_| corrupt("integer_overflow"))
}
fn unsigned(value: i64) -> Result<u64, ArtifactAdministrationError> {
    u64::try_from(value).map_err(|_| corrupt("negative_usage"))
}
fn sequence(value: Option<i64>) -> Result<Option<u64>, ArtifactAdministrationError> {
    value.map(unsigned).transpose()
}
fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for byte in digest {
        s.push(char::from(HEX[usize::from(byte >> 4)]));
        s.push(char::from(HEX[usize::from(byte & 15)]));
    }
    s
}
fn parse_digest(text: &str) -> Result<[u8; 32], ArtifactAdministrationError> {
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        let a = char::from(text.as_bytes()[i * 2])
            .to_digit(16)
            .ok_or_else(|| corrupt("expected_digest"))?;
        let b = char::from(text.as_bytes()[i * 2 + 1])
            .to_digit(16)
            .ok_or_else(|| corrupt("expected_digest"))?;
        *byte = u8::try_from(a * 16 + b).map_err(|_| corrupt("expected_digest"))?;
    }
    Ok(digest)
}
const fn unavailable() -> ArtifactAdministrationError {
    ArtifactAdministrationError::Unavailable
}
const fn corrupt(field: &'static str) -> ArtifactAdministrationError {
    ArtifactAdministrationError::Corrupt { field }
}

fn observed_read_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| format!("{VISIBLE_RUN} \
        /* artifact_private_read_record_snapshot */ \
        SELECT a.*, \
          CASE t.anchor_kind WHEN 'channel' THEN 'channel' WHEN 'direct_bot' THEN 'thread' END AS source_workspace_kind, \
          CASE t.anchor_kind WHEN 'channel' THEN t.anchor_id WHEN 'direct_bot' THEN t.thread_id END AS source_workspace_id, \
          o.state AS op_state,o.store_id AS op_store_id,o.workspace_kind AS op_workspace_kind,o.workspace_id AS op_workspace_id, \
          o.expected_sha256 AS op_expected_sha256,o.expected_bytes AS op_expected_bytes,o.charged_bytes AS op_charged_bytes, \
          o.actual_absent AS op_actual_absent,o.actual_byte_length AS op_actual_byte_length,o.actual_sha256 AS op_actual_sha256, \
          o.actual_location AS op_actual_location,o.observation_phase AS op_observation_phase, \
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d \
             JOIN openbot_internal.artifact_store_bindings s USING(deployment_id,tenant_id,dataset_id) \
             WHERE d.deployment_id=$4 AND d.tenant_id=$5 AND d.dataset_id=$8 AND d.binding_schema=$9 \
               AND d.initial_origin=$10 AND d.created_at=$11 AND s.store_id=$12 \
               AND s.root_device=$13 AND s.root_inode=$14 AND s.root_uid=$15) AS current_store_binding \
        FROM visible_run r JOIN openbot_internal.artifact_records a \
          ON a.source_thread_id=r.thread_id AND a.source_run_id=r.run_id \
        JOIN public.threads t ON t.thread_id=r.thread_id \
        JOIN public.messages m ON m.message_id=a.source_message_id AND m.thread_id=a.source_thread_id \
          AND m.run_id=a.source_run_id AND m.actor_id=a.owner_actor_id AND m.role='user' \
        LEFT JOIN openbot_internal.artifact_save_operations o \
          ON o.deployment_id=a.deployment_id AND o.tenant_id=a.tenant_id AND o.dataset_id=a.dataset_id \
          AND o.operation_id=a.operation_id AND o.artifact_id=a.artifact_id AND o.request_id=a.request_id \
          AND o.owner_actor_id=a.owner_actor_id AND o.source_thread_id=a.source_thread_id \
          AND o.source_run_id=a.source_run_id AND o.source_message_id=a.source_message_id \
          AND o.source_call_seq IS NOT DISTINCT FROM a.source_call_seq \
          AND o.source_attempt_seq IS NOT DISTINCT FROM a.source_attempt_seq \
        WHERE a.owner_actor_id=$3 AND a.deployment_id=$4 AND a.tenant_id=$5 \
          AND a.artifact_id=$7 AND a.dataset_id=$8"))
}

#[cfg(test)]
#[path = "artifact_read_bridge_tests.rs"]
mod read_bridge_tests;
