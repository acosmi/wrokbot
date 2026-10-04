//! Private original-host first-chunk consumer. The final own-Pool RC statement observes host
//! and source together; the original FD and initialized RAII buffer survive every final await.

use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use openbot_application::{ArtifactAdministrationError, CurrentArtifactReadChunk};
use openbot_contracts::artifact_read::PendingArtifactReadBuffer;
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, ArtifactWorkspace};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    ArtifactReadCurrentError, ArtifactReadCurrentTarget, ArtifactReadRecordFacts,
    ArtifactReadTailWitness, BorrowedServerSessionEpoch, HostRequestBindingError,
    HostRequestBindingIdentity, HostRequestBindingKind,
};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::identity::session::{SessionLifetimePolicy, SessionState, evaluate_session};
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row};
use tracing::instrument::WithSubscriber;

use super::artifact_read_lifecycle::{
    AllocationLease, ArtifactReadLifecycle, LifecycleReadOperation, PendingReadOwnership,
    PhysicalResourceLease, ReadOperationState, ReadPhase,
};

use super::{ObservedArtifactReadRecord, PostgresArtifactAdministration};
use crate::artifact_store::StoreBoundArtifactReader;
use crate::auth::single_user::desktop_local::{
    DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL, DesktopLocalAuthority,
};

/// One actual administration identity, with weak ownership back to that real adapter.
/// It neither accepts a caller Pool/transaction nor prolongs any real host-owner lease.
pub struct PostgresArtifactReadAuthority {
    administration: Weak<PostgresArtifactAdministration>,
    identity: Arc<()>,
    lifecycle: Arc<ArtifactReadLifecycle>,
    #[cfg(test)]
    final_query_gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

impl PostgresArtifactReadAuthority {
    pub(super) fn from_administration(
        administration: &Arc<PostgresArtifactAdministration>,
    ) -> Self {
        Self {
            administration: Arc::downgrade(administration),
            identity: Arc::new(()),
            lifecycle: ArtifactReadLifecycle::new(),
            #[cfg(test)]
            final_query_gate: Mutex::new(None),
        }
    }

    /// The exact same authority/root inventory, never a request-created tracker.
    pub fn read_lifecycle(&self) -> Arc<ArtifactReadLifecycle> {
        Arc::clone(&self.lifecycle)
    }

    pub(super) async fn open_host_bound_read_operation(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, AppError> {
        let state = ReadOperationState::new(Arc::clone(self), auth.clone(), artifact_id.to_owned());
        self.lifecycle.register(&state)?;
        openbot_application::CurrentArtifactReadOperation::from_trusted_operation(
            auth.clone(),
            Box::new(LifecycleReadOperation { state }),
        )
    }

    /// Prove enrollment in this adapter's actual Pool manager and original namespace.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        self.administration.upgrade().is_some_and(|administration| {
            administration
                .registry
                .matches_pool_scope(pool, deployment, tenant)
        })
    }

    /// Observe the original real Session epoch and unchanged source predicate in one statement.
    pub async fn observe_server_session(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        epoch: BorrowedServerSessionEpoch<'_>,
        lifetime: SessionLifetimePolicy,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        self.observe(
            auth,
            target,
            CurrentHost::Session { epoch, lifetime },
            deadline,
        )
        .await
    }

    /// Require actual Desktop canary adoption and current original installation/row facts.
    pub async fn observe_desktop_local(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        installation: &DesktopLocalAuthority,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        self.observe(auth, target, CurrentHost::Desktop(installation), deadline)
            .await
    }

    pub(super) async fn read_host_bound_chunk(
        self: &Arc<Self>,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        let state = ReadOperationState::new(Arc::clone(self), auth.clone(), artifact_id.to_owned());
        self.lifecycle.register(&state)?;
        let job = self.lifecycle.admit(&state.stopped)?;
        state.begin()?;
        let dispatcher = tracing::dispatcher::get_default(Clone::clone);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let authority = Arc::clone(self);
        let collected = Arc::clone(&state);
        tokio::spawn(
            async move {
                let mut result = authority
                    .read_first_chunk_collected(&collected, dispatcher)
                    .await;
                if result.is_ok() {
                    let pending_recorded = match collected.data.lock() {
                        Ok(mut data) => {
                            data.phase = ReadPhase::Pending;
                            true
                        }
                        Err(_) => false,
                    };
                    if !pending_recorded {
                        result = Err(ArtifactReadCurrentError::Unavailable.into());
                    }
                }
                if result.is_err() {
                    collected.finish_failed();
                }
                drop(sender.send(result));
                drop(job);
            }
            .with_current_subscriber(),
        );
        let mut attempt = LegacyReadAttempt {
            state,
            completed: false,
        };
        let result = receiver
            .await
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        attempt.completed = true;
        result
    }

    async fn read_first_chunk_collected(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
        dispatcher: tracing::Dispatch,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        let auth = &state.auth;
        let artifact_id = state.artifact_id.as_str();
        let original = auth
            .request_binding()
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        if !matches!(
            original.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
        ) {
            return Err(host_unavailable().into());
        }
        // The initial check only protects expensive physical work; it is never the final proof.
        original
            .verify_current(auth)
            .await
            .map_err(|error| AppError::from(ArtifactReadCurrentError::Host(error)))?;
        let administration = self
            .administration
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let snapshot = administration.observe_read_record(auth, artifact_id).await;
        let worker = match snapshot {
            Ok(snapshot) => {
                let identity = Arc::clone(&self.identity);
                let store = Arc::clone(&administration.store);
                let state = Arc::clone(state);
                let resource = self.lifecycle.resource();
                tokio::task::spawn_blocking(move || {
                    tracing::dispatcher::with_default(&dispatcher, || {
                        let resource = resource;
                        // Every initialized byte, including the unread suffix, remains owned by
                        // this RAII value on worker error, abandoned JoinHandle and cancelled await.
                        let mut pending = PendingArtifactReadBuffer::new_initialized()?;
                        let mut reader = store
                            .open_observed_record(snapshot)
                            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                        read_segments(&mut reader, &mut pending, &state, 0)?;
                        let target: Arc<dyn ArtifactReadCurrentTarget> =
                            Arc::new(TrackedArtifactReadTarget {
                                inner: Arc::new(ActualArtifactReadTarget::from_reader(
                                    identity, reader,
                                )),
                                state: Arc::clone(&state),
                                _resource: resource,
                            });
                        Ok::<_, ArtifactReadCurrentError>(ArtifactReadWorkerResult {
                            pending,
                            target,
                        })
                    })
                })
                .await
                .map_err(|_| ArtifactReadCurrentError::Unavailable)
                .and_then(|value| value)
            }
            Err(error) => Err(source_error(error)),
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let request_target;
        let target: &dyn ArtifactReadCurrentTarget = match &worker {
            Ok(result) => {
                tracing::trace!(
                    artifact_read_phase = "actual_io_completed_before_joint",
                    "artifact_read_current_phase"
                );
                result.target.as_ref()
            }
            Err(_) => {
                // Missing/invisible/gone and physical errors still execute the real anchored
                // final statement. No request-only target can release any bytes.
                request_target = RequestedArtifactReadTarget {
                    id: artifact_id.to_owned(),
                    auth: auth.clone(),
                    identity: Arc::clone(&self.identity),
                };
                &request_target
            }
        };
        let witness = original
            .verify_artifact_read_current_before(auth, target, deadline)
            .await?;
        let result = worker?;
        let target: Arc<dyn ArtifactReadCurrentTarget> = result.target;
        CurrentArtifactReadChunk::from_trusted_observation(
            result.pending,
            auth.clone(),
            target,
            witness,
            deadline,
        )
    }

    pub(super) async fn read_operation_block(
        self: &Arc<Self>,
        state: &Arc<ReadOperationState>,
    ) -> Result<openbot_application::CurrentArtifactReadBlock, AppError> {
        let auth = &state.auth;
        let original = auth
            .request_binding()
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        original
            .verify_current(auth)
            .await
            .map_err(|error| AppError::from(ArtifactReadCurrentError::Host(error)))?;
        let administration = self
            .administration
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let (reader, position) = {
            let mut data = state
                .data
                .try_lock()
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
            (data.reader.take(), data.position)
        };
        let input = match reader {
            Some(reader) => Ok(ReadInput::Retained(reader)),
            None => administration
                .observe_read_record(auth, &state.artifact_id)
                .await
                .map(ReadInput::Fresh)
                .map_err(source_error),
        };
        let worker = match input {
            Ok(input) => {
                {
                    let mut data = state
                        .data
                        .try_lock()
                        .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                    if data.resource.is_none() {
                        data.resource = Some(self.lifecycle.resource());
                    }
                }
                let worker_state = Arc::clone(state);
                let dispatcher = tracing::dispatcher::get_default(Clone::clone);
                let store = Arc::clone(&administration.store);
                tokio::task::spawn_blocking(move || {
                    tracing::dispatcher::with_default(&dispatcher, || {
                        let mut pending = PendingArtifactReadBuffer::new_initialized()?;
                        let mut reader = match input {
                            ReadInput::Retained(reader) => reader,
                            ReadInput::Fresh(snapshot) => store
                                .open_observed_record(snapshot)
                                .map_err(|_| ArtifactReadCurrentError::Unavailable)?,
                        };
                        let read =
                            read_segments(&mut reader, &mut pending, &worker_state, position);
                        Ok::<_, ArtifactReadCurrentError>(OperationWorkerResult {
                            pending,
                            reader,
                            read,
                        })
                    })
                })
                .await
                .map_err(|_| ArtifactReadCurrentError::Unavailable)
                .and_then(|result| result)
            }
            Err(error) => Err(error),
        };
        let mut owned = match worker {
            Ok(result) => {
                let mut data = state
                    .data
                    .try_lock()
                    .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
                data.reader = Some(result.reader);
                data.phase = ReadPhase::FinalJoint;
                if let Ok(position) = &result.read {
                    data.position = *position;
                }
                data.eof = result.pending.actual_length() == Some(0);
                drop(data);
                (
                    Some(PendingReadOwnership {
                        pending: Some(result.pending),
                        lease: Some(Box::new(AllocationLease::new(Arc::clone(state)))),
                    }),
                    result.read.map(|_| ()),
                )
            }
            Err(error) => (None, Err(error)),
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| AppError::from(host_unavailable()))?;
        let target: Arc<dyn ArtifactReadCurrentTarget> = if owned.0.is_some() {
            tracing::trace!(
                artifact_read_phase = "actual_io_completed_before_joint",
                "artifact_read_current_phase"
            );
            Arc::new(RetainedOperationTarget::from_state(
                Arc::clone(&self.identity),
                state,
            )?)
        } else {
            Arc::new(RequestedArtifactReadTarget {
                id: state.artifact_id.clone(),
                auth: auth.clone(),
                identity: Arc::clone(&self.identity),
            })
        };
        // Missing/physical errors use this same anchored host-first statement, never early404.
        let witness = original
            .verify_artifact_read_current_before(auth, target.as_ref(), deadline)
            .await?;
        owned.1?;
        let owner = owned
            .0
            .as_mut()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        {
            let mut data = state
                .data
                .try_lock()
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
            if state.is_stopped() {
                return Err(ArtifactReadCurrentError::Unavailable.into());
            }
            data.phase = ReadPhase::Pending;
        }
        let pending = owner
            .pending
            .take()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let lease = owner
            .lease
            .take()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        openbot_application::CurrentArtifactReadBlock::from_trusted_observation(
            pending,
            auth.clone(),
            target,
            witness,
            deadline,
            lease,
        )
    }

    async fn observe(
        &self,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        host: CurrentHost<'_>,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        remaining(deadline)?;
        if !target.matches_authority(&self.identity) || !target.matches_auth(auth) {
            return Err(host_not_current());
        }
        let administration = self.administration.upgrade().ok_or_else(host_unavailable)?;
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
        let limit = tokio::time::Instant::from_std(deadline);
        tokio::time::timeout_at(
            limit,
            self.observe_inner(&administration, auth, target, host, deadline),
        )
        .await
        .map_err(|_| host_unavailable())?
    }

    async fn observe_inner(
        &self,
        administration: &PostgresArtifactAdministration,
        auth: &AuthContext,
        target: &dyn ArtifactReadCurrentTarget,
        host: CurrentHost<'_>,
        deadline: Instant,
    ) -> Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError> {
        super::verify_artifact_registration_schema(administration.registry.pool())
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
            tx.batch_execute(&format!("SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"))
                .await.map_err(|_| host_unavailable())?;
            let binding = administration.registry.binding();
            let seed = tx.query_opt(
                "SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
                 WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND owner_actor_id=$5",
                &[&binding.deployment_id(), &binding.tenant_id(), &binding.dataset_id(), &target.lookup_id(), &auth.actor().as_str()],
            ).await.map_err(|_| host_unavailable())?;
            let thread: Option<String> = seed.as_ref().map(|row| super::value(row, "source_thread_id")).transpose().map_err(source_error)?;
            let run: Option<String> = seed.as_ref().map(|row| super::value(row, "source_run_id")).transpose().map_err(source_error)?;
            let generation = i64::try_from(auth.auth_generation().get()).map_err(|_| host_not_current())?;
            let physical = administration.store.physical_binding();
            let session_id = match &host { CurrentHost::Session { epoch, .. } => Some(epoch.lookup_id()), CurrentHost::Desktop(_) => None };
            #[cfg(test)]
            {
                let gate = self.final_query_gate.lock().map_err(|_| host_unavailable())?.take();
                if let Some((reached, proceed)) = gate {
                    reached.send(()).map_err(|_| host_unavailable())?;
                    proceed.await.map_err(|_| host_unavailable())?;
                }
            }
            remaining(deadline)?;
            tracing::trace!(artifact_read_phase = "joint_statement_ready", "artifact_read_current_phase");
            let row = tx.query_one(
                current_read_sql(matches!(&host, CurrentHost::Desktop(_))),
                &[&thread, &run, &auth.actor().as_str(), &auth.deployment().as_str(), &auth.tenant().as_str(),
                    &generation, &target.lookup_id(), &binding.dataset_id(), &binding.binding_schema(),
                    &binding.initial_origin(), &binding.created_at(), &administration.store.store_id().to_string(),
                    &physical.device(), &physical.inode(), &physical.uid(), &session_id],
            ).await.map_err(|_| host_unavailable())?;
            // Host classification is first even for a missing/invisible/gone source. Retain the
            // current host witness on error paths, so rollback cannot outlive its clock/owner.
            let witness = decode_host(administration, auth, &row, &host)?;
            let source = (|| {
                let id: Option<String> = super::value(&row, "artifact_id").map_err(source_error)?;
                if id.is_none() { return Err(ArtifactReadCurrentError::NotVisible); }
                let record = administration.decode_read_record(auth, &row).map_err(source_error)?;
                let workspace = workspace(&record);
                let sha256 = Sha256Digest::from_bytes(*record.blob().sha256()).to_hex();
                if !target.matches_current_record(ArtifactReadRecordFacts {
                    artifact_id: &record.source_snapshot.artifact_id, sha256: &sha256,
                    byte_length: record.blob().byte_length(), source: &record.source_snapshot, workspace: &workspace,
                }) { return Err(ArtifactReadCurrentError::Unavailable); }
                Ok(())
            })();
            Ok::<_, ArtifactReadCurrentError>((witness, source))
        }.await;
        // Every real statement result, including host/source errors, awaits explicit rollback.
        // A dropped/timeout future is not reported as acknowledged rollback or worker completion.
        let rollback = tx.rollback().await.map_err(|_| host_unavailable());
        if let Ok((witness, _)) = &outcome {
            witness.verify_current(auth, deadline)?;
        }
        remaining(deadline)?;
        rollback?;
        let (witness, source) = outcome?;
        source?;
        Ok(Box::new(witness))
    }
}

enum CurrentHost<'a> {
    Session {
        epoch: BorrowedServerSessionEpoch<'a>,
        lifetime: SessionLifetimePolicy,
    },
    Desktop(&'a DesktopLocalAuthority),
}

struct ArtifactReadWorkerResult {
    pending: PendingArtifactReadBuffer,
    target: Arc<dyn ArtifactReadCurrentTarget>,
}

struct LegacyReadAttempt {
    state: Arc<ReadOperationState>,
    completed: bool,
}
impl Drop for LegacyReadAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.state.close();
        }
    }
}
struct TrackedArtifactReadTarget {
    inner: Arc<ActualArtifactReadTarget>,
    state: Arc<ReadOperationState>,
    _resource: PhysicalResourceLease,
}
impl ArtifactReadCurrentTarget for TrackedArtifactReadTarget {
    fn lookup_id(&self) -> &str {
        self.inner.lookup_id()
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        self.inner.matches_authority(identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.inner.matches_auth(auth)
    }
    fn matches_current_record(&self, facts: ArtifactReadRecordFacts<'_>) -> bool {
        self.inner.matches_current_record(facts)
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        if self._resource.is_closed() || self.state.is_stopped() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        self.inner.verify_physical_current()
    }
}
enum ReadInput {
    Fresh(ObservedArtifactReadRecord),
    Retained(StoreBoundArtifactReader),
}
struct OperationWorkerResult {
    pending: PendingArtifactReadBuffer,
    reader: StoreBoundArtifactReader,
    read: Result<u64, ArtifactReadCurrentError>,
}
fn read_segments(
    reader: &mut StoreBoundArtifactReader,
    pending: &mut PendingArtifactReadBuffer,
    state: &ReadOperationState,
    mut position: u64,
) -> Result<u64, ArtifactReadCurrentError> {
    const SEGMENT: usize = 64 * 1024;
    let expected = reader.record_snapshot().blob().byte_length();
    let mut actual = 0;
    while actual < openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES {
        if state.is_stopped() {
            pending.wipe();
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let end =
            (actual + SEGMENT).min(openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES);
        let count = reader
            .read_observed_chunk(&mut pending.initialized_mut()[actual..end])
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        actual += count;
        position = position
            .checked_add(count as u64)
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        if count == 0 {
            break;
        }
        if actual == SEGMENT && position < expected {
            tracing::trace!(
                artifact_read_lifecycle_phase = "physical_segment_completed_before_more_io",
                "artifact_read_lifecycle_phase"
            );
        }
    }
    if state.is_stopped() {
        pending.wipe();
        return Err(ArtifactReadCurrentError::Unavailable);
    }
    pending.record_actual_length(actual)?;
    Ok(position)
}

struct RetainedOperationTarget {
    identity: Arc<()>,
    auth: AuthContext,
    source: ArtifactRegistrationReceipt,
    workspace: ArtifactWorkspace,
    sha256: String,
    byte_length: u64,
    state: Weak<ReadOperationState>,
}
impl RetainedOperationTarget {
    fn from_state(
        identity: Arc<()>,
        state: &Arc<ReadOperationState>,
    ) -> Result<Self, ArtifactReadCurrentError> {
        let data = state
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        let reader = data
            .reader
            .as_ref()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let record = reader.record_snapshot();
        Ok(Self {
            identity,
            auth: record.auth_snapshot.clone(),
            source: record.source_snapshot.clone(),
            workspace: workspace(record),
            sha256: Sha256Digest::from_bytes(*record.blob().sha256()).to_hex(),
            byte_length: record.blob().byte_length(),
            state: Arc::downgrade(state),
        })
    }
}
impl ArtifactReadCurrentTarget for RetainedOperationTarget {
    fn lookup_id(&self) -> &str {
        &self.source.artifact_id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.source.artifact_id
            && actual.sha256 == self.sha256
            && actual.byte_length == self.byte_length
            && actual.source == &self.source
            && actual.workspace == &self.workspace
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        let state = self
            .state
            .upgrade()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        if state.is_stopped() {
            return Err(ArtifactReadCurrentError::Unavailable);
        }
        let data = state
            .data
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        data.reader
            .as_ref()
            .ok_or(ArtifactReadCurrentError::Unavailable)?
            .verify_physical_current()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }
}

struct ActualArtifactReadTarget {
    identity: Arc<()>,
    auth: AuthContext,
    source: ArtifactRegistrationReceipt,
    workspace: ArtifactWorkspace,
    sha256: String,
    byte_length: u64,
    reader: Mutex<StoreBoundArtifactReader>,
}
impl ActualArtifactReadTarget {
    fn from_reader(identity: Arc<()>, reader: StoreBoundArtifactReader) -> Self {
        let record = reader.record_snapshot();
        Self {
            identity,
            auth: record.auth_snapshot.clone(),
            source: record.source_snapshot.clone(),
            workspace: workspace(record),
            sha256: Sha256Digest::from_bytes(*record.blob().sha256()).to_hex(),
            byte_length: record.blob().byte_length(),
            reader: Mutex::new(reader),
        }
    }
}
impl ArtifactReadCurrentTarget for ActualArtifactReadTarget {
    fn lookup_id(&self) -> &str {
        &self.source.artifact_id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.source.artifact_id
            && actual.sha256 == self.sha256
            && actual.byte_length == self.byte_length
            && actual.source == &self.source
            && actual.workspace == &self.workspace
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        self.reader
            .try_lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?
            .verify_physical_current()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)
    }
}

struct RequestedArtifactReadTarget {
    id: String,
    auth: AuthContext,
    identity: Arc<()>,
}
impl ArtifactReadCurrentTarget for RequestedArtifactReadTarget {
    fn lookup_id(&self) -> &str {
        &self.id
    }
    fn matches_authority(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        same_original_auth(&self.auth, auth)
    }
    fn matches_current_record(&self, actual: ArtifactReadRecordFacts<'_>) -> bool {
        actual.artifact_id == self.id
    }
    fn verify_physical_current(&self) -> Result<(), ArtifactReadCurrentError> {
        Err(ArtifactReadCurrentError::Unavailable)
    }
}

fn same_original_auth(original: &AuthContext, current: &AuthContext) -> bool {
    original == current
        && original
            .request_binding()
            .zip(current.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
}
fn workspace(record: &ObservedArtifactReadRecord) -> ArtifactWorkspace {
    match record.workspace_snapshot.kind().as_str() {
        "channel" => ArtifactWorkspace::Channel {
            id: record.workspace_snapshot.id().to_owned(),
        },
        _ => ArtifactWorkspace::Thread {
            id: record.workspace_snapshot.id().to_owned(),
        },
    }
}
fn remaining(deadline: Instant) -> Result<Duration, ArtifactReadCurrentError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(host_unavailable)
}
fn host_unavailable() -> ArtifactReadCurrentError {
    ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable)
}
fn host_not_current() -> ArtifactReadCurrentError {
    ArtifactReadCurrentError::Host(HostRequestBindingError::NotCurrent)
}
fn source_error(error: ArtifactAdministrationError) -> ArtifactReadCurrentError {
    match error {
        ArtifactAdministrationError::NotVisible => ArtifactReadCurrentError::NotVisible,
        ArtifactAdministrationError::Gone { status } => ArtifactReadCurrentError::Gone(status),
        _ => ArtifactReadCurrentError::Unavailable,
    }
}

struct CurrentReadTail {
    auth: AuthContext,
    identity: HostRequestBindingIdentity,
    observed_wall: OffsetDateTime,
    observed_monotonic: Instant,
    session: Option<(
        OffsetDateTime,
        OffsetDateTime,
        OffsetDateTime,
        SessionLifetimePolicy,
    )>,
}
impl ArtifactReadTailWitness for CurrentReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        remaining(deadline)?;
        if auth != &self.auth
            || !auth
                .request_binding()
                .is_some_and(|binding| self.identity.same_binding(binding.identity()))
        {
            return Err(host_not_current());
        }
        let now = OffsetDateTime::now_utc();
        if now < self.observed_wall || Instant::now() < self.observed_monotonic {
            return Err(host_not_current());
        }
        if let Some((created, updated, expires, lifetime)) = self.session
            && (now >= expires
                || evaluate_session(
                    lifetime,
                    SessionState::rehydrate(created, updated, auth.auth_generation()),
                    auth.auth_generation(),
                    now,
                )
                .is_err())
        {
            return Err(host_not_current());
        }
        Ok(())
    }
}

fn decode_host(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    row: &Row,
    host: &CurrentHost<'_>,
) -> Result<CurrentReadTail, ArtifactReadCurrentError> {
    fn field<T: for<'a> tokio_postgres::types::FromSql<'a>>(
        row: &Row,
        name: &'static str,
    ) -> Result<T, ArtifactReadCurrentError> {
        row.try_get(name).map_err(|_| host_unavailable())
    }
    let user: Option<String> = field(row, "read_host_user")?;
    let raw_generation: Option<i64> = field(row, "read_host_generation")?;
    let generation = raw_generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(host_not_current)?;
    if user.as_deref() != Some(auth.actor().as_str())
        || generation != auth.auth_generation().get()
        || field::<bool>(row, "read_host_revoked")?
    {
        return Err(host_not_current());
    }
    let roles: Vec<String> = field(row, "read_host_roles")?;
    let parsed = roles
        .iter()
        .map(|role| role.parse::<Role>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| host_not_current())?;
    let now = OffsetDateTime::now_utc();
    let session = match host {
        CurrentHost::Session { epoch, lifetime } => {
            if auth.is_single_user()
                || auth
                    .request_binding()
                    .is_none_or(|value| value.kind() != HostRequestBindingKind::ServerSession)
            {
                return Err(host_not_current());
            }
            let (
                Some(id),
                Some(user),
                Some(token),
                Some(created),
                Some(updated),
                Some(expires),
                Some(issued),
            ) = (
                field::<Option<String>>(row, "read_session_id")?,
                field::<Option<String>>(row, "read_session_user")?,
                field::<Option<String>>(row, "read_session_token")?,
                field::<Option<OffsetDateTime>>(row, "read_session_created")?,
                field::<Option<OffsetDateTime>>(row, "read_session_updated")?,
                field::<Option<OffsetDateTime>>(row, "read_session_expires")?,
                field::<Option<i64>>(row, "read_session_generation")?,
            )
            else {
                return Err(host_not_current());
            };
            if !epoch.matches_raw_row(&id, &user, &token, created, issued)
                || issued < 0
                || issued != raw_generation.unwrap_or(-1)
                || now >= expires
                || evaluate_session(
                    *lifetime,
                    SessionState::rehydrate(created, updated, AuthGeneration::new(generation)),
                    AuthGeneration::new(generation),
                    now,
                )
                .is_err()
            {
                return Err(host_not_current());
            }
            let role = resolve_effective_role(parsed).map_err(|_| host_not_current())?;
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                false,
            )
            .with_role(role)
            .build();
            if current != *auth {
                return Err(host_not_current());
            }
            Some((created, updated, expires, *lifetime))
        }
        CurrentHost::Desktop(installation) => {
            if !auth.is_single_user()
                || auth.actor().as_str() != DESKTOP_LOCAL_ACTOR_ID
                || field::<Option<String>>(row, "read_host_email")?.as_deref()
                    != Some(DESKTOP_LOCAL_EMAIL)
                || roles.as_slice() != ["admin"]
                || auth
                    .request_binding()
                    .is_none_or(|value| value.kind() != HostRequestBindingKind::DesktopWindow)
                || installation.auth_context().deployment() != auth.deployment()
                || installation.auth_context().tenant() != auth.tenant()
                || !administration
                    .registry
                    .matches_desktop_read_current_row(row)
                    .map_err(|_| ArtifactReadCurrentError::Unavailable)?
            {
                return Err(host_not_current());
            }
            let current = AuthContextBuilder::from_verified_session(
                auth.deployment().clone(),
                auth.tenant().clone(),
                auth.actor().clone(),
                AuthGeneration::new(generation),
                true,
            )
            .with_roles([Role::Admin, Role::User])
            .build();
            if current != *auth {
                return Err(host_not_current());
            }
            None
        }
    };
    Ok(CurrentReadTail {
        auth: auth.clone(),
        identity: auth
            .request_binding()
            .ok_or_else(host_not_current)?
            .identity()
            .clone(),
        observed_wall: now,
        observed_monotonic: Instant::now(),
        session,
    })
}

fn current_read_sql(desktop: bool) -> &'static str {
    static SESSION: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    let sql = if desktop { &DESKTOP } else { &SESSION };
    sql.get_or_init(|| {
        // Embed the unchanged original CTE and snapshot SELECT. The outer anchor always
        // supplies a host row, including when no visible artifact/source row remains.
        let visible = crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;
        let source = super::observed_read_sql().strip_prefix(visible).expect("original artifact CTE prefix");
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
        format!("/* artifact_current_host_joint_read_after_io */ {visible}, current_artifact AS ({source}) \
          SELECT a.*,u.id AS read_host_user,u.auth_generation AS read_host_generation, \
            CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS read_host_email, \
            EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked, \
            ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS read_host_roles, \
            s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token, \
            s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires, \
            s.auth_generation AS read_session_generation {canary_columns} \
          FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$3 \
          LEFT JOIN public.sessions s ON s.id=$16 AND s.user_id=u.id \
          LEFT JOIN current_artifact a ON true {canary_joins}")
    })
}

#[cfg(test)]
#[path = "artifact_read_authority/tests.rs"]
mod tests;
