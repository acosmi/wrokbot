//! Public preparation uses one original sequential operation, descriptor and allocation.
//! The completion observer is notified before any admission/await/IO, including failure paths.

use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_application::CurrentArtifactReadOperation;
use openbot_application::artifact_read_protocol::{
    ArtifactReadOperationCompletion, ArtifactReadPreparationObserver, PreparedArtifactRead,
    PreparedArtifactReadFacts,
};
use openbot_contracts::artifacts::canonical_artifact_uuid_v7;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
#[cfg(test)]
use openbot_contracts::request_binding::ArtifactReadCurrentError;
use openbot_contracts::request_binding::HostRequestBindingKind;
use openbot_domain::audit::hash::Sha256Digest;

use super::super::artifact_read_lifecycle::{
    LifecycleReadOperation, OperationCompletion, ReadOperationState,
};
use super::PostgresArtifactReadAuthority;

const fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifacts",
    }
}

struct PreparationAttempt {
    completion: Arc<dyn ArtifactReadOperationCompletion>,
    completed: bool,
}
impl Drop for PreparationAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.completion.close();
        }
    }
}

pub(super) async fn prepare(
    authority: &Arc<PostgresArtifactReadAuthority>,
    auth: &AuthContext,
    artifact_id: &str,
    original_deadline: Instant,
    observer: Arc<dyn ArtifactReadPreparationObserver>,
) -> Result<PreparedArtifactRead, AppError> {
    let _remaining = original_deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero() && *duration <= Duration::from_secs(600))
        .ok_or_else(unavailable)?;
    if canonical_artifact_uuid_v7(artifact_id).as_deref() != Some(artifact_id) {
        return Err(AppError::MalformedPayload {
            field: "artifactId",
        });
    }
    let binding = auth
        .request_binding()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    if !matches!(
        binding.kind(),
        HostRequestBindingKind::ServerSession
            | HostRequestBindingKind::ServerSingleUserOwner
            | HostRequestBindingKind::DesktopWindow
    ) {
        return Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        });
    }
    let state = ReadOperationState::with_deadline(
        Arc::clone(authority),
        auth.clone(),
        artifact_id.to_owned(),
        Some(original_deadline),
    );
    state.enroll_store(authority.read_store()?, observer.original_entry_stop())?;
    let completion: Arc<dyn ArtifactReadOperationCompletion> = Arc::new(OperationCompletion {
        state: Arc::clone(&state),
    });
    let mut attempt = PreparationAttempt {
        completion: Arc::clone(&completion),
        completed: false,
    };
    // Root can supervise this exact State even if this future is dropped during actual IO.
    if let Err(error) = observer.enrolled(Arc::clone(&completion)) {
        completion.close();
        return Err(error);
    }
    #[cfg(test)]
    {
        let probe = authority
            .public_prepare_probe
            .lock()
            .map_err(|_| unavailable())?
            .take();
        if let Some(probe) = probe {
            probe.enroll(&state)?;
            *state
                .public_prepare_probe
                .lock()
                .map_err(|_| unavailable())? = Some(probe);
        }
    }
    authority.lifecycle.register(&state)?;
    let mut operation = CurrentArtifactReadOperation::from_trusted_operation(
        auth.clone(),
        Box::new(LifecycleReadOperation {
            state: Arc::clone(&state),
        }),
    )?;
    // This performs the actual full SHA, first prefix, own-Pool joint and awaited rollback.
    let first = operation.next_block(auth).await?;
    state.check_current()?;
    let facts = {
        let data = state.data.try_lock().map_err(|_| unavailable())?;
        let record = data
            .reader
            .as_ref()
            .ok_or_else(unavailable)?
            .record_snapshot();
        PreparedArtifactReadFacts {
            artifact_id: record.source_snapshot.artifact_id.clone(),
            sha256: Sha256Digest::from_bytes(*record.blob().sha256()).to_hex(),
            byte_length: record.blob().byte_length(),
        }
    };
    // No data guard crosses the constructor: rejection drops its original allocation lease.
    let prepared = PreparedArtifactRead::from_trusted_preparation(
        auth.clone(),
        facts,
        original_deadline,
        operation,
        first,
        completion,
    )?;
    attempt.completed = true;
    Ok(prepared)
}

#[cfg(test)]
pub(in crate::artifact_administration) struct PublicPrepareProbe {
    pub(super) state: std::sync::Mutex<std::sync::Weak<ReadOperationState>>,
    worker_gate: std::sync::Mutex<Option<BlockingGate>>,
    hash_gate: std::sync::Mutex<Option<BlockingGate>>,
    pub(super) sha_segments: std::sync::atomic::AtomicUsize,
    pub(super) prefix: std::sync::Mutex<Option<(usize, usize, String)>>,
}
#[cfg(test)]
struct BlockingGate {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
#[cfg(test)]
impl PublicPrepareProbe {
    fn enroll(&self, state: &Arc<ReadOperationState>) -> Result<(), AppError> {
        let mut original = self.state.lock().map_err(|_| unavailable())?;
        if original.strong_count() != 0 {
            return Err(unavailable());
        }
        *original = Arc::downgrade(state);
        Ok(())
    }
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(std::sync::Weak::new()),
            worker_gate: std::sync::Mutex::new(None),
            hash_gate: std::sync::Mutex::new(None),
            sha_segments: std::sync::atomic::AtomicUsize::new(0),
            prefix: std::sync::Mutex::new(None),
        })
    }
    pub(super) fn hold_worker(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        Self::hold(&self.worker_gate)
    }
    pub(super) fn hold_first_sha_segment(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        Self::hold(&self.hash_gate)
    }
    fn hold(
        gate: &std::sync::Mutex<Option<BlockingGate>>,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, receipt) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        *gate.lock().expect("private original gate") = Some(BlockingGate {
            entered,
            release: wait,
        });
        (receipt, release)
    }
    fn wait(gate: &std::sync::Mutex<Option<BlockingGate>>) -> Result<(), ArtifactReadCurrentError> {
        let original = gate
            .lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)?
            .take();
        if let Some(original) = original {
            original
                .entered
                .send(())
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
            original
                .release
                .recv()
                .map_err(|_| ArtifactReadCurrentError::Unavailable)?;
        }
        Ok(())
    }
}

#[cfg(test)]
fn actual_probe(
    state: &Arc<ReadOperationState>,
) -> Result<Option<Arc<PublicPrepareProbe>>, ArtifactReadCurrentError> {
    state
        .public_prepare_probe
        .lock()
        .map(|probe| probe.as_ref().map(Arc::clone))
        .map_err(|_| ArtifactReadCurrentError::Unavailable)
}

#[cfg(test)]
pub(super) fn worker_entered(
    state: &Arc<ReadOperationState>,
) -> Result<(), ArtifactReadCurrentError> {
    if let Some(probe) = actual_probe(state)? {
        PublicPrepareProbe::wait(&probe.worker_gate)?;
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn hash_guard(
    state: &Arc<ReadOperationState>,
    after_sha_segment: bool,
) -> Result<(), ArtifactReadCurrentError> {
    if after_sha_segment && let Some(probe) = actual_probe(state)? {
        let segment = probe
            .sha_segments
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if segment == 1 {
            PublicPrepareProbe::wait(&probe.hash_gate)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn observe_prefix(
    state: &Arc<ReadOperationState>,
    pending: &mut openbot_contracts::artifact_read::PendingArtifactReadBuffer,
) -> Result<(), ArtifactReadCurrentError> {
    if let Some(probe) = actual_probe(state)? {
        let length = pending
            .actual_length()
            .ok_or(ArtifactReadCurrentError::Unavailable)?;
        let capacity = pending.initialized_mut().len();
        let sha256 = Sha256Digest::of(&pending.initialized_mut()[..length]).to_hex();
        *probe
            .prefix
            .lock()
            .map_err(|_| ArtifactReadCurrentError::Unavailable)? = Some((length, capacity, sha256));
    }
    Ok(())
}

#[cfg(test)]
#[path = "public_read_prepare_tests.rs"]
mod tests;
