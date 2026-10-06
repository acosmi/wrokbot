//! One original public artifact reader. Control JSON cannot mint byte ownership.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_contracts::artifact_read_protocol::{
    AcknowledgeArtifactReadBlock, ArtifactReadAcknowledged, ArtifactReadChunkDescriptor,
    ArtifactReadClosed, ArtifactReadOpened, CloseArtifactRead, OpenArtifactRead,
    ReadArtifactReadBlock, is_canonical_artifact_read_handle,
};
use openbot_contracts::artifacts::{
    MAX_ARTIFACT_BYTES, canonical_artifact_uuid_v7, is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::AppReply;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    ArtifactReadCurrentTarget, HostRequestBindingIdentity, HostRequestBindingKind,
    RequestBindingIssuer,
};
use tokio::sync::{Mutex as AsyncMutex, Notify};

use crate::artifact_read_lifecycle::{
    CurrentArtifactReadBlock, CurrentArtifactReadControlTail, CurrentArtifactReadFrame,
    CurrentArtifactReadOperation,
};
use crate::artifacts::ArtifactAdministration;

/// Actual trusted facts from the same prepared original reader snapshot, never client input.
pub struct PreparedArtifactReadFacts {
    /// Canonical UUIDv7 of that original artifact record.
    pub artifact_id: String,
    /// Whole SHA256 verified on that original descriptor.
    pub sha256: String,
    /// Exact original logical byte length.
    pub byte_length: u64,
}

/// A trusted completion port for this actual operation, independent of other live readers.
#[async_trait]
pub trait ArtifactReadOperationCompletion: Send + Sync {
    /// Permanently stop the original producer without claiming it already ended.
    fn close(&self);
    /// Wait only this operation's actual worker, FD, full allocation and controlled owners.
    /// Unsupported or unproved implementations must refuse instead of reporting completion.
    async fn drain_before(&self, deadline: Instant) -> Result<(), AppError>;
}

/// Rust-only enrollment of the real producer before its first preparation await or IO.
/// The runtime can then supervise true cleanup even if the preparation waiter disappears.
pub trait ArtifactReadPreparationObserver: Send + Sync {
    /// Register only the completion port of the same actual original operation.
    fn enrolled(
        &self,
        completion: Arc<dyn ArtifactReadOperationCompletion>,
    ) -> Result<(), AppError>;
}

/// One actual prepared retained reader and first pending allocation.
/// It carries no host-owner lease and cannot be cloned or deserialized.
pub struct PreparedArtifactRead {
    pub(crate) auth: AuthContext,
    pub(crate) facts: PreparedArtifactReadFacts,
    pub(crate) original_deadline: Instant,
    pub(crate) operation: CurrentArtifactReadOperation,
    pub(crate) first: Option<CurrentArtifactReadBlock>,
    pub(crate) completion: Arc<dyn ArtifactReadOperationCompletion>,
}
impl PreparedArtifactRead {
    /// Build only from the same trusted real preparation; the public caller supplies none of it.
    #[doc(hidden)]
    pub fn from_trusted_preparation(
        auth: AuthContext,
        facts: PreparedArtifactReadFacts,
        original_deadline: Instant,
        operation: CurrentArtifactReadOperation,
        first: CurrentArtifactReadBlock,
        completion: Arc<dyn ArtifactReadOperationCompletion>,
    ) -> Result<Self, AppError> {
        // Couple every owner before any fallible check, so rejection closes the real producer.
        let prepared = Self {
            auth,
            facts,
            original_deadline,
            operation,
            first: Some(first),
            completion,
        };
        let binding = prepared
            .auth
            .request_binding()
            .ok_or_else(host_unavailable)?;
        if !matches!(
            binding.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
        ) {
            return Err(host_unavailable());
        }
        if canonical_artifact_uuid_v7(&prepared.facts.artifact_id).as_deref()
            != Some(prepared.facts.artifact_id.as_str())
            || !is_valid_artifact_sha256(&prepared.facts.sha256)
            || prepared.facts.byte_length > MAX_ARTIFACT_BYTES
        {
            return Err(artifacts_unavailable());
        }
        prepared
            .original_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero() && *remaining <= Duration::from_secs(600))
            .ok_or_else(artifacts_unavailable)?;
        prepared
            .first
            .as_ref()
            .ok_or_else(artifacts_unavailable)?
            .prefix_length()?;
        Ok(prepared)
    }
}
impl Drop for PreparedArtifactRead {
    fn drop(&mut self) {
        // Stop before dropping a pending full allocation; its real lease closes the original FD.
        self.completion.close();
        drop(self.first.take());
    }
}

const HANDLE_LIFETIME: Duration = Duration::from_secs(600);
const CONTROL_BUDGET: Duration = Duration::from_secs(5);
const MAX_OPEN_READERS: usize = 64;
const MAX_BINDING_READERS: usize = 8;

/// Instance-local reader owners. Locators never replace the original host identity.
pub(crate) struct PublicArtifactReadRegistry {
    inner: Arc<RegistryInner>,
}
struct RegistryInner {
    stopped: AtomicBool,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}
struct Entry {
    id: String,
    auth: AuthContext,
    original_deadline: Instant,
    registry: Weak<RegistryInner>,
    runtime: tokio::runtime::Handle,
    stopped: AtomicBool,
    preparation_finished: AtomicBool,
    cleanup_started: AtomicBool,
    changed: Notify,
    completion: Mutex<Option<Arc<dyn ArtifactReadOperationCompletion>>>,
    data: AsyncMutex<EntryData>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opening,
    Ready,
    DescriptorReady,
    DeliverySelected,
    AwaitingAcknowledgment,
    ReleasePending,
    EofReady,
    Closing,
    Closed,
}
struct EntryData {
    phase: Phase,
    prepared: Option<PreparedArtifactRead>,
    target: Option<Arc<dyn ArtifactReadCurrentTarget>>,
    sequence: u32,
    last_ack: Option<CompletedAcknowledgment>,
    pending: Option<CurrentArtifactReadBlock>,
    descriptor: Option<ArtifactReadChunkDescriptor>,
    registry_block: Option<Arc<SharedBlock>>,
    released: Option<Arc<ActualRelease>>,
    eof_tail: Option<Arc<CurrentArtifactReadControlTail>>,
    terminal_ready_before: Option<Instant>,
    control: Option<ControlRecord>,
}
struct ControlRecord {
    reply: AppReply,
    tail: Arc<CurrentArtifactReadControlTail>,
    valid_before: Instant,
}
struct CompletedAcknowledgment {
    sequence: u32,
    tail: Arc<CurrentArtifactReadControlTail>,
    valid_before: Instant,
}
impl EntryData {
    fn opening() -> Self {
        Self {
            phase: Phase::Opening,
            prepared: None,
            target: None,
            sequence: 0,
            last_ack: None,
            pending: None,
            descriptor: None,
            registry_block: None,
            released: None,
            eof_tail: None,
            terminal_ready_before: None,
            control: None,
        }
    }
    fn close_owned(&mut self) {
        self.phase = Phase::Closing;
        drop(self.pending.take());
        drop(self.registry_block.take());
        drop(self.eof_tail.take());
        drop(self.last_ack.take());
        if let Some(prepared) = &mut self.prepared {
            prepared.operation.close();
            drop(prepared.first.take());
        }
    }
    fn record_control(
        &mut self,
        reply: AppReply,
        tail: Arc<CurrentArtifactReadControlTail>,
        valid_before: Instant,
    ) -> Result<(), AppError> {
        if self.control.is_some() {
            return Err(busy());
        }
        self.control = Some(ControlRecord {
            reply,
            tail,
            valid_before,
        });
        Ok(())
    }
}
impl PublicArtifactReadRegistry {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                stopped: AtomicBool::new(false),
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }
    fn original_entry(&self, auth: &AuthContext, id: &str) -> Result<Arc<Entry>, AppError> {
        if !is_canonical_artifact_read_handle(id) {
            return Err(AppError::MalformedPayload { field: "handleId" });
        }
        let entry = self
            .inner
            .entries
            .lock()
            .map_err(|_| artifacts_unavailable())?
            .get(id)
            .cloned()
            .ok_or(AppError::NotVisible)?;
        // Foreign locators are indistinguishable from absent ones, and never stop their owner.
        if !entry.matches(auth) {
            return Err(AppError::NotVisible);
        }
        Ok(entry)
    }
    fn admit(&self, auth: &AuthContext) -> Result<Arc<Entry>, AppError> {
        let binding = auth.request_binding().ok_or_else(host_unavailable)?;
        if !matches!(
            binding.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::DesktopWindow
        ) {
            return Err(host_unavailable());
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| artifacts_unavailable())?;
        let original_deadline = Instant::now()
            .checked_add(HANDLE_LIFETIME)
            .ok_or_else(artifacts_unavailable)?;
        binding.check_source_run_artifact_ids_attachment(auth, original_deadline)?;
        let mut entries = self
            .inner
            .entries
            .lock()
            .map_err(|_| artifacts_unavailable())?;
        if self.inner.stopped.load(Ordering::SeqCst) {
            return Err(artifacts_unavailable());
        }
        let owned = entries.values().filter(|entry| entry.matches(auth)).count();
        if entries.len() >= MAX_OPEN_READERS || owned >= MAX_BINDING_READERS {
            return Err(busy());
        }
        let id = uuid::Uuid::now_v7().to_string();
        if entries.contains_key(&id) {
            return Err(artifacts_unavailable());
        }
        let entry = Arc::new(Entry {
            id: id.clone(),
            auth: auth.clone(),
            original_deadline,
            registry: Arc::downgrade(&self.inner),
            runtime,
            stopped: AtomicBool::new(false),
            preparation_finished: AtomicBool::new(false),
            cleanup_started: AtomicBool::new(false),
            changed: Notify::new(),
            completion: Mutex::new(None),
            data: AsyncMutex::new(EntryData::opening()),
        });
        entries.insert(id, Arc::clone(&entry));
        drop(entries);
        let timer_entry = Arc::clone(&entry);
        entry.runtime.spawn(expire_original_reader(timer_entry));
        Ok(entry)
    }
    pub(crate) async fn open(
        &self,
        administration: &dyn ArtifactAdministration,
        auth: &AuthContext,
        input: OpenArtifactRead,
    ) -> Result<ArtifactReadOpened, AppError> {
        if canonical_artifact_uuid_v7(&input.artifact_id).as_deref()
            != Some(input.artifact_id.as_str())
        {
            return Err(AppError::MalformedPayload {
                field: "artifactId",
            });
        }
        let entry = self.admit(auth)?;
        let mut attempt = PreparationAttempt {
            entry: Arc::clone(&entry),
            completed: false,
        };
        let observer: Arc<dyn ArtifactReadPreparationObserver> =
            Arc::new(EntryObserver(Arc::clone(&entry)));
        let prepared = administration
            .prepare_host_bound_artifact_read(
                auth,
                &input.artifact_id,
                entry.original_deadline,
                observer,
            )
            .await?;
        entry.preparation_finished.store(true, Ordering::SeqCst);
        let enrolled = entry
            .completion
            .lock()
            .map_err(|_| artifacts_unavailable())?
            .clone()
            .ok_or_else(artifacts_unavailable)?;
        if entry.stopped.load(Ordering::SeqCst)
            || prepared.auth != *auth
            || prepared.facts.artifact_id != input.artifact_id
            || prepared.original_deadline != entry.original_deadline
            || !Arc::ptr_eq(&enrolled, &prepared.completion)
        {
            return Err(artifacts_unavailable());
        }
        let target = prepared
            .first
            .as_ref()
            .ok_or_else(artifacts_unavailable)?
            .current_target();
        let deadline = entry.budget()?;
        let tail = Arc::new(
            CurrentArtifactReadControlTail::observe_current_before(
                auth,
                Arc::clone(&target),
                deadline,
            )
            .await?,
        );
        let remaining_millis = u32::try_from(
            entry
                .original_deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(artifacts_unavailable)?
                .as_millis(),
        )
        .map_err(|_| artifacts_unavailable())?;
        let reply = ArtifactReadOpened {
            handle_id: entry.id.clone(),
            artifact_id: prepared.facts.artifact_id.clone(),
            sha256: prepared.facts.sha256.clone(),
            byte_length: prepared.facts.byte_length,
            remaining_millis,
        };
        let mut data = entry.data.lock().await;
        if entry.stopped.load(Ordering::SeqCst) {
            return Err(artifacts_unavailable());
        }
        data.prepared = Some(prepared);
        data.target = Some(target);
        data.phase = Phase::Ready;
        data.record_control(AppReply::ArtifactReadOpened(reply.clone()), tail, deadline)?;
        attempt.completed = true;
        Ok(reply)
    }
    pub(crate) async fn next(
        &self,
        auth: &AuthContext,
        input: ReadArtifactReadBlock,
    ) -> Result<ArtifactReadChunkDescriptor, AppError> {
        let entry = self.original_entry(auth, &input.handle_id)?;
        let mut data = entry.data.try_lock().map_err(|_| busy())?;
        if data.sequence != input.sequence || data.phase != Phase::Ready || data.control.is_some() {
            return Err(busy());
        }
        let deadline = entry.budget()?;
        let mut attempt = AcceptedAttempt::new(Arc::clone(&entry));
        let prepared = data.prepared.as_mut().ok_or_else(artifacts_unavailable)?;
        let mut block = if let Some(first) = prepared.first.take() {
            first
        } else {
            prepared.operation.next_block(auth).await?
        };
        // The prepared first block is not reread, rehashed, or reopened after a delayed client.
        block.refresh_current_before(auth, deadline).await?;
        let length = block.prefix_length()?;
        let byte_length = u32::try_from(length).map_err(|_| artifacts_unavailable())?;
        if length > openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES {
            return Err(artifacts_unavailable());
        }
        let descriptor = ArtifactReadChunkDescriptor {
            handle_id: entry.id.clone(),
            sequence: input.sequence,
            byte_length,
            eof: length == 0,
        };
        if length == 0 {
            // A real zero read releases the full initialized allocation before any EOF success.
            let tail = Arc::new(block.handoff_frame(auth)?.into_control_tail());
            entry.signal_stop()?;
            data.close_owned();
            let completion = entry.actual_completion()?;
            completion.drain_before(deadline).await?;
            tail.verify_current_tail(auth)?;
            data.eof_tail = Some(tail);
            data.terminal_ready_before = Some(deadline);
            data.phase = Phase::EofReady;
        } else {
            data.pending = Some(block);
            data.phase = Phase::DescriptorReady;
        }
        data.descriptor = Some(descriptor.clone());
        attempt.completed = true;
        drop(data);
        if descriptor.eof {
            entry.start_cleanup();
        }
        Ok(descriptor)
    }
    pub(crate) fn take_delivery(
        &self,
        auth: &AuthContext,
        input: ReadArtifactReadBlock,
    ) -> Result<PublicArtifactReadDelivery, AppError> {
        let entry = self.original_entry(auth, &input.handle_id)?;
        let mut data = entry.data.try_lock().map_err(|_| busy())?;
        let descriptor = data
            .descriptor
            .as_ref()
            .filter(|value| value.sequence == input.sequence)
            .cloned()
            .ok_or_else(busy)?;
        let payload = match data.phase {
            Phase::DescriptorReady if !entry.stopped.load(Ordering::SeqCst) => {
                DeliveryPayload::Data(Box::new(
                    data.pending.take().ok_or_else(artifacts_unavailable)?,
                ))
            }
            Phase::EofReady if descriptor.eof => {
                DeliveryPayload::Eof(data.eof_tail.take().ok_or_else(artifacts_unavailable)?)
            }
            _ => return Err(busy()),
        };
        data.phase = Phase::DeliverySelected;
        drop(data);
        Ok(PublicArtifactReadDelivery {
            entry,
            descriptor,
            payload: Some(payload),
            completed: false,
        })
    }
    pub(crate) async fn acknowledge(
        &self,
        auth: &AuthContext,
        input: AcknowledgeArtifactReadBlock,
    ) -> Result<ArtifactReadAcknowledged, AppError> {
        let entry = self.original_entry(auth, &input.handle_id)?;
        let mut data = entry.data.try_lock().map_err(|_| busy())?;
        if data.control.is_some() {
            return Err(busy());
        }
        if let Some(previous) = data
            .last_ack
            .as_ref()
            .filter(|ack| ack.sequence == input.sequence)
        {
            let mut attempt = AcceptedAttempt::new(Arc::clone(&entry));
            // A duplicate reuses the same completed proof and its original window. It cannot
            // acquire a new budget, observe the artifact again, or release any carrier twice.
            if entry.stopped.load(Ordering::SeqCst)
                || Instant::now() >= entry.original_deadline
                || Instant::now() >= previous.valid_before
            {
                return Err(artifacts_unavailable());
            }
            previous.tail.verify_current_tail(auth)?;
            let tail = Arc::clone(&previous.tail);
            let valid_before = previous.valid_before;
            let reply = ArtifactReadAcknowledged {
                handle_id: entry.id.clone(),
                sequence: input.sequence,
            };
            data.record_control(
                AppReply::ArtifactReadAcknowledged(reply.clone()),
                tail,
                valid_before,
            )?;
            attempt.completed = true;
            return Ok(reply);
        }
        if data.sequence != input.sequence
            || !matches!(
                data.phase,
                Phase::AwaitingAcknowledgment | Phase::ReleasePending
            )
        {
            return Err(busy());
        }
        let deadline = entry.budget()?;
        let mut attempt = AcceptedAttempt::new(Arc::clone(&entry));
        let target = data
            .target
            .as_ref()
            .cloned()
            .ok_or_else(artifacts_unavailable)?;
        let tail = Arc::new(
            CurrentArtifactReadControlTail::observe_current_before(auth, target, deadline).await?,
        );
        // The registry hold is relinquished exactly once. Success waits for the real last
        // transport owner's Drop, which wipes the full allocation before setting release.
        if data.phase == Phase::AwaitingAcknowledgment {
            data.phase = Phase::ReleasePending;
            drop(data.registry_block.take());
        }
        let release = data
            .released
            .as_ref()
            .cloned()
            .ok_or_else(artifacts_unavailable)?;
        release.wait_before(deadline).await?;
        tail.verify_current_tail(auth)?;
        data.sequence = data
            .sequence
            .checked_add(1)
            .ok_or_else(artifacts_unavailable)?;
        data.last_ack = Some(CompletedAcknowledgment {
            sequence: input.sequence,
            tail: Arc::clone(&tail),
            valid_before: deadline,
        });
        data.released = None;
        data.descriptor = None;
        data.phase = Phase::Ready;
        tail.verify_current_tail(auth)?;
        let reply = ArtifactReadAcknowledged {
            handle_id: entry.id.clone(),
            sequence: input.sequence,
        };
        data.record_control(
            AppReply::ArtifactReadAcknowledged(reply.clone()),
            tail,
            deadline,
        )?;
        attempt.completed = true;
        Ok(reply)
    }
    pub(crate) async fn close(
        &self,
        auth: &AuthContext,
        input: CloseArtifactRead,
    ) -> Result<ArtifactReadClosed, AppError> {
        let entry = self.original_entry(auth, &input.handle_id)?;
        let mut data = entry.data.try_lock().map_err(|_| busy())?;
        if data.control.is_some() {
            return Err(busy());
        }
        let deadline = entry.budget()?;
        let mut attempt = AcceptedAttempt::new(Arc::clone(&entry));
        let target = data
            .target
            .as_ref()
            .cloned()
            .ok_or_else(artifacts_unavailable)?;
        let tail = Arc::new(
            CurrentArtifactReadControlTail::observe_current_before(auth, target, deadline).await?,
        );
        entry.signal_stop()?;
        data.close_owned();
        entry.actual_completion()?.drain_before(deadline).await?;
        tail.verify_current_tail(auth)?;
        let reply = ArtifactReadClosed {
            handle_id: entry.id.clone(),
        };
        data.phase = Phase::Closed;
        data.record_control(AppReply::ArtifactReadClosed(reply.clone()), tail, deadline)?;
        attempt.completed = true;
        drop(data);
        entry.start_cleanup();
        Ok(reply)
    }
    pub(crate) fn take_control(
        &self,
        auth: &AuthContext,
        reply: AppReply,
    ) -> Result<PublicArtifactReadControlDelivery, AppError> {
        let id = match &reply {
            AppReply::ArtifactReadOpened(value) => &value.handle_id,
            AppReply::ArtifactReadAcknowledged(value) => &value.handle_id,
            AppReply::ArtifactReadClosed(value) => &value.handle_id,
            _ => return Err(artifacts_unavailable()),
        };
        let entry = self.original_entry(auth, id)?;
        let mut data = entry.data.try_lock().map_err(|_| busy())?;
        let record = data.control.as_ref().ok_or_else(busy)?;
        if record.reply != reply {
            return Err(busy());
        }
        let record = data.control.take().ok_or_else(busy)?;
        drop(data);
        entry.changed.notify_one();
        Ok(PublicArtifactReadControlDelivery {
            entry,
            reply: record.reply,
            tail: record.tail,
            verified: AtomicBool::new(false),
        })
    }
    pub(crate) fn close_all(&self) -> Result<(), AppError> {
        self.inner.stopped.store(true, Ordering::SeqCst);
        self.close_matching(|_| true)
    }
    pub(crate) fn close_for_issuer(&self, issuer: &RequestBindingIssuer) -> Result<(), AppError> {
        self.close_matching(|entry| {
            entry
                .auth
                .request_binding()
                .is_some_and(|binding| issuer.owns_identity(binding.identity()))
        })
    }
    pub(crate) fn close_for_binding(
        &self,
        identity: &HostRequestBindingIdentity,
    ) -> Result<(), AppError> {
        self.close_matching(|entry| {
            entry
                .auth
                .request_binding()
                .is_some_and(|binding| binding.identity().same_binding(identity))
        })
    }
    fn close_matching(&self, predicate: impl Fn(&Entry) -> bool) -> Result<(), AppError> {
        let entries: Vec<_> = self
            .inner
            .entries
            .lock()
            .map_err(|_| artifacts_unavailable())?
            .values()
            .filter(|entry| predicate(entry))
            .cloned()
            .collect();
        for entry in entries {
            entry.stop();
        }
        Ok(())
    }
}
impl Drop for PublicArtifactReadRegistry {
    fn drop(&mut self) {
        let _ = self.close_all();
    }
}
async fn expire_original_reader(entry: Arc<Entry>) {
    loop {
        if entry.stopped.load(Ordering::SeqCst) {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(entry.original_deadline)) => {
                entry.stop();
                return;
            }
            () = entry.changed.notified() => {}
        }
    }
}
impl Entry {
    fn matches(&self, auth: &AuthContext) -> bool {
        self.auth == *auth
            && self
                .auth
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(original, current)| {
                    original.identity().same_binding(current.identity())
                })
    }
    fn budget(&self) -> Result<Instant, AppError> {
        if self.stopped.load(Ordering::SeqCst) || Instant::now() >= self.original_deadline {
            return Err(artifacts_unavailable());
        }
        let deadline = Instant::now()
            .checked_add(CONTROL_BUDGET)
            .ok_or_else(artifacts_unavailable)?
            .min(self.original_deadline);
        self.auth
            .request_binding()
            .ok_or_else(host_unavailable)?
            .check_source_run_artifact_ids_attachment(&self.auth, deadline)?;
        Ok(deadline)
    }
    fn actual_completion(&self) -> Result<Arc<dyn ArtifactReadOperationCompletion>, AppError> {
        self.completion
            .lock()
            .map_err(|_| artifacts_unavailable())?
            .clone()
            .ok_or_else(artifacts_unavailable)
    }
    fn signal_stop(&self) -> Result<(), AppError> {
        self.stopped.store(true, Ordering::SeqCst);
        self.changed.notify_one();
        if let Some(completion) = self
            .completion
            .lock()
            .map_err(|_| artifacts_unavailable())?
            .as_ref()
        {
            completion.close();
        }
        Ok(())
    }
    fn stop(self: &Arc<Self>) {
        let _ = self.signal_stop();
        self.start_cleanup();
    }
    fn start_cleanup(self: &Arc<Self>) {
        if self.cleanup_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let entry = Arc::clone(self);
        self.runtime.spawn(async move {
            entry.cleanup().await;
        });
    }
    async fn cleanup(self: Arc<Self>) {
        loop {
            let keep_terminal = {
                let mut data = self.data.lock().await;
                let keep_eof = data.phase == Phase::EofReady
                    && data.eof_tail.is_some()
                    && data
                        .terminal_ready_before
                        .is_some_and(|deadline| Instant::now() < deadline);
                let eof = if keep_eof { data.eof_tail.take() } else { None };
                data.close_owned();
                if keep_eof {
                    data.eof_tail = eof;
                    data.phase = Phase::EofReady;
                }
                // A genuine already-closed control may still be waiting for its actual first
                // transport poll. Keep its finite original proof, never renew its budget.
                let keep = data.control.as_ref().is_some_and(|record| {
                    matches!(record.reply, AppReply::ArtifactReadClosed(_))
                        && Instant::now() < record.valid_before
                });
                if !keep {
                    data.control = None;
                }
                keep || keep_eof
            };
            if !self.preparation_finished.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            let completion = { self.completion.lock().ok().map(|value| value.clone()) };
            let Some(completion) = completion else {
                tokio::time::sleep(CONTROL_BUDGET).await;
                continue;
            };
            let closed = if let Some(completion) = completion {
                completion.close();
                match Instant::now().checked_add(CONTROL_BUDGET) {
                    Some(deadline) => completion.drain_before(deadline).await.is_ok(),
                    None => false,
                }
            } else {
                // The trusted factory enrolls before its first await/IO; a finished unsupported
                // preparation without enrollment has no admitted physical producer.
                true
            };
            if closed && !keep_terminal {
                if let Some(registry) = self.registry.upgrade() {
                    let Ok(mut entries) = registry.entries.lock() else {
                        return;
                    };
                    if entries
                        .get(&self.id)
                        .is_some_and(|actual| Arc::ptr_eq(actual, &self))
                    {
                        entries.remove(&self.id);
                    }
                }
                return;
            }
            tokio::time::sleep(if closed {
                Duration::from_millis(10)
            } else {
                CONTROL_BUDGET
            })
            .await;
        }
    }
}
struct EntryObserver(Arc<Entry>);
impl ArtifactReadPreparationObserver for EntryObserver {
    fn enrolled(
        &self,
        completion: Arc<dyn ArtifactReadOperationCompletion>,
    ) -> Result<(), AppError> {
        let mut original = self
            .0
            .completion
            .lock()
            .map_err(|_| artifacts_unavailable())?;
        if original.is_some() {
            completion.close();
            return Err(artifacts_unavailable());
        }
        *original = Some(Arc::clone(&completion));
        if self.0.stopped.load(Ordering::SeqCst) {
            completion.close();
            return Err(artifacts_unavailable());
        }
        Ok(())
    }
}
struct PreparationAttempt {
    entry: Arc<Entry>,
    completed: bool,
}
impl Drop for PreparationAttempt {
    fn drop(&mut self) {
        self.entry
            .preparation_finished
            .store(true, Ordering::SeqCst);
        if !self.completed {
            self.entry.stop();
        }
    }
}
struct AcceptedAttempt {
    entry: Arc<Entry>,
    completed: bool,
}
impl AcceptedAttempt {
    fn new(entry: Arc<Entry>) -> Self {
        Self {
            entry,
            completed: false,
        }
    }
}
impl Drop for AcceptedAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.entry.stop();
        }
    }
}
struct ActualRelease {
    released: AtomicBool,
    changed: Notify,
}
impl ActualRelease {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }
    async fn wait_before(&self, deadline: Instant) -> Result<(), AppError> {
        loop {
            let notified = self.changed.notified();
            if self.released.load(Ordering::SeqCst) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(artifacts_unavailable());
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), notified)
                .await
                .map_err(|_| artifacts_unavailable())?;
        }
    }
}
struct ReleaseAfterFrame(Arc<ActualRelease>);
impl Drop for ReleaseAfterFrame {
    fn drop(&mut self) {
        self.0.released.store(true, Ordering::SeqCst);
        self.0.changed.notify_waiters();
        self.0.changed.notify_one();
    }
}
// Rust drops fields in declaration order: the same full allocation and actual lease end
// before ReleaseAfterFrame marks successful disposal. No borrowed unlocked mutex slice.
struct SharedBlock {
    frame: CurrentArtifactReadFrame,
    _release_after_frame: ReleaseAfterFrame,
}
enum DeliveryPayload {
    Data(Box<CurrentArtifactReadBlock>),
    Eof(Arc<CurrentArtifactReadControlTail>),
}

/// One real pending body, selected once. Abandoning it stops only the original producer.
pub struct PublicArtifactReadDelivery {
    entry: Arc<Entry>,
    descriptor: ArtifactReadChunkDescriptor,
    payload: Option<DeliveryPayload>,
    completed: bool,
}
impl PublicArtifactReadDelivery {
    /// The matched scalar descriptor grants no ownership on its own.
    #[must_use]
    pub const fn descriptor(&self) -> &ArtifactReadChunkDescriptor {
        &self.descriptor
    }
    /// Actual synchronous transport boundary; genuine EOF already has true close completion.
    pub fn handoff(
        mut self,
        auth: &AuthContext,
    ) -> Result<Option<PublicArtifactReadTransportBlock>, AppError> {
        if !self.entry.matches(auth) {
            return Err(AppError::Unauthenticated);
        }
        let payload = self.payload.take().ok_or_else(artifacts_unavailable)?;
        let mut data = self.entry.data.try_lock().map_err(|_| busy())?;
        if data.descriptor.as_ref() != Some(&self.descriptor)
            || (matches!(payload, DeliveryPayload::Data(_))
                && data.phase != Phase::DeliverySelected)
        {
            return Err(artifacts_unavailable());
        }
        match payload {
            DeliveryPayload::Data(block) => {
                if self.entry.stopped.load(Ordering::SeqCst) {
                    return Err(artifacts_unavailable());
                }
                let frame = block.handoff_frame(auth)?;
                if frame.is_empty()
                    || frame.len() != self.descriptor.byte_length as usize
                    || self.descriptor.eof
                {
                    return Err(artifacts_unavailable());
                }
                let released = Arc::new(ActualRelease::new());
                let shared = Arc::new(SharedBlock {
                    frame,
                    _release_after_frame: ReleaseAfterFrame(Arc::clone(&released)),
                });
                shared.frame.verify_current_tail(auth)?;
                data.registry_block = Some(Arc::clone(&shared));
                data.released = Some(released);
                data.phase = Phase::AwaitingAcknowledgment;
                self.completed = true;
                Ok(Some(PublicArtifactReadTransportBlock {
                    shared,
                    entry: Arc::clone(&self.entry),
                }))
            }
            DeliveryPayload::Eof(tail) => {
                if !self.descriptor.eof || self.descriptor.byte_length != 0 {
                    return Err(artifacts_unavailable());
                }
                tail.verify_current_tail(auth)?;
                data.phase = Phase::Closed;
                self.completed = true;
                drop(data);
                self.entry.start_cleanup();
                Ok(None)
            }
        }
    }
}
impl Drop for PublicArtifactReadDelivery {
    fn drop(&mut self) {
        // Drop the pending owner before supervising completion.
        drop(self.payload.take());
        if !self.completed {
            self.entry.stop();
        }
    }
}

/// Immutable controlled prefix owner, suitable for the existing Bytes::from_owner carrier.
pub struct PublicArtifactReadTransportBlock {
    shared: Arc<SharedBlock>,
    entry: Arc<Entry>,
}
impl AsRef<[u8]> for PublicArtifactReadTransportBlock {
    fn as_ref(&self) -> &[u8] {
        self.shared.frame.as_bytes()
    }
}
impl PublicArtifactReadTransportBlock {
    /// Actual prefix length; the original full initialized allocation remains retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared.frame.len()
    }
    /// Report only the real already-read prefix.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.frame.is_empty()
    }
    /// Final original host, physical reader, window and clock check. A failure closes its owner.
    pub fn verify_current_tail(&self, auth: &AuthContext) -> Result<(), AppError> {
        let result = if self.entry.stopped.load(Ordering::SeqCst) {
            Err(artifacts_unavailable())
        } else {
            self.shared.frame.verify_current_tail(auth)
        };
        if result.is_err() {
            self.entry.stop();
        }
        result
    }
    /// Stop only this producer for an actual framing/copy refusal; completion remains factual.
    pub fn close(&self) {
        self.entry.stop();
    }
}

/// The actual current proof retained for an original scalar control until its real handoff.
pub struct PublicArtifactReadControlDelivery {
    entry: Arc<Entry>,
    reply: AppReply,
    tail: Arc<CurrentArtifactReadControlTail>,
    verified: AtomicBool,
}
impl PublicArtifactReadControlDelivery {
    /// Borrow the finite control while retaining its real original proof.
    #[must_use]
    pub const fn reply(&self) -> &AppReply {
        &self.reply
    }
    /// Last synchronous original host/window/clock check; grants no bytes or new FD authority.
    pub fn verify_current_tail(&self, auth: &AuthContext) -> Result<(), AppError> {
        let result = if !self.entry.matches(auth) {
            Err(AppError::Unauthenticated)
        } else {
            self.tail.verify_current_tail(auth)
        };
        if result.is_ok() {
            self.verified.store(true, Ordering::SeqCst);
        } else {
            self.entry.stop();
        }
        result
    }
}
impl Drop for PublicArtifactReadControlDelivery {
    fn drop(&mut self) {
        if !self.verified.load(Ordering::SeqCst) {
            self.entry.stop();
        }
    }
}

const fn busy() -> AppError {
    AppError::RequestConflict {
        resource: "artifact_read",
    }
}

const fn host_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "host_request_binding",
    }
}
const fn artifacts_unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifacts",
    }
}

#[cfg(test)]
#[path = "artifact_read_protocol_tests.rs"]
mod tests;
