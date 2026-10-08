//! Same original Store admission and finite controlled inventory. No deletion authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use openbot_application::artifact_read_protocol::ArtifactReadEntryStop;
use openbot_domain::artifact_cleanup::ArtifactCleanupFenceKey;
use tokio::sync::Notify;

use super::{ArtifactStoreError, DatasetBoundArtifactStore};
use crate::artifact_administration::ObservedArtifactReadRecord;
use crate::artifact_read_lifecycle::{ArtifactReadDrainError, ReadOperationState};

/// Permanent closure of one strictly observed key on the same actual Store.
/// Neither this handle nor its finite ACK authorizes physical deletion or refunds.
pub struct ArtifactReadControlledBarrier {
    store: Arc<DatasetBoundArtifactStore>,
    key: ArtifactCleanupFenceKey,
}

/// The original admitted controlled owners ended. External raw byte copies are excluded.
/// Private construction, no Serde, no conversion from the older instance drain ACK.
pub struct ArtifactReadControlledDrainAck {
    _store: Arc<DatasetBoundArtifactStore>,
    _key: ArtifactCleanupFenceKey,
}

impl ArtifactReadControlledBarrier {
    pub(super) fn new(store: Arc<DatasetBoundArtifactStore>, key: ArtifactCleanupFenceKey) -> Self {
        Self { store, key }
    }

    /// Wait for this exact permanently closed key without renewing any original read budget.
    /// Timeout, cancellation and Drop keep the original closure and all unproved facts.
    pub async fn drain_before(
        &self,
        deadline: Instant,
    ) -> Result<ArtifactReadControlledDrainAck, ArtifactReadDrainError> {
        loop {
            let changed = self.store.reads.changed.notified();
            if Instant::now() >= deadline {
                return Err(ArtifactReadDrainError::Elapsed);
            }
            if self.store.reads.is_drained(&self.key)? {
                return Ok(ArtifactReadControlledDrainAck {
                    _store: Arc::clone(&self.store),
                    _key: self.key.clone(),
                });
            }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    return Err(ArtifactReadDrainError::Elapsed);
                },
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            }
        }
    }
}

struct TrackedState {
    state: Weak<ReadOperationState>,
    // An operation is never guessed from a caller selector. Only the original snapshot binds it.
    key: Option<ArtifactCleanupFenceKey>,
    admitted: bool,
    queries: usize,
    jobs: usize,
    entry_stop: Option<Arc<dyn ArtifactReadEntryStop>>,
}

#[derive(Default)]
struct SelectorInventory {
    // Actual snapshot/FD enrollment fixes the original operation for this Store selector.
    // Never replace it with a differently labelled operation, even after all owners ended.
    original_key: Option<ArtifactCleanupFenceKey>,
    closed: BTreeSet<ArtifactCleanupFenceKey>,
    unproven: BTreeSet<ArtifactCleanupFenceKey>,
    // A real query lost its proof before minting an operation. Conservatively keep that fact.
    unbound_unproven: bool,
    states: Vec<TrackedState>,
    fds: BTreeMap<ArtifactCleanupFenceKey, usize>,
    // The original authority joint covers also Application cached/control-tail callers.
    // Those actual futures need inventory even after Entry/State disposed all body resources.
    original_queries: usize,
    // This invocation owns only its metadata query. It never subtracts an old read owner.
    // Plain terminal facts avoid a Store -> invocation -> original Store ownership cycle.
    physical: Option<PhysicalInvocationSlot>,
    generation: u64,
}

impl SelectorInventory {
    fn controlled_counts_empty(&self, key: &ArtifactCleanupFenceKey) -> bool {
        self.original_queries == 0
            && self.fds.get(key).copied().unwrap_or_default() == 0
            && !self.states.iter().any(|entry| {
                entry.admitted
                    && entry.key.as_ref().is_none_or(|bound| bound == key)
                    && (entry.queries != 0 || entry.jobs != 0)
            })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InvocationKind {
    Physical,
    Terminal,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalQueryAck {
    Commit(uuid::Uuid),
    Rollback,
}

struct PhysicalInvocationSlot {
    kind: InvocationKind,
    id: uuid::Uuid,
    key: ArtifactCleanupFenceKey,
    query_alive: bool,
    query_acknowledged: bool,
    terminal_ack: Option<TerminalQueryAck>,
    worker_reserved: bool,
    worker_started: bool,
    worker_ended: bool,
}

impl PhysicalInvocationSlot {
    fn matches(&self, kind: InvocationKind, id: uuid::Uuid, key: &ArtifactCleanupFenceKey) -> bool {
        self.kind == kind && self.id == id && self.key == *key
    }

    fn is_retired(&self) -> bool {
        !self.query_alive && self.query_acknowledged && (!self.worker_reserved || self.worker_ended)
    }

    fn terminal_precommit_ready(&self) -> bool {
        self.kind == InvocationKind::Terminal
            && self.query_alive
            && !self.query_acknowledged
            && self.terminal_ack.is_none()
            && self.worker_reserved
            && self.worker_started
            && !self.worker_ended
    }

    fn terminal_publish_ready(
        &self,
        mode: TerminalPublishMode,
        original_fact: Option<uuid::Uuid>,
    ) -> bool {
        if self.kind != InvocationKind::Terminal || self.query_alive || !self.query_acknowledged {
            return false;
        }
        match mode {
            TerminalPublishMode::CommittedWorker => {
                matches!(self.terminal_ack, Some(TerminalQueryAck::Commit(id)) if Some(id) == original_fact)
                    && self.worker_reserved
                    && self.worker_started
                    && self.worker_ended
            }
            TerminalPublishMode::CompletedNoWorker => {
                self.terminal_ack == Some(TerminalQueryAck::Rollback)
                    && original_fact.is_some()
                    && !self.worker_reserved
                    && !self.worker_started
                    && !self.worker_ended
            }
        }
    }
}

fn keep_unproven(selector: &mut SelectorInventory, key: Option<ArtifactCleanupFenceKey>) {
    if let Some(key) = key {
        selector.unproven.insert(key.clone());
        selector.closed.insert(key);
    } else {
        selector.unbound_unproven = true;
    }
}

#[derive(Default)]
struct Inventory {
    selectors: BTreeMap<String, SelectorInventory>,
    // Plain committed association, independent of either invocation's lifetime. It carries
    // no original Store/Auth/worker/closure owner and is never repaired or overwritten.
    committed_terminals: BTreeMap<ArtifactCleanupFenceKey, CommittedTerminalFact>,
}

struct CommittedTerminalFact {
    key: ArtifactCleanupFenceKey,
    audit_event_id: uuid::Uuid,
}

impl Inventory {
    fn register_terminal(
        &mut self,
        key: &ArtifactCleanupFenceKey,
        id: uuid::Uuid,
    ) -> Result<(), ArtifactStoreError> {
        let selector = self
            .selectors
            .entry(key.artifact_id().to_owned())
            .or_default();
        if selector
            .original_key
            .as_ref()
            .is_some_and(|original| original != key)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if selector.unbound_unproven
            || selector.unproven.contains(key)
            || selector
                .physical
                .as_ref()
                .is_some_and(|slot| !slot.is_retired())
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        selector.original_key = Some(key.clone());
        selector.physical = Some(PhysicalInvocationSlot {
            kind: InvocationKind::Terminal,
            id,
            key: key.clone(),
            query_alive: true,
            query_acknowledged: false,
            terminal_ack: None,
            worker_reserved: false,
            worker_started: false,
            worker_ended: false,
        });
        selector.generation = selector.generation.wrapping_add(1);
        Ok(())
    }

    // This pure transition is reached only by the consuming typed owner after its real
    // original guarded ACK. Test calls exercise state rules, not PostgreSQL ACK evidence.
    fn acknowledge_terminal(
        &mut self,
        key: &ArtifactCleanupFenceKey,
        id: uuid::Uuid,
        acknowledgement: TerminalQueryAck,
        now: Instant,
        deadline: Instant,
    ) -> Result<(), ArtifactStoreError> {
        let Self {
            selectors,
            committed_terminals,
        } = self;
        let selector = selectors
            .get_mut(key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Terminal, id, key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive || slot.query_acknowledged || slot.terminal_ack.is_some() {
            return Err(ArtifactStoreError::Unavailable);
        }
        let had_live_worker = slot.terminal_precommit_ready();
        // Preserve the real ACK even when registration below fails. This is not permission
        // to publish and never changes a known committed transaction into rollback/unknown.
        slot.query_alive = false;
        slot.query_acknowledged = true;
        slot.terminal_ack = Some(acknowledgement);
        selector.generation = selector.generation.wrapping_add(1);
        if now >= deadline
            || selector.original_key.as_ref() != Some(key)
            || !selector.closed.contains(key)
        {
            keep_unproven(selector, Some(key.clone()));
            return Err(ArtifactStoreError::Unavailable);
        }
        // The real ACK stays known above, but an earlier independent unknown cannot mint
        // a new committed fact. Existing facts remain separate and are never erased here.
        if selector.unbound_unproven || selector.unproven.contains(key) {
            return Err(ArtifactStoreError::Unavailable);
        }
        if let TerminalQueryAck::Commit(audit_event_id) = acknowledgement {
            if !had_live_worker {
                keep_unproven(selector, Some(key.clone()));
                return Err(ArtifactStoreError::Unavailable);
            }
            match committed_terminals.entry(key.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(CommittedTerminalFact {
                        key: key.clone(),
                        audit_event_id,
                    });
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get().key != *key || entry.get().audit_event_id != audit_event_id {
                        keep_unproven(selector, Some(key.clone()));
                        return Err(ArtifactStoreError::BindingMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    fn abandon_terminal(&mut self, key: &ArtifactCleanupFenceKey, id: uuid::Uuid) {
        if let Some(selector) = self.selectors.get_mut(key.artifact_id()) {
            if let Some(slot) = selector
                .physical
                .as_mut()
                .filter(|slot| slot.matches(InvocationKind::Terminal, id, key))
            {
                slot.query_alive = false;
            }
            keep_unproven(selector, Some(key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
        }
    }

    fn terminal_fact(
        &self,
        key: &ArtifactCleanupFenceKey,
    ) -> Result<uuid::Uuid, ArtifactStoreError> {
        self.committed_terminals
            .get(key)
            .filter(|fact| fact.key == *key)
            .map(|fact| fact.audit_event_id)
            .ok_or(ArtifactStoreError::Unavailable)
    }
}

pub(super) struct StoreReadGate {
    deployment: String,
    tenant: String,
    dataset: String,
    inventory: Mutex<Inventory>,
    changed: Notify,
}

impl StoreReadGate {
    pub(super) fn new(deployment: &str, tenant: &str, dataset: &str) -> Arc<Self> {
        Arc::new(Self {
            deployment: deployment.to_owned(),
            tenant: tenant.to_owned(),
            dataset: dataset.to_owned(),
            inventory: Mutex::new(Inventory::default()),
            changed: Notify::new(),
        })
    }

    fn matches_key(&self, key: &ArtifactCleanupFenceKey) -> bool {
        key.deployment_id().as_str() == self.deployment
            && key.tenant_id().as_str() == self.tenant
            && key.dataset_id() == self.dataset
    }

    pub(super) fn enroll(
        self: &Arc<Self>,
        store: Arc<DatasetBoundArtifactStore>,
        state: &Arc<ReadOperationState>,
        artifact_id: &str,
        entry_stop: Option<Arc<dyn ArtifactReadEntryStop>>,
    ) -> Result<StoreReadEnrollment, ArtifactStoreError> {
        if openbot_contracts::artifacts::canonical_artifact_uuid_v7(artifact_id).as_deref()
            != Some(artifact_id)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let original = Arc::downgrade(state);
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .entry(artifact_id.to_owned())
            .or_default();
        selector
            .states
            .retain(|entry| entry.state.strong_count() != 0);
        if selector
            .states
            .iter()
            .any(|entry| Weak::ptr_eq(&entry.state, &original))
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        // A closed new caller may still run the no-body host-first classification. It never
        // joins the previously admitted body inventory and cannot acquire an FD/pending grant.
        let admitted = selector.closed.is_empty() && !selector.unbound_unproven;
        selector.states.push(TrackedState {
            state: original.clone(),
            key: None,
            admitted,
            queries: 0,
            jobs: 0,
            entry_stop,
        });
        selector.generation = selector.generation.wrapping_add(1);
        Ok(StoreReadEnrollment {
            store,
            gate: Arc::clone(self),
            state: original,
            artifact_id: artifact_id.to_owned(),
        })
    }

    pub(super) fn close(&self, key: &ArtifactCleanupFenceKey) -> Result<(), ArtifactStoreError> {
        if !self.matches_key(key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let (states, ports) = {
            let mut inventory = self
                .inventory
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let selector = inventory
                .selectors
                .entry(key.artifact_id().to_owned())
                .or_default();
            if selector
                .original_key
                .as_ref()
                .is_some_and(|original| original != key)
            {
                return Err(ArtifactStoreError::BindingMismatch);
            }
            selector.original_key = Some(key.clone());
            selector.closed.insert(key.clone());
            let mut states = Vec::new();
            let mut ports = Vec::new();
            selector
                .states
                .retain(|entry| entry.state.strong_count() != 0);
            for entry in &selector.states {
                if entry.admitted && entry.key.as_ref().is_none_or(|bound| bound == key) {
                    if let Some(state) = entry.state.upgrade() {
                        states.push(state);
                    }
                    if let Some(port) = &entry.entry_stop {
                        ports.push(Arc::clone(port));
                    }
                }
            }
            selector.generation = selector.generation.wrapping_add(1);
            (states, ports)
        };
        // These can dispose resources and reenter State/gate. Never call them under this lock.
        for state in states {
            state.close();
        }
        for port in ports {
            port.request_stop();
        }
        self.changed.notify_waiters();
        Ok(())
    }

    pub(super) fn admit_fd(
        self: &Arc<Self>,
        key: ArtifactCleanupFenceKey,
    ) -> Result<StoreReadFdLease, ArtifactStoreError> {
        if !self.matches_key(&key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .entry(key.artifact_id().to_owned())
            .or_default();
        if selector
            .original_key
            .as_ref()
            .is_some_and(|original| original != &key)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if selector.closed.contains(&key)
            || selector.unproven.contains(&key)
            || selector.unbound_unproven
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        let count = selector.fds.entry(key.clone()).or_default();
        *count = count
            .checked_add(1)
            .ok_or(ArtifactStoreError::Unavailable)?;
        selector.original_key = Some(key.clone());
        selector.generation = selector.generation.wrapping_add(1);
        Ok(StoreReadFdLease {
            gate: Arc::clone(self),
            key,
        })
    }

    pub(super) fn begin_read_query(
        &self,
        store: Arc<DatasetBoundArtifactStore>,
        artifact_id: &str,
    ) -> Result<StoreReadQueryReservation, ArtifactStoreError> {
        if openbot_contracts::artifacts::canonical_artifact_uuid_v7(artifact_id).as_deref()
            != Some(artifact_id)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .entry(artifact_id.to_owned())
            .or_default();
        // This is a genuine no-body classification query, not FD/pending admission. A closed
        // key still verifies host/source/terminal priority on the same original connection.
        selector.original_queries = selector
            .original_queries
            .checked_add(1)
            .ok_or(ArtifactStoreError::Unavailable)?;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(StoreReadQueryReservation {
            store,
            artifact_id: artifact_id.to_owned(),
            acknowledged: false,
        })
    }

    fn is_drained(&self, key: &ArtifactCleanupFenceKey) -> Result<bool, ArtifactReadDrainError> {
        self.drained_generation(key)
            .map(|generation| generation.is_some())
    }

    fn drained_generation(
        &self,
        key: &ArtifactCleanupFenceKey,
    ) -> Result<Option<u64>, ArtifactReadDrainError> {
        let (generation, states) = {
            let inventory = self
                .inventory
                .lock()
                .map_err(|_| ArtifactReadDrainError::Unavailable)?;
            let selector = inventory
                .selectors
                .get(key.artifact_id())
                .ok_or(ArtifactReadDrainError::Unavailable)?;
            if !selector.closed.contains(key)
                || selector.unproven.contains(key)
                || selector.unbound_unproven
            {
                return Err(ArtifactReadDrainError::Unavailable);
            }
            if !selector.controlled_counts_empty(key) {
                return Ok(None);
            }
            // Strong temporary owners are returned out of the lock before any can drop.
            let states = selector
                .states
                .iter()
                .filter(|entry| {
                    entry.admitted && entry.key.as_ref().is_none_or(|bound| bound == key)
                })
                .filter_map(|entry| entry.state.upgrade())
                .collect::<Vec<_>>();
            (selector.generation, states)
        };
        for state in &states {
            if !state.shared_inventory_drained()? {
                return Ok(None);
            }
        }
        let inventory = self
            .inventory
            .lock()
            .map_err(|_| ArtifactReadDrainError::Unavailable)?;
        // Recheck after the actual State proof. No admitted body job can begin on a closed key.
        let selector = inventory
            .selectors
            .get(key.artifact_id())
            .ok_or(ArtifactReadDrainError::Unavailable)?;
        Ok((selector.generation == generation).then_some(generation))
    }
}

/// Unique same-Store metadata invocation. The slot is neither a current grant nor a drain ACK.
pub(crate) struct PhysicalInvocationClaim {
    store: Arc<DatasetBoundArtifactStore>,
    key: ArtifactCleanupFenceKey,
    id: uuid::Uuid,
    deadline: Instant,
}

/// Only the original guarded transaction's on-time explicit ROLLBACK ACK consumes this owner.
pub(crate) struct PhysicalInvocationQueryOwner {
    claim: Arc<PhysicalInvocationClaim>,
    acknowledged: bool,
}

/// Declared before the worker IO guard and leaf so actual resource Drop precedes ended facts.
pub(crate) struct PhysicalWorkerLease {
    claim: Arc<PhysicalInvocationClaim>,
    active: bool,
}

impl PhysicalInvocationClaim {
    pub(crate) fn register(
        store: Arc<DatasetBoundArtifactStore>,
        key: ArtifactCleanupFenceKey,
        deadline: Instant,
    ) -> Result<(Arc<Self>, PhysicalInvocationQueryOwner), ArtifactStoreError> {
        let strict = ArtifactCleanupFenceKey::from_stored(
            key.deployment_id().clone(),
            key.tenant_id().clone(),
            key.dataset_id(),
            key.operation_id().as_str(),
            key.artifact_id(),
        )
        .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        if strict != key || !store.reads.matches_key(&key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if Instant::now() >= deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        let id = uuid::Uuid::now_v7();
        {
            let mut inventory = store
                .reads
                .inventory
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let selector = inventory
                .selectors
                .entry(key.artifact_id().to_owned())
                .or_default();
            if selector
                .original_key
                .as_ref()
                .is_some_and(|original| original != &key)
            {
                return Err(ArtifactStoreError::BindingMismatch);
            }
            if selector.unbound_unproven
                || selector.unproven.contains(&key)
                || selector
                    .physical
                    .as_ref()
                    .is_some_and(|slot| !slot.is_retired())
            {
                return Err(ArtifactStoreError::Unavailable);
            }
            selector.original_key = Some(key.clone());
            selector.physical = Some(PhysicalInvocationSlot {
                kind: InvocationKind::Physical,
                id,
                key: key.clone(),
                query_alive: true,
                query_acknowledged: false,
                terminal_ack: None,
                worker_reserved: false,
                worker_started: false,
                worker_ended: false,
            });
            selector.generation = selector.generation.wrapping_add(1);
        }
        let claim = Arc::new(Self {
            store,
            key,
            id,
            deadline,
        });
        let owner = PhysicalInvocationQueryOwner {
            claim: Arc::clone(&claim),
            acknowledged: false,
        };
        // Permanent close requests genuine original owners to stop, outside the inventory lock.
        claim.store.reads.close(&claim.key)?;
        if Instant::now() >= deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok((claim, owner))
    }

    pub(crate) async fn wait_original_reads_before(&self) -> Result<(), ArtifactStoreError> {
        loop {
            let changed = self.store.reads.changed.notified();
            self.check_deadline()?;
            if self
                .store
                .reads
                .is_drained(&self.key)
                .map_err(|_| ArtifactStoreError::Unavailable)?
            {
                return Ok(());
            }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline)) => {
                    self.mark_unproven();
                    return Err(ArtifactStoreError::Unavailable);
                },
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            }
        }
    }

    pub(crate) fn reserve_worker(
        self: &Arc<Self>,
    ) -> Result<PhysicalWorkerLease, ArtifactStoreError> {
        self.check_deadline()?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(self.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector.unbound_unproven || selector.unproven.contains(&self.key) {
            return Err(ArtifactStoreError::Unavailable);
        }
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Physical, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive || slot.query_acknowledged || slot.worker_reserved {
            return Err(ArtifactStoreError::Unavailable);
        }
        slot.worker_reserved = true;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(PhysicalWorkerLease {
            claim: Arc::clone(self),
            active: true,
        })
    }

    pub(crate) fn try_start_worker(
        &self,
        worker: &PhysicalWorkerLease,
    ) -> Result<(), ArtifactStoreError> {
        self.check_deadline()?;
        if !std::ptr::eq(self, worker.claim.as_ref()) || !worker.active {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let generation = self
            .store
            .reads
            .drained_generation(&self.key)
            .map_err(|_| ArtifactStoreError::Unavailable)?
            .ok_or(ArtifactStoreError::Unavailable)?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(self.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector.generation != generation
            || selector.unbound_unproven
            || selector.unproven.contains(&self.key)
            || !selector.closed.contains(&self.key)
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        if Instant::now() >= self.deadline {
            keep_unproven(selector, Some(self.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
            return Err(ArtifactStoreError::Unavailable);
        }
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Physical, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive
            || slot.query_acknowledged
            || !slot.worker_reserved
            || slot.worker_started
            || slot.worker_ended
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        slot.worker_started = true;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn verify_publish(&self) -> Result<(), ArtifactStoreError> {
        self.check_deadline()?;
        let generation = self
            .store
            .reads
            .drained_generation(&self.key)
            .map_err(|_| ArtifactStoreError::Unavailable)?
            .ok_or(ArtifactStoreError::Unavailable)?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(self.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector.generation != generation
            || selector.unbound_unproven
            || selector.unproven.contains(&self.key)
            || !selector.closed.contains(&self.key)
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        if Instant::now() >= self.deadline {
            keep_unproven(selector, Some(self.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
            return Err(ArtifactStoreError::Unavailable);
        }
        let slot = selector
            .physical
            .as_ref()
            .filter(|slot| slot.matches(InvocationKind::Physical, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if slot.query_alive
            || !slot.query_acknowledged
            || !slot.worker_reserved
            || !slot.worker_started
            || !slot.worker_ended
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn mark_unproven(&self) {
        if let Ok(mut inventory) = self.store.reads.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(self.key.artifact_id())
        {
            keep_unproven(selector, Some(self.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.store.reads.changed.notify_waiters();
    }

    fn check_deadline(&self) -> Result<(), ArtifactStoreError> {
        if Instant::now() >= self.deadline {
            self.mark_unproven();
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }
}

impl PhysicalInvocationQueryOwner {
    pub(crate) fn acknowledge_rollback(mut self) -> Result<(), ArtifactStoreError> {
        self.claim.check_deadline()?;
        let mut inventory = self
            .claim
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(self.claim.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if Instant::now() >= self.claim.deadline {
            keep_unproven(selector, Some(self.claim.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
            return Err(ArtifactStoreError::Unavailable);
        }
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Physical, self.claim.id, &self.claim.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive || slot.query_acknowledged {
            return Err(ArtifactStoreError::Unavailable);
        }
        slot.query_alive = false;
        slot.query_acknowledged = true;
        selector.generation = selector.generation.wrapping_add(1);
        self.acknowledged = true;
        drop(inventory);
        self.claim.store.reads.changed.notify_waiters();
        Ok(())
    }
}

impl Drop for PhysicalInvocationQueryOwner {
    fn drop(&mut self) {
        if !self.acknowledged {
            if let Ok(mut inventory) = self.claim.store.reads.inventory.lock()
                && let Some(selector) = inventory.selectors.get_mut(self.claim.key.artifact_id())
            {
                if let Some(slot) = selector.physical.as_mut().filter(|slot| {
                    slot.matches(InvocationKind::Physical, self.claim.id, &self.claim.key)
                }) {
                    slot.query_alive = false;
                }
                keep_unproven(selector, Some(self.claim.key.clone()));
                selector.generation = selector.generation.wrapping_add(1);
            }
            self.claim.store.reads.changed.notify_waiters();
        }
    }
}

impl PhysicalWorkerLease {
    pub(crate) fn finish_after_resources(mut self) {
        self.record_ended();
        self.active = false;
    }

    fn record_ended(&self) {
        if let Ok(mut inventory) = self.claim.store.reads.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(self.claim.key.artifact_id())
            && let Some(slot) = selector.physical.as_mut().filter(|slot| {
                slot.matches(InvocationKind::Physical, self.claim.id, &self.claim.key)
            })
        {
            slot.worker_ended = true;
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.claim.store.reads.changed.notify_waiters();
    }
}

impl Drop for PhysicalWorkerLease {
    fn drop(&mut self) {
        if self.active {
            // The worker declares this lease first. Unwind drops its leaf/IO owners first.
            self.record_ended();
        }
    }
}

/// The terminal producer's own original query and worker, never an old read owner.
pub(crate) struct TerminalInvocationClaim {
    store: Arc<DatasetBoundArtifactStore>,
    key: ArtifactCleanupFenceKey,
    id: uuid::Uuid,
    deadline: Instant,
}

/// Consumed only after this original guarded transaction's normal on-time disposition ACK.
pub(crate) struct TerminalInvocationQueryOwner {
    claim: Arc<TerminalInvocationClaim>,
    acknowledged: bool,
}

/// Declare before IO/FD locals; finish explicitly only after those real resources drop.
pub(crate) struct TerminalWorkerLease {
    claim: Arc<TerminalInvocationClaim>,
    active: bool,
    started: bool,
}

/// Each branch requires a different typed original ACK and actual worker state.
#[derive(Clone, Copy)]
pub(crate) enum TerminalPublishMode {
    CommittedWorker,
    CompletedNoWorker,
}

impl TerminalInvocationClaim {
    pub(crate) fn register(
        store: Arc<DatasetBoundArtifactStore>,
        key: ArtifactCleanupFenceKey,
        deadline: Instant,
    ) -> Result<(Arc<Self>, TerminalInvocationQueryOwner), ArtifactStoreError> {
        let strict = ArtifactCleanupFenceKey::from_stored(
            key.deployment_id().clone(),
            key.tenant_id().clone(),
            key.dataset_id(),
            key.operation_id().as_str(),
            key.artifact_id(),
        )
        .map_err(|_| ArtifactStoreError::BindingMismatch)?;
        if strict != key || !store.reads.matches_key(&key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if Instant::now() >= deadline {
            return Err(ArtifactStoreError::Unavailable);
        }
        let id = uuid::Uuid::now_v7();
        store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?
            .register_terminal(&key, id)?;
        let claim = Arc::new(Self {
            store,
            key,
            id,
            deadline,
        });
        let owner = TerminalInvocationQueryOwner {
            claim: Arc::clone(&claim),
            acknowledged: false,
        };
        // Stop ports and State disposal can reenter the gate; close calls them out of lock.
        claim.store.reads.close(&claim.key)?;
        claim.check_deadline()?;
        Ok((claim, owner))
    }

    pub(crate) async fn wait_original_reads_before(&self) -> Result<(), ArtifactStoreError> {
        loop {
            let changed = self.store.reads.changed.notified();
            self.check_deadline()?;
            if let Some(generation) = self.drained_generation()? {
                let mut inventory = self
                    .store
                    .reads
                    .inventory
                    .lock()
                    .map_err(|_| ArtifactStoreError::Unavailable)?;
                let selector = self.verify_selector(&mut inventory, None)?;
                let slot = selector
                    .physical
                    .as_ref()
                    .filter(|slot| slot.matches(InvocationKind::Terminal, self.id, &self.key))
                    .ok_or(ArtifactStoreError::BindingMismatch)?;
                if !slot.query_alive || slot.query_acknowledged || slot.terminal_ack.is_some() {
                    return Err(ArtifactStoreError::Unavailable);
                }
                if selector.generation == generation {
                    return Ok(());
                }
                // A new real no-body owner changed inventory after the outside-lock State
                // proof. Wait again inside this original budget rather than reuse that proof.
            }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline)) => {
                    self.mark_unproven();
                    return Err(ArtifactStoreError::Unavailable);
                },
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            }
        }
    }

    pub(crate) fn reserve_worker(
        self: &Arc<Self>,
    ) -> Result<TerminalWorkerLease, ArtifactStoreError> {
        self.check_deadline()?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = self.verify_selector(&mut inventory, None)?;
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Terminal, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive
            || slot.query_acknowledged
            || slot.terminal_ack.is_some()
            || slot.worker_reserved
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        slot.worker_reserved = true;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(TerminalWorkerLease {
            claim: Arc::clone(self),
            active: true,
            started: false,
        })
    }

    pub(crate) fn check_deadline(&self) -> Result<(), ArtifactStoreError> {
        if Instant::now() >= self.deadline {
            self.mark_unproven();
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn verify_precommit(&self) -> Result<(), ArtifactStoreError> {
        self.check_deadline()?;
        let generation = self
            .drained_generation()?
            .ok_or(ArtifactStoreError::Unavailable)?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = self.verify_selector(&mut inventory, Some(generation))?;
        let slot = selector
            .physical
            .as_ref()
            .filter(|slot| slot.matches(InvocationKind::Terminal, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.terminal_precommit_ready() {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn verify_terminal_publish(
        &self,
        mode: TerminalPublishMode,
    ) -> Result<(), ArtifactStoreError> {
        self.check_deadline()?;
        let generation = self
            .drained_generation()?
            .ok_or(ArtifactStoreError::Unavailable)?;
        let mut inventory = self
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let original_fact = inventory.terminal_fact(&self.key).ok();
        let selector = self.verify_selector(&mut inventory, Some(generation))?;
        let slot = selector
            .physical
            .as_ref()
            .filter(|slot| slot.matches(InvocationKind::Terminal, self.id, &self.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.terminal_publish_ready(mode, original_fact) {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn mark_unproven(&self) {
        if let Ok(mut inventory) = self.store.reads.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(self.key.artifact_id())
        {
            keep_unproven(selector, Some(self.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.store.reads.changed.notify_waiters();
    }

    pub(crate) fn completed_audit_event_id(&self) -> Result<uuid::Uuid, ArtifactStoreError> {
        self.check_deadline()?;
        let result = {
            let mut inventory = self
                .store
                .reads
                .inventory
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let selector = self.verify_selector(&mut inventory, None)?;
            selector
                .physical
                .as_ref()
                .filter(|slot| slot.matches(InvocationKind::Terminal, self.id, &self.key))
                .ok_or(ArtifactStoreError::BindingMismatch)?;
            inventory.terminal_fact(&self.key)
        };
        if result.is_err() {
            // A completed tuple cannot repair a missing association or invent the old ACK.
            self.mark_unproven();
        }
        result
    }

    fn drained_generation(&self) -> Result<Option<u64>, ArtifactStoreError> {
        self.store
            .reads
            .drained_generation(&self.key)
            .map_err(|_| ArtifactStoreError::Unavailable)
    }

    fn verify_selector<'a>(
        &self,
        inventory: &'a mut Inventory,
        generation: Option<u64>,
    ) -> Result<&'a mut SelectorInventory, ArtifactStoreError> {
        let selector = inventory
            .selectors
            .get_mut(self.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector.original_key.as_ref() != Some(&self.key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        if generation.is_some_and(|expected| selector.generation != expected)
            || !selector.closed.contains(&self.key)
            || selector.unbound_unproven
            || selector.unproven.contains(&self.key)
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        if Instant::now() >= self.deadline {
            keep_unproven(selector, Some(self.key.clone()));
            selector.generation = selector.generation.wrapping_add(1);
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(selector)
    }
}

impl TerminalInvocationQueryOwner {
    pub(crate) fn acknowledge_commit(
        self,
        audit_event_id: uuid::Uuid,
    ) -> Result<(), ArtifactStoreError> {
        self.acknowledge(TerminalQueryAck::Commit(audit_event_id))
    }

    pub(crate) fn acknowledge_rollback(self) -> Result<(), ArtifactStoreError> {
        self.acknowledge(TerminalQueryAck::Rollback)
    }

    fn acknowledge(mut self, acknowledgement: TerminalQueryAck) -> Result<(), ArtifactStoreError> {
        // The producer invokes this consuming port only for a real normal on-time ACK.
        // Even a gate/clock/fact registration failure after that ACK keeps its known truth.
        self.acknowledged = true;
        let result = match self.claim.store.reads.inventory.lock() {
            Ok(mut inventory) => inventory.acknowledge_terminal(
                &self.claim.key,
                self.claim.id,
                acknowledgement,
                Instant::now(),
                self.claim.deadline,
            ),
            Err(_) => Err(ArtifactStoreError::Unavailable),
        };
        if result.is_err() {
            self.claim.mark_unproven();
        }
        self.claim.store.reads.changed.notify_waiters();
        result
    }
}

impl Drop for TerminalInvocationQueryOwner {
    fn drop(&mut self) {
        if !self.acknowledged {
            if let Ok(mut inventory) = self.claim.store.reads.inventory.lock() {
                inventory.abandon_terminal(&self.claim.key, self.claim.id);
            }
            self.claim.store.reads.changed.notify_waiters();
        }
    }
}

impl TerminalWorkerLease {
    pub(crate) fn mark_started(&mut self) -> Result<(), ArtifactStoreError> {
        self.claim.check_deadline()?;
        if !self.active || self.started {
            return Err(ArtifactStoreError::Unavailable);
        }
        let generation = self
            .claim
            .drained_generation()?
            .ok_or(ArtifactStoreError::Unavailable)?;
        let mut inventory = self
            .claim
            .store
            .reads
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = self
            .claim
            .verify_selector(&mut inventory, Some(generation))?;
        let slot = selector
            .physical
            .as_mut()
            .filter(|slot| slot.matches(InvocationKind::Terminal, self.claim.id, &self.claim.key))
            .ok_or(ArtifactStoreError::BindingMismatch)?;
        if !slot.query_alive
            || slot.query_acknowledged
            || slot.terminal_ack.is_some()
            || !slot.worker_reserved
            || slot.worker_started
            || slot.worker_ended
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        slot.worker_started = true;
        selector.generation = selector.generation.wrapping_add(1);
        self.started = true;
        Ok(())
    }

    pub(crate) fn finish_after_resources(mut self) {
        self.record_ended(false);
        self.active = false;
    }

    fn record_ended(&self, unexpected: bool) {
        if let Ok(mut inventory) = self.claim.store.reads.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(self.claim.key.artifact_id())
            && let Some(slot) = selector.physical.as_mut().filter(|slot| {
                slot.matches(InvocationKind::Terminal, self.claim.id, &self.claim.key)
            })
        {
            slot.worker_ended = true;
            if unexpected && self.started {
                keep_unproven(selector, Some(self.claim.key.clone()));
            }
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.claim.store.reads.changed.notify_waiters();
    }
}

impl Drop for TerminalWorkerLease {
    fn drop(&mut self) {
        if self.active {
            // Original worker declared this lease first: unwind has already dropped IO/FDs.
            // An unexpected started worker loss supplies no final durable-absence proof.
            self.record_ended(true);
        }
    }
}

/// The same authority's original joint query after all pure identity checks. Constructed only
/// before its first real PG await; only original explicit rollback ACK may consume it normally.
pub(crate) struct StoreReadQueryReservation {
    // Retain the actual registry/root/kernel owner, not a selector-labelled surrogate tracker.
    store: Arc<DatasetBoundArtifactStore>,
    artifact_id: String,
    acknowledged: bool,
}
impl StoreReadQueryReservation {
    pub(crate) fn complete(mut self) {
        self.acknowledged = true;
    }
}
impl Drop for StoreReadQueryReservation {
    fn drop(&mut self) {
        if let Ok(mut inventory) = self.store.reads.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(&self.artifact_id)
        {
            let count = selector.original_queries.checked_sub(1);
            if let Some(count) = count {
                selector.original_queries = count;
            }
            if !self.acknowledged || count.is_none() {
                // Original operation comes only from the actual prior snapshot/full-key bind.
                // With no minted record retain unbound uncertainty; never guess an operation.
                let key = selector.original_key.clone();
                keep_unproven(selector, key);
            }
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.store.reads.changed.notify_waiters();
    }
}

pub(crate) struct StoreReadEnrollment {
    // The original physical owner; a same-label replacement Store cannot supply this field.
    store: Arc<DatasetBoundArtifactStore>,
    gate: Arc<StoreReadGate>,
    state: Weak<ReadOperationState>,
    artifact_id: String,
}

impl StoreReadEnrollment {
    pub(crate) fn bind_observed_record(
        &self,
        record: &ObservedArtifactReadRecord,
    ) -> Result<(), ArtifactStoreError> {
        if !record.matches_store(&self.store) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let key = record.read_cleanup_key()?;
        if !self.gate.matches_key(&key) || key.artifact_id() != self.artifact_id {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let mut inventory = self
            .gate
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(&self.artifact_id)
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector
            .original_key
            .as_ref()
            .is_some_and(|original| original != &key)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let entry = selector
            .states
            .iter_mut()
            .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            .ok_or(ArtifactStoreError::Unavailable)?;
        if entry.key.as_ref().is_some_and(|bound| bound != &key) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        entry.key = Some(key.clone());
        selector.original_key = Some(key);
        selector.generation = selector.generation.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn body_is_admitted(&self) -> Result<(), ArtifactStoreError> {
        let inventory = self
            .gate
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get(&self.artifact_id)
            .ok_or(ArtifactStoreError::Unavailable)?;
        let entry = selector
            .states
            .iter()
            .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            .ok_or(ArtifactStoreError::Unavailable)?;
        let closed = entry.key.as_ref().map_or_else(
            || !selector.closed.is_empty() || !selector.unproven.is_empty(),
            |key| selector.closed.contains(key) || selector.unproven.contains(key),
        );
        if !entry.admitted || closed || selector.unbound_unproven {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn original_admission_closed(&self) -> bool {
        match self.gate.inventory.lock() {
            Ok(inventory) => {
                let Some(selector) = inventory.selectors.get(&self.artifact_id) else {
                    return true;
                };
                let Some(entry) = selector
                    .states
                    .iter()
                    .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
                else {
                    return true;
                };
                entry.admitted
                    && (selector.unbound_unproven
                        || entry.key.as_ref().map_or_else(
                            || !selector.closed.is_empty() || !selector.unproven.is_empty(),
                            |key| selector.closed.contains(key) || selector.unproven.contains(key),
                        ))
            }
            Err(_) => true,
        }
    }

    pub(crate) fn begin_query(&self) -> Result<StoreReadQueryLease, ArtifactStoreError> {
        let mut inventory = self
            .gate
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(&self.artifact_id)
            .ok_or(ArtifactStoreError::Unavailable)?;
        let entry = selector
            .states
            .iter_mut()
            .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            .ok_or(ArtifactStoreError::Unavailable)?;
        entry.queries = entry
            .queries
            .checked_add(1)
            .ok_or(ArtifactStoreError::Unavailable)?;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(StoreReadQueryLease {
            gate: Arc::clone(&self.gate),
            state: self.state.clone(),
            artifact_id: self.artifact_id.clone(),
            acknowledged: false,
        })
    }

    pub(crate) fn begin_job(&self) -> Result<StoreReadJobLease, ArtifactStoreError> {
        let mut inventory = self
            .gate
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get_mut(&self.artifact_id)
            .ok_or(ArtifactStoreError::Unavailable)?;
        let entry = selector
            .states
            .iter_mut()
            .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            .ok_or(ArtifactStoreError::Unavailable)?;
        if entry.admitted
            && (selector.unbound_unproven
                || entry.key.as_ref().map_or_else(
                    || !selector.closed.is_empty() || !selector.unproven.is_empty(),
                    |key| selector.closed.contains(key) || selector.unproven.contains(key),
                ))
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        entry.jobs = entry
            .jobs
            .checked_add(1)
            .ok_or(ArtifactStoreError::Unavailable)?;
        selector.generation = selector.generation.wrapping_add(1);
        Ok(StoreReadJobLease {
            gate: Arc::clone(&self.gate),
            state: self.state.clone(),
            artifact_id: self.artifact_id.clone(),
        })
    }

    pub(crate) fn mark_unproven(&self) {
        if let Ok(mut inventory) = self.gate.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(&self.artifact_id)
        {
            let key = selector
                .states
                .iter()
                .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
                .and_then(|entry| entry.key.clone());
            keep_unproven(selector, key);
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.gate.changed.notify_waiters();
    }

    pub(crate) fn mark_waiter_cancellation(&self) -> bool {
        let Ok(mut inventory) = self.gate.inventory.lock() else {
            return true;
        };
        let Some(selector) = inventory.selectors.get_mut(&self.artifact_id) else {
            return true;
        };
        let Some(entry) = selector
            .states
            .iter()
            .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
        else {
            return true;
        };
        if entry.queries == 0 {
            return false;
        }
        let key = entry.key.clone();
        let already_shared_closed = key.as_ref().map_or_else(
            || !selector.closed.is_empty() || selector.unbound_unproven,
            |key| selector.closed.contains(key),
        );
        if already_shared_closed {
            // Shared closure requests body/Entry stop while the original query owner keeps
            // running to its actual ACK. Its unfinished future still has an unconditional
            // poison-on-Drop guard; this stop request cannot turn that guard into an ACK.
            return false;
        }
        // A normal waiter cancellation precedes closure and loses the original query proof.
        // Even a producer which later obtains ACK cannot clear this retained uncertainty.
        keep_unproven(selector, key);
        selector.generation = selector.generation.wrapping_add(1);
        self.gate.changed.notify_waiters();
        true
    }

    pub(crate) fn notify_changed(&self) {
        self.gate.changed.notify_waiters();
    }
}

impl Drop for StoreReadEnrollment {
    fn drop(&mut self) {
        if let Ok(mut inventory) = self.gate.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(&self.artifact_id)
            && let Some(index) = selector
                .states
                .iter()
                .position(|entry| Weak::ptr_eq(&entry.state, &self.state))
        {
            let entry = selector.states.remove(index);
            // Actual query/job leases hold State, so a nonzero tail here is unproved.
            if entry.queries != 0 || entry.jobs != 0 {
                keep_unproven(selector, entry.key);
            }
            selector.generation = selector.generation.wrapping_add(1);
        }
        self.gate.changed.notify_waiters();
    }
}

pub(crate) struct StoreReadQueryLease {
    gate: Arc<StoreReadGate>,
    state: Weak<ReadOperationState>,
    artifact_id: String,
    acknowledged: bool,
}
impl StoreReadQueryLease {
    pub(crate) fn complete(mut self) {
        self.acknowledged = true;
    }
}
impl Drop for StoreReadQueryLease {
    fn drop(&mut self) {
        if let Ok(mut inventory) = self.gate.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(&self.artifact_id)
        {
            if let Some(entry) = selector
                .states
                .iter_mut()
                .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            {
                let count = entry.queries.checked_sub(1);
                let key = entry.key.clone();
                if let Some(count) = count {
                    entry.queries = count;
                }
                if !self.acknowledged || count.is_none() {
                    keep_unproven(selector, key);
                }
                selector.generation = selector.generation.wrapping_add(1);
            } else {
                keep_unproven(selector, None);
                selector.generation = selector.generation.wrapping_add(1);
            }
        }
        self.gate.changed.notify_waiters();
    }
}

pub(crate) struct StoreReadJobLease {
    gate: Arc<StoreReadGate>,
    state: Weak<ReadOperationState>,
    artifact_id: String,
}
impl Drop for StoreReadJobLease {
    fn drop(&mut self) {
        if let Ok(mut inventory) = self.gate.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(&self.artifact_id)
        {
            if let Some(entry) = selector
                .states
                .iter_mut()
                .find(|entry| Weak::ptr_eq(&entry.state, &self.state))
            {
                let count = entry.jobs.checked_sub(1);
                let key = entry.key.clone();
                if let Some(count) = count {
                    entry.jobs = count;
                } else {
                    keep_unproven(selector, key);
                }
                selector.generation = selector.generation.wrapping_add(1);
            } else {
                keep_unproven(selector, None);
                selector.generation = selector.generation.wrapping_add(1);
            }
        }
        self.gate.changed.notify_waiters();
    }
}

pub(super) struct StoreReadFdLease {
    gate: Arc<StoreReadGate>,
    key: ArtifactCleanupFenceKey,
}
impl StoreReadFdLease {
    pub(super) fn verify_admission(&self) -> Result<(), ArtifactStoreError> {
        let inventory = self
            .gate
            .inventory
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let selector = inventory
            .selectors
            .get(self.key.artifact_id())
            .ok_or(ArtifactStoreError::Unavailable)?;
        if selector.closed.contains(&self.key)
            || selector.unproven.contains(&self.key)
            || selector.unbound_unproven
        {
            return Err(ArtifactStoreError::Unavailable);
        }
        Ok(())
    }
}
impl Drop for StoreReadFdLease {
    fn drop(&mut self) {
        if let Ok(mut inventory) = self.gate.inventory.lock()
            && let Some(selector) = inventory.selectors.get_mut(self.key.artifact_id())
        {
            if let Some(count) = selector.fds.get_mut(&self.key) {
                if let Some(remaining) = count.checked_sub(1) {
                    *count = remaining;
                    if remaining == 0 {
                        selector.fds.remove(&self.key);
                    }
                } else {
                    keep_unproven(selector, Some(self.key.clone()));
                }
                selector.generation = selector.generation.wrapping_add(1);
            } else {
                keep_unproven(selector, Some(self.key.clone()));
                selector.generation = selector.generation.wrapping_add(1);
            }
        }
        self.gate.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::{DeploymentId, TenantId};

    const OPERATION: &str = "018f03ae-1234-7abc-8def-123456789abc";
    const OTHER_OPERATION: &str = "018f03ae-1234-7abc-8def-123456789abe";
    const ARTIFACT: &str = "018f03ae-1234-7abc-8def-123456789abd";
    const AUDIT_ONE: uuid::Uuid = uuid::Uuid::from_u128(0x00112233_4455_4677_8899_aabbccddee01);
    const AUDIT_TWO: uuid::Uuid = uuid::Uuid::from_u128(0x00112233_4455_4677_8899_aabbccddee02);

    fn key(tenant: &str, operation: &str) -> ArtifactCleanupFenceKey {
        ArtifactCleanupFenceKey::from_stored(
            DeploymentId::new("deployment"),
            TenantId::new(tenant),
            "dataset",
            operation,
            ARTIFACT,
        )
        .unwrap()
    }

    fn opened_inventory(key: &ArtifactCleanupFenceKey, id: uuid::Uuid) -> Inventory {
        let mut inventory = Inventory::default();
        inventory.register_terminal(key, id).unwrap();
        inventory
            .selectors
            .get_mut(key.artifact_id())
            .unwrap()
            .closed
            .insert(key.clone());
        inventory
    }

    fn live_worker(inventory: &mut Inventory, key: &ArtifactCleanupFenceKey) {
        let slot = inventory
            .selectors
            .get_mut(key.artifact_id())
            .unwrap()
            .physical
            .as_mut()
            .unwrap();
        slot.worker_reserved = true;
        slot.worker_started = true;
    }

    fn ended_worker(inventory: &mut Inventory, key: &ArtifactCleanupFenceKey) {
        inventory
            .selectors
            .get_mut(key.artifact_id())
            .unwrap()
            .physical
            .as_mut()
            .unwrap()
            .worker_ended = true;
    }

    // These tests exercise the plain production state transitions only. Their slot/ACK/ended
    // inputs are not evidence of PostgreSQL protocol, filesystem sync or resource closure.
    #[test]
    fn terminal_claim_excludes_live_physical_invocation_and_keeps_original_key() {
        let original = key("tenant", OPERATION);
        let first = uuid::Uuid::now_v7();
        let next = uuid::Uuid::now_v7();
        let mut inventory = opened_inventory(&original, first);
        let selector = inventory.selectors.get_mut(original.artifact_id()).unwrap();
        selector.physical.as_mut().unwrap().kind = InvocationKind::Physical;
        assert_eq!(
            inventory.register_terminal(&original, next),
            Err(ArtifactStoreError::Unavailable)
        );
        let slot = inventory
            .selectors
            .get(original.artifact_id())
            .unwrap()
            .physical
            .as_ref()
            .unwrap();
        assert!(slot.matches(InvocationKind::Physical, first, &original));
        assert!(!slot.matches(InvocationKind::Terminal, first, &original));

        let selector = inventory.selectors.get_mut(original.artifact_id()).unwrap();
        let slot = selector.physical.as_mut().unwrap();
        slot.query_alive = false;
        slot.query_acknowledged = true;
        assert!(slot.is_retired());
        inventory.register_terminal(&original, next).unwrap();
        assert_eq!(
            inventory.register_terminal(&original, first),
            Err(ArtifactStoreError::Unavailable)
        );
        let wrong_operation = key("tenant", OTHER_OPERATION);
        assert_eq!(
            inventory.register_terminal(&wrong_operation, first),
            Err(ArtifactStoreError::BindingMismatch)
        );
        let selector = inventory.selectors.get(original.artifact_id()).unwrap();
        assert_eq!(selector.original_key.as_ref(), Some(&original));
        let slot = selector.physical.as_ref().unwrap();
        assert!(slot.matches(InvocationKind::Terminal, next, &original));
        assert!(!slot.matches(InvocationKind::Physical, next, &original));
        assert!(!slot.matches(InvocationKind::Terminal, first, &original));
    }

    #[test]
    fn terminal_precommit_excludes_only_own_query_worker_and_refuses_other_owners() {
        let original = key("tenant", OPERATION);
        let id = uuid::Uuid::now_v7();
        let mut inventory = opened_inventory(&original, id);
        live_worker(&mut inventory, &original);
        let selector = inventory.selectors.get_mut(original.artifact_id()).unwrap();
        assert!(
            selector
                .physical
                .as_ref()
                .unwrap()
                .terminal_precommit_ready()
        );
        assert!(selector.controlled_counts_empty(&original));
        selector.original_queries = 1;
        assert!(!selector.controlled_counts_empty(&original));
        selector.original_queries = 0;
        selector.fds.insert(original.clone(), 1);
        assert!(!selector.controlled_counts_empty(&original));
        selector.fds.clear();
        selector.states.push(TrackedState {
            state: Weak::new(),
            key: None,
            admitted: true,
            queries: 1,
            jobs: 0,
            entry_stop: None,
        });
        assert!(!selector.controlled_counts_empty(&original));
        selector.states[0].queries = 0;
        selector.states[0].jobs = 1;
        assert!(!selector.controlled_counts_empty(&original));
        selector.states.clear();
        assert!(selector.controlled_counts_empty(&original));
        let slot = selector.physical.as_mut().unwrap();
        slot.worker_ended = true;
        assert!(!slot.terminal_precommit_ready());
        slot.worker_ended = false;
        slot.query_alive = false;
        slot.query_acknowledged = true;
        slot.terminal_ack = Some(TerminalQueryAck::Rollback);
        assert!(!slot.terminal_precommit_ready());
        // Real full allocation/transport/resource proof remains the separate actual State
        // shared_inventory_drained observation and its generation recheck, not these counts.
    }

    #[test]
    fn terminal_commit_ack_fact_survives_slot_retirement_without_overwrite_or_namespace_leak() {
        let original = key("tenant", OPERATION);
        let same_ids_foreign_namespace = key("other-tenant", OPERATION);
        let first = uuid::Uuid::now_v7();
        let second = uuid::Uuid::now_v7();
        let audit_id = AUDIT_ONE;
        let other_audit_id = AUDIT_TWO;
        let mut inventory = opened_inventory(&original, first);
        live_worker(&mut inventory, &original);
        let now = Instant::now();
        inventory
            .acknowledge_terminal(
                &original,
                first,
                TerminalQueryAck::Commit(audit_id),
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(inventory.terminal_fact(&original), Ok(audit_id));
        assert_eq!(
            inventory.terminal_fact(&same_ids_foreign_namespace),
            Err(ArtifactStoreError::Unavailable)
        );
        let slot = inventory
            .selectors
            .get(original.artifact_id())
            .unwrap()
            .physical
            .as_ref()
            .unwrap();
        assert!(!slot.is_retired());
        assert!(!slot.terminal_publish_ready(TerminalPublishMode::CommittedWorker, Some(audit_id)));
        ended_worker(&mut inventory, &original);
        assert!(
            inventory
                .selectors
                .get(original.artifact_id())
                .unwrap()
                .physical
                .as_ref()
                .unwrap()
                .is_retired()
        );

        // Neither a retired physical slot nor a new terminal claim owns the separate fact.
        let slot = inventory
            .selectors
            .get_mut(original.artifact_id())
            .unwrap()
            .physical
            .as_mut()
            .unwrap();
        slot.kind = InvocationKind::Physical;
        inventory.register_terminal(&original, second).unwrap();
        assert_eq!(inventory.terminal_fact(&original), Ok(audit_id));
        live_worker(&mut inventory, &original);
        let now = Instant::now();
        assert_eq!(
            inventory.acknowledge_terminal(
                &original,
                second,
                TerminalQueryAck::Commit(other_audit_id),
                now,
                now + Duration::from_secs(1)
            ),
            Err(ArtifactStoreError::BindingMismatch)
        );
        assert_eq!(inventory.terminal_fact(&original), Ok(audit_id));
        assert_eq!(inventory.committed_terminals.len(), 1);
        let selector = inventory.selectors.get(original.artifact_id()).unwrap();
        assert!(selector.unproven.contains(&original));
        let slot = selector.physical.as_ref().unwrap();
        assert!(!slot.query_alive && slot.query_acknowledged);
        assert!(slot.terminal_ack == Some(TerminalQueryAck::Commit(other_audit_id)));
        assert!(!slot.terminal_publish_ready(TerminalPublishMode::CommittedWorker, Some(audit_id)));

        let foreign_claim = uuid::Uuid::now_v7();
        let mut foreign_inventory = opened_inventory(&same_ids_foreign_namespace, foreign_claim);
        live_worker(&mut foreign_inventory, &same_ids_foreign_namespace);
        let now = Instant::now();
        foreign_inventory
            .acknowledge_terminal(
                &same_ids_foreign_namespace,
                foreign_claim,
                TerminalQueryAck::Commit(other_audit_id),
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            foreign_inventory.terminal_fact(&same_ids_foreign_namespace),
            Ok(other_audit_id)
        );
        assert_eq!(
            foreign_inventory.terminal_fact(&original),
            Err(ArtifactStoreError::Unavailable)
        );
        assert_eq!(inventory.terminal_fact(&original), Ok(audit_id));
    }

    #[test]
    fn terminal_completed_no_worker_requires_true_rollback_and_original_fact() {
        let original = key("tenant", OPERATION);
        let first = uuid::Uuid::now_v7();
        let completed = uuid::Uuid::now_v7();
        let audit_id = AUDIT_ONE;
        let mut inventory = opened_inventory(&original, first);
        live_worker(&mut inventory, &original);
        let now = Instant::now();
        inventory
            .acknowledge_terminal(
                &original,
                first,
                TerminalQueryAck::Commit(audit_id),
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        ended_worker(&mut inventory, &original);
        inventory.register_terminal(&original, completed).unwrap();
        let slot = inventory
            .selectors
            .get(original.artifact_id())
            .unwrap()
            .physical
            .as_ref()
            .unwrap();
        assert!(!slot.terminal_precommit_ready());
        assert!(
            !slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, Some(audit_id))
        );
        let now = Instant::now();
        inventory
            .acknowledge_terminal(
                &original,
                completed,
                TerminalQueryAck::Rollback,
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(inventory.committed_terminals.len(), 1);
        assert_eq!(inventory.terminal_fact(&original), Ok(audit_id));
        let slot = inventory
            .selectors
            .get_mut(original.artifact_id())
            .unwrap()
            .physical
            .as_mut()
            .unwrap();
        assert!(
            slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, Some(audit_id))
        );
        assert!(!slot.terminal_publish_ready(TerminalPublishMode::CommittedWorker, Some(audit_id)));
        assert!(!slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, None));
        slot.worker_ended = true;
        assert!(
            !slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, Some(audit_id))
        );
        slot.worker_ended = false;
        slot.worker_reserved = true;
        assert!(
            !slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, Some(audit_id))
        );
        slot.worker_reserved = false;
        slot.terminal_ack = Some(TerminalQueryAck::Commit(audit_id));
        assert!(
            !slot.terminal_publish_ready(TerminalPublishMode::CompletedNoWorker, Some(audit_id))
        );
    }

    #[test]
    fn terminal_unknown_late_or_abandoned_query_is_permanent_unproven_after_known_host_refusal() {
        let original = key("tenant", OPERATION);
        let known_refusal = uuid::Uuid::now_v7();
        let unknown = uuid::Uuid::now_v7();
        let retry = uuid::Uuid::now_v7();
        let mut inventory = opened_inventory(&original, known_refusal);
        let now = Instant::now();
        inventory
            .acknowledge_terminal(
                &original,
                known_refusal,
                TerminalQueryAck::Rollback,
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        let selector = inventory.selectors.get(original.artifact_id()).unwrap();
        assert!(selector.unproven.is_empty() && !selector.unbound_unproven);
        assert!(selector.physical.as_ref().unwrap().is_retired());
        assert!(inventory.committed_terminals.is_empty());
        inventory.register_terminal(&original, unknown).unwrap();
        inventory.abandon_terminal(&original, unknown);
        let selector = inventory.selectors.get(original.artifact_id()).unwrap();
        assert!(selector.closed.contains(&original) && selector.unproven.contains(&original));
        let slot = selector.physical.as_ref().unwrap();
        assert!(!slot.query_alive && !slot.query_acknowledged && slot.terminal_ack.is_none());
        ended_worker(&mut inventory, &original);
        assert_eq!(
            inventory.register_terminal(&original, retry),
            Err(ArtifactStoreError::Unavailable)
        );
        assert!(inventory.committed_terminals.is_empty());

        let late_id = uuid::Uuid::now_v7();
        let mut late = opened_inventory(&original, late_id);
        live_worker(&mut late, &original);
        let now = Instant::now();
        assert_eq!(
            late.acknowledge_terminal(
                &original,
                late_id,
                TerminalQueryAck::Commit(AUDIT_ONE),
                now,
                now
            ),
            Err(ArtifactStoreError::Unavailable)
        );
        assert!(late.committed_terminals.is_empty());
        ended_worker(&mut late, &original);
        assert_eq!(
            late.register_terminal(&original, retry),
            Err(ArtifactStoreError::Unavailable)
        );
        let selector = late.selectors.get(original.artifact_id()).unwrap();
        assert!(selector.unproven.contains(&original));
        assert!(selector.physical.as_ref().unwrap().query_acknowledged);

        // A later known refusal cannot clear an earlier independent old read/query unknown.
        let known_id = uuid::Uuid::now_v7();
        let mut previously_unknown = opened_inventory(&original, known_id);
        keep_unproven(
            previously_unknown
                .selectors
                .get_mut(original.artifact_id())
                .unwrap(),
            Some(original.clone()),
        );
        let now = Instant::now();
        assert_eq!(
            previously_unknown.acknowledge_terminal(
                &original,
                known_id,
                TerminalQueryAck::Rollback,
                now,
                now + Duration::from_secs(1)
            ),
            Err(ArtifactStoreError::Unavailable)
        );
        assert!(
            previously_unknown
                .selectors
                .get(original.artifact_id())
                .unwrap()
                .unproven
                .contains(&original)
        );
        assert_eq!(
            previously_unknown.register_terminal(&original, retry),
            Err(ArtifactStoreError::Unavailable)
        );

        // A true on-time original COMMIT also cannot mint a fact after an old independent
        // query/main-owner unknown. Preserve its known ACK without granting publication.
        for unbound in [false, true] {
            let id = uuid::Uuid::now_v7();
            let mut pre_ack_unknown = opened_inventory(&original, id);
            live_worker(&mut pre_ack_unknown, &original);
            keep_unproven(
                pre_ack_unknown
                    .selectors
                    .get_mut(original.artifact_id())
                    .unwrap(),
                if unbound {
                    None
                } else {
                    Some(original.clone())
                },
            );
            let now = Instant::now();
            assert_eq!(
                pre_ack_unknown.acknowledge_terminal(
                    &original,
                    id,
                    TerminalQueryAck::Commit(AUDIT_ONE),
                    now,
                    now + Duration::from_secs(1)
                ),
                Err(ArtifactStoreError::Unavailable)
            );
            assert!(pre_ack_unknown.committed_terminals.is_empty());
            let slot = pre_ack_unknown
                .selectors
                .get(original.artifact_id())
                .unwrap()
                .physical
                .as_ref()
                .unwrap();
            assert!(!slot.query_alive && slot.query_acknowledged);
            assert!(slot.terminal_ack == Some(TerminalQueryAck::Commit(AUDIT_ONE)));
            ended_worker(&mut pre_ack_unknown, &original);
            assert_eq!(
                pre_ack_unknown.register_terminal(&original, retry),
                Err(ArtifactStoreError::Unavailable)
            );
        }

        // Pre-ACK poison forbids new minting/overwriting, and keeps an earlier normal fact.
        let first = uuid::Uuid::now_v7();
        let next = uuid::Uuid::now_v7();
        let mut retained_fact = opened_inventory(&original, first);
        live_worker(&mut retained_fact, &original);
        let now = Instant::now();
        retained_fact
            .acknowledge_terminal(
                &original,
                first,
                TerminalQueryAck::Commit(AUDIT_ONE),
                now,
                now + Duration::from_secs(1),
            )
            .unwrap();
        ended_worker(&mut retained_fact, &original);
        retained_fact.register_terminal(&original, next).unwrap();
        live_worker(&mut retained_fact, &original);
        keep_unproven(
            retained_fact
                .selectors
                .get_mut(original.artifact_id())
                .unwrap(),
            Some(original.clone()),
        );
        let now = Instant::now();
        assert_eq!(
            retained_fact.acknowledge_terminal(
                &original,
                next,
                TerminalQueryAck::Commit(AUDIT_TWO),
                now,
                now + Duration::from_secs(1)
            ),
            Err(ArtifactStoreError::Unavailable)
        );
        assert_eq!(retained_fact.terminal_fact(&original), Ok(AUDIT_ONE));
        assert_eq!(retained_fact.committed_terminals.len(), 1);
    }
}
