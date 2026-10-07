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
    generation: u64,
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
            if selector.original_queries != 0
                || selector.fds.get(key).copied().unwrap_or_default() != 0
                || selector.states.iter().any(|entry| {
                    entry.admitted
                        && entry.key.as_ref().is_none_or(|bound| bound == key)
                        && (entry.queries != 0 || entry.jobs != 0)
                })
            {
                return Ok(false);
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
                return Ok(false);
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
        Ok(selector.generation == generation)
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
