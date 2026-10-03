//! App-owned mutation latch: navigation cannot cancel or replay an uncertain write.
use crate::api::model_connections::{self as api, Write, WriteError};
use crate::api::model_connections::{MetadataChange, MetadataError};
use crate::revision_editor::Phase;
use leptos::prelude::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MetadataHold {
    serial: u64,
    pub(super) pending: bool,
    pub(super) phase: Phase,
    pub(super) uncertain: bool,
    recovery: bool,
}

#[derive(Clone, Copy)]
pub(super) struct MetadataLease(u64);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Status {
    #[default]
    Idle,
    Pending,
    Saved,
    Failed(WriteError),
}
impl Status {
    pub fn locked(self) -> bool {
        matches!(self, Self::Pending | Self::Failed(WriteError::Unknown))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ModelActions {
    pub(super) status: RwSignal<Status>,
    pub(crate) revision: RwSignal<u64>,
    metadata: RwSignal<BTreeMap<String, MetadataHold>>,
    metadata_serial: RwSignal<u64>,
    owner: StoredValue<Option<Owner>>,
}
impl ModelActions {
    pub(crate) fn new() -> Self {
        Self {
            status: RwSignal::new(Status::Idle),
            revision: RwSignal::new(0),
            metadata: RwSignal::new(BTreeMap::new()),
            metadata_serial: RwSignal::new(0),
            owner: StoredValue::new(Owner::current()),
        }
    }
    pub(super) fn launch(self, input: Write, finished: impl FnOnce(bool) + 'static) {
        let metadata_locked = match &input {
            Write::Create(_) => false,
            Write::Update(id, _) | Write::Delete(id, _) => self.metadata_hold(id).is_some(),
        };
        if self.status.get_untracked().locked() || metadata_locked {
            return;
        }
        self.status.set(Status::Pending);
        leptos::task::spawn_local(async move {
            let result = api::write(input).await;
            self.complete(result, finished);
        });
    }

    pub(super) fn metadata_hold(self, id: &str) -> Option<MetadataHold> {
        self.metadata
            .try_with(|holds| holds.get(id).copied())
            .flatten()
    }

    pub(super) fn claim_metadata(self, id: &str, explicit_recovery: bool) -> Option<MetadataLease> {
        if self.status.try_get_untracked()?.locked() {
            return None;
        }
        let mut holds = self.metadata.try_get_untracked()?;
        let old = holds.get(id).copied();
        if old.is_some_and(|hold| hold.pending || !explicit_recovery) {
            return None;
        }
        if old.is_none() && holds.len() >= 1_000 {
            return None;
        }
        let serial = self.metadata_serial.try_get_untracked()?.checked_add(1)?;
        self.metadata_serial.try_set(serial);
        holds.insert(
            id.to_owned(),
            MetadataHold {
                serial,
                pending: true,
                phase: Phase::Saving,
                uncertain: old.is_some_and(|hold| hold.uncertain),
                recovery: explicit_recovery,
            },
        );
        self.metadata.try_set(holds);
        Some(MetadataLease(serial))
    }

    pub(super) fn timeout_metadata(self, id: &str, lease: MetadataLease) {
        self.metadata.try_update(|holds| {
            if let Some(hold) = holds.get_mut(id)
                && hold.serial == lease.0
                && hold.pending
            {
                hold.phase = Phase::Error;
                hold.uncertain = true;
            }
        });
    }

    fn finish_metadata(
        self,
        id: &str,
        lease: MetadataLease,
        result: &Result<openbot_contracts::model_connections::ModelConnection, MetadataError>,
    ) -> bool {
        let Some(mut holds) = self.metadata.try_get_untracked() else {
            return false;
        };
        let Some(mut hold) = holds.get(id).copied().filter(|hold| hold.serial == lease.0) else {
            return false;
        };
        hold.pending = false;
        match result {
            Ok(_) if hold.phase == Phase::Saving && (hold.recovery || !hold.uncertain) => {
                holds.remove(id);
            }
            Ok(_) => {
                hold.phase = Phase::Error;
                // Exact same-lease metadata ACK settles this intent; only a fresh explicit load
                // may resume editing after its timeout. It says nothing about generic effects.
                hold.uncertain = false;
                holds.insert(id.to_owned(), hold);
            }
            Err(MetadataError::Conflict(_)) => {
                hold.phase = Phase::Conflict;
                holds.insert(id.to_owned(), hold);
            }
            Err(error) => {
                hold.phase = Phase::Error;
                hold.uncertain |= *error == MetadataError::Unknown;
                holds.insert(id.to_owned(), hold);
            }
        }
        self.metadata.try_set(holds);
        if result.is_ok() {
            self.revision
                .try_update(|value| *value = value.saturating_add(1));
        }
        true
    }

    /// Called only after a fresh, authorized, explicitly confirmed load has been accepted by core.
    pub(super) fn release_metadata_after_read(self, id: &str) -> bool {
        if self.status.try_get_untracked().is_none_or(Status::locked) {
            return false;
        }
        let Some(mut holds) = self.metadata.try_get_untracked() else {
            return false;
        };
        if holds.get(id).is_some_and(|hold| hold.pending) {
            return false;
        }
        holds.remove(id);
        self.metadata.try_set(holds);
        true
    }

    pub(super) fn launch_metadata(
        self,
        change: MetadataChange,
        lease: MetadataLease,
        finished: impl FnOnce(
            Result<openbot_contracts::model_connections::ModelConnection, MetadataError>,
        ) + 'static,
    ) {
        let Some(Some(owner)) = self.owner.try_get_value() else {
            return;
        };
        owner.with(|| {
            leptos::task::spawn_local(async move {
                let id = change.base.id.clone();
                let result = api::write_metadata(change).await;
                if self.finish_metadata(&id, lease, &result) {
                    finished(result);
                }
            })
        });
    }
    fn complete(self, result: Result<(), WriteError>, finished: impl FnOnce(bool)) {
        if self.status.try_get_untracked().is_none() {
            return;
        }
        self.status.try_set(match result {
            Ok(()) => Status::Saved,
            Err(e) => Status::Failed(e),
        });
        finished(result.is_ok());
        // Only acknowledged mutations trigger a fresh read. Unknown never clears on list refresh.
        if result.is_ok() {
            self.revision.try_update(|v| *v = v.saturating_add(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> openbot_contracts::model_connections::ModelConnection {
        use openbot_contracts::model_connections::{
            CustomModelProtocol, ModelConnection, ModelConnectionSource,
        };
        ModelConnection {
            id: "01991389-7380-7000-8000-000000000061".into(),
            source: ModelConnectionSource::Custom,
            name: "Acknowledged metadata".into(),
            protocol: CustomModelProtocol::OpenaiResponses,
            endpoint: "https://example.test/v1/responses".into(),
            model: "model-1".into(),
            enabled: true,
            revision: 2,
            has_credential: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn metadata_timeout_keeps_physical_flight_and_late_exact_ack_requires_fresh_load() {
        Owner::new().with(|| {
            let actions = ModelActions::new();
            let row = receipt();
            let lease = actions.claim_metadata(&row.id, false).unwrap();
            actions.timeout_metadata(&row.id, lease);
            assert!(actions.claim_metadata(&row.id, true).is_none());
            assert!(!actions.release_metadata_after_read(&row.id));
            assert!(actions.finish_metadata(&row.id, lease, &Ok(row.clone())));
            let hold = actions.metadata_hold(&row.id).unwrap();
            assert_eq!(hold.phase, Phase::Error);
            assert!(!hold.pending && !hold.uncertain);
            assert!(actions.claim_metadata(&row.id, false).is_none());
            assert!(actions.release_metadata_after_read(&row.id));
            assert!(actions.claim_metadata(&row.id, false).is_some());
        });
    }

    #[test]
    fn original_unknown_survives_retry_conflict_and_stale_lease_cannot_finish_new_intent() {
        Owner::new().with(|| {
            let actions = ModelActions::new();
            let row = receipt();
            let original = actions.claim_metadata(&row.id, false).unwrap();
            assert!(actions.finish_metadata(&row.id, original, &Err(MetadataError::Unknown)));
            let retry = actions.claim_metadata(&row.id, true).unwrap();
            assert!(!actions.finish_metadata(&row.id, original, &Ok(row.clone())));
            assert!(actions.metadata_hold(&row.id).unwrap().pending);
            let snapshot = openbot_contracts::revision::RevisionSnapshot::from_public(
                row.revision,
                row.updated_at,
                &row,
            )
            .unwrap();
            assert!(actions.finish_metadata(
                &row.id,
                retry,
                &Err(MetadataError::Conflict(snapshot))
            ));
            let hold = actions.metadata_hold(&row.id).unwrap();
            assert_eq!(hold.phase, Phase::Conflict);
            assert!(hold.uncertain && !hold.pending);
            assert!(actions.claim_metadata(&row.id, false).is_none());
            actions.status.set(Status::Failed(WriteError::Unknown));
            assert!(!actions.release_metadata_after_read(&row.id));
            assert!(actions.claim_metadata(&row.id, true).is_none());
        });
    }

    #[test]
    fn old_auth_metadata_ack_never_finishes_new_account_state() {
        let row = receipt();
        let old_owner = Owner::new();
        let old = old_owner.with(ModelActions::new);
        let lease = old_owner.with(|| old.claim_metadata(&row.id, false).unwrap());
        old_owner.cleanup();
        Owner::new().with(|| {
            let new = ModelActions::new();
            assert!(!old.finish_metadata(&row.id, lease, &Ok(row.clone())));
            assert!(new.metadata_hold(&row.id).is_none());
            assert_eq!(new.revision.get_untracked(), 0);
            assert_eq!(new.status.get_untracked(), Status::Idle);
        });
    }
    #[test]
    fn unknown_is_a_persistent_write_barrier() {
        assert!(Status::Pending.locked());
        assert!(Status::Failed(WriteError::Unknown).locked());
        assert!(!Status::Saved.locked());
        assert!(!Status::Failed(WriteError::InvalidInput).locked());
    }
    #[test]
    fn late_write_after_sign_out_cannot_finish_a_new_account_dialog() {
        for result in [Ok(()), Err(WriteError::Unknown)] {
            let old_owner = Owner::new();
            let old = old_owner.with(ModelActions::new);
            old.status.set(Status::Pending);
            old_owner.cleanup();
            let new_owner = Owner::new();
            new_owner.with(|| {
                let new = ModelActions::new();
                let invoked = std::cell::Cell::new(false);
                old.complete(result, |_| invoked.set(true));
                assert!(!invoked.get());
                assert_eq!(new.status.get_untracked(), Status::Idle);
                assert_eq!(new.revision.get_untracked(), 0);
            });
        }
    }
}
