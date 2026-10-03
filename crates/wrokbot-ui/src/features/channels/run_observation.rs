//! Only current-run output learned from an authoritative active snapshot or typed live events.
use leptos::prelude::*;
use openbot_contracts::ids::{RunId, ThreadId};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputPhase {
    Running,
    UnobservedTerminal,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunObservation {
    pub run: RunId,
    pub phase: OutputPhase,
    pub text: String,
    pub terminal_sequence: Option<u64>,
}

impl RunObservation {
    pub(crate) fn running(run: RunId, text: String) -> Self {
        Self {
            run,
            phase: OutputPhase::Running,
            text,
            terminal_sequence: None,
        }
    }
}

/// Authentication-owned minimal source references. Output and approval parameters are not cached.
#[derive(Clone, Copy)]
pub(crate) struct ObservedRunDirectory(RwSignal<BTreeMap<ThreadId, RunObservation>>);
impl ObservedRunDirectory {
    pub(crate) fn new() -> Self {
        Self(RwSignal::new(BTreeMap::new()))
    }
    pub(crate) fn latest(self, thread: Option<&ThreadId>) -> Option<RunObservation> {
        thread.and_then(|thread| self.0.with_untracked(|rows| rows.get(thread).cloned()))
    }
    pub(crate) fn record(self, thread: ThreadId, mut observation: RunObservation) {
        observation.text.clear();
        self.0.update(|rows| {
            rows.insert(thread, observation);
        });
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn forget(self, thread: &ThreadId) {
        self.0.update(|rows| {
            rows.remove(thread);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_reference_keeps_only_observed_binding_and_dies_with_authentication() {
        let owner = Owner::new();
        let directory = owner.with(|| {
            let directory = ObservedRunDirectory::new();
            directory.record(
                ThreadId::new("thread-1"),
                RunObservation {
                    run: RunId::new("run-1"),
                    phase: OutputPhase::Unknown,
                    text: "sensitive output".into(),
                    terminal_sequence: Some(8),
                },
            );
            let reference = directory.latest(Some(&ThreadId::new("thread-1"))).unwrap();
            assert!(reference.text.is_empty());
            assert_eq!(reference.terminal_sequence, Some(8));
            assert_eq!(reference.run, RunId::new("run-1"));
            assert!(directory.latest(Some(&ThreadId::new("other"))).is_none());
            directory
        });
        owner.cleanup();
        assert!(directory.0.try_get_untracked().is_none());
        let next = Owner::new();
        next.with(|| {
            assert!(
                ObservedRunDirectory::new()
                    .latest(Some(&ThreadId::new("thread-1")))
                    .is_none()
            )
        });
    }
}
