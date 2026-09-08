//! App-owned mutation latch: navigation cannot cancel or replay an uncertain write.
use crate::api::model_connections::{self as api, Write, WriteError};
use leptos::prelude::*;

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
    pub(super) revision: RwSignal<u64>,
}
impl ModelActions {
    pub(crate) fn new() -> Self {
        Self {
            status: RwSignal::new(Status::Idle),
            revision: RwSignal::new(0),
        }
    }
    pub(super) fn launch(self, input: Write, finished: impl FnOnce(bool) + 'static) {
        if self.status.get_untracked().locked() {
            return;
        }
        self.status.set(Status::Pending);
        leptos::task::spawn_local(async move {
            let result = api::write(input).await;
            self.status.try_set(match result {
                Ok(()) => Status::Saved,
                Err(e) => Status::Failed(e),
            });
            finished(result.is_ok());
            // Only acknowledged mutations trigger a fresh read. Unknown never clears on list refresh.
            if result.is_ok() {
                self.revision.try_update(|v| *v = v.saturating_add(1));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_is_a_persistent_write_barrier() {
        assert!(Status::Pending.locked());
        assert!(Status::Failed(WriteError::Unknown).locked());
        assert!(!Status::Saved.locked());
        assert!(!Status::Failed(WriteError::InvalidInput).locked());
    }
}
