//! Payload-free authenticated ownership for existing configuration writes.

use std::collections::BTreeMap;

use leptos::prelude::*;

use crate::api::ApiError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConfigurationKind {
    Agents,
    ToolConnections,
    IdentityProviders,
    Components,
    Sandbox,
    Memory,
    Preferences,
    People,
    Boundaries,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteStatus {
    Pending,
    PendingPublication,
    Unknown,
    DraftSavedPublicationUnknown,
}

type WriteKey = (ConfigurationKind, String);
const MAX_UNRESOLVED_WRITES: usize = 512;

pub(crate) fn resource_lock(
    kind: ConfigurationKind,
    id: impl Fn() -> String + Send + Sync + 'static,
) -> Signal<bool> {
    let writes = expect_context::<ConfigurationWrites>();
    Signal::derive(move || writes.locked(kind, &id()))
}

pub(crate) fn family_lock(kind: ConfigurationKind) -> Signal<bool> {
    let writes = expect_context::<ConfigurationWrites>();
    Signal::derive(move || writes.family_status(kind).is_some())
}

/// A bounded latch, never a configuration cache or permission projection.
#[derive(Clone, Copy)]
pub(crate) struct ConfigurationWrites {
    writes: RwSignal<BTreeMap<WriteKey, WriteStatus>>,
}

impl ConfigurationWrites {
    pub fn new() -> Self {
        Self {
            writes: RwSignal::new(BTreeMap::new()),
        }
    }

    pub fn status(self, kind: ConfigurationKind, id: &str) -> Option<WriteStatus> {
        self.writes
            .with(|writes| writes.get(&(kind, id.to_owned())).copied())
    }

    pub fn family_status(self, kind: ConfigurationKind) -> Option<WriteStatus> {
        self.writes.with(|writes| {
            let mut status = None;
            for ((family, _), entry) in writes {
                if *family == kind {
                    if matches!(
                        entry,
                        WriteStatus::Unknown | WriteStatus::DraftSavedPublicationUnknown
                    ) {
                        return Some(*entry);
                    }
                    status = Some(*entry);
                }
            }
            status
        })
    }

    pub fn locked(self, kind: ConfigurationKind, id: &str) -> bool {
        self.status(kind, id).is_some()
            || self
                .writes
                .with(|writes| writes.len() >= MAX_UNRESOLVED_WRITES)
    }

    fn sandbox_draft_saved(self, id: &str) {
        self.writes.try_update(|writes| {
            let key = (ConfigurationKind::Sandbox, id.to_owned());
            if writes.get(&key) == Some(&WriteStatus::Pending) {
                writes.insert(key, WriteStatus::PendingPublication);
            }
        });
    }

    fn begin(self, key: &WriteKey) -> bool {
        if key.1.is_empty() || key.1.len() > 512 || key.1.chars().any(char::is_control) {
            return false;
        }
        self.writes
            .try_update(|writes| {
                if writes.contains_key(key) || writes.len() >= MAX_UNRESOLVED_WRITES {
                    return false;
                }
                writes.insert(key.clone(), WriteStatus::Pending);
                true
            })
            .unwrap_or(false)
    }

    fn complete(self, key: &WriteKey, outcome: Result<(), ApiError>) -> bool {
        self.writes
            .try_update(|writes| {
                let phase = writes.get(key).copied();
                if !matches!(
                    phase,
                    Some(WriteStatus::Pending | WriteStatus::PendingPublication)
                ) {
                    return false;
                }
                if outcome.is_ok()
                    || (phase == Some(WriteStatus::Pending)
                        && outcome.is_err_and(definite_rejection))
                {
                    writes.remove(key);
                } else {
                    writes.insert(
                        key.clone(),
                        if phase == Some(WriteStatus::PendingPublication) {
                            WriteStatus::DraftSavedPublicationUnknown
                        } else {
                            WriteStatus::Unknown
                        },
                    );
                }
                true
            })
            .unwrap_or(false)
    }
}

struct SubmittedWrite {
    writes: ConfigurationWrites,
    key: WriteKey,
}

impl SubmittedWrite {
    #[inline(never)]
    fn start(kind: ConfigurationKind, id: String) -> Result<Option<Self>, ApiError> {
        let writes = match use_context::<ConfigurationWrites>() {
            Some(writes) => writes,
            #[cfg(not(target_arch = "wasm32"))]
            None => return Ok(None),
            #[cfg(target_arch = "wasm32")]
            None => return Err(ApiError::Unavailable),
        };
        let key = (kind, id);
        if !writes.begin(&key) {
            return Err(ApiError::ReconciliationRequired);
        }
        Ok(Some(Self { writes, key }))
    }

    #[inline(never)]
    fn finish(&self, outcome: Result<(), ApiError>) -> Result<(), ApiError> {
        if self.writes.complete(&self.key, outcome) {
            Ok(())
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

/// A captured phase handle; it carries no request body or permission claim.
pub(crate) struct WritePhase(Option<(ConfigurationWrites, WriteKey)>);

impl WritePhase {
    pub fn sandbox_draft_saved(&self) {
        if let Some((writes, key)) = &self.0 {
            writes.sandbox_draft_saved(&key.1);
        }
    }
}

impl Drop for SubmittedWrite {
    fn drop(&mut self) {
        // Cancelling a page's response wait is not evidence that a dispatched write did not commit.
        self.writes
            .complete(&self.key, Err(ApiError::ReconciliationRequired));
    }
}

/// Guard only the existing typed adapter, including cancellation while awaiting its receipt.
pub(crate) fn track<'a, T: 'a>(
    kind: ConfigurationKind,
    id: String,
    work: impl std::future::Future<Output = Result<T, ApiError>> + 'a,
) -> impl std::future::Future<Output = Result<T, ApiError>> + 'a {
    track_boxed(kind, id, Box::pin(work))
}

async fn track_boxed<T>(
    kind: ConfigurationKind,
    id: String,
    work: std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, ApiError>> + '_>>,
) -> Result<T, ApiError> {
    track_with_phase(kind, id, |_| work).await
}

pub(crate) async fn track_with_phase<T, F>(
    kind: ConfigurationKind,
    id: String,
    work: impl FnOnce(WritePhase) -> F,
) -> Result<T, ApiError>
where
    F: std::future::Future<Output = Result<T, ApiError>>,
{
    let guard = SubmittedWrite::start(kind, id)?;
    let phase = WritePhase(
        guard
            .as_ref()
            .map(|guard| (guard.writes, guard.key.clone())),
    );
    let result = work(phase).await;
    if let Some(guard) = &guard {
        guard.finish(result.as_ref().map(|_| ()).map_err(|error| *error))?;
    }
    result
}

#[component]
pub(crate) fn ConfigurationWriteNotice() -> impl IntoView {
    use crate::i18n::{t, use_i18n};
    let i18n = use_i18n();
    let writes = expect_context::<ConfigurationWrites>();
    let pathname = leptos_router::hooks::use_location().pathname;
    let plugins = expect_context::<crate::features::admin::plugins::PluginActions>();
    let plugin_page = Signal::derive(move || {
        let path = pathname.get();
        path == "/skills"
            || path == "/admin/skills"
            || path == "/admin/credentials"
            || path.starts_with("/admin/plugins")
    });
    let status = Signal::derive(move || {
        if plugin_page.get() {
            return if plugins.unknown.get() {
                Some(WriteStatus::Unknown)
            } else if plugins.busy.get() {
                Some(WriteStatus::Pending)
            } else {
                None
            };
        }
        let path = pathname.get();
        let family = if path == "/agents" {
            ConfigurationKind::Agents
        } else if path.starts_with("/settings/connected-accounts") {
            ConfigurationKind::ToolConnections
        } else if path == "/settings/memory" {
            ConfigurationKind::Memory
        } else if path == "/settings" {
            ConfigurationKind::Preferences
        } else if path == "/admin/identity-providers" {
            ConfigurationKind::IdentityProviders
        } else if path.starts_with("/admin/components") {
            ConfigurationKind::Components
        } else if path == "/admin/playground" {
            ConfigurationKind::Sandbox
        } else if path == "/admin/people" {
            ConfigurationKind::People
        } else if path == "/admin/boundaries" {
            ConfigurationKind::Boundaries
        } else {
            return None;
        };
        writes.family_status(family)
    });
    view! {
        <Show when=move || status.get().is_some()>
            <p class="ob-configuration-notice" role="status">
                {move || if status.get() == Some(WriteStatus::DraftSavedPublicationUnknown) {
                    t!(i18n, common.configuration_publication_unknown).into_any()
                } else if status.get() == Some(WriteStatus::Unknown) {
                    t!(i18n, common.configuration_write_unknown).into_any()
                } else { t!(i18n, common.configuration_write_pending).into_any() }}
                {move || (plugin_page.get() && plugins.unknown.get()).then(|| plugins.target.get()).flatten().map(|target| view! {<code>{target}</code>})}
            </p>
        </Show>
    }
}

// These statuses precede the command in the existing single-write Server handlers.
// Partial multi-step operations must report ReconciliationRequired even after a later rejection.
fn definite_rejection(error: ApiError) -> bool {
    matches!(
        error,
        ApiError::NotSubmitted | ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_or_unbound_ack_remains_locked_but_another_object_can_progress() {
        Owner::new().with(|| {
            for error in [
                ApiError::Network,
                ApiError::ReconciliationRequired,
                ApiError::InvalidResponse,
                ApiError::Server,
                ApiError::Conflict,
                ApiError::Unavailable,
            ] {
                let writes = ConfigurationWrites::new();
                let key = (ConfigurationKind::Components, "one".to_owned());
                assert!(writes.begin(&key));
                assert!(writes.complete(&key, Err(error)));
                assert_eq!(writes.status(key.0, &key.1), Some(WriteStatus::Unknown));
                assert!(!writes.begin(&key));
                assert!(writes.begin(&(key.0, "two".to_owned())));
                // An unrelated completion cannot erase the unresolved receipt.
                assert!(!writes.complete(&key, Ok(())));
                assert!(writes.locked(key.0, &key.1));
            }
        });
    }

    #[test]
    fn exact_ack_or_pre_command_rejection_is_local_to_its_object() {
        Owner::new().with(|| {
            for result in [
                Ok(()),
                Err(ApiError::NotSubmitted),
                Err(ApiError::Unauthorized),
                Err(ApiError::Forbidden),
                Err(ApiError::NotFound),
            ] {
                let writes = ConfigurationWrites::new();
                let key = (ConfigurationKind::Memory, "one".to_owned());
                assert!(writes.begin(&key));
                assert!(writes.complete(&key, result));
                assert!(!writes.locked(key.0, &key.1));
            }
        });
    }

    #[test]
    fn logout_rejects_late_completion_and_the_latch_never_evicts_unknown() {
        let old_owner = Owner::new();
        let old = old_owner.with(ConfigurationWrites::new);
        let key = (ConfigurationKind::Preferences, "account".to_owned());
        assert!(old.begin(&key));
        old_owner.cleanup();
        Owner::new().with(|| {
            assert!(!old.complete(&key, Ok(())));
            let new = ConfigurationWrites::new();
            assert!(!new.locked(key.0, &key.1));
            for index in 0..MAX_UNRESOLVED_WRITES {
                let key = (ConfigurationKind::Components, index.to_string());
                assert!(new.begin(&key));
                assert!(new.complete(&key, Err(ApiError::Network)));
            }
            assert!(!new.begin(&(ConfigurationKind::Components, "overflow".into())));
            assert_eq!(
                new.status(ConfigurationKind::Components, "0"),
                Some(WriteStatus::Unknown)
            );
        });
    }

    #[test]
    fn dropped_route_wait_retains_partial_publication_even_when_the_second_step_is_denied() {
        Owner::new().with(|| {
            let writes = ConfigurationWrites::new();
            let key = (ConfigurationKind::Sandbox, "custom_example".to_owned());
            assert!(writes.begin(&key));
            writes.sandbox_draft_saved(&key.1);
            assert!(writes.complete(&key, Err(ApiError::Forbidden)));
            assert_eq!(
                writes.status(key.0, &key.1),
                Some(WriteStatus::DraftSavedPublicationUnknown)
            );
            assert!(!writes.begin(&key));
            let second = (ConfigurationKind::Memory, "memory".to_owned());
            assert!(writes.begin(&second));
            drop(SubmittedWrite {
                writes,
                key: second.clone(),
            });
            assert_eq!(
                writes.status(second.0, &second.1),
                Some(WriteStatus::Unknown)
            );
        });
    }
}
