//! Payload-free authenticated ownership for existing configuration writes.

use std::collections::BTreeMap;

use leptos::prelude::*;

use crate::api::ApiError;
use crate::revision_editor::Phase;

/// Closed single-CAS outcomes; this never changes the generic effect error taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) enum CasWriteError {
    Conflict(openbot_contracts::revision::RevisionSnapshot),
    Rejected(ApiError),
    Unknown(ApiError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SandboxCasMode {
    Automatic,
    #[cfg(any(target_arch = "wasm32", test))]
    RetryOriginal,
    #[cfg(any(target_arch = "wasm32", test))]
    Reapply,
}

#[derive(Clone, Copy)]
struct SandboxCasEntry {
    #[cfg(any(target_arch = "wasm32", test))]
    serial: u64,
    #[cfg(any(target_arch = "wasm32", test))]
    expected_revision: i64,
    current: bool,
    paused: Option<Phase>,
    uncertain: bool,
    /// Exact CAS attempt that owns an unresolved barrier; generic effects never acquire it.
    #[cfg(any(target_arch = "wasm32", test))]
    uncertain_serial: Option<u64>,
    #[cfg(any(target_arch = "wasm32", test))]
    timed_out: bool,
    #[cfg(any(target_arch = "wasm32", test))]
    recovery: bool,
}

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
    sandbox_cas: RwSignal<BTreeMap<String, SandboxCasEntry>>,
    #[cfg(any(target_arch = "wasm32", test))]
    cas_serial: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    worker_owner: StoredValue<Option<Owner>>,
}

impl ConfigurationWrites {
    pub fn new() -> Self {
        Self {
            writes: RwSignal::new(BTreeMap::new()),
            sandbox_cas: RwSignal::new(BTreeMap::new()),
            #[cfg(any(target_arch = "wasm32", test))]
            cas_serial: RwSignal::new(0),
            #[cfg(target_arch = "wasm32")]
            worker_owner: StoredValue::new(Owner::current()),
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn owner(self) -> Option<Owner> {
        self.worker_owner.try_get_value().flatten()
    }

    pub(crate) fn sandbox_pause(self, name: &str) -> Option<(Phase, bool)> {
        self.sandbox_cas
            .try_with(|entries| {
                entries
                    .get(name)
                    .and_then(|entry| entry.paused.map(|phase| (phase, entry.uncertain)))
            })
            .flatten()
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn sandbox_wait_timed_out(self, name: &str, serial: u64) {
        self.sandbox_cas.try_update(|entries| {
            if let Some(entry) = entries
                .get_mut(name)
                .filter(|entry| entry.current && entry.serial == serial)
            {
                entry.timed_out = true;
                entry.uncertain = true;
                entry.uncertain_serial = Some(serial);
                entry.paused = Some(Phase::Error);
            }
        });
    }

    /// Explicit discard after an authorized read clears only a settled, definite CAS hold.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn sandbox_loaded(self, name: &str) {
        if self.status(ConfigurationKind::Sandbox, name).is_some() {
            return;
        }
        self.sandbox_cas.try_update(|entries| {
            if entries
                .get(name)
                .is_some_and(|entry| !entry.current && !entry.uncertain)
            {
                entries.remove(name);
            }
        });
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn begin_sandbox_cas(
        self,
        name: &str,
        expected_revision: i64,
        mode: SandboxCasMode,
    ) -> Option<u64> {
        if !openbot_contracts::sandboxed::is_sandboxed_component_name(name)
            || expected_revision <= 0
        {
            return None;
        }
        let key = (ConfigurationKind::Sandbox, name.to_owned());
        let previous = self
            .sandbox_cas
            .try_with(|entries| entries.get(name).copied())
            .flatten();
        if previous.is_some_and(|entry| entry.current) {
            return None;
        }
        let writes = self.writes.try_get_untracked()?;
        if writes
            .iter()
            .any(|((kind, other), _)| *kind == ConfigurationKind::Sandbox && other != name)
        {
            return None;
        }
        match mode {
            SandboxCasMode::Automatic
                if previous.is_some_and(|entry| entry.paused.is_some())
                    || writes.contains_key(&key) =>
            {
                return None;
            }
            SandboxCasMode::RetryOriginal | SandboxCasMode::Reapply => {
                let previous = previous.filter(|entry| entry.paused.is_some())?;
                if mode == SandboxCasMode::RetryOriginal
                    && previous.expected_revision != expected_revision
                {
                    return None;
                }
                if writes
                    .get(&key)
                    .is_some_and(|status| *status != WriteStatus::Unknown)
                {
                    return None;
                }
                let owned_unknown = writes.get(&key) == Some(&WriteStatus::Unknown)
                    && previous.uncertain
                    && previous
                        .uncertain_serial
                        .is_some_and(|serial| serial <= previous.serial);
                if (writes.contains_key(&key) || previous.uncertain) && !owned_unknown {
                    return None;
                }
            }
            SandboxCasMode::Automatic => {}
        }
        if !writes.contains_key(&key) && writes.len() >= MAX_UNRESOLVED_WRITES {
            return None;
        }
        let entries = self.sandbox_cas.try_get_untracked()?;
        if !entries.contains_key(name) && entries.len() >= MAX_UNRESOLVED_WRITES {
            return None;
        }
        let serial = self.cas_serial.try_get_untracked()?.checked_add(1)?;
        self.cas_serial.try_set(serial);
        self.writes.try_update(|writes| {
            writes.insert(key, WriteStatus::Pending);
        })?;
        self.sandbox_cas.try_update(|entries| {
            entries.insert(
                name.to_owned(),
                SandboxCasEntry {
                    serial,
                    expected_revision,
                    current: true,
                    paused: previous.and_then(|entry| entry.paused),
                    uncertain: previous.is_some_and(|entry| entry.uncertain),
                    uncertain_serial: previous.and_then(|entry| entry.uncertain_serial),
                    timed_out: false,
                    recovery: mode != SandboxCasMode::Automatic,
                },
            );
        })?;
        Some(serial)
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn complete_sandbox_cas(
        self,
        name: &str,
        serial: u64,
        result: Result<(), CasWriteError>,
    ) -> bool {
        let mut entry = match self
            .sandbox_cas
            .try_with(|entries| entries.get(name).copied())
            .flatten()
        {
            Some(entry) if entry.serial == serial && entry.current => entry,
            _ => return false,
        };
        let key = (ConfigurationKind::Sandbox, name.to_owned());
        if self
            .writes
            .try_with(|writes| writes.get(&key).copied())
            .flatten()
            != Some(WriteStatus::Pending)
        {
            return false;
        }
        entry.current = false;
        match result {
            Ok(()) => {
                self.writes.try_update(|writes| {
                    writes.remove(&key);
                });
                if entry.recovery && !entry.timed_out {
                    entry.paused = None;
                }
                entry.uncertain = false;
                entry.uncertain_serial = None;
            }
            Err(CasWriteError::Conflict(_)) => {
                self.writes.try_update(|writes| {
                    if entry.uncertain {
                        writes.insert(key.clone(), WriteStatus::Unknown);
                    } else {
                        writes.remove(&key);
                    }
                });
                entry.paused = Some(Phase::Conflict);
            }
            Err(CasWriteError::Rejected(_)) => {
                self.writes.try_update(|writes| {
                    if entry.uncertain {
                        writes.insert(key.clone(), WriteStatus::Unknown);
                    } else {
                        writes.remove(&key);
                    }
                });
                entry.paused = Some(Phase::Error);
            }
            Err(CasWriteError::Unknown(_)) => {
                self.writes.try_update(|writes| {
                    writes.insert(key, WriteStatus::Unknown);
                });
                entry.uncertain = true;
                entry.uncertain_serial = Some(serial);
                entry.paused = Some(Phase::Error);
            }
        }
        self.sandbox_cas
            .try_update(|entries| {
                if entry.paused.is_some() {
                    entries.insert(name.to_owned(), entry);
                } else {
                    entries.remove(name);
                }
            })
            .is_some()
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
        if key.0 == ConfigurationKind::Sandbox
            && self
                .sandbox_cas
                .try_with(|entries| {
                    entries.get(&key.1).is_some_and(|entry| {
                        entry.current || entry.paused.is_some() || entry.uncertain
                    })
                })
                .unwrap_or(true)
        {
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

#[cfg(target_arch = "wasm32")]
struct SandboxCasGuard {
    writes: ConfigurationWrites,
    name: String,
    serial: u64,
    finished: bool,
}

#[cfg(target_arch = "wasm32")]
impl Drop for SandboxCasGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.writes.complete_sandbox_cas(
                &self.name,
                self.serial,
                Err(CasWriteError::Unknown(ApiError::ReconciliationRequired)),
            );
        }
    }
}

/// Existing single draft CAS only. It never handles creation, publishing or arbitrary Unknowns.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn track_sandbox_cas<T>(
    name: String,
    expected_revision: i64,
    mode: SandboxCasMode,
    work: impl std::future::Future<Output = Result<T, CasWriteError>>,
) -> Result<T, CasWriteError> {
    let writes = use_context::<ConfigurationWrites>()
        .ok_or(CasWriteError::Rejected(ApiError::Unavailable))?;
    let serial = writes
        .begin_sandbox_cas(&name, expected_revision, mode)
        .ok_or(CasWriteError::Rejected(ApiError::ReconciliationRequired))?;
    #[cfg(target_arch = "wasm32")]
    {
        let timed_name = name.clone();
        crate::editor_runtime::after(10_000, move || {
            writes.sandbox_wait_timed_out(&timed_name, serial)
        });
    }
    let mut guard = SandboxCasGuard {
        writes,
        name,
        serial,
        finished: false,
    };
    let result = work.await;
    let settled = guard.writes.complete_sandbox_cas(
        &guard.name,
        guard.serial,
        result.as_ref().map(|_| ()).map_err(|error| *error),
    );
    guard.finished = true;
    if !settled {
        return Err(CasWriteError::Rejected(ApiError::Unauthorized));
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

    #[test]
    fn single_cas_recovery_preserves_uncertainty_and_rejects_an_old_completion() {
        Owner::new().with(|| {
            let writes = ConfigurationWrites::new();
            let name = "custom_cas";
            let original = writes
                .begin_sandbox_cas(name, 4, SandboxCasMode::Automatic)
                .unwrap();
            assert!(writes.complete_sandbox_cas(
                name,
                original,
                Err(CasWriteError::Unknown(ApiError::Network))
            ));
            writes.sandbox_loaded(name);
            assert_eq!(writes.sandbox_pause(name), Some((Phase::Error, true)));
            assert!(
                writes
                    .begin_sandbox_cas(name, 4, SandboxCasMode::Automatic)
                    .is_none()
            );
            assert!(
                writes
                    .begin_sandbox_cas(name, 5, SandboxCasMode::RetryOriginal)
                    .is_none()
            );
            let retry = writes
                .begin_sandbox_cas(name, 4, SandboxCasMode::RetryOriginal)
                .unwrap();
            assert!(!writes.complete_sandbox_cas(name, original, Ok(())));
            assert_eq!(
                writes.status(ConfigurationKind::Sandbox, name),
                Some(WriteStatus::Pending)
            );
            let snapshot = openbot_contracts::revision::RevisionSnapshot::from_public(
                5,
                time::OffsetDateTime::UNIX_EPOCH,
                &serde_json::json!({"name":name}),
            )
            .unwrap();
            assert!(writes.complete_sandbox_cas(
                name,
                retry,
                Err(CasWriteError::Conflict(snapshot))
            ));
            assert_eq!(writes.sandbox_pause(name), Some((Phase::Conflict, true)));
            assert_eq!(
                writes.status(ConfigurationKind::Sandbox, name),
                Some(WriteStatus::Unknown)
            );
            assert!(!writes.begin(&(ConfigurationKind::Sandbox, name.to_owned())));
            writes.sandbox_loaded(name);
            assert_eq!(writes.sandbox_pause(name), Some((Phase::Conflict, true)));
            let reapplied = writes
                .begin_sandbox_cas(name, 5, SandboxCasMode::Reapply)
                .unwrap();
            assert!(writes.complete_sandbox_cas(name, reapplied, Ok(())));
            assert_eq!(writes.sandbox_pause(name), None);
        });
    }

    #[test]
    fn cas_recovery_never_consumes_a_generic_or_partial_publication_lock() {
        Owner::new().with(|| {
            for partial in [false, true] {
                let writes = ConfigurationWrites::new();
                let key = (ConfigurationKind::Sandbox, "custom_generic".to_owned());
                assert!(writes.begin(&key));
                if partial {
                    writes.sandbox_draft_saved(&key.1);
                }
                assert!(writes.complete(&key, Err(ApiError::Network)));
                for mode in [
                    SandboxCasMode::Automatic,
                    SandboxCasMode::RetryOriginal,
                    SandboxCasMode::Reapply,
                ] {
                    assert!(writes.begin_sandbox_cas(&key.1, 4, mode).is_none());
                    assert!(writes.begin_sandbox_cas("custom_other", 4, mode).is_none());
                }
                assert_eq!(
                    writes.status(key.0, &key.1),
                    Some(if partial {
                        WriteStatus::DraftSavedPublicationUnknown
                    } else {
                        WriteStatus::Unknown
                    })
                );
            }
        });
    }

    #[test]
    fn authenticated_timeout_survives_page_absence_and_old_timer_cannot_claim_new_attempt() {
        Owner::new().with(|| {
            let writes = ConfigurationWrites::new();
            let name = "custom_timed";
            let first = writes
                .begin_sandbox_cas(name, 4, SandboxCasMode::Automatic)
                .unwrap();
            // No editor or page owner participates in this authenticated receipt timeout.
            writes.sandbox_wait_timed_out(name, first);
            assert!(writes.complete_sandbox_cas(name, first, Ok(())));
            assert_eq!(writes.sandbox_pause(name), Some((Phase::Error, false)));
            writes.sandbox_loaded(name);
            let next = writes
                .begin_sandbox_cas(name, 5, SandboxCasMode::Automatic)
                .unwrap();
            writes.sandbox_wait_timed_out(name, first);
            assert!(writes.complete_sandbox_cas(name, next, Ok(())));
            assert_eq!(writes.sandbox_pause(name), None);
        });
    }

    #[test]
    fn paused_cas_metadata_cannot_authorize_an_unrelated_generic_unknown() {
        Owner::new().with(|| {
            let writes = ConfigurationWrites::new();
            let name = "custom_provenance";
            let attempt = writes
                .begin_sandbox_cas(name, 4, SandboxCasMode::Automatic)
                .unwrap();
            assert!(writes.complete_sandbox_cas(
                name,
                attempt,
                Err(CasWriteError::Rejected(ApiError::Forbidden))
            ));
            assert!(!writes.begin(&(ConfigurationKind::Sandbox, name.to_owned())));
            // A foreign effect's lock has no CAS serial provenance, even beside old CAS metadata.
            writes.writes.update(|entries| {
                entries.insert(
                    (ConfigurationKind::Sandbox, name.to_owned()),
                    WriteStatus::Unknown,
                );
            });
            assert!(
                writes
                    .begin_sandbox_cas(name, 4, SandboxCasMode::RetryOriginal)
                    .is_none()
            );
            assert!(
                writes
                    .begin_sandbox_cas(name, 5, SandboxCasMode::Reapply)
                    .is_none()
            );
            assert_eq!(
                writes.status(ConfigurationKind::Sandbox, name),
                Some(WriteStatus::Unknown)
            );
        });
    }
}
