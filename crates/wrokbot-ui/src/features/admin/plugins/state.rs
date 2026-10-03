use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::mcp::{McpAdminPage, McpConnections};

use crate::api::ApiError;
use crate::api::skills::SkillBinding;
use crate::revision_editor::Phase;

#[derive(Clone)]
struct SkillCasCurrent {
    binding: SkillBinding,
    serial: u64,
    timed_out: bool,
    explicit: bool,
}

#[derive(Clone, Copy, Default)]
struct SkillCasHold {
    paused: bool,
    phase: Option<Phase>,
    /// Historical uncertainty is never changed into an assertion of non-commit.
    uncertain: bool,
    /// A matching receipt may settle the current uncertainty while keeping its history.
    unresolved: bool,
}

/// Authenticated-mount-owned write state survives route unmount; it holds no request payload.
#[derive(Clone, Copy)]
pub(crate) struct PluginActions {
    pub busy: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub failed: RwSignal<bool>,
    pub unknown: RwSignal<bool>,
    pub target: RwSignal<Option<String>>,
    skill_serial: RwSignal<u64>,
    skill_current: RwSignal<Option<SkillCasCurrent>>,
    skill_unknown: RwSignal<Option<SkillBinding>>,
    skill_holds: RwSignal<std::collections::BTreeMap<SkillBinding, SkillCasHold>>,
    #[cfg(target_arch = "wasm32")]
    focus: RwSignal<Option<(String, String)>>,
}

impl PluginActions {
    pub fn new() -> Self {
        Self {
            busy: RwSignal::new(false),
            revision: RwSignal::new(0),
            failed: RwSignal::new(false),
            unknown: RwSignal::new(false),
            target: RwSignal::new(None),
            skill_serial: RwSignal::new(0),
            skill_current: RwSignal::new(None),
            skill_unknown: RwSignal::new(None),
            skill_holds: RwSignal::new(std::collections::BTreeMap::new()),
            #[cfg(target_arch = "wasm32")]
            focus: RwSignal::new(None),
        }
    }

    pub(crate) fn skill_paused(self, binding: &SkillBinding) -> bool {
        self.skill_holds
            .try_get_untracked()
            .is_none_or(|holds| holds.get(binding).is_some_and(|hold| hold.paused))
    }

    pub(crate) fn skill_hold(self, binding: &SkillBinding) -> Option<(Phase, bool)> {
        self.skill_holds
            .try_get_untracked()?
            .get(binding)
            .filter(|hold| hold.paused)
            .map(|hold| (hold.phase.unwrap_or(Phase::Error), hold.unresolved))
    }

    pub(crate) fn hold_skill(self, binding: &SkillBinding, phase: Phase) {
        self.skill_holds.try_update(|holds| {
            if holds.contains_key(binding) || holds.len() < 512 {
                let hold = holds.entry(binding.clone()).or_default();
                hold.paused = true;
                hold.phase = Some(phase);
            }
        });
    }

    /// Only a consumer-confirmed Load with no uncertain/live effect may clear a local pause.
    /// This never clears a generic or exact-skill Unknown barrier.
    pub(crate) fn loaded_skill(self, binding: &SkillBinding) {
        if self.skill_current.try_get_untracked().flatten().is_some()
            || self.skill_unknown.try_get_untracked().flatten().is_some()
            || self.busy.try_get_untracked() != Some(false)
        {
            return;
        }
        self.skill_holds.try_update(|holds| {
            if let Some(hold) = holds.get_mut(binding)
                && !hold.unresolved
            {
                hold.paused = false;
                hold.phase = None;
            }
        });
    }

    /// A recovery admission is used only after an explicit, fresh authorized same-object read.
    /// It cannot traverse a generic plugin Unknown or another object's lock.
    pub(crate) fn begin_skill(self, binding: SkillBinding, explicit: bool) -> Option<u64> {
        if self.skill_current.try_get_untracked()?.is_some() {
            return None;
        }
        let busy = self.busy.try_get_untracked()?;
        if busy
            && !(explicit
                && self.unknown.try_get_untracked()?
                && self.skill_unknown.try_get_untracked()? == Some(binding.clone()))
        {
            return None;
        }
        if !explicit && self.skill_paused(&binding) {
            return None;
        }
        let holds = self.skill_holds.try_get_untracked()?;
        if holds.len() >= 512 && !holds.contains_key(&binding) {
            return None;
        }
        let serial = self.skill_serial.try_get_untracked()?.checked_add(1)?;
        self.skill_serial.try_set(serial);
        self.skill_current.try_set(Some(SkillCasCurrent {
            binding: binding.clone(),
            serial,
            timed_out: false,
            explicit,
        }));
        self.busy.try_set(true);
        self.failed.try_set(false);
        self.target.try_set(Some(format!("skill:{}", binding.slug)));
        Some(serial)
    }

    pub(crate) fn timeout_skill(self, binding: &SkillBinding, serial: u64) {
        let Some(Some(mut current)) = self.skill_current.try_get_untracked() else {
            return;
        };
        if current.binding != *binding || current.serial != serial {
            return;
        }
        current.timed_out = true;
        self.skill_current.try_set(Some(current));
        self.skill_holds.try_update(|holds| {
            let hold = holds.entry(binding.clone()).or_default();
            hold.paused = true;
            hold.phase = Some(Phase::Error);
            hold.uncertain = true;
            hold.unresolved = true;
        });
        self.skill_unknown.try_set(Some(binding.clone()));
        self.failed.try_set(true);
        self.unknown.try_set(true);
        // The live future retains the one physical slot until it really finishes.
        self.busy.try_set(true);
    }

    pub(crate) fn finish_skill(
        self,
        binding: &SkillBinding,
        serial: u64,
        acknowledged: bool,
        unknown: bool,
        conflict: bool,
    ) -> bool {
        let Some(Some(current)) = self.skill_current.try_get_untracked() else {
            return false;
        };
        if current.binding != *binding || current.serial != serial {
            return false;
        }
        self.skill_current.try_set(None);
        let prior_hold = self
            .skill_holds
            .try_get_untracked()
            .and_then(|holds| holds.get(binding).copied())
            .unwrap_or_default();
        let prior_uncertain = prior_hold.uncertain;
        let prior_unknown =
            self.skill_unknown.try_get_untracked().flatten().as_ref() == Some(binding);
        self.skill_holds.try_update(|holds| {
            if acknowledged && !current.timed_out && !prior_hold.paused && !prior_uncertain {
                holds.remove(binding);
            } else {
                let hold = holds.entry(binding.clone()).or_default();
                hold.paused = if acknowledged {
                    current.timed_out || (prior_hold.paused && !current.explicit)
                } else {
                    true
                };
                hold.phase = hold.paused.then_some(
                    if conflict || (acknowledged && prior_hold.phase == Some(Phase::Conflict)) {
                        Phase::Conflict
                    } else {
                        Phase::Error
                    },
                );
                hold.uncertain |= unknown || current.timed_out;
                hold.unresolved = !acknowledged && (unknown || prior_hold.unresolved);
            }
        });
        // A closed409 settles only its own attempt. An older unknown remains unknown.
        let keep_unknown = !acknowledged && (unknown || prior_unknown);
        self.skill_unknown
            .try_set(keep_unknown.then(|| binding.clone()));
        self.busy.try_set(keep_unknown);
        self.unknown.try_set(keep_unknown);
        self.failed.try_set(!acknowledged || current.timed_out);
        if acknowledged {
            self.revision
                .try_update(|revision| *revision = revision.saturating_add(1));
        }
        true
    }

    pub fn launch(
        self,
        target: String,
        work: impl std::future::Future<Output = Result<(), ApiError>> + 'static,
        finished: impl FnOnce(bool) + 'static,
    ) {
        if self.busy.get_untracked() {
            return;
        }
        #[cfg(target_arch = "wasm32")]
        self.focus.set(capture_focus());
        self.busy.set(true);
        self.failed.set(false);
        self.unknown.set(false);
        self.target.set(Some(target));
        // A write is not a mount-scoped read: dropping the page must not pretend the submitted
        // operation was cancelled. Completion only updates app-owned state and guarded UI signals.
        leptos::task::spawn_local(async move {
            let result = work.await;
            self.complete(result, finished);
        });
    }

    fn complete(self, result: Result<(), ApiError>, finished: impl FnOnce(bool)) {
        if self.busy.try_get_untracked().is_none() {
            return;
        }
        let unknown = result.is_err_and(plugin_write_unknown);
        self.failed.try_set(result.is_err());
        self.unknown.try_set(unknown);
        // No exact effect readback exists here. A list refresh cannot prove non-commit.
        self.busy.try_set(unknown);
        finished(result.is_ok());
        if result.is_ok() {
            self.revision
                .try_update(|revision| *revision = revision.saturating_add(1));
        }
    }

    pub fn return_to(self, id: &str) {
        #[cfg(target_arch = "wasm32")]
        if let Some(window) = web_sys::window()
            && let Ok(path) = window.location().pathname()
        {
            self.focus.set(Some((path, id.to_owned())));
            if !self.busy.get_untracked() {
                self.restore_focus();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = id;
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn restore_focus(self) {
        let saved = self.focus.get_untracked();
        self.focus.set(None);
        if let Some((path, id)) = saved {
            use wasm_bindgen::JsCast;
            leptos::task::spawn_local(async move {
                leptos::task::tick().await;
                if self.focus.try_get_untracked().is_none() {
                    return;
                }
                let Some(window) = web_sys::window() else {
                    return;
                };
                if window.location().pathname().ok().as_deref() != Some(&path) {
                    return;
                }
                let Some(document) = window.document() else {
                    return;
                };
                // Do not steal focus if the person moved to a different surviving control.
                if document.active_element().is_some_and(|active| {
                    active.tag_name() != "BODY"
                        && active.id() != id
                        && active.closest("[hidden]").ok().flatten().is_none()
                }) {
                    return;
                }
                let target = document
                    .get_element_by_id(&id)
                    .filter(|element| {
                        !element.has_attribute("disabled")
                            && element.closest("[hidden]").ok().flatten().is_none()
                    })
                    .or_else(|| document.query_selector("main h1").ok().flatten());
                if let Some(target) =
                    target.and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    if target.tag_name() == "H1" {
                        target.set_tab_index(-1);
                    }
                    let _ = target.focus();
                }
            });
        }
    }
}

fn plugin_write_unknown(error: ApiError) -> bool {
    !matches!(
        error,
        ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound | ApiError::Conflict
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_or_lost_ack_never_unlocks_an_effect() {
        for error in [
            ApiError::Network,
            ApiError::ReconciliationRequired,
            ApiError::InvalidResponse,
            ApiError::Server,
            ApiError::Unavailable,
        ] {
            assert!(plugin_write_unknown(error));
        }
        for error in [
            ApiError::Unauthorized,
            ApiError::Forbidden,
            ApiError::NotFound,
            ApiError::Conflict,
        ] {
            assert!(!plugin_write_unknown(error));
        }
    }
    #[test]
    fn late_plugin_completion_does_not_enter_the_next_authenticated_mount() {
        for result in [Ok(()), Err(ApiError::ReconciliationRequired)] {
            let old_owner = Owner::new();
            let old = old_owner.with(PluginActions::new);
            old.busy.set(true);
            old_owner.cleanup();
            Owner::new().with(|| {
                let new = PluginActions::new();
                let invoked = std::cell::Cell::new(false);
                old.complete(result, |_| invoked.set(true));
                assert!(!invoked.get());
                assert!(!new.busy.get_untracked());
                assert!(!new.unknown.get_untracked());
                assert_eq!(new.revision.get_untracked(), 0);
            });
        }
    }
    #[test]
    fn refresh_cannot_release_unknown_and_only_acknowledgements_advance_revision() {
        Owner::new().with(|| {
            let actions = PluginActions::new();
            actions.complete(Err(ApiError::ReconciliationRequired), |_| {});
            assert!(actions.busy.get_untracked());
            assert!(actions.unknown.get_untracked());
            assert_eq!(actions.revision.get_untracked(), 0);
            // Page reload has no reference to the latch. No new dispatch can be admitted.
            actions.launch("blocked".into(), async { Ok(()) }, |_| {
                panic!("must remain blocked")
            });
            assert!(actions.busy.get_untracked());
            let acknowledged = PluginActions::new();
            acknowledged.complete(Ok(()), |_| {});
            assert!(!acknowledged.busy.get_untracked());
            assert_eq!(acknowledged.revision.get_untracked(), 1);
        });
    }

    #[test]
    fn skill_cas_recovery_is_exact_and_closed_conflict_keeps_prior_unknown() {
        Owner::new().with(|| {
            let actions = PluginActions::new();
            let binding = SkillBinding {
                id: "row-1".into(),
                slug: "review".into(),
                owner: Some("actor".into()),
            };
            let mut another = binding.clone();
            another.id = "row-2".into();
            let first = actions.begin_skill(binding.clone(), false).unwrap();
            actions.timeout_skill(&binding, first);
            assert!(
                actions.begin_skill(binding.clone(), true).is_none(),
                "timeout does not end the physical slot"
            );
            assert!(actions.finish_skill(&binding, first, false, true, false));
            assert!(actions.begin_skill(binding.clone(), false).is_none());
            assert!(actions.begin_skill(another.clone(), true).is_none());
            let retry = actions.begin_skill(binding.clone(), true).unwrap();
            assert!(
                !actions.finish_skill(&binding, first, true, false, false),
                "old serial cannot release retry"
            );
            assert!(actions.finish_skill(&binding, retry, false, false, true));
            assert!(actions.busy.get_untracked());
            assert!(actions.unknown.get_untracked());
            assert_eq!(actions.skill_hold(&binding), Some((Phase::Conflict, true)));
            actions.loaded_skill(&binding);
            assert!(
                actions.busy.get_untracked(),
                "ordinary read/load does not clear historical unknown"
            );
            let reapply = actions.begin_skill(binding.clone(), true).unwrap();
            assert!(actions.finish_skill(&binding, reapply, true, false, false));
            assert!(!actions.busy.get_untracked());
            assert!(!actions.skill_paused(&binding));
            assert!(
                actions.skill_holds.get_untracked()[&binding].uncertain,
                "history is not relabelled noncommit"
            );
            // Generic operations have no typed skill identity and cannot grant a recovery admission.
            let generic = PluginActions::new();
            generic.complete(Err(ApiError::ReconciliationRequired), |_| {});
            assert!(generic.begin_skill(binding, true).is_none());
        });
    }

    #[test]
    fn late_skill_ack_keeps_timeout_pause_and_disposed_auth_owner_cannot_touch_next_mount() {
        let owner = Owner::new();
        let old = owner.with(PluginActions::new);
        let binding = SkillBinding {
            id: "row".into(),
            slug: "review".into(),
            owner: None,
        };
        let serial = owner.with(|| old.begin_skill(binding.clone(), false).unwrap());
        owner.with(|| {
            old.timeout_skill(&binding, serial);
            old.finish_skill(&binding, serial, true, false, false);
            assert_eq!(old.skill_hold(&binding), Some((Phase::Error, false)));
            old.loaded_skill(&binding);
            assert!(
                !old.skill_paused(&binding),
                "confirmed fresh Load can resume after this same attempt's exact late receipt"
            );
        });
        let next = owner.with(|| old.begin_skill(binding.clone(), false).unwrap());
        owner.cleanup();
        Owner::new().with(|| {
            let fresh = PluginActions::new();
            assert!(!old.finish_skill(&binding, next, true, false, false));
            assert!(!fresh.busy.get_untracked());
            assert_eq!(fresh.revision.get_untracked(), 0);
        });
    }
}

#[cfg(target_arch = "wasm32")]
fn capture_focus() -> Option<(String, String)> {
    let window = web_sys::window()?;
    let element = window.document()?.active_element()?;
    Some((window.location().pathname().ok()?, element.id()))
}

#[derive(Clone)]
pub struct PluginData {
    pub page: McpAdminPage,
    pub connections: McpConnections,
    pub agents: Vec<AgentProfile>,
}

#[derive(Clone, Copy)]
pub struct PluginPageState {
    #[cfg(target_arch = "wasm32")]
    owner: StoredValue<Option<Owner>>,
    pub data: RwSignal<Option<PluginData>>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<bool>,
    pub serial: RwSignal<u64>,
}

impl PluginPageState {
    pub fn new() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            owner: StoredValue::new(Owner::current()),
            data: RwSignal::new(None),
            loading: RwSignal::new(true),
            error: RwSignal::new(false),
            serial: RwSignal::new(0),
        }
    }

    pub fn reload(self) {
        self.serial
            .update(|serial| *serial = serial.saturating_add(1));
        let serial = self.serial.get_untracked();
        self.loading.set(true);
        self.error.set(false);
        self.data.set(None);
        #[cfg(target_arch = "wasm32")]
        let actions = expect_context::<PluginActions>();
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = self.owner.try_get_value().flatten() {
            owner.with(|| {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result = load().await;
                    if self.serial.try_get_untracked() != Some(serial) {
                        return;
                    }
                    match result {
                        Ok(data) => {
                            self.data.set(Some(data));
                        }
                        Err(_) => {
                            self.error.set(true);
                        }
                    }
                    self.loading.set(false);
                    if !actions.busy.get_untracked() {
                        actions.restore_focus();
                    }
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = serial;
            self.error.set(true);
            self.loading.set(false);
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn load() -> Result<PluginData, ApiError> {
    crate::api::require_admin_status().await?;
    let page = crate::api::plugins::load_page().await?;
    let connections = crate::api::load_mcp_connections().await?;
    let mut agents = crate::api::list_agents(false).await?;
    agents.extend(crate::api::list_agents(true).await?);
    agents.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if agents.len() > 4096 || agents.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(PluginData {
        page,
        connections,
        agents,
    })
}
