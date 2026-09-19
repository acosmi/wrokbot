//! Scope-separated skill reads; mutations use app-owned PluginActions and refetch after completion.

use leptos::prelude::*;
use openbot_contracts::{agent::AgentProfile, mcp::McpAdminSkill};

#[cfg(target_arch = "wasm32")]
use crate::api::ApiError;

#[derive(Clone)]
pub struct SkillData {
    pub all: Vec<McpAdminSkill>,
    pub actor_id: String,
    pub actor_is_admin: bool,
    pub agents: Vec<AgentProfile>,
    pub agents_available: bool,
}

impl SkillData {
    pub fn scoped(&self, deployment: bool) -> Vec<McpAdminSkill> {
        self.all
            .iter()
            .filter(|skill| in_scope(skill, deployment, &self.actor_id))
            .cloned()
            .collect()
    }
    pub fn selected(&self, slug: &str, deployment: bool) -> Option<McpAdminSkill> {
        self.all
            .iter()
            .find(|skill| skill.slug == slug && in_scope(skill, deployment, &self.actor_id))
            .cloned()
    }
}

pub fn in_scope(skill: &McpAdminSkill, deployment: bool, actor_id: &str) -> bool {
    if deployment {
        skill.owner_user_id.is_none()
    } else {
        skill.owner_user_id.as_deref() == Some(actor_id)
    }
}

#[derive(Clone, Copy)]
pub struct SkillPageState {
    pub data: RwSignal<Option<SkillData>>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<bool>,
    serial: RwSignal<u64>,
}
impl SkillPageState {
    pub fn new() -> Self {
        Self {
            data: RwSignal::new(None),
            loading: RwSignal::new(true),
            error: RwSignal::new(false),
            serial: RwSignal::new(0),
        }
    }
    pub fn reload(self, deployment: bool) {
        let Some(serial) = self.serial.get_untracked().checked_add(1) else {
            self.error.set(true);
            return;
        };
        self.serial.set(serial);
        self.loading.set(true);
        self.error.set(false);
        // Keep previously validated data while refreshing a write; disable controls until it settles.
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load(deployment).await;
            if self.serial.try_get_untracked() != Some(serial) {
                return;
            }
            match result {
                Ok(data) => self.data.set(Some(data)),
                Err(_) => {
                    self.data.set(None);
                    self.error.set(true);
                }
            }
            self.loading.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (serial, deployment);
            self.loading.set(false);
            self.error.set(true);
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn load(deployment: bool) -> Result<SkillData, ApiError> {
    if deployment {
        crate::api::require_admin_status().await?;
    }
    let actor = crate::api::load_current_user().await?;
    let all = crate::api::skills::load_skills().await?;
    let agents_result = async {
        let mut agents = crate::api::list_agents(false).await?;
        agents.extend(crate::api::list_agents(true).await?);
        agents.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        if agents.len() > 4096 || agents.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ApiError::InvalidResponse);
        }
        Ok(agents)
    }
    .await;
    let agents_available = agents_result.is_ok();
    Ok(SkillData {
        all,
        actor_id: actor.id.as_str().to_owned(),
        actor_is_admin: actor.role == openbot_contracts::auth::Role::Admin,
        agents: agents_result.unwrap_or_default(),
        agents_available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_personal_view_cannot_alias_another_owners_or_deployment_skill() {
        let mut row = McpAdminSkill {
            id: "review".into(),
            slug: "review".into(),
            owner_user_id: Some("other".into()),
            title: "Review".into(),
            summary: String::new(),
            instructions: "Keep sources".into(),
            origin: "yours".into(),
            installed_by: None,
            granted_to: Vec::new(),
        };
        assert!(!in_scope(&row, false, "admin"));
        assert!(!in_scope(&row, true, "admin"));
        row.owner_user_id = Some("admin".into());
        assert!(in_scope(&row, false, "admin"));
        row.owner_user_id = None;
        assert!(in_scope(&row, true, "admin"));
        assert!(!in_scope(&row, false, "admin"));
    }
}

/// UX availability mirrors the owner/admin branch; the Server rechecks every mutation.
pub(super) const fn may_grant_to_agent(actor_is_admin: bool, agent_is_owned: bool) -> bool {
    actor_is_admin || agent_is_owned
}

#[cfg(test)]
mod grant_tests {
    #[test]
    fn visible_non_owned_agents_are_not_management_authority_for_a_member() {
        assert!(!super::may_grant_to_agent(false, false));
        assert!(super::may_grant_to_agent(false, true));
        assert!(super::may_grant_to_agent(true, false));
    }
}
