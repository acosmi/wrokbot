//! Bounded framing for the existing personal/deployment skill and grant contracts.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use openbot_contracts::mcp::{
    McpAdminPage, McpAdminSkill, PluginGrantKind, PluginGrantMutation, PluginSkillMutation,
    PluginSkills,
};
use serde_json::json;

use super::{ApiError, encode_url_component};

/// Shared server limits (mcp_connections::prepare_skill_mutation), mirrored without widening.
pub(crate) fn valid_slug(slug: &str) -> bool {
    (2..=40).contains(&slug.len())
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn validate_mutation(mutation: &PluginSkillMutation) -> Result<(), ApiError> {
    if !valid_slug(&mutation.slug)
        || mutation.title.trim().is_empty()
        || mutation.title.len() > 256
        || mutation.title.chars().any(char::is_control)
        || mutation.summary.len() > 4096
        || mutation.summary.chars().any(char::is_control)
        || mutation.instructions.trim().is_empty()
        || mutation.instructions.len() > 64 * 1024
        || mutation.instructions.as_bytes().contains(&0)
    {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

fn validate_skills(skills: &[McpAdminSkill]) -> Result<(), ApiError> {
    let mut slugs = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut instruction_bytes = 0_usize;
    if skills.len() > 512 {
        return Err(ApiError::InvalidResponse);
    }
    for skill in skills {
        instruction_bytes = instruction_bytes.saturating_add(skill.instructions.len());
        if !slugs.insert(&skill.slug)
            || !ids.insert(&skill.id)
            || skill.id.is_empty()
            || skill.id.len() > 512
            || skill
                .owner_user_id
                .as_deref()
                .is_some_and(|id| id.is_empty() || id.len() > 512)
            || skill.origin.len() > 256
            || skill.origin.chars().any(char::is_control)
            || skill.granted_to.len() > 4096
            || instruction_bytes > 4 * 1024 * 1024
        {
            return Err(ApiError::InvalidResponse);
        }
        validate_mutation(&PluginSkillMutation {
            slug: skill.slug.clone(),
            title: skill.title.clone(),
            summary: skill.summary.clone(),
            instructions: skill.instructions.clone(),
            deployment_wide: skill.owner_user_id.is_none(),
        })?;
        let mut grants = std::collections::BTreeSet::new();
        for grant in &skill.granted_to {
            if grant.is_empty()
                || grant.len() > 512
                || grant.chars().any(char::is_control)
                || !grants.insert(grant)
            {
                return Err(ApiError::InvalidResponse);
            }
        }
    }
    Ok(())
}

/// Only display metadata enters composer state; instruction expansion belongs to the Server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SkillChoice {
    pub slug: String,
    pub title: String,
    pub summary: String,
}

pub(crate) async fn granted_choices(agent_id: &str) -> Result<Vec<SkillChoice>, ApiError> {
    super::bot_chat_href(agent_id)?;
    let granted: openbot_contracts::mcp::GrantedPlugins = serde_json::from_value(
        super::plugins::request(
            "GET",
            &format!("/api/plugins/for/{}", encode_url_component(agent_id)),
            None,
        )
        .await?,
    )
    .map_err(|_| ApiError::InvalidResponse)?;
    if granted.skills.len() > 512 {
        return Err(ApiError::InvalidResponse);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0_usize;
    let mut choices = Vec::new();
    for skill in granted.skills {
        total = total.saturating_add(skill.instructions.len());
        if !seen.insert(skill.slug.clone()) || total > 4 * 1024 * 1024 {
            return Err(ApiError::InvalidResponse);
        }
        validate_mutation(&PluginSkillMutation {
            slug: skill.slug.clone(),
            title: skill.title.clone(),
            summary: skill.summary.clone(),
            instructions: skill.instructions,
            deployment_wide: false,
        })?;
        choices.push(SkillChoice {
            slug: skill.slug,
            title: skill.title,
            summary: skill.summary,
        });
    }
    Ok(choices)
}

pub(crate) async fn load_skills() -> Result<Vec<McpAdminSkill>, ApiError> {
    let page: McpAdminPage =
        serde_json::from_value(super::plugins::request("GET", "/api/plugins", None).await?)
            .map_err(|_| ApiError::InvalidResponse)?;
    validate_skills(&page.skills)?;
    Ok(page.skills)
}

pub(crate) async fn save(
    mutation: PluginSkillMutation,
    expected_owner: Option<String>,
) -> Result<(), ApiError> {
    validate_mutation(&mutation)?;
    let skills: PluginSkills = serde_json::from_value(
        super::plugins::request(
            "POST",
            "/api/plugins/skills",
            Some(serde_json::to_value(&mutation).map_err(|_| ApiError::InvalidResponse)?),
        )
        .await?,
    )
    .map_err(|_| ApiError::InvalidResponse)?;
    validate_skills(&skills.skills)?;
    // A 200 response with no matching authoritative row is not a successful save.
    if !skills.skills.iter().any(|skill| {
        skill.slug == mutation.slug
            && skill.title == mutation.title
            && skill.summary == mutation.summary
            && skill.instructions == mutation.instructions
            && skill.owner_user_id == expected_owner
    }) {
        return Err(ApiError::InvalidResponse);
    }
    Ok(())
}

pub(crate) async fn remove(slug: &str) -> Result<(), ApiError> {
    if !valid_slug(slug) {
        return Err(ApiError::InvalidResponse);
    }
    let receipt = super::plugins::request(
        "DELETE",
        &format!("/api/plugins/skills/{}", encode_url_component(slug)),
        None,
    )
    .await?;
    acknowledged(receipt)
}

pub(crate) async fn set_grant(slug: &str, agent_id: &str, enabled: bool) -> Result<(), ApiError> {
    if !valid_slug(slug) || super::bot_chat_href(agent_id).is_err() {
        return Err(ApiError::InvalidResponse);
    }
    let receipt = if enabled {
        super::plugins::request(
            "POST",
            "/api/plugins/grants",
            Some(
                serde_json::to_value(PluginGrantMutation {
                    kind: PluginGrantKind::Skill,
                    reference: slug.to_owned(),
                    agent_id: agent_id.to_owned(),
                })
                .map_err(|_| ApiError::InvalidResponse)?,
            ),
        )
        .await?
    } else {
        super::plugins::request(
            "DELETE",
            &format!(
                "/api/plugins/grants?kind=skill&ref={}&agentId={}",
                encode_url_component(slug),
                encode_url_component(agent_id)
            ),
            None,
        )
        .await?
    };
    acknowledged(receipt)
}

fn acknowledged(value: serde_json::Value) -> Result<(), ApiError> {
    if value == json!({"ok":true}) {
        Ok(())
    } else {
        Err(ApiError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(slug: &str, owner: Option<&str>) -> McpAdminSkill {
        McpAdminSkill {
            id: slug.to_owned(),
            slug: slug.to_owned(),
            owner_user_id: owner.map(str::to_owned),
            title: "Daily review".to_owned(),
            summary: String::new(),
            instructions: "Keep citations.".to_owned(),
            origin: "yours".to_owned(),
            installed_by: None,
            granted_to: vec!["bot-1".to_owned()],
        }
    }

    #[test]
    fn skill_bounds_and_duplicate_names_are_rejected_before_ui_state() {
        for slug in ["a", "-skill", "skill-", "Skill", "foo/bar", "foo%2fbar"] {
            assert!(!valid_slug(slug));
        }
        assert!(valid_slug("daily-review"));
        let row = skill("daily-review", Some("actor"));
        assert!(validate_skills(std::slice::from_ref(&row)).is_ok());
        assert!(validate_skills(&[row.clone(), row.clone()]).is_err());
        let mut duplicate = row;
        duplicate.granted_to.push("bot-1".to_owned());
        assert!(validate_skills(&[duplicate]).is_err());
        assert!(acknowledged(json!({"ok":false})).is_err());
        assert!(acknowledged(json!({"ok":true,"owner":"forged"})).is_err());
    }

    #[test]
    fn skill_mutation_preserves_instruction_text_but_rejects_empty_and_nul() {
        let mut m = PluginSkillMutation {
            slug: "review".to_owned(),
            title: "Review".to_owned(),
            summary: String::new(),
            instructions: "\n先核实来源。\n".to_owned(),
            deployment_wide: false,
        };
        assert!(validate_mutation(&m).is_ok());
        assert_eq!(m.instructions, "\n先核实来源。\n");
        m.instructions = "\0".to_owned();
        assert!(validate_mutation(&m).is_err());
        m.instructions = "  \n".to_owned();
        assert!(validate_mutation(&m).is_err());
    }
}
