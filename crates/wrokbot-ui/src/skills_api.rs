//! Bounded framing for the existing personal/deployment skill and grant contracts.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use openbot_contracts::mcp::{
    McpAdminPage, McpAdminSkill, PluginGrantKind, PluginGrantMutation, PluginSkillMutation,
    PluginSkillRevisionRequest, PluginSkills,
};
use serde_json::json;

use super::{ApiError, encode_url_component};

/// Payload-free exact identity used only by the authenticated skill CAS owner.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SkillBinding {
    pub id: String,
    pub slug: String,
    pub owner: Option<String>,
}

impl SkillBinding {
    pub(crate) fn of(row: &McpAdminSkill) -> Self {
        Self {
            id: row.id.clone(),
            slug: row.slug.clone(),
            owner: row.owner_user_id.clone(),
        }
    }
}

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
        || mutation
            .expected_revision
            .is_some_and(|revision| revision <= 0)
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
            || skill.revision <= 0
            || skill.revision_snapshot().is_err()
        {
            return Err(ApiError::InvalidResponse);
        }
        validate_mutation(&PluginSkillMutation {
            slug: skill.slug.clone(),
            title: skill.title.clone(),
            summary: skill.summary.clone(),
            instructions: skill.instructions.clone(),
            deployment_wide: skill.owner_user_id.is_none(),
            expected_revision: Some(skill.revision),
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
            expected_revision: None,
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
    matching_ack(&skills.skills, &mutation, &expected_owner, None)?;
    Ok(())
}

fn matching_ack(
    skills: &[McpAdminSkill],
    mutation: &PluginSkillMutation,
    expected_owner: &Option<String>,
    existing: Option<&McpAdminSkill>,
) -> Result<McpAdminSkill, ApiError> {
    validate_skills(skills)?;
    let expected_revision = mutation
        .expected_revision
        .map_or(Some(1), |r| r.checked_add(1))
        .ok_or(ApiError::InvalidResponse)?;
    // A 200 response with no matching authoritative row is not a successful save.
    let matching = skills.iter().find(|skill| {
        skill.slug == mutation.slug
            && skill.title == mutation.title
            && skill.summary == mutation.summary
            && skill.instructions == mutation.instructions
            && &skill.owner_user_id == expected_owner
            && skill.revision == expected_revision
            && existing.is_none_or(|old| {
                skill.id == old.id
                    && skill.slug == old.slug
                    && skill.owner_user_id == old.owner_user_id
                    && skill.origin == old.origin
                    && skill.installed_by == old.installed_by
            })
    });
    matching.cloned().ok_or(ApiError::InvalidResponse)
}

/// A closed stale-snapshot receipt belongs only to this existing-object CAS attempt.
/// Generic plugin operations retain their original error and Unknown classifications.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SkillWriteError {
    Conflict(openbot_contracts::revision::RevisionSnapshot),
    Rejected(ApiError),
    Unknown(ApiError),
}

/// Save only metadata of a captured, already-authorized existing skill. Creation is explicit.
pub(crate) async fn save_existing(
    mutation: PluginSkillMutation,
    existing: McpAdminSkill,
) -> Result<McpAdminSkill, SkillWriteError> {
    validate_mutation(&mutation).map_err(SkillWriteError::Rejected)?;
    if mutation.expected_revision != Some(existing.revision)
        || mutation.slug != existing.slug
        || mutation.deployment_wide != existing.owner_user_id.is_none()
        || existing.revision <= 0
    {
        return Err(SkillWriteError::Rejected(ApiError::NotSubmitted));
    }
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api::request::Request;
        let request = Request::post("/api/plugins/skills")
            .json(&mutation)
            .map_err(|_| SkillWriteError::Rejected(ApiError::NotSubmitted))?;
        let response = Request::send(request).await.map_err(|error| match error {
            ApiError::NotSubmitted => SkillWriteError::Rejected(error),
            _ => SkillWriteError::Unknown(error),
        })?;
        if response.status() == 409 {
            let body = response
                .text()
                .await
                .map_err(|_| SkillWriteError::Unknown(ApiError::InvalidResponse))?;
            return decode_existing_reply(409, &body, &mutation, &existing);
        }
        if response.status() != 200 {
            let error = super::status_error(response.status());
            return Err(match error {
                ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound => {
                    SkillWriteError::Rejected(error)
                }
                _ => SkillWriteError::Unknown(error),
            });
        }
        let body = response
            .text()
            .await
            .map_err(|_| SkillWriteError::Unknown(ApiError::InvalidResponse))?;
        decode_existing_reply(200, &body, &mutation, &existing)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (mutation, existing);
        Err(SkillWriteError::Rejected(ApiError::Unavailable))
    }
}

fn decode_existing_reply(
    status: u16,
    body: &str,
    mutation: &PluginSkillMutation,
    existing: &McpAdminSkill,
) -> Result<McpAdminSkill, SkillWriteError> {
    // Preserve the existing Plugins 8 MiB post-read bound; this is not a preallocation cap.
    if body.len() > 8 * 1024 * 1024 {
        return Err(SkillWriteError::Unknown(ApiError::InvalidResponse));
    }
    match status {
        409 => {
            let snapshot: openbot_contracts::revision::RevisionSnapshot =
                serde_json::from_str(body)
                    .map_err(|_| SkillWriteError::Unknown(ApiError::InvalidResponse))?;
            if snapshot.current_revision() <= existing.revision {
                return Err(SkillWriteError::Unknown(ApiError::InvalidResponse));
            }
            Err(SkillWriteError::Conflict(snapshot))
        }
        200 => {
            let skills: PluginSkills = serde_json::from_str(body)
                .map_err(|_| SkillWriteError::Unknown(ApiError::InvalidResponse))?;
            matching_ack(
                &skills.skills,
                mutation,
                &existing.owner_user_id,
                Some(existing),
            )
            .map_err(SkillWriteError::Unknown)
        }
        _ => Err(SkillWriteError::Unknown(super::status_error(status))),
    }
}

/// Fresh explicit recovery read uses the real Plugins list and rechecks current scope authority.
pub(crate) async fn read_existing(existing: &McpAdminSkill) -> Result<McpAdminSkill, ApiError> {
    if existing.owner_user_id.is_none() {
        let status: openbot_contracts::people::AdminStatus = serde_json::from_value(
            super::plugins::request("GET", "/api/admin/status", None).await?,
        )
        .map_err(|_| ApiError::InvalidResponse)?;
        if status.status != openbot_contracts::people::AdminState::Ok {
            return Err(ApiError::Forbidden);
        }
    }
    let envelope: openbot_contracts::people::CurrentUserResponse =
        serde_json::from_value(super::plugins::request("GET", "/api/me", None).await?)
            .map_err(|_| ApiError::InvalidResponse)?;
    let actor = envelope.user;
    if existing
        .owner_user_id
        .as_deref()
        .is_some_and(|owner| owner != actor.id.as_str())
        || (existing.owner_user_id.is_none() && actor.role != openbot_contracts::auth::Role::Admin)
    {
        return Err(ApiError::Forbidden);
    }
    load_skills()
        .await?
        .into_iter()
        .find(|row| {
            row.id == existing.id
                && row.slug == existing.slug
                && row.owner_user_id == existing.owner_user_id
                && row.origin == existing.origin
                && row.installed_by == existing.installed_by
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn remove(slug: &str, expected_revision: i64) -> Result<(), ApiError> {
    if !valid_slug(slug) || expected_revision <= 0 {
        return Err(ApiError::InvalidResponse);
    }
    let receipt = super::plugins::request(
        "DELETE",
        &format!("/api/plugins/skills/{}", encode_url_component(slug)),
        Some(
            serde_json::to_value(PluginSkillRevisionRequest { expected_revision })
                .map_err(|_| ApiError::InvalidResponse)?,
        ),
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
            revision: 1,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
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
        for revision in [0, -1] {
            let mut invalid_revision = row.clone();
            invalid_revision.revision = revision;
            assert!(validate_skills(&[invalid_revision]).is_err());
        }
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
            expected_revision: None,
        };
        assert!(validate_mutation(&m).is_ok());
        assert_eq!(m.instructions, "\n先核实来源。\n");
        m.expected_revision = Some(0);
        assert!(validate_mutation(&m).is_err());
        m.expected_revision = Some(4);
        assert!(validate_mutation(&m).is_ok());
        m.instructions = "\0".to_owned();
        assert!(validate_mutation(&m).is_err());
        m.instructions = "  \n".to_owned();
        assert!(validate_mutation(&m).is_err());
    }

    #[test]
    fn existing_skill_ack_requires_same_identity_and_next_revision_not_merely_same_content() {
        let known = skill("review", Some("actor"));
        let mutation = PluginSkillMutation {
            slug: known.slug.clone(),
            title: "New title".into(),
            summary: known.summary.clone(),
            instructions: known.instructions.clone(),
            deployment_wide: false,
            expected_revision: Some(1),
        };
        let mut row = known.clone();
        row.title = mutation.title.clone();
        row.revision = 2;
        assert!(
            matching_ack(
                &[row.clone()],
                &mutation,
                &known.owner_user_id,
                Some(&known)
            )
            .is_ok()
        );
        for field in 0..5 {
            let mut forged = row.clone();
            match field {
                0 => forged.id = "another-row".into(),
                1 => forged.owner_user_id = None,
                2 => forged.revision = 3,
                3 => forged.origin = "another-source".into(),
                _ => forged.installed_by = Some("another-actor".into()),
            }
            assert!(
                matching_ack(&[forged], &mutation, &known.owner_user_id, Some(&known)).is_err()
            );
        }
        let receipt = serde_json::to_string(&PluginSkills {
            skills: vec![row.clone()],
        })
        .unwrap();
        assert!(matches!(
            decode_existing_reply(202, &receipt, &mutation, &known),
            Err(SkillWriteError::Unknown(_))
        ));
        for revision in [3, 4] {
            let mut newer_base = known.clone();
            newer_base.revision = 4;
            let mut newer_mutation = mutation.clone();
            newer_mutation.expected_revision = Some(newer_base.revision);
            let mut inconsistent = row.clone();
            inconsistent.revision = revision;
            let body = serde_json::to_string(&inconsistent.revision_snapshot().unwrap()).unwrap();
            assert!(
                matches!(
                    decode_existing_reply(409, &body, &newer_mutation, &newer_base),
                    Err(SkillWriteError::Unknown(_))
                ),
                "equal or regressed conflict metadata is not a no-write receipt"
            );
        }
        let snapshot = row.revision_snapshot().unwrap();
        let conflict = serde_json::to_string(&snapshot).unwrap();
        assert!(
            matches!(decode_existing_reply(409, &conflict, &mutation, &known), Err(SkillWriteError::Conflict(actual)) if actual == snapshot)
        );
        let mut extra = serde_json::to_value(snapshot).unwrap();
        extra["ok"] = json!(true);
        assert!(matches!(
            decode_existing_reply(409, &extra.to_string(), &mutation, &known),
            Err(SkillWriteError::Unknown(_))
        ));
        row.granted_to.push("other-agent".into());
        assert_eq!(
            row.revision_snapshot().unwrap(),
            snapshot,
            "grant membership is excluded from editing metadata"
        );
        let wire = serde_json::to_value(&mutation).unwrap();
        assert_eq!(wire["global"], json!(false));
        assert!(wire.get("deploymentWide").is_none());
    }
}
