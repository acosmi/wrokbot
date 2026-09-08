//! Explicit skill instructions are snapshotted with the run, never read from renderer text.

use std::collections::BTreeMap;

use openbot_application::{BeginThreadRunRequest, ThreadDirectoryError};
use openbot_contracts::command::{BeginThreadRun, valid_selected_skill_slugs};
use openbot_contracts::mcp::MAX_SKILL_INSTRUCTIONS_BYTES;
use serde_json::{Value, json};
use tokio_postgres::Transaction;

use super::{decode, unavailable};

pub(super) struct Snapshot {
    pub(super) slug: String,
    pub(super) instructions: String,
}

pub(super) fn input_content(command: &BeginThreadRun) -> Value {
    let mut content = json!({"text": command.message});
    if !command.selected_skill_slugs.is_empty() {
        content["selectedSkillSlugs"] = json!(command.selected_skill_slugs);
    }
    if let Some(selection) = &command.model_selection {
        content["modelSelection"] = json!(selection);
    }
    content
}

pub(super) async fn validate_actor(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), ThreadDirectoryError> {
    if !valid_selected_skill_slugs(&request.command.selected_skill_slugs) {
        return Err(ThreadDirectoryError::InvalidInput {
            field: "selected_skill_slugs",
        });
    }
    if request.command.selected_skill_slugs.is_empty() {
        return Ok(());
    }
    let generation = i64::try_from(request.auth_generation.get())
        .map_err(|_| ThreadDirectoryError::NotVisible)?;
    // Same current-actor predicate as plugin administration. The user row lock serializes
    // authorization revocation with accepting the instruction snapshot.
    let actor = transaction
        .query_opt(
            "SELECT u.id FROM public.users u \
          WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 \
            AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) \
            AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) \
          FOR SHARE OF u",
            &[&request.actor.as_str(), &generation],
        )
        .await
        .map_err(|error| unavailable("验证 skill invocation actor 失败", error))?;
    actor.map(|_| ()).ok_or(ThreadDirectoryError::NotVisible)
}

pub(super) async fn resolve(
    transaction: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<Vec<Snapshot>, ThreadDirectoryError> {
    let slugs = &request.command.selected_skill_slugs;
    if slugs.is_empty() {
        return Ok(Vec::new());
    }
    // An Agent grant shares the instruction with the Agent's callers. Skill ownership controls
    // editing/granting, not invocation. Recheck Agent visibility and package tenant here and hold
    // all selected source rows until commit, so a revoke/edit cannot race snapshot acceptance.
    let rows = transaction
        .query(
            "SELECT s.slug,s.instructions FROM public.skills s \
          JOIN public.plugin_grants g ON g.kind='skill' AND g.ref=s.slug \
          JOIN public.agents a ON a.id=g.agent_id \
          JOIN public.agent_profiles p ON p.agent_id=a.id \
          LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id \
          WHERE g.agent_id=$1 AND s.slug=ANY($2) \
            AND (a.package_id IS NULL OR dp.tenant_id=$3) \
            AND p.deleted_at IS NULL \
            AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS( \
                  SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin')) \
          ORDER BY s.slug FOR SHARE OF s,g,a,p",
            &[
                &request.command.bot_id.as_str(),
                slugs,
                &request.tenant.as_str(),
                &request.actor.as_str(),
            ],
        )
        .await
        .map_err(|error| unavailable("读取 selected skill snapshot 失败", error))?;
    if rows.len() != slugs.len() {
        return Err(ThreadDirectoryError::NotVisible);
    }
    let mut snapshots = BTreeMap::new();
    for row in rows {
        let slug: String = decode(&row, "slug")?;
        let instructions: String = decode(&row, "instructions")?;
        if instructions.is_empty()
            || instructions.len() > MAX_SKILL_INSTRUCTIONS_BYTES
            || instructions.as_bytes().contains(&0)
        {
            return Err(ThreadDirectoryError::Corrupt {
                field: "skill_instructions",
            });
        }
        snapshots.insert(slug, instructions);
    }
    slugs
        .iter()
        .map(|slug| {
            snapshots
                .remove(slug)
                .map(|instructions| Snapshot {
                    slug: slug.clone(),
                    instructions,
                })
                .ok_or(ThreadDirectoryError::Corrupt {
                    field: "selected_skill_slug",
                })
        })
        .collect()
}
