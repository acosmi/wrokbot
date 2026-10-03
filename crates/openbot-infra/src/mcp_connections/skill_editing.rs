//! Editing CAS for the already-delivered skill source; grants keep separate authority.

use super::{
    ActorId, AuditEvent, AuditEventType, AuditFact, AuditIdentifier, AuditLabel, AuditPayload,
    AuthContext, IsolationLevel, McpAdminSkill, McpConnectionError, PLUGIN_ADMIN_LOCK_SEED,
    PluginMutationAcknowledged, PluginSkillMutation, PluginSkills, PostgresMcpConnections, Role,
    append_event_in_transaction, corrupt, decode_admin_skill, ensure_transaction_actor,
    next_event_coordinates, prepare_skill_mutation, query_unavailable, unavailable,
    validate_skill_slug, visible_skills,
};

const LOCKED_SKILL: &str = "SELECT id,slug,owner_user_id,title,summary,instructions,origin,
    installed_by,coalesce(revision,1)::bigint AS revision,updated_at
    FROM public.skills WHERE slug=$1 FOR UPDATE";

impl PostgresMcpConnections {
    pub(super) async fn save_skill_revision(
        &self,
        auth: &AuthContext,
        mutation: &PluginSkillMutation,
    ) -> Result<PluginSkills, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        let prepared = prepare_skill_mutation(mutation)?;
        validate_expected(mutation.expected_revision)?;
        if prepared.deployment_wide && !auth.has_role(Role::Admin) {
            return Err(McpConnectionError::NotVisible);
        }
        let mut client = self.pool.get().await.map_err(unavailable)?;
        // A waiter must see the committed winner rather than its old RR snapshot.
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        transaction
            .batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(query_unavailable)?;
        ensure_editing_actor(
            &transaction,
            auth,
            prepared.deployment_wide || auth.has_role(Role::Admin),
        )
        .await?;
        lock_slug(&transaction, &prepared.slug).await?;
        let current = transaction
            .query_opt(LOCKED_SKILL, &[&prepared.slug])
            .await
            .map_err(query_unavailable)?;
        if let Some(row) = &current {
            ensure_skill_owner(row, auth)?;
        }
        // FK owner deletion does not acquire our advisory lock. Read retirement AFTER the
        // source lock wait, in a fresh RC statement, so that its committed cascade is visible.
        if transaction
            .query_opt(
                "SELECT slug FROM public.skill_retired_slugs WHERE slug=$1",
                &[&prepared.slug],
            )
            .await
            .map_err(query_unavailable)?
            .is_some()
        {
            return Err(McpConnectionError::NotVisible);
        }
        let revision =
            if let Some(row) = current {
                let skill = decode_admin_skill(&row, Vec::new())?;
                ensure_expected(&skill, mutation.expected_revision)?;
                let next = next_revision(skill.revision)?;
                let changed = transaction
                    .execute(
                        "UPDATE public.skills SET title=$2,summary=$3,instructions=$4,
                    revision=$5,updated_at=clock_timestamp() WHERE slug=$1",
                        &[
                            &prepared.slug,
                            &prepared.title,
                            &prepared.summary,
                            &prepared.instructions,
                            &next,
                        ],
                    )
                    .await
                    .map_err(query_unavailable)?;
                if changed != 1 {
                    return Err(corrupt("skill_update"));
                }
                next
            } else {
                if mutation.expected_revision.is_some() {
                    return Err(McpConnectionError::NotVisible);
                }
                let owner = (!prepared.deployment_wide).then(|| auth.actor().as_str().to_owned());
                transaction.execute(
                "INSERT INTO public.skills(id,owner_user_id,slug,title,summary,instructions,
                    origin,installed_by,created_at,updated_at,revision)
                 VALUES($1,$2,$1,$3,$4,$5,'yours',$6,clock_timestamp(),clock_timestamp(),1)",
                &[&prepared.slug,&owner,&prepared.title,&prepared.summary,&prepared.instructions,
                  &auth.actor().as_str()],
            ).await.map_err(query_unavailable)?;
                1
            };
        append_editing_audit(
            &transaction,
            auth.actor(),
            &prepared.slug,
            "skill_saved",
            revision,
            self.checkpoint_key.expose(),
        )
        .await?;
        let skills = visible_skills(&transaction, auth, &self.tenant).await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "plugin skill save commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(PluginSkills { skills })
    }

    pub(super) async fn remove_skill_revision(
        &self,
        auth: &AuthContext,
        slug: &str,
        expected_revision: i64,
    ) -> Result<PluginMutationAcknowledged, McpConnectionError> {
        self.ensure_auth_current(auth).await?;
        validate_skill_slug(slug)?;
        validate_expected(Some(expected_revision))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        transaction
            .batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(query_unavailable)?;
        ensure_editing_actor(&transaction, auth, auth.has_role(Role::Admin)).await?;
        lock_slug(&transaction, slug).await?;
        let row = transaction
            .query_opt(LOCKED_SKILL, &[&slug])
            .await
            .map_err(query_unavailable)?
            .ok_or(McpConnectionError::NotVisible)?;
        ensure_skill_owner(&row, auth)?;
        if transaction
            .query_opt(
                "SELECT slug FROM public.skill_retired_slugs WHERE slug=$1",
                &[&slug],
            )
            .await
            .map_err(query_unavailable)?
            .is_some()
        {
            return Err(McpConnectionError::NotVisible);
        }
        let skill = decode_admin_skill(&row, Vec::new())?;
        ensure_expected(&skill, Some(expected_revision))?;
        let retired_revision = next_revision(skill.revision)?;
        transaction
            .execute(
                "DELETE FROM public.plugin_grants WHERE kind='skill' AND ref=$1",
                &[&slug],
            )
            .await
            .map_err(query_unavailable)?;
        // AFTER DELETE also covers owner FK cascades and does not invert the lock order.
        if transaction
            .execute("DELETE FROM public.skills WHERE slug=$1", &[&slug])
            .await
            .map_err(query_unavailable)?
            != 1
        {
            return Err(corrupt("skill_delete"));
        }
        append_editing_audit(
            &transaction,
            auth.actor(),
            slug,
            "skill_removed",
            retired_revision,
            self.checkpoint_key.expose(),
        )
        .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "plugin skill removal commit 结果未知");
            McpConnectionError::CommitUnknown
        })?;
        Ok(PluginMutationAcknowledged::success())
    }
}

async fn lock_slug(
    transaction: &tokio_postgres::Transaction<'_>,
    slug: &str,
) -> Result<(), McpConnectionError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,$2))",
            &[&slug, &PLUGIN_ADMIN_LOCK_SEED],
        )
        .await
        .map_err(query_unavailable)?;
    Ok(())
}

async fn ensure_editing_actor(
    transaction: &tokio_postgres::Transaction<'_>,
    auth: &AuthContext,
    require_admin: bool,
) -> Result<(), McpConnectionError> {
    // Role/deny changes are ordered through this user lock. Those subqueries must run
    // AFTER a lock wait, using a new RC statement rather than its original snapshot.
    transaction
        .query_opt(
            "SELECT id FROM public.users WHERE id=$1 FOR SHARE",
            &[&auth.actor().as_str()],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(McpConnectionError::NotVisible)?;
    ensure_transaction_actor(transaction, auth, require_admin).await
}

fn ensure_skill_owner(
    row: &tokio_postgres::Row,
    auth: &AuthContext,
) -> Result<(), McpConnectionError> {
    let owner: Option<String> = row
        .try_get("owner_user_id")
        .map_err(|_| corrupt("skill_owner"))?;
    if !auth.has_role(Role::Admin) && owner.as_deref() != Some(auth.actor().as_str()) {
        return Err(McpConnectionError::NotVisible);
    }
    Ok(())
}

fn validate_expected(expected: Option<i64>) -> Result<(), McpConnectionError> {
    if expected.is_some_and(|revision| revision <= 0) {
        return Err(McpConnectionError::InvalidInput {
            field: "expected_revision",
        });
    }
    Ok(())
}

fn next_revision(revision: i64) -> Result<i64, McpConnectionError> {
    revision
        .checked_add(1)
        .filter(|next| *next > 1)
        .ok_or_else(|| corrupt("skill_revision"))
}

fn ensure_expected(skill: &McpAdminSkill, expected: Option<i64>) -> Result<(), McpConnectionError> {
    if expected != Some(skill.revision) {
        return Err(McpConnectionError::StaleSnapshot(
            skill
                .revision_snapshot()
                .map_err(|_| corrupt("skill_snapshot"))?,
        ));
    }
    Ok(())
}

async fn append_editing_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorId,
    slug: &str,
    change: &'static str,
    revision: i64,
    key: &[u8],
) -> Result<(), McpConnectionError> {
    let payload = AuditPayload::from_facts([
        AuditFact::ConfigurationChange(AuditLabel::new(change)),
        AuditFact::SkillRevision(u64::try_from(revision).map_err(|_| corrupt("skill_revision"))?),
    ])
    .map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(query_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type: AuditEventType::parse("configuration.changed")
            .ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("skill"),
        target_id: Some(AuditIdentifier::new(slug).map_err(|_| corrupt("skill_slug"))?),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, key)
        .await
        .map(|_| ())
        .map_err(query_unavailable)
}
