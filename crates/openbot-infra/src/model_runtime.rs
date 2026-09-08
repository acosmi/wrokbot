//! Explicit custom run acceptance. Source locks never grant later credential access.

use openbot_application::model_connections::normalize_model_configuration;
use openbot_application::{BeginThreadRunRequest, ThreadDirectoryError as Error};
use openbot_contracts::{command::ThreadRunAnchor, model_connections::CustomModelProtocol};
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(crate) struct SelectionSnapshot {
    connection_id: Uuid,
    connection_revision: i64,
    secret_id: Uuid,
    protocol: CustomModelProtocol,
    endpoint: String,
    model: String,
}

fn corrupt() -> Error {
    Error::Corrupt {
        field: "model_selection",
    }
}
fn value<T: for<'a> tokio_postgres::types::FromSql<'a>>(row: &Row, name: &str) -> Result<T, Error> {
    row.try_get(name).map_err(|_| corrupt())
}

pub(crate) async fn validate_actor(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let Some(selection) = &request.command.model_selection else {
        return Ok(());
    };
    if !selection.is_valid() {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    let row = tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) FOR SHARE OF u",
        &[&request.actor.as_str(), &generation]).await.map_err(|_| Error::Unavailable)?;
    row.map(|_| ()).ok_or(Error::NotVisible)
}

/// Validate the new target before creating a thread; a visible remote target is a bad selection.
pub(crate) async fn validate_target(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let channel = match &request.command.anchor {
        ThreadRunAnchor::DirectBot => None,
        ThreadRunAnchor::Channel { channel_id } => Some(channel_id.as_str()),
    };
    let row = tx
        .query_opt(
            "SELECT a.type::text AS agent_type FROM public.agents a
        JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE a.id=$1 AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3)
          AND (p.visibility='public' OR p.owner_user_id=$2 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$2 AND ur.role='admin'))
          AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM public.channels c
            JOIN public.channel_memberships cm ON cm.channel_id=c.id AND cm.user_id=$2
            JOIN public.channel_agents ca ON ca.channel_id=c.id AND ca.agent_id=a.id
            LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
            WHERE c.id=$4 AND (c.package_id IS NULL OR cp.tenant_id=$3)))",
            &[
                &request.command.bot_id.as_str(),
                &request.actor.as_str(),
                &request.tenant.as_str(),
                &channel,
            ],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)?;
    if value::<String>(&row, "agent_type")? != "built_in" {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    Ok(())
}

/// Historical replay requires current thread visibility but does not reselect a source object.
pub(crate) async fn validate_thread(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let visible: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM public.threads t
        WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.status<>'deleted'
        AND ((t.anchor_kind='direct_bot' AND EXISTS(SELECT 1 FROM public.thread_memberships tm
          WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) OR (t.anchor_kind='channel' AND EXISTS(
          SELECT 1 FROM public.channels c JOIN public.channel_memberships cm ON cm.channel_id=c.id
          LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
          WHERE c.id=t.anchor_id AND cm.user_id=$4 AND (c.package_id IS NULL OR cp.tenant_id=$3))))) AS visible",
        &[&request.command.thread_id.as_str(), &request.deployment.as_str(), &request.tenant.as_str(), &request.actor.as_str()])
        .await.map_err(|_| Error::Unavailable)?.try_get("visible").map_err(|_| corrupt())?;
    if !visible {
        return Err(Error::NotVisible);
    }
    Ok(())
}

/// Lock order after user/thread/lease/skills: connection, then its current active secret.
pub(crate) async fn resolve(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<Option<SelectionSnapshot>, Error> {
    let Some(selection) = &request.command.model_selection else {
        return Ok(None);
    };
    let id = Uuid::parse_str(&selection.connection_id).map_err(|_| Error::InvalidInput {
        field: "model_selection",
    })?;
    // Target, current membership, source ownership and source configuration share this SQL snapshot.
    let row = tx.query_opt("SELECT c.id,c.revision,c.current_secret_id,c.name,c.protocol,c.endpoint,c.model
        FROM public.model_connections c
        WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4
          AND c.deleted_at IS NULL AND c.enabled
          AND EXISTS(SELECT 1 FROM public.threads t JOIN public.agents a ON a.id=$6
            JOIN public.agent_profiles p ON p.agent_id=a.id
            LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
            WHERE t.thread_id=$5 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.status='active'
              AND a.type='built_in' AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3)
              AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(
                SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))
              AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(
                SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4))
                OR (t.anchor_kind='channel' AND EXISTS(SELECT 1 FROM public.channels ch
                  JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4
                  JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
                  LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
                  WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$3)))))
        FOR SHARE OF c", &[&id,&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str(),
            &request.command.thread_id.as_str(),&request.command.bot_id.as_str()])
        .await.map_err(|_| Error::Unavailable)?.ok_or(Error::NotVisible)?;
    let revision = value::<i64>(&row, "revision")?;
    if revision != selection.expected_revision {
        return Err(Error::RequestConflict);
    }
    let secret_id: Uuid = value(&row, "current_secret_id")?;
    tx.query_opt(
        "SELECT s.id FROM public.model_connection_secrets s
        WHERE s.id=$1 AND s.connection_id=$2 AND s.deployment_id=$3 AND s.tenant_id=$4
          AND s.owner_user_id=$5 AND s.retired_at IS NULL FOR SHARE OF s",
        &[
            &secret_id,
            &id,
            &request.deployment.as_str(),
            &request.tenant.as_str(),
            &request.actor.as_str(),
        ],
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .ok_or_else(corrupt)?;
    let protocol = match value::<String>(&row, "protocol")?.as_str() {
        "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
        "openai_responses" => CustomModelProtocol::OpenaiResponses,
        "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
        _ => return Err(corrupt()),
    };
    let endpoint: String = value(&row, "endpoint")?;
    let normalized = normalize_model_configuration(
        &value::<String>(&row, "name")?,
        protocol,
        &endpoint,
        &value::<String>(&row, "model")?,
        true,
    )
    .map_err(|_| corrupt())?;
    if normalized.endpoint != endpoint {
        return Err(corrupt());
    }
    Ok(Some(SelectionSnapshot {
        connection_id: id,
        connection_revision: revision,
        secret_id,
        protocol,
        endpoint,
        model: normalized.model,
    }))
}

pub(crate) async fn insert(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
    snapshot: &SelectionSnapshot,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    let affected = tx.execute("INSERT INTO public.run_model_selections(run_id,deployment_id,tenant_id,owner_user_id,
        auth_generation,connection_id,connection_revision,secret_id,protocol,endpoint,model,created_at)
        SELECT r.run_id,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 FROM public.runs r
        JOIN public.threads t ON t.thread_id=r.thread_id WHERE r.run_id=$1 AND r.actor_id=$4
          AND t.deployment_id=$2 AND t.tenant_id=$3 AND r.thread_id=$13 AND r.bot_id=$14",
        &[&request.command.run_id.as_str(),&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str(),
          &generation,&snapshot.connection_id,&snapshot.connection_revision,&snapshot.secret_id,
          &snapshot.protocol.as_str(),&snapshot.endpoint,&snapshot.model,&now,
          &request.command.thread_id.as_str(),&request.command.bot_id.as_str()])
        .await.map_err(|_| Error::Unavailable)?;
    if affected != 1 {
        return Err(corrupt());
    }
    Ok(())
}

/// Current source material stays inside Infra. Ciphertext is never projected into a request.
pub(crate) struct LoadedSelection {
    pub(crate) binding: openbot_application::RunModelBinding,
    pub(crate) has_cost_cap: bool,
    pub(crate) encrypted_value: zeroize::Zeroizing<String>,
}

/// Read-only context validation takes no authority row locks and cannot authorize a send.
/// Each read ends before the next one; the final source statement repeats current actor predicates.
pub(crate) async fn load_selection_for_context(
    client: &tokio_postgres::Client,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<Option<openbot_application::RunModelBinding>, openbot_application::AgentContextError> {
    load_selection(
        client,
        deployment,
        tenant,
        lease,
        SelectionPurpose::ContextCheck,
    )
    .await
    .map(|value| value.map(|loaded| loaded.binding))
}

/// A real start owns a guarded transaction and takes user → connection → current secret SHARE.
/// Both immutable intent and snapshot must exist; neither missing half means a legacy route.
pub(crate) async fn load_current_selection(
    tx: &Transaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<Option<LoadedSelection>, openbot_application::AgentContextError> {
    load_selection(
        tx,
        deployment,
        tenant,
        lease,
        SelectionPurpose::AuthorizedStart,
    )
    .await
}

#[derive(Clone, Copy)]
enum SelectionPurpose {
    ContextCheck,
    AuthorizedStart,
}
impl SelectionPurpose {
    fn statement(self, query: &'static str, lock: &'static str) -> std::borrow::Cow<'static, str> {
        match self {
            Self::ContextCheck => std::borrow::Cow::Borrowed(query),
            Self::AuthorizedStart => std::borrow::Cow::Owned(format!("{query}{lock}")),
        }
    }
}

async fn load_selection<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
    purpose: SelectionPurpose,
) -> Result<Option<LoadedSelection>, openbot_application::AgentContextError> {
    use openbot_application::AgentContextError as ContextError;
    use openbot_contracts::model_connections::RunModelSelection;
    let bad = || ContextError::Corrupt {
        field: "model_selection",
    };
    let initial = tx.query_opt("SELECT s.*,
        coalesce(input.content ? 'modelSelection',false) AS has_intent,
        input.content->'modelSelection' AS intent,
        input.run_id AS input_run_id,input.thread_id AS input_thread_id,input.actor_id AS input_actor_id,
        input.role AS input_role
        FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
        LEFT JOIN public.messages input ON input.message_id=r.run_id||':input'
        LEFT JOIN public.run_model_selections s ON s.run_id=r.run_id
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4
          AND r.fencing_token=$5 AND r.status='running' AND t.deployment_id=$6 AND t.tenant_id=$7
          AND t.status='active'",
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str()])
        .await.map_err(|_| ContextError::Unavailable)?.ok_or(ContextError::Stale)?;
    // Detect explicit intent by exact input identity only. Corrupt metadata must never hide
    // the marker and turn a missing snapshot into a legacy route.
    let has_intent: bool = initial.try_get("has_intent").map_err(|_| bad())?;
    let snapshot_id: Option<String> = initial.try_get("run_id").map_err(|_| bad())?;
    if !has_intent && snapshot_id.is_none() {
        return Ok(None);
    }
    if !has_intent
        || snapshot_id.is_none()
        || initial
            .try_get::<_, Option<String>>("input_role")
            .map_err(|_| bad())?
            .as_deref()
            != Some("user")
    {
        return Err(bad());
    }
    let intent: serde_json::Value = initial.try_get("intent").map_err(|_| bad())?;
    let selection: RunModelSelection = serde_json::from_value(intent.clone()).map_err(|_| bad())?;
    let stored =
        crate::db::tables::run_model_selections::Row::try_from(&initial).map_err(|_| bad())?;
    let generation = u64::try_from(stored.auth_generation).map_err(|_| bad())?;
    if stored.run_id != lease.run_id().as_str()
        || stored.deployment_id != deployment.as_str()
        || stored.tenant_id != tenant.as_str()
        || stored.owner_user_id != lease.actor_id().as_str()
        || Uuid::parse_str(&selection.connection_id).map_err(|_| bad())? != stored.connection_id
        || selection.expected_revision != stored.connection_revision
        || initial
            .try_get::<_, Option<String>>("input_run_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.run_id().as_str())
        || initial
            .try_get::<_, Option<String>>("input_thread_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.thread_id().as_str())
        || initial
            .try_get::<_, Option<String>>("input_actor_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.actor_id().as_str())
    {
        return Err(bad());
    }
    tx.query_opt(purpose.statement("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))", " FOR SHARE OF u").as_ref(),
        &[&lease.actor_id().as_str(),&stored.auth_generation]).await.map_err(|_| ContextError::Unavailable)?
        .ok_or(ContextError::Stale)?;
    let current = tx.query_opt(purpose.statement("SELECT c.name,c.protocol,c.endpoint,c.model,
        (r.budget_cost_currency IS NOT NULL OR r.budget_max_cost_micro_units IS NOT NULL) AS has_cost_cap
        FROM public.model_connections c
        JOIN public.run_model_selections s ON s.connection_id=c.id AND s.run_id=$1
        JOIN public.runs r ON r.run_id=s.run_id JOIN public.threads t ON t.thread_id=r.thread_id
        JOIN public.messages input ON input.message_id=r.run_id||':input'
        JOIN public.agents a ON a.id=r.bot_id JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 AND r.fencing_token=$5
          AND r.status='running' AND t.deployment_id=$6 AND t.tenant_id=$7 AND t.status='active'
          AND EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4 AND coalesce(u.auth_generation,0)=$8
            AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
            AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)))
          AND EXISTS(SELECT 1 FROM public.thread_leases l WHERE l.thread_id=t.thread_id
            AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp())
          AND input.role='user' AND input.run_id=r.run_id AND input.thread_id=t.thread_id AND input.actor_id=r.actor_id
          AND input.content->'modelSelection'=$15::jsonb
          AND s.deployment_id=$6 AND s.tenant_id=$7 AND s.owner_user_id=$4 AND s.auth_generation=$8
          AND s.connection_id=$9 AND s.connection_revision=$10 AND s.secret_id=$11
          AND s.protocol=$12 AND s.endpoint=$13 AND s.model=$14 AND s.created_at=r.created_at
          AND c.deployment_id=$6 AND c.tenant_id=$7 AND c.owner_user_id=$4
          AND c.revision=s.connection_revision AND c.current_secret_id=s.secret_id
          AND c.protocol=s.protocol AND c.endpoint=s.endpoint AND c.model=s.model
          AND c.enabled AND c.deleted_at IS NULL
          AND a.type='built_in' AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$7)
          AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))
          AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(
            SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4))
            OR (t.anchor_kind='channel' AND EXISTS(SELECT 1 FROM public.channels ch
              JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4
              JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
              LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
              WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$7))))
        ", " FOR SHARE OF c").as_ref(),
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str(),&stored.auth_generation,&stored.connection_id,
          &stored.connection_revision,&stored.secret_id,&stored.protocol,&stored.endpoint,&stored.model,&intent])
        .await.map_err(|_| ContextError::Unavailable)?.ok_or(ContextError::Stale)?;
    let secret = tx
        .query_opt(
            purpose
                .statement(
                    "SELECT s.encrypted_value FROM public.model_connection_secrets s
        WHERE s.id=$1 AND s.connection_id=$2 AND s.deployment_id=$3 AND s.tenant_id=$4
          AND s.owner_user_id=$5 AND s.retired_at IS NULL",
                    " FOR SHARE OF s",
                )
                .as_ref(),
            &[
                &stored.secret_id,
                &stored.connection_id,
                &deployment.as_str(),
                &tenant.as_str(),
                &lease.actor_id().as_str(),
            ],
        )
        .await
        .map_err(|_| ContextError::Unavailable)?
        .ok_or(ContextError::Stale)?;
    let protocol = match stored.protocol.as_str() {
        "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
        "openai_responses" => CustomModelProtocol::OpenaiResponses,
        "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
        _ => return Err(bad()),
    };
    let name: String = current.try_get("name").map_err(|_| bad())?;
    let normalized =
        normalize_model_configuration(&name, protocol, &stored.endpoint, &stored.model, true)
            .map_err(|_| bad())?;
    if normalized.endpoint != stored.endpoint {
        return Err(bad());
    }
    let binding = openbot_application::RunModelBinding::from_verified_snapshot(
        lease,
        deployment.clone(),
        tenant.clone(),
        openbot_contracts::auth::AuthGeneration::new(generation),
        selection,
        stored.secret_id.to_string(),
        normalized,
    )?;
    Ok(Some(LoadedSelection {
        binding,
        has_cost_cap: current.try_get("has_cost_cap").map_err(|_| bad())?,
        encrypted_value: zeroize::Zeroizing::new(
            secret.try_get("encrypted_value").map_err(|_| bad())?,
        ),
    }))
}
