//! Agent 三张表的类型化 PostgreSQL repositories 与 roster/detail reader。

#[path = "../agent_lifecycle.rs"]
mod lifecycle;
pub use lifecycle::PostgresAgentAdministration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use openbot_application::{AgentDirectory, AgentReadScope, PortError};
use openbot_contracts::agent::{AgentProfile, AgentVisibility};
use openbot_contracts::ids::BotId;
use openbot_domain::agent::profile_policy::{
    AgentActor, AgentProfileFacts, can_access_agent, can_manage_agent,
};
use serde_json::Value;

use crate::repo::common::define_table_repo;

const DEPENDENCY: &str = "database";

const LIST_VISIBLE_AGENTS_SQL: &str = "\
SELECT a.id,a.name,a.type::text AS agent_type,p.title,p.role_description,p.avatar_seed,
       p.visibility::text,p.owner_user_id,a.package_id,a.configuration,
       (p.callback_token_hash IS NOT NULL) AS has_callback_token,
       (pref.hidden_at IS NOT NULL) AS hidden
FROM public.agents a
JOIN public.agent_profiles p ON p.agent_id=a.id
LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
LEFT JOIN public.agent_preferences pref
  ON pref.agent_id=a.id AND pref.user_id=$1
WHERE p.deleted_at IS NULL
  AND (a.package_id IS NULL OR dp.tenant_id=$2)
  AND ($3 OR p.visibility='public' OR p.owner_user_id=$1)
  AND (($4 AND pref.hidden_at IS NOT NULL)
    OR (NOT $4 AND pref.hidden_at IS NULL))
ORDER BY a.id";

const GET_VISIBLE_AGENT_SQL: &str = "\
SELECT a.id,a.name,a.type::text AS agent_type,p.title,p.role_description,p.avatar_seed,
       p.visibility::text,p.owner_user_id,a.package_id,a.configuration,
       (p.callback_token_hash IS NOT NULL) AS has_callback_token,
       (pref.hidden_at IS NOT NULL) AS hidden
FROM public.agents a
JOIN public.agent_profiles p ON p.agent_id=a.id
LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
LEFT JOIN public.agent_preferences pref
  ON pref.agent_id=a.id AND pref.user_id=$1
WHERE a.id=$4 AND p.deleted_at IS NULL
  AND (a.package_id IS NULL OR dp.tenant_id=$2)
  AND ($3 OR p.visibility='public' OR p.owner_user_id=$1)";

/// PostgreSQL current-user Agent roster/detail adapter.
#[derive(Clone)]
pub struct PostgresAgentDirectory {
    pool: Pool,
}

impl PostgresAgentDirectory {
    /// Construct from the host's shared current-schema pool.
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, PortError> {
        self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "agent directory pool unavailable");
            PortError::Unavailable {
                dependency: DEPENDENCY,
            }
        })
    }
}

impl core::fmt::Debug for PostgresAgentDirectory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresAgentDirectory")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AgentDirectory for PostgresAgentDirectory {
    async fn list_visible_agents(
        &self,
        scope: &AgentReadScope,
        hidden: bool,
    ) -> Result<Vec<AgentProfile>, PortError> {
        let client = self.client().await?;
        let rows = client
            .query(
                LIST_VISIBLE_AGENTS_SQL,
                &[
                    &scope.actor.as_str(),
                    &scope.tenant.as_str(),
                    &scope.admin,
                    &hidden,
                ],
            )
            .await
            .map_err(|error| unavailable("list agent profiles", error))?;
        rows.iter().map(|row| decode_profile(row, scope)).collect()
    }

    async fn get_visible_agent(
        &self,
        scope: &AgentReadScope,
        agent_id: &BotId,
    ) -> Result<Option<AgentProfile>, PortError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                GET_VISIBLE_AGENT_SQL,
                &[
                    &scope.actor.as_str(),
                    &scope.tenant.as_str(),
                    &scope.admin,
                    &agent_id.as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("get agent profile", error))?;
        row.as_ref()
            .map(|row| decode_profile(row, scope))
            .transpose()
    }
}

fn decode_profile(
    row: &tokio_postgres::Row,
    scope: &AgentReadScope,
) -> Result<AgentProfile, PortError> {
    let id: String = get(row, "id")?;
    let owner: Option<String> = get(row, "owner_user_id")?;
    let package_id: Option<uuid::Uuid> = get(row, "package_id")?;
    let configuration: Value = get(row, "configuration")?;
    let visibility = match get::<String>(row, "visibility")?.as_str() {
        "public" => AgentVisibility::Public,
        "private" => AgentVisibility::Private,
        _ => {
            return Err(PortError::Corrupt {
                dependency: DEPENDENCY,
                field: "visibility",
            });
        }
    };
    let agent_type: String = get(row, "agent_type")?;
    let (endpoint, has_auth) = match agent_type.as_str() {
        "built_in" => {
            if configuration.get("auth").is_some() || configuration.get("endpoint").is_some() {
                return Err(corrupt("agent_configuration"));
            }
            (None, false)
        }
        "remote_ag_ui" => {
            let endpoint = configuration
                .get("endpoint")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| corrupt("endpoint"))?
                .to_owned();
            let has_auth = strict_auth_reference(&configuration)?;
            (Some(endpoint), has_auth)
        }
        _ => return Err(corrupt("agent_type")),
    };
    let mine = owner.as_deref() == Some(scope.actor.as_str());
    let system_owned = package_id.is_some();
    let actor = AgentActor {
        id: scope.actor.as_str(),
        admin: scope.admin,
    };
    let facts = AgentProfileFacts {
        owner_user_id: owner.as_deref(),
        visibility,
        system_owned,
        deleted: false,
    };
    if !can_access_agent(&actor, &facts) {
        tracing::error!("agent directory SQL returned a profile denied by domain policy");
        return Err(PortError::Corrupt {
            dependency: DEPENDENCY,
            field: "agent_access",
        });
    }
    Ok(AgentProfile {
        id: BotId::new(id),
        name: get(row, "name")?,
        title: get(row, "title")?,
        role_description: get(row, "role_description")?,
        avatar_seed: get(row, "avatar_seed")?,
        visibility,
        endpoint,
        has_auth,
        has_callback_token: get(row, "has_callback_token")?,
        hidden: get(row, "hidden")?,
        system_owned,
        can_manage: can_manage_agent(&actor, &facts),
        mine,
    })
}

fn get<'a, T>(row: &'a tokio_postgres::Row, field: &'static str) -> Result<T, PortError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(field).map_err(|error| {
        tracing::error!(field, error = %error, "agent profile decode failed");
        PortError::Corrupt {
            dependency: DEPENDENCY,
            field,
        }
    })
}

fn unavailable(context: &'static str, error: tokio_postgres::Error) -> PortError {
    tracing::error!(context, error = %error, "agent directory query failed");
    PortError::Unavailable {
        dependency: DEPENDENCY,
    }
}

fn strict_auth_reference(configuration: &Value) -> Result<bool, PortError> {
    let Some(auth) = configuration.get("auth") else {
        return Ok(false);
    };
    let auth = auth.as_object().ok_or_else(|| corrupt("agent_auth"))?;
    if auth.len() != 2 || auth.get("header").and_then(Value::as_str) != Some("Authorization") {
        return Err(corrupt("agent_auth"));
    }
    let credential_id = auth
        .get("credentialId")
        .and_then(Value::as_str)
        .ok_or_else(|| corrupt("credential_id"))?;
    uuid::Uuid::parse_str(credential_id).map_err(|_| corrupt("credential_id"))?;
    Ok(true)
}

const fn corrupt(field: &'static str) -> PortError {
    PortError::Corrupt {
        dependency: DEPENDENCY,
        field,
    }
}

define_table_repo!(
    /// `agents` repository。
    AgentRepo,
    table = agents,
    order_by = "\"id\"",
    find = find_by_id(id: &str) where "\"id\" = $1"
);

define_table_repo!(
    /// `agent_profiles` repository。
    AgentProfileRepo,
    table = agent_profiles,
    order_by = "\"agent_id\"",
    find = find_by_agent_id(agent_id: &str) where "\"agent_id\" = $1"
);

define_table_repo!(
    /// `agent_preferences` repository。
    AgentPreferenceRepo,
    table = agent_preferences,
    order_by = "\"user_id\", \"agent_id\"",
    find = find_by_key(user_id: &str, agent_id: &str) where "\"user_id\" = $1 AND \"agent_id\" = $2"
);
