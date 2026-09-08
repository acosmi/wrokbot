//! Current-actor Agent roster and detail reads.

use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentLifecycleReceipt, AgentLifecycleState,
    AgentMutationRequest, AgentProfile, AgentVisibility, MAX_AGENT_ENDPOINT_BYTES,
    MAX_AGENT_NAME_BYTES, MAX_AGENT_ROLE_DESCRIPTION_BYTES, MAX_AGENT_TITLE_BYTES,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;

use crate::ports::{
    AgentAdministration, AgentAdministrationError, AgentAdministrationScope, AgentDirectory,
    AgentReadScope, PortError,
};

/// List visible or hidden coworkers using only authoritative actor/role scope.
pub async fn list_visible_agents(
    directory: &dyn AgentDirectory,
    auth: &AuthContext,
    hidden: bool,
) -> Result<Vec<AgentProfile>, AppError> {
    directory
        .list_visible_agents(&scope(auth), hidden)
        .await
        .map_err(PortError::into_app_error)
}

/// Read one accessible profile; missing/invisible/deleted collapse to NotVisible.
pub async fn get_visible_agent(
    directory: &dyn AgentDirectory,
    auth: &AuthContext,
    agent_id: BotId,
) -> Result<AgentProfile, AppError> {
    if agent_id.as_str().is_empty()
        || agent_id.as_str().len() > 512
        || agent_id.as_str().chars().any(char::is_control)
    {
        return Err(AppError::MalformedPayload { field: "agent_id" });
    }
    directory
        .get_visible_agent(&scope(auth), &agent_id)
        .await
        .map_err(PortError::into_app_error)?
        .ok_or(AppError::NotVisible)
}

/// Create one caller-owned managed or remote Agent after canonical form validation.
pub async fn create_agent(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    request: AgentMutationRequest,
) -> Result<AgentProfile, AppError> {
    let request = normalize_request(request)?;
    let expected = request.clone();
    let profile = administration
        .create_agent(&administration_scope(auth), request)
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    validate_mutation_profile(&profile, &expected, None, true)?;
    Ok(profile)
}

/// Update one manageable non-package Agent. Missing auth preserves the existing remote secret.
pub async fn update_agent(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    agent_id: BotId,
    request: AgentMutationRequest,
) -> Result<AgentProfile, AppError> {
    validate_agent_id(&agent_id)?;
    let request = normalize_request(request)?;
    let expected = request.clone();
    let profile = administration
        .update_agent(&administration_scope(auth), &agent_id, request)
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    validate_mutation_profile(&profile, &expected, Some(&agent_id), false)?;
    Ok(profile)
}

/// Duplicate one visible Agent into a new private caller-owned managed-slot profile.
pub async fn duplicate_agent(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    agent_id: BotId,
) -> Result<AgentProfile, AppError> {
    validate_agent_id(&agent_id)?;
    let profile = administration
        .duplicate_agent(&administration_scope(auth), &agent_id)
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    if profile.id == agent_id
        || profile.visibility != AgentVisibility::Private
        || profile.endpoint.is_some()
        || profile.has_auth
        || profile.hidden
        || profile.system_owned
        || !profile.can_manage
        || !profile.mine
    {
        return Err(AppError::DependencyUnavailable {
            dependency: "agent_administration",
        });
    }
    Ok(profile)
}

/// Hide/unhide only for the current actor.
pub async fn set_agent_hidden(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    agent_id: BotId,
    hidden: bool,
) -> Result<AgentLifecycleReceipt, AppError> {
    validate_agent_id(&agent_id)?;
    let receipt = administration
        .set_agent_hidden(&administration_scope(auth), &agent_id, hidden)
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    let expected = if hidden {
        AgentLifecycleState::Hidden
    } else {
        AgentLifecycleState::Visible
    };
    validate_receipt(&receipt, &agent_id, expected)?;
    Ok(receipt)
}

/// Soft-delete one manageable non-package Agent and retire its credentials.
pub async fn delete_agent(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    agent_id: BotId,
) -> Result<AgentLifecycleReceipt, AppError> {
    validate_agent_id(&agent_id)?;
    let receipt = administration
        .delete_agent(&administration_scope(auth), &agent_id)
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    validate_receipt(&receipt, &agent_id, AgentLifecycleState::Deleted)?;
    Ok(receipt)
}

/// Run one bounded real AG-UI connection probe through the production safe transport.
pub async fn test_agent_connection(
    administration: &dyn AgentAdministration,
    auth: &AuthContext,
    request: AgentConnectionTestRequest,
) -> Result<AgentConnectionVerdict, AppError> {
    let endpoint = normalize_endpoint(Some(request.endpoint))?
        .ok_or(AppError::MalformedPayload { field: "endpoint" })?;
    let verdict = administration
        .test_agent_connection(
            &administration_scope(auth),
            AgentConnectionTestRequest {
                endpoint,
                auth: request.auth,
            },
        )
        .await
        .map_err(AgentAdministrationError::into_app_error)?;
    if verdict.ok != verdict.reason.is_none()
        || (verdict.ok && verdict.events.is_empty())
        || (!verdict.ok && !verdict.events.is_empty())
        || verdict.events.len() > 64
        || verdict.events.iter().any(|event| {
            event.is_empty()
                || event.len() > 128
                || !event
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
        })
    {
        return Err(AppError::DependencyUnavailable {
            dependency: "agent_administration",
        });
    }
    Ok(verdict)
}

fn normalize_request(mut request: AgentMutationRequest) -> Result<AgentMutationRequest, AppError> {
    request.name = bounded_line(request.name, MAX_AGENT_NAME_BYTES, "name")?;
    request.title = bounded_line(request.title, MAX_AGENT_TITLE_BYTES, "title")?;
    request.role_description = bounded_role(request.role_description)?;
    request.endpoint = normalize_endpoint(request.endpoint)?;
    if request.auth.is_some() && request.endpoint.is_none() {
        return Err(AppError::MalformedPayload { field: "auth" });
    }
    Ok(request)
}

fn bounded_line(value: String, maximum: usize, field: &'static str) -> Result<String, AppError> {
    let value = ecmascript_trim(&value);
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(AppError::MalformedPayload { field });
    }
    Ok(value.to_owned())
}

fn bounded_role(value: String) -> Result<String, AppError> {
    let value = ecmascript_trim(&value);
    if value.is_empty()
        || value.len() > MAX_AGENT_ROLE_DESCRIPTION_BYTES
        || value.as_bytes().contains(&0)
    {
        return Err(AppError::MalformedPayload {
            field: "role_description",
        });
    }
    Ok(value.to_owned())
}

fn normalize_endpoint(endpoint: Option<String>) -> Result<Option<String>, AppError> {
    let Some(endpoint) = endpoint else {
        return Ok(None);
    };
    let endpoint = ecmascript_trim(&endpoint);
    if endpoint.is_empty() {
        return Ok(None);
    }
    if endpoint.len() > MAX_AGENT_ENDPOINT_BYTES
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.chars().any(char::is_control)
        || !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
    {
        return Err(AppError::MalformedPayload { field: "endpoint" });
    }
    Ok(Some(endpoint.to_owned()))
}

fn validate_agent_id(agent_id: &BotId) -> Result<(), AppError> {
    if agent_id.as_str().is_empty()
        || agent_id.as_str().len() > 512
        || agent_id.as_str().chars().any(char::is_control)
    {
        return Err(AppError::MalformedPayload { field: "agent_id" });
    }
    Ok(())
}

fn validate_mutation_profile(
    profile: &AgentProfile,
    request: &AgentMutationRequest,
    expected_id: Option<&BotId>,
    create: bool,
) -> Result<(), AppError> {
    if expected_id.is_some_and(|expected| &profile.id != expected)
        || profile.name != request.name
        || profile.title != request.title
        || profile.role_description != request.role_description
        || profile.visibility != request.visibility
        || profile.endpoint != request.endpoint
        || profile.system_owned
        || !profile.can_manage
        || !profile.mine
        || (create && (profile.hidden || profile.has_callback_token))
        || (create && profile.has_auth != request.auth.is_some())
        || (request.auth.is_some() && !profile.has_auth)
        || (request.endpoint.is_none() && (profile.has_auth || profile.has_callback_token))
    {
        return Err(AppError::DependencyUnavailable {
            dependency: "agent_administration",
        });
    }
    Ok(())
}

fn validate_receipt(
    receipt: &AgentLifecycleReceipt,
    agent_id: &BotId,
    state: AgentLifecycleState,
) -> Result<(), AppError> {
    if &receipt.agent_id != agent_id || receipt.state != state {
        return Err(AppError::DependencyUnavailable {
            dependency: "agent_administration",
        });
    }
    Ok(())
}

fn ecmascript_trim(value: &str) -> &str {
    value.trim_matches(|character| {
        matches!(
            character,
            '\u{0009}'
                | '\u{000A}'
                | '\u{000B}'
                | '\u{000C}'
                | '\u{000D}'
                | '\u{0020}'
                | '\u{00A0}'
                | '\u{1680}'
                | '\u{2000}'
                ..='\u{200A}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202F}'
                    | '\u{205F}'
                    | '\u{3000}'
                    | '\u{FEFF}'
        )
    })
}

fn scope(auth: &AuthContext) -> AgentReadScope {
    AgentReadScope {
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        admin: auth.has_role(Role::Admin),
    }
}

fn administration_scope(auth: &AuthContext) -> AgentAdministrationScope {
    AgentAdministrationScope {
        tenant: auth.tenant().clone(),
        actor: auth.actor().clone(),
        admin: auth.has_role(Role::Admin),
        auth_generation: auth.auth_generation(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::agent::AgentVisibility;
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    use super::*;

    struct FakeAgents {
        profile: AgentProfile,
        calls: Mutex<Vec<(AgentReadScope, Option<BotId>, bool)>>,
    }

    type AdministrationCall = (AgentAdministrationScope, &'static str, Option<BotId>, bool);

    #[derive(Default)]
    struct FakeAdministration {
        calls: Mutex<Vec<AdministrationCall>>,
    }

    #[async_trait]
    impl AgentAdministration for FakeAdministration {
        async fn create_agent(
            &self,
            scope: &AgentAdministrationScope,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push((scope.clone(), "create", None, false));
            Ok(profile_from("agent-created", request))
        }

        async fn update_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls.lock().unwrap().push((
                scope.clone(),
                "update",
                Some(agent_id.clone()),
                false,
            ));
            Ok(profile_from(agent_id.as_str(), request))
        }

        async fn duplicate_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls.lock().unwrap().push((
                scope.clone(),
                "duplicate",
                Some(agent_id.clone()),
                false,
            ));
            Ok(profile_from(
                "agent-copy",
                AgentMutationRequest {
                    name: "Copy".to_owned(),
                    title: "Copy title".to_owned(),
                    role_description: "Copy role".to_owned(),
                    visibility: AgentVisibility::Private,
                    endpoint: None,
                    auth: None,
                },
            ))
        }

        async fn set_agent_hidden(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
            hidden: bool,
        ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
            self.calls.lock().unwrap().push((
                scope.clone(),
                "hidden",
                Some(agent_id.clone()),
                hidden,
            ));
            Ok(AgentLifecycleReceipt {
                agent_id: agent_id.clone(),
                state: if hidden {
                    AgentLifecycleState::Hidden
                } else {
                    AgentLifecycleState::Visible
                },
            })
        }

        async fn delete_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
        ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
            self.calls.lock().unwrap().push((
                scope.clone(),
                "delete",
                Some(agent_id.clone()),
                false,
            ));
            Ok(AgentLifecycleReceipt {
                agent_id: agent_id.clone(),
                state: AgentLifecycleState::Deleted,
            })
        }

        async fn test_agent_connection(
            &self,
            _scope: &AgentAdministrationScope,
            _request: AgentConnectionTestRequest,
        ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
            Ok(AgentConnectionVerdict::working(vec![
                "RUN_STARTED".to_owned(),
            ]))
        }
    }

    fn profile_from(id: &str, request: AgentMutationRequest) -> AgentProfile {
        AgentProfile {
            id: BotId::new(id),
            name: request.name,
            title: request.title,
            role_description: request.role_description,
            avatar_seed: id.to_owned(),
            visibility: request.visibility,
            endpoint: request.endpoint,
            has_auth: request.auth.is_some(),
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: true,
            mine: true,
        }
    }

    #[async_trait]
    impl AgentDirectory for FakeAgents {
        async fn list_visible_agents(
            &self,
            scope: &AgentReadScope,
            hidden: bool,
        ) -> Result<Vec<AgentProfile>, PortError> {
            self.calls
                .lock()
                .unwrap()
                .push((scope.clone(), None, hidden));
            Ok(vec![self.profile.clone()])
        }

        async fn get_visible_agent(
            &self,
            scope: &AgentReadScope,
            agent_id: &BotId,
        ) -> Result<Option<AgentProfile>, PortError> {
            self.calls
                .lock()
                .unwrap()
                .push((scope.clone(), Some(agent_id.clone()), false));
            Ok((agent_id == &self.profile.id).then(|| self.profile.clone()))
        }
    }

    fn auth(admin: bool) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            if admin {
                vec![Role::Admin, Role::User]
            } else {
                vec![Role::User]
            },
            AuthGeneration::new(1),
            false,
        )
    }

    fn fake() -> FakeAgents {
        FakeAgents {
            profile: AgentProfile {
                id: BotId::new("agent-1"),
                name: "Agent".to_owned(),
                title: "Title".to_owned(),
                role_description: "Role".to_owned(),
                avatar_seed: "seed".to_owned(),
                visibility: AgentVisibility::Public,
                endpoint: None,
                has_auth: false,
                has_callback_token: false,
                hidden: false,
                system_owned: false,
                can_manage: true,
                mine: true,
            },
            calls: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn list_and_detail_inject_actor_admin_and_hidden_without_self_report() {
        let fake = fake();
        assert_eq!(
            list_visible_agents(&fake, &auth(true), true)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            get_visible_agent(&fake, &auth(false), BotId::new("agent-1"))
                .await
                .unwrap()
                .id
                .as_str(),
            "agent-1"
        );
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            [
                (
                    AgentReadScope {
                        tenant: TenantId::new("tenant"),
                        actor: ActorId::new("actor"),
                        admin: true,
                    },
                    None,
                    true,
                ),
                (
                    AgentReadScope {
                        tenant: TenantId::new("tenant"),
                        actor: ActorId::new("actor"),
                        admin: false,
                    },
                    Some(BotId::new("agent-1")),
                    false,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn malformed_or_missing_detail_never_becomes_an_empty_success() {
        let fake = fake();
        assert_eq!(
            get_visible_agent(&fake, &auth(false), BotId::new("missing")).await,
            Err(AppError::NotVisible)
        );
        let before = fake.calls.lock().unwrap().len();
        assert_eq!(
            get_visible_agent(&fake, &auth(false), BotId::new("bad\nagent")).await,
            Err(AppError::MalformedPayload { field: "agent_id" })
        );
        assert_eq!(fake.calls.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn lifecycle_normalizes_full_forms_and_injects_only_authoritative_scope() {
        let fake = FakeAdministration::default();
        let created = create_agent(
            &fake,
            &auth(true),
            AgentMutationRequest {
                name: "\u{00a0}Agent\u{00a0}".to_owned(),
                title: " Title ".to_owned(),
                role_description: " Role ".to_owned(),
                visibility: AgentVisibility::Private,
                endpoint: None,
                auth: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(created.name, "Agent");
        assert_eq!(created.title, "Title");
        assert_eq!(created.role_description, "Role");
        assert_eq!(
            set_agent_hidden(&fake, &auth(false), created.id.clone(), true)
                .await
                .unwrap()
                .state,
            AgentLifecycleState::Hidden
        );
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[0].0.tenant, TenantId::new("tenant"));
        assert_eq!(calls[0].0.actor, ActorId::new("actor"));
        assert!(calls[0].0.admin);
        assert_eq!(calls[0].0.auth_generation, AuthGeneration::new(1));
        assert!(!calls[1].0.admin);
        assert_eq!(calls[1].0.auth_generation, AuthGeneration::new(1));
        assert!(calls[1].3);
    }

    #[tokio::test]
    async fn malformed_or_secret_without_remote_endpoint_never_reaches_lifecycle_port() {
        let fake = FakeAdministration::default();
        let invalid = AgentMutationRequest {
            name: "Agent".to_owned(),
            title: "Title".to_owned(),
            role_description: "Role".to_owned(),
            visibility: AgentVisibility::Private,
            endpoint: None,
            auth: Some(
                openbot_contracts::agent::AgentAuthInput::new(
                    "Authorization".to_owned(),
                    "Bearer secret".to_owned(),
                )
                .unwrap(),
            ),
        };
        assert_eq!(
            create_agent(&fake, &auth(false), invalid).await,
            Err(AppError::MalformedPayload { field: "auth" })
        );
        assert_eq!(
            update_agent(
                &fake,
                &auth(false),
                BotId::new("bad\nagent"),
                AgentMutationRequest {
                    name: "Agent".to_owned(),
                    title: "Title".to_owned(),
                    role_description: "Role".to_owned(),
                    visibility: AgentVisibility::Private,
                    endpoint: None,
                    auth: None,
                },
            )
            .await,
            Err(AppError::MalformedPayload { field: "agent_id" })
        );
        assert!(fake.calls.lock().unwrap().is_empty());
    }
}
