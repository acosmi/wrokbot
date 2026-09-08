//! PostgreSQL/Vault/SafeDialer Agent lifecycle administration.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use deadpool_postgres::Pool;
#[cfg(test)]
use openbot_application::RemoteAguiEventStream;
use openbot_application::{
    AgentAdministration, AgentAdministrationError, AgentAdministrationScope, AgentReadScope,
    RemoteAguiAuthorization, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_contracts::agent::{
    AgentConnectionFailure, AgentConnectionTestRequest, AgentConnectionVerdict,
    AgentLifecycleReceipt, AgentLifecycleState, AgentMutationRequest, AgentProfile,
    AgentVisibility,
};
use openbot_contracts::ids::BotId;
use openbot_domain::agent::profile_policy::{
    AgentActor, AgentProfileFacts, can_access_agent, can_manage_agent,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{
    AuditEndpointOrigin, AuditFact, AuditIdentifier, AuditLabel, AuditPayload,
};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde_json::{Value, json};
use tokio_postgres::{IsolationLevel, Row, Transaction};
use url::Url;
use uuid::Uuid;

use crate::db::types::{AgentType, AgentVisibility as PgAgentVisibility};
use crate::net::safe_http::AuthorizationValue;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::vault::CredentialRecordVault;

const MAX_CONNECTION_EVENTS: usize = 64;

/// Production lifecycle adapter. Every durable mutation and its allowlisted audit event commits in
/// one row-locked transaction; credentials are v2 Vault records and never profile JSON values.
pub struct PostgresAgentAdministration {
    pool: Pool,
    vault: CredentialRecordVault,
    checkpoint_key: SecretBytes,
    probe: Arc<dyn RemoteAguiTransport>,
    managed_slot_available: bool,
}

impl PostgresAgentAdministration {
    /// Construct from already validated production dependencies.
    pub fn new(
        pool: Pool,
        vault: CredentialRecordVault,
        checkpoint_key: Vec<u8>,
        probe: Arc<dyn RemoteAguiTransport>,
        managed_slot_available: bool,
    ) -> Result<Self, AgentAdministrationError> {
        if checkpoint_key.is_empty() {
            return Err(AgentAdministrationError::Unavailable);
        }
        Ok(Self {
            pool,
            vault,
            checkpoint_key: SecretBytes::new(checkpoint_key),
            probe,
            managed_slot_available,
        })
    }

    fn managed_configuration(
        &self,
        role_description: &str,
    ) -> Result<Value, AgentAdministrationError> {
        if !self.managed_slot_available {
            return Err(AgentAdministrationError::InvalidInput { field: "endpoint" });
        }
        Ok(json!({
            "systemPrompt": role_description,
            "providerSource": "managed"
        }))
    }

    fn prepare_credential(
        &self,
        agent_id: &str,
        owner: &str,
        auth: &openbot_contracts::agent::AgentAuthInput,
    ) -> Result<PreparedCredential, AgentAdministrationError> {
        AuthorizationValue::parse(auth.expose_value())
            .map_err(|_| AgentAdministrationError::InvalidInput { field: "auth" })?;
        let id = Uuid::now_v7();
        let plaintext = SecretBytes::new(auth.expose_value().as_bytes().to_vec());
        let encrypted = self
            .vault
            .seal(
                &id,
                SecretKind::Agent,
                SecretPrincipal::Actor(openbot_contracts::ids::ActorId::new(owner)),
                SecretPrincipal::Service(ServiceId::new(agent_id)),
                &plaintext,
            )
            .map_err(|_| AgentAdministrationError::Unavailable)?;
        Ok(PreparedCredential {
            id,
            encrypted,
            configuration: json!({
                "header": "Authorization",
                "credentialId": id.to_string()
            }),
        })
    }
}

impl core::fmt::Debug for PostgresAgentAdministration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresAgentAdministration")
            .field("vault", &"[redacted]")
            .field("checkpoint_key", &"[redacted]")
            .field("managed_slot_available", &self.managed_slot_available)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AgentAdministration for PostgresAgentAdministration {
    async fn create_agent(
        &self,
        scope: &AgentAdministrationScope,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let agent_id = format!("agent_{}", Uuid::now_v7());
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        if let Some(endpoint) = request.endpoint.as_deref() {
            self.probe
                .validate_endpoint(endpoint)
                .await
                .map_err(|_| AgentAdministrationError::InvalidInput { field: "endpoint" })?;
        }
        let endpoint_audit = endpoint_audit_fact(request.endpoint.as_deref())?;
        let (agent_type, configuration, credential) = match &request.endpoint {
            Some(endpoint) => {
                let credential = request
                    .auth
                    .as_ref()
                    .map(|auth| self.prepare_credential(&agent_id, scope.actor.as_str(), auth))
                    .transpose()?;
                let configuration = remote_configuration(endpoint, credential.as_ref());
                (AgentType::RemoteAgUi, configuration, credential)
            }
            None => (
                AgentType::BuiltIn,
                self.managed_configuration(&request.role_description)?,
                None,
            ),
        };
        if let Some(credential) = &credential {
            insert_credential(&transaction, credential, &agent_id, scope.actor.as_str()).await?;
            append_credential_audit(
                &transaction,
                scope,
                scope.actor.as_str(),
                credential.id,
                AuditEventType::CREDENTIAL_CREATED,
                "agent_created",
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        transaction
            .execute(
                "INSERT INTO public.agents(id,name,type,configuration,package_id,created_at,updated_at)
                 VALUES($1,$2,$3,$4,NULL,clock_timestamp(),clock_timestamp())",
                &[&agent_id, &request.name, &agent_type, &configuration],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,
                   deleted_at,created_at,updated_at,callback_token_hash,callback_token_issued_at)
                 VALUES($1,$2,$3,$4,$1,$5::public.agent_visibility,NULL,
                        clock_timestamp(),clock_timestamp(),NULL,NULL)",
                &[
                    &agent_id,
                    &scope.actor.as_str(),
                    &request.title,
                    &request.role_description,
                    &pg_visibility(request.visibility),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        append_lifecycle_audit(
            &transaction,
            scope,
            &agent_id,
            AuditEventType::BOT_CREATED,
            endpoint_audit,
            self.checkpoint_key.expose(),
        )
        .await?;
        let read_scope = scope.read_scope();
        let profile = load_profile(&transaction, &read_scope, &agent_id, false).await?;
        commit(transaction, "agent create").await?;
        Ok(profile)
    }

    async fn update_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        lock_profile_rows(&transaction, agent_id.as_str()).await?;
        let read_scope = scope.read_scope();
        let current = load_profile(&transaction, &read_scope, agent_id.as_str(), false).await?;
        require_manageable(scope, &current)?;
        if let Some(endpoint) = request.endpoint.as_deref() {
            self.probe
                .validate_endpoint(endpoint)
                .await
                .map_err(|_| AgentAdministrationError::InvalidInput { field: "endpoint" })?;
        }
        let endpoint_audit = endpoint_audit_fact(request.endpoint.as_deref())?;
        let row = transaction
            .query_one(
                "SELECT a.type::text,a.configuration,p.owner_user_id
                   FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
                  WHERE a.id=$1 FOR UPDATE OF a,p",
                &[&agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let previous_configuration: Value = required(&row, "configuration")?;
        let owner: String =
            required_optional(&row, "owner_user_id")?.ok_or_else(|| corrupt("owner_user_id"))?;
        let previous_credential = credential_reference(&previous_configuration)?;
        let previous_credential_id = previous_credential.as_ref().map(|(id, _)| *id);
        let (agent_type, configuration, replacement) = match &request.endpoint {
            Some(endpoint) => {
                let replacement = request
                    .auth
                    .as_ref()
                    .map(|auth| self.prepare_credential(agent_id.as_str(), &owner, auth))
                    .transpose()?;
                let auth = replacement
                    .as_ref()
                    .map(|value| value.configuration.clone())
                    .or_else(|| previous_credential.as_ref().map(|(_, value)| value.clone()));
                (
                    AgentType::RemoteAgUi,
                    remote_configuration_value(endpoint, auth),
                    replacement,
                )
            }
            None => (
                AgentType::BuiltIn,
                self.managed_configuration(&request.role_description)?,
                None,
            ),
        };
        if let Some(replacement) = &replacement {
            insert_credential(&transaction, replacement, agent_id.as_str(), &owner).await?;
        }
        let keep_previous = request.endpoint.is_some() && replacement.is_none();
        if keep_previous && let Some((credential_id, _)) = previous_credential.as_ref() {
            validate_credential(&transaction, *credential_id, agent_id.as_str(), &owner).await?;
        }
        if !keep_previous && let Some((credential_id, _)) = previous_credential {
            revoke_credential(&transaction, credential_id, agent_id.as_str()).await?;
        }
        if let Some(replacement) = &replacement {
            append_credential_audit(
                &transaction,
                scope,
                &owner,
                replacement.id,
                AuditEventType::CREDENTIAL_ROTATED,
                "agent_key_replaced",
                self.checkpoint_key.expose(),
            )
            .await?;
        } else if request.endpoint.is_none()
            && let Some(previous_id) = previous_credential_id
        {
            append_credential_audit(
                &transaction,
                scope,
                &owner,
                previous_id,
                AuditEventType::CREDENTIAL_REVOKED,
                "agent_switched_to_managed",
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        transaction
            .execute(
                "UPDATE public.agents SET name=$2,type=$3,configuration=$4,
                        updated_at=clock_timestamp() WHERE id=$1",
                &[
                    &agent_id.as_str(),
                    &request.name,
                    &agent_type,
                    &configuration,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "UPDATE public.agent_profiles SET title=$2,role_description=$3,
                        visibility=$4::public.agent_visibility,updated_at=clock_timestamp(),
                        callback_token_hash=CASE WHEN $5 THEN callback_token_hash ELSE NULL END,
                        callback_token_issued_at=CASE WHEN $5 THEN callback_token_issued_at ELSE NULL END
                  WHERE agent_id=$1",
                &[
                    &agent_id.as_str(),
                    &request.title,
                    &request.role_description,
                    &pg_visibility(request.visibility),
                    &request.endpoint.is_some(),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        append_lifecycle_audit(
            &transaction,
            scope,
            agent_id.as_str(),
            AuditEventType::BOT_UPDATED,
            endpoint_audit,
            self.checkpoint_key.expose(),
        )
        .await?;
        let profile = load_profile(&transaction, &read_scope, agent_id.as_str(), false).await?;
        commit(transaction, "agent update").await?;
        Ok(profile)
    }

    async fn duplicate_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        if !self.managed_slot_available {
            return Err(AgentAdministrationError::InvalidInput { field: "endpoint" });
        }
        lock_profile_rows(&transaction, agent_id.as_str()).await?;
        let read_scope = scope.read_scope();
        let source = load_profile(&transaction, &read_scope, agent_id.as_str(), false).await?;
        let duplicate_id = format!("agent_{}", Uuid::now_v7());
        let configuration = json!({
            "systemPrompt": source.role_description,
            "providerSource": "managed"
        });
        transaction
            .execute(
                "INSERT INTO public.agents(id,name,type,configuration,package_id,created_at,updated_at)
                 VALUES($1,$2,'built_in',$3,NULL,clock_timestamp(),clock_timestamp())",
                &[&duplicate_id, &source.name, &configuration],
            )
            .await
            .map_err(query_unavailable)?;
        transaction
            .execute(
                "INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,
                   deleted_at,created_at,updated_at,callback_token_hash,callback_token_issued_at)
                 VALUES($1,$2,$3,$4,$5,'private',NULL,clock_timestamp(),clock_timestamp(),NULL,NULL)",
                &[
                    &duplicate_id,
                    &scope.actor.as_str(),
                    &source.title,
                    &source.role_description,
                    &source.avatar_seed,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        append_lifecycle_audit(
            &transaction,
            scope,
            &duplicate_id,
            AuditEventType::BOT_DUPLICATED,
            Some(AuditFact::TargetId(
                AuditIdentifier::new(agent_id.as_str().to_owned())
                    .map_err(|_| corrupt("agent_id"))?,
            )),
            self.checkpoint_key.expose(),
        )
        .await?;
        let profile = load_profile(&transaction, &read_scope, &duplicate_id, false).await?;
        commit(transaction, "agent duplicate").await?;
        Ok(profile)
    }

    async fn set_agent_hidden(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
        hidden: bool,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        lock_profile_rows(&transaction, agent_id.as_str()).await?;
        let read_scope = scope.read_scope();
        let _profile = load_profile(&transaction, &read_scope, agent_id.as_str(), false).await?;
        transaction
            .execute(
                "INSERT INTO public.agent_preferences(user_id,agent_id,hidden_at)
                 VALUES($1,$2,CASE WHEN $3 THEN clock_timestamp() ELSE NULL END)
                 ON CONFLICT(user_id,agent_id) DO UPDATE SET
                   hidden_at=CASE WHEN $3 THEN coalesce(public.agent_preferences.hidden_at,
                                                        clock_timestamp()) ELSE NULL END",
                &[&scope.actor.as_str(), &agent_id.as_str(), &hidden],
            )
            .await
            .map_err(query_unavailable)?;
        let state = if hidden {
            AgentLifecycleState::Hidden
        } else {
            AgentLifecycleState::Visible
        };
        append_lifecycle_audit(
            &transaction,
            scope,
            agent_id.as_str(),
            if hidden {
                AuditEventType::BOT_HIDDEN
            } else {
                AuditEventType::BOT_UNHIDDEN
            },
            None,
            self.checkpoint_key.expose(),
        )
        .await?;
        commit(transaction, "agent preference").await?;
        Ok(AgentLifecycleReceipt {
            agent_id: agent_id.clone(),
            state,
        })
    }

    async fn delete_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        lock_profile_rows(&transaction, agent_id.as_str()).await?;
        let read_scope = scope.read_scope();
        let profile = load_profile(&transaction, &read_scope, agent_id.as_str(), false).await?;
        require_manageable(scope, &profile)?;
        let row = transaction
            .query_one(
                "SELECT a.configuration,p.owner_user_id FROM public.agents a
                   JOIN public.agent_profiles p ON p.agent_id=a.id
                  WHERE a.id=$1 FOR UPDATE OF a,p",
                &[&agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        let configuration: Value = required(&row, "configuration")?;
        let owner: String =
            required_optional(&row, "owner_user_id")?.ok_or_else(|| corrupt("owner_user_id"))?;
        if let Some((credential_id, _)) = credential_reference(&configuration)? {
            revoke_credential(&transaction, credential_id, agent_id.as_str()).await?;
            append_credential_audit(
                &transaction,
                scope,
                &owner,
                credential_id,
                AuditEventType::CREDENTIAL_REVOKED,
                "agent_deleted",
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        transaction
            .execute(
                "UPDATE public.agent_profiles SET deleted_at=coalesce(deleted_at,clock_timestamp()),
                        updated_at=clock_timestamp(),callback_token_hash=NULL,
                        callback_token_issued_at=NULL WHERE agent_id=$1 AND deleted_at IS NULL",
                &[&agent_id.as_str()],
            )
            .await
            .map_err(query_unavailable)?;
        append_lifecycle_audit(
            &transaction,
            scope,
            agent_id.as_str(),
            AuditEventType::BOT_DELETED,
            None,
            self.checkpoint_key.expose(),
        )
        .await?;
        commit(transaction, "agent delete").await?;
        Ok(AgentLifecycleReceipt {
            agent_id: agent_id.clone(),
            state: AgentLifecycleState::Deleted,
        })
    }

    async fn test_agent_connection(
        &self,
        scope: &AgentAdministrationScope,
        request: AgentConnectionTestRequest,
    ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
        let mut client = self.pool.get().await.map_err(pool_unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(query_unavailable)?;
        authorize_scope(&transaction, scope).await?;
        transaction.commit().await.map_err(query_unavailable)?;
        probe_agent_connection(self.probe.as_ref(), request).await
    }
}

async fn probe_agent_connection(
    probe: &dyn RemoteAguiTransport,
    request: AgentConnectionTestRequest,
) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
    let authorization = request
        .auth
        .map(|auth| {
            RemoteAguiAuthorization::new(SecretBytes::new(auth.expose_value().as_bytes().to_vec()))
                .map_err(|_| corrupt("authorization"))
        })
        .transpose()?;
    if let Err(error) = probe.validate_endpoint(&request.endpoint).await {
        return Ok(AgentConnectionVerdict::rejected(connection_failure(error)));
    }
    let thread_id = format!("openbot-connection-test-{}", Uuid::now_v7());
    let run_id = format!("openbot-connection-test-{}", Uuid::now_v7());
    let message_id = Uuid::now_v7().to_string();
    let body = serde_json::to_vec(&json!({
        "threadId": thread_id,
        "runId": run_id,
        "messages": [{
            "id": message_id,
            "role": "user",
            "content": "OpenBot connection test. Reply briefly."
        }],
        "tools": [],
        "context": [],
        "state": {},
        "forwardedProps": {}
    }))
    .map_err(|_| corrupt("connection_probe"))?;
    let mut stream = match probe
        .start(&request.endpoint, authorization.as_ref(), body)
        .await
    {
        Ok(stream) => stream,
        Err(error) => return Ok(AgentConnectionVerdict::rejected(connection_failure(error))),
    };
    let mut events = BTreeSet::new();
    while events.len() < MAX_CONNECTION_EVENTS {
        match stream.next_data().await {
            Ok(Some(data)) => {
                if let Some(event) = serde_json::from_str::<Value>(&data)
                    .ok()
                    .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
                    .filter(|event| valid_event_type(event))
                {
                    events.insert(event);
                    break;
                }
            }
            Ok(None) => break,
            Err(
                RemoteAguiTransportError::StreamStalled | RemoteAguiTransportError::CommitUnknown,
            ) => {
                return Ok(AgentConnectionVerdict::rejected(
                    AgentConnectionFailure::Inconclusive,
                ));
            }
            Err(_) => {
                return Ok(AgentConnectionVerdict::rejected(
                    AgentConnectionFailure::Protocol,
                ));
            }
        }
    }
    if events.is_empty() {
        Ok(AgentConnectionVerdict::rejected(
            AgentConnectionFailure::Protocol,
        ))
    } else {
        Ok(AgentConnectionVerdict::working(
            events.into_iter().collect(),
        ))
    }
}

const fn connection_failure(error: RemoteAguiTransportError) -> AgentConnectionFailure {
    match error {
        RemoteAguiTransportError::DestinationRejected => {
            AgentConnectionFailure::DestinationRejected
        }
        RemoteAguiTransportError::Authentication => AgentConnectionFailure::Authentication,
        RemoteAguiTransportError::Unavailable => AgentConnectionFailure::Unreachable,
        RemoteAguiTransportError::InvalidResponse
        | RemoteAguiTransportError::RateLimited
        | RemoteAguiTransportError::ServerUnavailable => AgentConnectionFailure::Protocol,
        RemoteAguiTransportError::CommitUnknown | RemoteAguiTransportError::StreamStalled => {
            AgentConnectionFailure::Inconclusive
        }
    }
}

struct PreparedCredential {
    id: Uuid,
    encrypted: String,
    configuration: Value,
}

fn remote_configuration(endpoint: &str, credential: Option<&PreparedCredential>) -> Value {
    match credential {
        Some(credential) => json!({
            "endpoint": endpoint,
            "auth": credential.configuration
        }),
        None => json!({"endpoint": endpoint}),
    }
}

fn remote_configuration_value(endpoint: &str, auth: Option<Value>) -> Value {
    match auth {
        Some(auth) => json!({"endpoint": endpoint, "auth": auth}),
        None => json!({"endpoint": endpoint}),
    }
}

fn endpoint_audit_fact(
    endpoint: Option<&str>,
) -> Result<Option<AuditFact>, AgentAdministrationError> {
    endpoint
        .map(|endpoint| {
            let parsed = Url::parse(endpoint).map_err(|_| corrupt("endpoint"))?;
            let origin = parsed.origin().ascii_serialization();
            AuditEndpointOrigin::new(origin)
                .map(AuditFact::AgentEndpointOrigin)
                .map_err(|_| corrupt("endpoint_origin"))
        })
        .transpose()
}

async fn insert_credential(
    transaction: &Transaction<'_>,
    credential: &PreparedCredential,
    agent_id: &str,
    owner: &str,
) -> Result<(), AgentAdministrationError> {
    transaction
        .execute(
            "INSERT INTO public.credentials(
               id,kind,provider,encrypted_value,key_id,metadata,revoked_at,created_at,updated_at)
             VALUES($1,'agent',$2,$3,$4,$5,NULL,clock_timestamp(),clock_timestamp())",
            &[
                &credential.id,
                &agent_id,
                &credential.encrypted,
                &owner,
                &json!({"header": "Authorization"}),
            ],
        )
        .await
        .map_err(query_unavailable)?;
    Ok(())
}

async fn revoke_credential(
    transaction: &Transaction<'_>,
    credential_id: Uuid,
    agent_id: &str,
) -> Result<(), AgentAdministrationError> {
    let updated = transaction
        .execute(
            "UPDATE public.credentials SET revoked_at=coalesce(revoked_at,clock_timestamp()),
                    updated_at=clock_timestamp()
              WHERE id=$1 AND kind='agent' AND provider=$2 AND revoked_at IS NULL",
            &[&credential_id, &agent_id],
        )
        .await
        .map_err(query_unavailable)?;
    if updated != 1 {
        return Err(corrupt("credential_id"));
    }
    Ok(())
}

async fn validate_credential(
    transaction: &Transaction<'_>,
    credential_id: Uuid,
    agent_id: &str,
    owner: &str,
) -> Result<(), AgentAdministrationError> {
    let exists: bool = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.credentials
                            WHERE id=$1 AND kind='agent' AND provider=$2 AND key_id=$3
                              AND revoked_at IS NULL)",
            &[&credential_id, &agent_id, &owner],
        )
        .await
        .map_err(query_unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("credential_id"))?;
    if !exists {
        return Err(corrupt("credential_id"));
    }
    Ok(())
}

fn credential_reference(
    configuration: &Value,
) -> Result<Option<(Uuid, Value)>, AgentAdministrationError> {
    let Some(auth) = configuration.get("auth") else {
        return Ok(None);
    };
    let object = auth.as_object().ok_or_else(|| corrupt("agent_auth"))?;
    if object.len() != 2 || object.get("header").and_then(Value::as_str) != Some("Authorization") {
        return Err(corrupt("agent_auth"));
    }
    let credential = object
        .get("credentialId")
        .and_then(Value::as_str)
        .ok_or_else(|| corrupt("credential_id"))?;
    let id = Uuid::parse_str(credential).map_err(|_| corrupt("credential_id"))?;
    Ok(Some((id, auth.clone())))
}

async fn authorize_scope(
    transaction: &Transaction<'_>,
    scope: &AgentAdministrationScope,
) -> Result<(), AgentAdministrationError> {
    let generation =
        i64::try_from(scope.auth_generation.get()).map_err(|_| corrupt("auth_generation"))?;
    let row = transaction
        .query_opt(
            "SELECT EXISTS(
                    SELECT 1 FROM public.user_roles ur
                     WHERE ur.user_id=u.id AND ur.role='admin') AS current_admin
               FROM public.users u
               LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email)
              WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 AND ra.email IS NULL
              FOR KEY SHARE OF u",
            &[&scope.actor.as_str(), &generation],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(AgentAdministrationError::Forbidden)?;
    let current_admin: bool = row
        .try_get("current_admin")
        .map_err(|_| corrupt("admin_role"))?;
    if scope.admin && !current_admin {
        return Err(AgentAdministrationError::Forbidden);
    }
    Ok(())
}

async fn load_profile(
    transaction: &Transaction<'_>,
    scope: &AgentReadScope,
    agent_id: &str,
    lock: bool,
) -> Result<AgentProfile, AgentAdministrationError> {
    let sql = if lock {
        "SELECT a.id,a.name,a.type::text AS agent_type,a.configuration,a.package_id,
                p.owner_user_id,p.title,p.role_description,p.avatar_seed,p.visibility::text,
                (p.callback_token_hash IS NOT NULL) AS has_callback_token,
                (pref.hidden_at IS NOT NULL) AS hidden
           FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
           LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
           LEFT JOIN public.agent_preferences pref ON pref.agent_id=a.id AND pref.user_id=$1
          WHERE a.id=$3 AND p.deleted_at IS NULL
            AND (a.package_id IS NULL OR dp.tenant_id=$2)
          FOR UPDATE OF a,p"
    } else {
        "SELECT a.id,a.name,a.type::text AS agent_type,a.configuration,a.package_id,
                p.owner_user_id,p.title,p.role_description,p.avatar_seed,p.visibility::text,
                (p.callback_token_hash IS NOT NULL) AS has_callback_token,
                (pref.hidden_at IS NOT NULL) AS hidden
           FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
           LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
           LEFT JOIN public.agent_preferences pref ON pref.agent_id=a.id AND pref.user_id=$1
          WHERE a.id=$3 AND p.deleted_at IS NULL
            AND (a.package_id IS NULL OR dp.tenant_id=$2)"
    };
    let row = transaction
        .query_opt(
            sql,
            &[&scope.actor.as_str(), &scope.tenant.as_str(), &agent_id],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(AgentAdministrationError::NotVisible)?;
    decode_profile(&row, scope)
}

async fn lock_profile_rows(
    transaction: &Transaction<'_>,
    agent_id: &str,
) -> Result<(), AgentAdministrationError> {
    transaction
        .query_opt(
            "SELECT id FROM public.agents WHERE id=$1 FOR UPDATE",
            &[&agent_id],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(AgentAdministrationError::NotVisible)?;
    transaction
        .query_opt(
            "SELECT agent_id FROM public.agent_profiles WHERE agent_id=$1 FOR UPDATE",
            &[&agent_id],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(AgentAdministrationError::NotVisible)?;
    Ok(())
}

fn decode_profile(
    row: &Row,
    scope: &AgentReadScope,
) -> Result<AgentProfile, AgentAdministrationError> {
    let id: String = required(row, "id")?;
    let owner: Option<String> = required_optional(row, "owner_user_id")?;
    let package_id: Option<Uuid> = required_optional(row, "package_id")?;
    let visibility = match required::<String>(row, "visibility")?.as_str() {
        "public" => AgentVisibility::Public,
        "private" => AgentVisibility::Private,
        _ => return Err(corrupt("visibility")),
    };
    let configuration: Value = required(row, "configuration")?;
    let agent_type: String = required(row, "agent_type")?;
    let endpoint = match agent_type.as_str() {
        "built_in" => None,
        "remote_ag_ui" => Some(
            configuration
                .get("endpoint")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| corrupt("endpoint"))?
                .to_owned(),
        ),
        _ => return Err(corrupt("agent_type")),
    };
    let has_auth = credential_reference(&configuration)?.is_some();
    let system_owned = package_id.is_some();
    let facts = AgentProfileFacts {
        owner_user_id: owner.as_deref(),
        visibility,
        system_owned,
        deleted: false,
    };
    let actor = AgentActor {
        id: scope.actor.as_str(),
        admin: scope.admin,
    };
    if !can_access_agent(&actor, &facts) {
        return Err(AgentAdministrationError::NotVisible);
    }
    Ok(AgentProfile {
        id: BotId::new(id),
        name: required(row, "name")?,
        title: required(row, "title")?,
        role_description: required(row, "role_description")?,
        avatar_seed: required(row, "avatar_seed")?,
        visibility,
        endpoint,
        has_auth,
        has_callback_token: required(row, "has_callback_token")?,
        hidden: required(row, "hidden")?,
        system_owned,
        can_manage: can_manage_agent(&actor, &facts),
        mine: owner.as_deref() == Some(scope.actor.as_str()),
    })
}

fn require_manageable(
    scope: &AgentAdministrationScope,
    profile: &AgentProfile,
) -> Result<(), AgentAdministrationError> {
    if profile.system_owned {
        return Err(AgentAdministrationError::Protected);
    }
    if !profile.can_manage {
        return Err(AgentAdministrationError::Forbidden);
    }
    if !profile.mine && !scope.admin {
        return Err(AgentAdministrationError::Forbidden);
    }
    Ok(())
}

async fn append_lifecycle_audit(
    transaction: &Transaction<'_>,
    scope: &AgentAdministrationScope,
    agent_id: &str,
    event_type: AuditEventType,
    extra: Option<AuditFact>,
    checkpoint_key: &[u8],
) -> Result<(), AgentAdministrationError> {
    let mut facts = vec![AuditFact::Bot(
        AuditIdentifier::new(agent_id.to_owned()).map_err(|_| corrupt("agent_id"))?,
    )];
    if let Some(extra) = extra {
        facts.push(extra);
    }
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(scope.actor.clone()),
        event_type,
        target_kind: AuditLabel::new("agent"),
        target_id: Some(
            AuditIdentifier::new(agent_id.to_owned()).map_err(|_| corrupt("agent_id"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(infra_unavailable)
}

#[allow(clippy::too_many_arguments)]
async fn append_credential_audit(
    transaction: &Transaction<'_>,
    scope: &AgentAdministrationScope,
    owner: &str,
    credential_id: Uuid,
    event_type: AuditEventType,
    reason: &'static str,
    checkpoint_key: &[u8],
) -> Result<(), AgentAdministrationError> {
    let payload = AuditPayload::from_facts([
        AuditFact::CredentialOwner(
            AuditIdentifier::new(owner.to_owned()).map_err(|_| corrupt("credential_owner"))?,
        ),
        AuditFact::RevocationReason(AuditLabel::new(reason)),
    ])
    .map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(scope.actor.clone()),
        event_type,
        target_kind: AuditLabel::new("credential"),
        target_id: Some(
            AuditIdentifier::new(credential_id.to_string())
                .map_err(|_| corrupt("credential_id"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(infra_unavailable)
}

async fn commit(
    transaction: deadpool_postgres::Transaction<'_>,
    context: &'static str,
) -> Result<(), AgentAdministrationError> {
    transaction.commit().await.map_err(|error| {
        tracing::error!(context, error = %error, "agent lifecycle commit result unknown");
        AgentAdministrationError::CommitUnknown
    })
}

fn pg_visibility(visibility: AgentVisibility) -> PgAgentVisibility {
    match visibility {
        AgentVisibility::Public => PgAgentVisibility::Public,
        AgentVisibility::Private => PgAgentVisibility::Private,
    }
}

fn valid_event_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
}

fn required<'a, T>(row: &'a Row, field: &'static str) -> Result<T, AgentAdministrationError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(field).map_err(|_| corrupt(field))
}

fn required_optional<'a, T>(
    row: &'a Row,
    field: &'static str,
) -> Result<Option<T>, AgentAdministrationError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(field).map_err(|_| corrupt(field))
}

fn pool_unavailable(error: deadpool_postgres::PoolError) -> AgentAdministrationError {
    tracing::error!(error = %error, "agent lifecycle pool unavailable");
    AgentAdministrationError::Unavailable
}

fn query_unavailable(error: tokio_postgres::Error) -> AgentAdministrationError {
    tracing::error!(error = %error, "agent lifecycle query unavailable");
    AgentAdministrationError::Unavailable
}

fn infra_unavailable(error: crate::db::InfraError) -> AgentAdministrationError {
    tracing::error!(error = %error, "agent lifecycle audit unavailable");
    AgentAdministrationError::Unavailable
}

const fn corrupt(field: &'static str) -> AgentAdministrationError {
    AgentAdministrationError::Corrupt { field }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;
    use openbot_contracts::agent::AgentAuthInput;

    use crate::net::safe_http::{
        CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
    };
    use crate::remote_agui::SafeRemoteAguiTransport;

    struct FakeStream {
        values: VecDeque<Result<String, RemoteAguiTransportError>>,
    }

    #[async_trait]
    impl RemoteAguiEventStream for FakeStream {
        async fn next_data(&mut self) -> Result<Option<String>, RemoteAguiTransportError> {
            self.values.pop_front().transpose()
        }
    }

    struct FakeProbe {
        start_error: Option<RemoteAguiTransportError>,
        values: Vec<Result<String, RemoteAguiTransportError>>,
        saw_authorization: AtomicBool,
    }

    #[async_trait]
    impl RemoteAguiTransport for FakeProbe {
        async fn validate_endpoint(&self, _endpoint: &str) -> Result<(), RemoteAguiTransportError> {
            Ok(())
        }

        async fn start(
            &self,
            _endpoint: &str,
            authorization: Option<&RemoteAguiAuthorization>,
            _body: Vec<u8>,
        ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
            self.saw_authorization
                .store(authorization.is_some(), Ordering::SeqCst);
            if let Some(error) = self.start_error {
                return Err(error);
            }
            Ok(Box::new(FakeStream {
                values: self.values.clone().into(),
            }))
        }
    }

    fn probe(
        values: Vec<Result<String, RemoteAguiTransportError>>,
        start_error: Option<RemoteAguiTransportError>,
    ) -> FakeProbe {
        FakeProbe {
            start_error,
            values,
            saw_authorization: AtomicBool::new(false),
        }
    }

    fn probe_request(secret: Option<&str>) -> AgentConnectionTestRequest {
        AgentConnectionTestRequest {
            endpoint: "https://agent.example/ag-ui".to_owned(),
            auth: secret.map(|secret| {
                AgentAuthInput::new("Authorization".to_owned(), secret.to_owned()).unwrap()
            }),
        }
    }

    #[tokio::test]
    async fn any_bounded_agui_event_proves_protocol_even_before_terminal() {
        for event in ["RUN_STARTED", "RUN_ERROR", "TOOL_CALL_START"] {
            let transport = probe(vec![Ok(format!(r#"{{"type":"{event}"}}"#))], None);
            assert_eq!(
                probe_agent_connection(&transport, probe_request(None)).await,
                Ok(AgentConnectionVerdict::working(vec![event.to_owned()]))
            );
            assert!(!transport.saw_authorization.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn connection_failures_are_closed_and_authorization_is_forwarded_once() {
        for (error, reason) in [
            (
                RemoteAguiTransportError::DestinationRejected,
                AgentConnectionFailure::DestinationRejected,
            ),
            (
                RemoteAguiTransportError::Authentication,
                AgentConnectionFailure::Authentication,
            ),
            (
                RemoteAguiTransportError::Unavailable,
                AgentConnectionFailure::Unreachable,
            ),
            (
                RemoteAguiTransportError::InvalidResponse,
                AgentConnectionFailure::Protocol,
            ),
            (
                RemoteAguiTransportError::CommitUnknown,
                AgentConnectionFailure::Inconclusive,
            ),
        ] {
            let transport = probe(Vec::new(), Some(error));
            assert_eq!(
                probe_agent_connection(&transport, probe_request(Some("Bearer test-secret"))).await,
                Ok(AgentConnectionVerdict::rejected(reason))
            );
            assert!(transport.saw_authorization.load(Ordering::SeqCst));
        }
        let invalid = probe(vec![Ok("not json".to_owned())], None);
        assert_eq!(
            probe_agent_connection(&invalid, probe_request(None)).await,
            Ok(AgentConnectionVerdict::rejected(
                AgentConnectionFailure::Protocol
            ))
        );
    }

    #[tokio::test]
    async fn production_probe_reuses_registration_policy_and_reports_closed_port_direction() {
        let budget = SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap();
        let denied = SafeRemoteAguiTransport::new(
            SafeDialer::new(EgressPolicy::default()),
            budget,
            Some(Duration::from_millis(500)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert_eq!(
            probe_agent_connection(
                &denied,
                AgentConnectionTestRequest {
                    endpoint: "http://169.254.169.254/latest/meta-data".to_owned(),
                    auth: None,
                },
            )
            .await,
            Ok(AgentConnectionVerdict::rejected(
                AgentConnectionFailure::DestinationRejected
            ))
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let allowlisted = SafeRemoteAguiTransport::new(
            SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
            budget,
            Some(Duration::from_millis(500)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert_eq!(
            probe_agent_connection(
                &allowlisted,
                AgentConnectionTestRequest {
                    endpoint: format!("http://{address}/ag-ui"),
                    auth: None,
                },
            )
            .await,
            Ok(AgentConnectionVerdict::rejected(
                AgentConnectionFailure::Unreachable
            ))
        );
    }
}
