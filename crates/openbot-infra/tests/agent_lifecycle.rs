//! PostgreSQL 17 evidence for user-created managed/remote Agent lifecycle and runtime auth.

mod harness;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    AgentAdministration, AgentAdministrationError, AgentAdministrationScope, AgentContextError,
    AgentContextSource, AgentDirectory, ProviderRoute, RemoteAguiEventStream, RemoteAguiTransport,
    RemoteAguiTransportError, RunExecutionLease,
};
use openbot_contracts::agent::{
    AgentAuthInput, AgentLifecycleState, AgentMutationRequest, AgentVisibility,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::thread::FencingToken;
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::repo::PostgresAgentDirectory;
use openbot_infra::repo::agents::PostgresAgentAdministration;
use openbot_infra::vault::CredentialRecordVault;
use serde_json::Value;

const TENANT: &str = "agent-lifecycle-tenant";
const DEPLOYMENT: &str = "agent-lifecycle-deployment";
const OWNER: &str = "agent-lifecycle-owner";
const OTHER: &str = "agent-lifecycle-other";
const ADMIN: &str = "agent-lifecycle-admin";
const AUDIT_KEY: &[u8] = b"agent-lifecycle-audit-key-at-least-32";

#[derive(Default)]
struct AllowlistedProbe {
    validations: AtomicUsize,
}

#[async_trait]
impl RemoteAguiTransport for AllowlistedProbe {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.validations.fetch_add(1, Ordering::SeqCst);
        if endpoint.starts_with("https://") {
            Ok(())
        } else {
            Err(RemoteAguiTransportError::InvalidResponse)
        }
    }

    async fn start(
        &self,
        _endpoint: &str,
        _authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        _body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}

fn request(
    name: &str,
    visibility: AgentVisibility,
    endpoint: Option<&str>,
    secret: Option<&str>,
) -> AgentMutationRequest {
    AgentMutationRequest {
        name: name.to_owned(),
        title: format!("{name} title"),
        role_description: format!("{name} standing role"),
        visibility,
        endpoint: endpoint.map(str::to_owned),
        auth: secret.map(|value| {
            AgentAuthInput::new("Authorization".to_owned(), value.to_owned()).unwrap()
        }),
    }
}

fn scope(actor: &str, admin: bool) -> AgentAdministrationScope {
    AgentAdministrationScope {
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(actor),
        admin,
        auth_generation: AuthGeneration::new(0),
    }
}

async fn race_package_attachment(
    pool: &deadpool_postgres::Pool,
    lifecycle: Arc<PostgresAgentAdministration>,
    actor: AgentAdministrationScope,
    agent_id: BotId,
    package_id: uuid::Uuid,
    delete: bool,
) -> Result<(), String> {
    let mut holder = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = holder
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE public.agents SET package_id=$2 WHERE id=$1",
            &[&agent_id.as_str(), &package_id],
        )
        .await
        .map_err(|error| error.to_string())?;
    let task_id = agent_id.clone();
    let mut task = tokio::spawn(async move {
        if delete {
            lifecycle.delete_agent(&actor, &task_id).await.map(|_| ())
        } else {
            lifecycle
                .update_agent(
                    &actor,
                    &task_id,
                    request("Racing", AgentVisibility::Public, None, None),
                )
                .await
                .map(|_| ())
        }
    });
    if tokio::time::timeout(core::time::Duration::from_millis(100), &mut task)
        .await
        .is_ok()
    {
        transaction.rollback().await.ok();
        return Err("Agent mutation did not block behind package attachment".to_owned());
    }
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    let outcome = task.await.map_err(|error| error.to_string())?;
    if outcome != Err(AgentAdministrationError::Protected) {
        return Err(format!(
            "racing mutation did not observe package protection: {outcome:?}"
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn lifecycle_is_atomic_secret_free_runnable_and_permission_scoped() {
    let admin = admin_config("lifecycle_is_atomic_secret_free_runnable_and_permission_scoped");
    with_temp_database(&admin, "agentlifecycle", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES
                       ('agent-lifecycle-owner','owner@example.test',0),
                       ('agent-lifecycle-other','other@example.test',0),
                       ('agent-lifecycle-admin','admin@example.test',0);
                     INSERT INTO public.user_roles(user_id,role) VALUES
                       ('agent-lifecycle-owner','user'),('agent-lifecycle-other','user'),
                       ('agent-lifecycle-admin','admin');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('agent-lifecycle-tenant','/fixture',repeat('a',64));
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'agent-system','System','built_in',
                              '{\"systemPrompt\":\"System role\",\"providerSource\":\"package\"}',id
                         FROM public.deployment_packages WHERE tenant_id='agent-lifecycle-tenant';
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                       VALUES('agent-system',NULL,'System title','System role','system-seed','public');",
                )
                .await
                .map_err(|error| format!("managed create: {error}"))?;
            drop(client);

            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x5a; 32]).map_err(|error| error.to_string())?,
            );
            let probe = Arc::new(AllowlistedProbe::default());
            let lifecycle = Arc::new(PostgresAgentAdministration::new(
                pool.clone(),
                vault.clone(),
                AUDIT_KEY.to_vec(),
                probe.clone(),
                true,
            )
            .map_err(|error| error.to_string())?);
            let without_managed = PostgresAgentAdministration::new(
                pool.clone(),
                vault.clone(),
                AUDIT_KEY.to_vec(),
                probe.clone(),
                false,
            )
            .map_err(|error| error.to_string())?;
            let owner = scope(OWNER, false);
            let other = scope(OTHER, false);
            let admin_scope = scope(ADMIN, true);
            let owner_read = owner.read_scope();
            let other_read = other.read_scope();

            let stale = AgentAdministrationScope {
                auth_generation: AuthGeneration::new(1),
                ..owner.clone()
            };
            let validations_before_stale = probe.validations.load(Ordering::SeqCst);
            if lifecycle
                .create_agent(
                    &stale,
                    request(
                        "Stale generation",
                        AgentVisibility::Private,
                        Some("https://stale.example.test/ag-ui"),
                        None,
                    ),
                )
                .await
                != Err(AgentAdministrationError::Forbidden)
                || probe.validations.load(Ordering::SeqCst) != validations_before_stale
            {
                return Err("stale auth generation reached endpoint preflight or mutation".to_owned());
            }

            if without_managed
                .create_agent(
                    &owner,
                    request("No managed", AgentVisibility::Private, None, None),
                )
                .await
                != Err(AgentAdministrationError::InvalidInput { field: "endpoint" })
            {
                return Err("missing managed slot did not refuse endpoint-less create".to_owned());
            }
            let before_refused_create: i64 = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one("SELECT count(*)::bigint FROM public.agents", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if lifecycle
                .create_agent(
                    &owner,
                    request(
                        "Refused endpoint",
                        AgentVisibility::Private,
                        Some("http://169.254.169.254/latest/meta-data"),
                        None,
                    ),
                )
                .await
                != Err(AgentAdministrationError::InvalidInput { field: "endpoint" })
            {
                return Err("refused endpoint did not fail the whole create".to_owned());
            }
            let after_refused_create: i64 = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one("SELECT count(*)::bigint FROM public.agents", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if before_refused_create != after_refused_create {
                return Err("refused endpoint left an Agent row".to_owned());
            }

            let managed = lifecycle
                .create_agent(
                    &owner,
                    request("Managed", AgentVisibility::Private, None, None),
                )
                .await
                .map_err(|error| format!("remote create: {error}"))?;
            if managed.endpoint.is_some() || managed.has_auth || !managed.mine || !managed.can_manage
            {
                return Err(format!("managed profile drifted: {managed:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            for (thread_id, run_id, actor) in [
                ("agent-private-forged-thread", "agent-private-forged-run", OTHER),
                ("agent-private-admin-thread", "agent-private-admin-run", ADMIN),
            ] {
                client
                    .execute(
                        "INSERT INTO public.threads(
                           thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                           next_message_seq,next_event_seq,created_at,updated_at)
                         VALUES($1,$2,$3,$4,'direct_bot',$5,'active',1,0,
                                clock_timestamp(),clock_timestamp())",
                        &[&thread_id, &TENANT, &DEPLOYMENT, &actor, &managed.id.as_str()],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .execute(
                        "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",
                        &[&thread_id, &actor],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .execute(
                        "INSERT INTO public.runs(
                           run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                           next_event_seq,created_at,started_at)
                         VALUES($1,$2,$3,$4,true,'running',1,0,
                                clock_timestamp(),clock_timestamp())",
                        &[&run_id, &thread_id, &managed.id.as_str(), &actor],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .execute(
                        "INSERT INTO public.messages(
                           message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at)
                         VALUES($1 || '-message',$2,0,'user','{\"text\":\"Run private.\"}',
                                'Run private.',$1,$3,clock_timestamp())",
                        &[&run_id, &thread_id, &actor],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
            }
            drop(client);
            let managed_context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new(DEPLOYMENT),
                TenantId::new(TENANT),
                Some(128),
            )
            .map_err(|error| error.to_string())?
            .with_agent_credential_vault(vault.clone());
            let forged_lease = RunExecutionLease::new(
                RunId::new("agent-private-forged-run"),
                ThreadId::new("agent-private-forged-thread"),
                managed.id.clone(),
                ActorId::new(OTHER),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            if managed_context.load(&forged_lease).await != Err(AgentContextError::Stale) {
                return Err("forged non-owner run reached private Agent context".to_owned());
            }
            let admin_lease = RunExecutionLease::new(
                RunId::new("agent-private-admin-run"),
                ThreadId::new("agent-private-admin-thread"),
                managed.id.clone(),
                ActorId::new(ADMIN),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            if !matches!(
                managed_context
                    .load(&admin_lease)
                    .await
                    .map_err(|error| error.to_string())?
                    .route,
                ProviderRoute::Managed
            ) {
                return Err("admin could not run another owner's private Agent".to_owned());
            }

            let first_secret = "Bearer AGENT_LIFECYCLE_SECRET_CANARY_ONE";
            let remote = lifecycle
                .create_agent(
                    &owner,
                    request(
                        "Remote",
                        AgentVisibility::Public,
                        Some("https://remote.example.test/ag-ui"),
                        Some(first_secret),
                    ),
                )
                .await
                .map_err(|error| error.to_string())?;
            if remote.endpoint.as_deref() != Some("https://remote.example.test/ag-ui")
                || !remote.has_auth
                || !remote.mine
                || !remote.can_manage
            {
                return Err(format!("remote profile drifted: {remote:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT a.type::text,a.configuration,c.id,c.encrypted_value,c.revoked_at
                       FROM public.agents a
                       JOIN public.credentials c ON c.id=(a.configuration->'auth'->>'credentialId')::uuid
                      WHERE a.id=$1",
                    &[&remote.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let encrypted: String = row.try_get("encrypted_value").map_err(|error| error.to_string())?;
            if row.try_get::<_, String>("type").map_err(|error| error.to_string())? != "remote_ag_ui"
                || encrypted.contains("AGENT_LIFECYCLE_SECRET_CANARY")
                || row.try_get::<_, Option<time::OffsetDateTime>>("revoked_at")
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("remote credential was not active encrypted Vault state".to_owned());
            }
            drop(client);

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at)
                     VALUES('agent-lifecycle-thread',$1,$2,$3,'direct_bot',$4,'active',1,0,
                            clock_timestamp(),clock_timestamp())",
                    &[&TENANT, &DEPLOYMENT, &OWNER, &remote.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('agent-lifecycle-thread',$1)",
                    &[&OWNER],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at)
                     VALUES('agent-lifecycle-run','agent-lifecycle-thread',$1,$2,true,'running',1,0,
                            clock_timestamp(),clock_timestamp())",
                    &[&remote.id.as_str(), &OWNER],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.messages(
                       message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at)
                     VALUES('agent-lifecycle-message','agent-lifecycle-thread',0,'user',
                            '{\"text\":\"Run remote.\"}','Run remote.','agent-lifecycle-run',$1,
                            clock_timestamp())",
                    &[&OWNER],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let lease = RunExecutionLease::new(
                RunId::new("agent-lifecycle-run"),
                ThreadId::new("agent-lifecycle-thread"),
                remote.id.clone(),
                ActorId::new(OWNER),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new(DEPLOYMENT),
                TenantId::new(TENANT),
                Some(128),
            )
            .map_err(|error| error.to_string())?
            .with_remote_assertions(Arc::new(
                RemoteRunAssertionSigner::new(vec![0x3c; 32])
                    .map_err(|error| error.to_string())?,
            ))
            .with_agent_credential_vault(vault.clone());
            let loaded = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            let ProviderRoute::RemoteAgUi(route) = loaded.route else {
                return Err("user-created remote row did not select remote route".to_owned());
            };
            if route.endpoint() != "https://remote.example.test/ag-ui"
                || route
                    .authorization()
                    .ok_or_else(|| "remote authorization missing".to_owned())?
                    .expose()
                    .map_err(|error| error.to_string())?
                    != first_secret
            {
                return Err("runtime did not load exact first Vault authorization".to_owned());
            }

            let second_secret = "Bearer AGENT_LIFECYCLE_SECRET_CANARY_TWO";
            let updated = lifecycle
                .update_agent(
                    &owner,
                    &remote.id,
                    request(
                        "Remote Updated",
                        AgentVisibility::Public,
                        Some("https://remote.example.test/ag-ui-v2"),
                        Some(second_secret),
                    ),
                )
                .await
                .map_err(|error| error.to_string())?;
            if updated.name != "Remote Updated" || !updated.has_auth {
                return Err(format!("remote update drifted: {updated:?}"));
            }
            let loaded = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            let ProviderRoute::RemoteAgUi(route) = loaded.route else {
                return Err("updated remote route disappeared".to_owned());
            };
            if route
                .authorization()
                .ok_or_else(|| "updated authorization missing".to_owned())?
                .expose()
                .map_err(|error| error.to_string())?
                != second_secret
            {
                return Err("runtime did not load rotated Vault authorization".to_owned());
            }

            let preserved = lifecycle
                .update_agent(
                    &owner,
                    &remote.id,
                    request(
                        "Remote Preserved",
                        AgentVisibility::Public,
                        Some("https://remote-v3.example.test:8443/ag-ui?mode=fresh"),
                        None,
                    ),
                )
                .await
                .map_err(|error| error.to_string())?;
            let loaded = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            let ProviderRoute::RemoteAgUi(route) = loaded.route else {
                return Err("preserved remote route disappeared".to_owned());
            };
            if preserved.name != "Remote Preserved"
                || route.endpoint()
                    != "https://remote-v3.example.test:8443/ag-ui?mode=fresh"
                || route
                    .authorization()
                    .ok_or_else(|| "preserved authorization missing".to_owned())?
                    .expose()
                    .map_err(|error| error.to_string())?
                    != second_secret
            {
                return Err("blank edit did not preserve current Vault authorization".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let lifecycle_audits = client
                .query(
                    "SELECT event_type,payload->>'agent_endpoint_origin' AS origin,payload::text
                      FROM public.audit_events
                      WHERE target_id=$1 AND event_type IN ('bot.created','bot.updated')
                      ORDER BY created_at,id",
                    &[&remote.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let origins = lifecycle_audits
                .iter()
                .map(|row| row.try_get::<_, String>("origin"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            if origins
                != [
                    "https://remote.example.test",
                    "https://remote.example.test",
                    "https://remote-v3.example.test:8443",
                ]
                || lifecycle_audits.iter().any(|row| {
                    row.try_get::<_, String>("payload")
                        .is_ok_and(|payload| payload.contains("/ag-ui") || payload.contains("mode=fresh"))
                })
            {
                return Err(format!("endpoint audit origin drifted: {origins:?}"));
            }
            let credential_rows = client
                .query(
                    "SELECT revoked_at FROM public.credentials WHERE kind='agent' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if credential_rows.len() != 2
                || credential_rows[0]
                    .try_get::<_, Option<time::OffsetDateTime>>(0)
                    .map_err(|error| error.to_string())?
                    .is_none()
                || credential_rows[1]
                    .try_get::<_, Option<time::OffsetDateTime>>(0)
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                return Err("rotation did not retire only the replaced key".to_owned());
            }
            let rotated_reason: String = client
                .query_one(
                    "SELECT payload->>'revocation_reason' FROM public.audit_events
                      WHERE event_type='credential.rotated'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if rotated_reason != "agent_key_replaced" {
                return Err(format!("credential rotation audit drifted: {rotated_reason}"));
            }
            drop(client);

            let validations_before_denial = probe.validations.load(Ordering::SeqCst);
            if lifecycle
                .update_agent(
                    &other,
                    &remote.id,
                    request(
                        "Forbidden",
                        AgentVisibility::Public,
                        Some("https://unauthorized.example.test/ag-ui"),
                        None,
                    ),
                )
                .await
                != Err(AgentAdministrationError::Forbidden)
            {
                return Err("non-owner public mutation was not forbidden".to_owned());
            }
            if probe.validations.load(Ordering::SeqCst) != validations_before_denial {
                return Err("unauthorized update reached endpoint preflight".to_owned());
            }
            if lifecycle
                    .update_agent(
                        &admin_scope,
                        &BotId::new("agent-system"),
                        request("Protected", AgentVisibility::Public, None, None),
                    )
                    .await
                    != Err(AgentAdministrationError::Protected)
                || lifecycle
                    .delete_agent(&admin_scope, &BotId::new("agent-system"))
                    .await
                    != Err(AgentAdministrationError::Protected)
                || lifecycle
                    .update_agent(
                        &other,
                        &managed.id,
                        request("Invisible", AgentVisibility::Private, None, None),
                    )
                    .await
                    != Err(AgentAdministrationError::NotVisible)
            {
                return Err("manage/protected permission matrix drifted".to_owned());
            }

            if lifecycle
                .set_agent_hidden(&owner, &remote.id, true)
                .await
                .map_err(|error| error.to_string())?
                .state
                != AgentLifecycleState::Hidden
            {
                return Err("hide/unhide receipt drifted".to_owned());
            }
            let directory = PostgresAgentDirectory::new(pool.clone());
            let owner_visible = directory
                .list_visible_agents(&owner_read, false)
                .await
                .map_err(|error| error.to_string())?;
            let owner_hidden = directory
                .list_visible_agents(&owner_read, true)
                .await
                .map_err(|error| error.to_string())?;
            let other_visible = directory
                .list_visible_agents(&other_read, false)
                .await
                .map_err(|error| error.to_string())?;
            if owner_visible.iter().any(|profile| profile.id == remote.id)
                || !owner_hidden.iter().any(|profile| profile.id == remote.id)
                || !other_visible.iter().any(|profile| profile.id == remote.id)
            {
                return Err("hidden preference was not actor-scoped".to_owned());
            }
            if lifecycle
                .set_agent_hidden(&owner, &remote.id, false)
                .await
                .map_err(|error| error.to_string())?
                .state
                != AgentLifecycleState::Visible
            {
                return Err("unhide receipt drifted".to_owned());
            }

            let copy = lifecycle
                .duplicate_agent(&owner, &remote.id)
                .await
                .map_err(|error| error.to_string())?;
            if copy.visibility != AgentVisibility::Private
                || copy.endpoint.is_some()
                || copy.has_auth
                || copy.hidden
                || !copy.mine
                || !copy.can_manage
                || copy.name != preserved.name
                || copy.title != preserved.title
                || copy.role_description != preserved.role_description
                || copy.avatar_seed != remote.avatar_seed
                || copy.id == remote.id
                || !copy.id.as_str().starts_with("agent_")
                || !managed.id.as_str().starts_with("agent_")
            {
                return Err(format!("duplicate authority drifted: {copy:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let copied_links: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.channel_agents WHERE agent_id=$1",
                    &[&copy.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if copied_links != 0 {
                return Err("duplicate copied channel membership".to_owned());
            }
            let duplicated_from: String = client
                .query_one(
                    "SELECT payload->>'target_id' FROM public.audit_events
                      WHERE event_type='bot.duplicated' AND target_id=$1",
                    &[&copy.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if duplicated_from != remote.id.as_str() {
                return Err("duplicate audit did not name the original Agent".to_owned());
            }
            drop(client);

            let admin_updated = lifecycle
                .update_agent(
                    &admin_scope,
                    &managed.id,
                    request("Admin managed", AgentVisibility::Private, None, None),
                )
                .await
                .map_err(|error| error.to_string())?;
            if admin_updated.mine || !admin_updated.can_manage || admin_updated.name != "Admin managed"
            {
                return Err(format!("admin update ownership split drifted: {admin_updated:?}"));
            }
            lifecycle
                .delete_agent(&admin_scope, &managed.id)
                .await
                .map_err(|error| error.to_string())?;

            let race_update = lifecycle
                .create_agent(
                    &owner,
                    request("Race update", AgentVisibility::Private, None, None),
                )
                .await
                .map_err(|error| error.to_string())?;
            let race_delete = lifecycle
                .create_agent(
                    &owner,
                    request("Race delete", AgentVisibility::Private, None, None),
                )
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let package_id: uuid::Uuid = client
                .query_one(
                    "SELECT id FROM public.deployment_packages WHERE tenant_id=$1",
                    &[&TENANT],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            race_package_attachment(
                &pool,
                lifecycle.clone(),
                owner.clone(),
                race_update.id.clone(),
                package_id,
                false,
            )
            .await?;
            race_package_attachment(
                &pool,
                lifecycle.clone(),
                owner.clone(),
                race_delete.id.clone(),
                package_id,
                true,
            )
            .await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let protected_rows = client
                .query(
                    "SELECT a.id,a.name,p.deleted_at FROM public.agents a
                       JOIN public.agent_profiles p ON p.agent_id=a.id
                      WHERE a.id=ANY($1) ORDER BY a.id",
                    &[&vec![
                        race_update.id.as_str().to_owned(),
                        race_delete.id.as_str().to_owned(),
                    ]],
                )
                .await
                .map_err(|error| error.to_string())?;
            if protected_rows.len() != 2
                || protected_rows.iter().any(|row| {
                    row.try_get::<_, String>("name").is_ok_and(|name| name == "Racing")
                        || row
                            .try_get::<_, Option<time::OffsetDateTime>>("deleted_at")
                            .is_ok_and(|value| value.is_some())
                })
            {
                return Err("racing package attachment allowed mutation".to_owned());
            }
            let before_agents: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.agents", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let before_credentials: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.credentials", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION public.reject_agent_lifecycle_audit() RETURNS trigger
                       LANGUAGE plpgsql AS $$ BEGIN
                         IF NEW.event_type='bot.created' THEN
                           RAISE EXCEPTION 'forced agent lifecycle audit failure';
                         END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER reject_agent_lifecycle_audit
                       BEFORE INSERT ON public.audit_events FOR EACH ROW
                       EXECUTE FUNCTION public.reject_agent_lifecycle_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if lifecycle
                .create_agent(
                    &owner,
                    request(
                        "Rollback",
                        AgentVisibility::Private,
                        Some("https://rollback.example.test/ag-ui"),
                        Some("Bearer AGENT_LIFECYCLE_SECRET_CANARY_ROLLBACK"),
                    ),
                )
                .await
                != Err(AgentAdministrationError::Unavailable)
            {
                return Err("forced audit failure did not fail closed".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let after_agents: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.agents", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let after_credentials: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.credentials", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if before_agents != after_agents || before_credentials != after_credentials {
                return Err("audit failure left an Agent or credential row".to_owned());
            }
            client
                .batch_execute("DROP TRIGGER reject_agent_lifecycle_audit ON public.audit_events")
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            if lifecycle
                .delete_agent(&owner, &remote.id)
                .await
                .map_err(|error| error.to_string())?
                .state
                != AgentLifecycleState::Deleted
            {
                return Err("delete receipt drifted".to_owned());
            }
            if context.load(&lease).await != Err(AgentContextError::Stale) {
                return Err("deleted user Agent remained runnable".to_owned());
            }
            if directory
                .get_visible_agent(&owner_read, &remote.id)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("soft-deleted Agent remained visible".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let deleted_at: Option<time::OffsetDateTime> = client
                .query_one(
                    "SELECT deleted_at FROM public.agent_profiles WHERE agent_id=$1",
                    &[&remote.id.as_str()],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if deleted_at.is_none() {
                return Err("soft delete removed the canonical profile row".to_owned());
            }
            let facts = client
                .query_one(
                    "SELECT
                       count(*) FILTER (WHERE kind='agent')::bigint AS credentials,
                       count(*) FILTER (WHERE kind='agent' AND revoked_at IS NULL)::bigint AS active,
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type IN ('bot.created','bot.updated','bot.duplicated',
                                              'bot.hidden','bot.unhidden','bot.deleted')) AS audits,
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type IN ('credential.created','credential.rotated',
                                              'credential.revoked')) AS credential_audits,
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE payload::text LIKE '%AGENT_LIFECYCLE_SECRET_CANARY%') AS leaked
                     FROM public.credentials",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let credentials: i64 = facts.try_get("credentials").map_err(|error| error.to_string())?;
            let active: i64 = facts.try_get("active").map_err(|error| error.to_string())?;
            let audits: i64 = facts.try_get("audits").map_err(|error| error.to_string())?;
            let credential_audits: i64 = facts
                .try_get("credential_audits")
                .map_err(|error| error.to_string())?;
            let leaked: i64 = facts.try_get("leaked").map_err(|error| error.to_string())?;
            if credentials != 2
                || active != 0
                || audits != 12
                || credential_audits != 3
                || leaked != 0
            {
                return Err(format!(
                    "final credential/audit facts drifted: credentials={credentials} active={active} audits={audits} credential_audits={credential_audits} leaked={leaked}"
                ));
            }
            let lifecycle_counts = client
                .query(
                    "SELECT event_type,count(*)::bigint FROM public.audit_events
                      WHERE event_type LIKE 'bot.%' GROUP BY event_type ORDER BY event_type",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get::<_, String>(0)?,
                        row.try_get::<_, i64>(1)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, tokio_postgres::Error>>()
                .map_err(|error| error.to_string())?;
            if lifecycle_counts
                != BTreeMap::from([
                    ("bot.created".to_owned(), 4),
                    ("bot.deleted".to_owned(), 2),
                    ("bot.duplicated".to_owned(), 1),
                    ("bot.hidden".to_owned(), 1),
                    ("bot.unhidden".to_owned(), 1),
                    ("bot.updated".to_owned(), 3),
                ])
            {
                return Err(format!("lifecycle audit event matrix drifted: {lifecycle_counts:?}"));
            }
            let credential_counts = client
                .query(
                    "SELECT event_type,count(*)::bigint FROM public.audit_events
                      WHERE event_type LIKE 'credential.%' GROUP BY event_type ORDER BY event_type",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get::<_, String>(0)?,
                        row.try_get::<_, i64>(1)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, tokio_postgres::Error>>()
                .map_err(|error| error.to_string())?;
            if credential_counts
                != BTreeMap::from([
                    ("credential.created".to_owned(), 1),
                    ("credential.revoked".to_owned(), 1),
                    ("credential.rotated".to_owned(), 1),
                ])
            {
                return Err(format!("credential audit event matrix drifted: {credential_counts:?}"));
            }
            let configurations = client
                .query("SELECT configuration FROM public.agents", &[])
                .await
                .map_err(|error| error.to_string())?;
            if configurations.iter().any(|row| {
                row.try_get::<_, Value>(0)
                    .is_ok_and(|value| value.to_string().contains("AGENT_LIFECYCLE_SECRET_CANARY"))
            }) {
                return Err("Agent configuration leaked authorization".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
