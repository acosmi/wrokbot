//! PostgreSQL evidence for dynamic sandbox provider definitions and call-time authorization.

mod harness;

use std::collections::BTreeMap;
use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AgentContextSource, ComponentAdministration, ComponentRuntimeScope, RunExecutionLease,
    SandboxedComponentAdministration, SandboxedComponentAdministrationError,
    SandboxedComponentDraft,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::components::{CompiledComponentKind, ComponentDecisionRefusal};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::thread::FencingToken;
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::sandboxed_components::PostgresSandboxedComponentAdministration;
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn published_sandbox_schema_grant_and_authorization_are_fresh_and_fail_closed() {
    let admin =
        admin_config("published_sandbox_schema_grant_and_authorization_are_fresh_and_fail_closed");
    with_temp_database(&admin, "sandboxedruntime", |config| async move {
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
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('actor-a','actor-a@example.test',0);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('actor-a','user'),('actor-a','admin');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('tenant-a','/fixture',repeat('a',64));
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'bot-1','Bot 1','built_in',
                              '{\"systemPrompt\":\"Test role.\",\"providerSource\":\"package\"}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant-a';
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES('bot-1',NULL,'Bot 1','role','seed','public',NULL);
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES('thread-1','tenant-a','deployment-a','actor-a','direct_bot','bot-1',
                              'active',1,0,clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-1','actor-a');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at
                     ) VALUES('run-1','thread-1','bot-1','actor-a',true,'running',1,0,
                              clock_timestamp(),clock_timestamp());
                     INSERT INTO public.messages(
                       message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                     ) VALUES('message-1','thread-1',0,'user','{\"text\":\"Show it.\"}',
                              'Show it.','run-1','actor-a',clock_timestamp());",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User, Role::Admin])
            .build();
            let sandboxed = Arc::new(
                PostgresSandboxedComponentAdministration::new(
                    pool.clone(),
                    b"sandboxed-runtime-audit-key".to_vec(),
                )
                .map_err(|error| error.to_string())?,
            );
            let v1 = draft(
                json!({
                    "type":"object",
                    "properties":{"title":{"type":"string"}},
                    "required":["title"],
                    "additionalProperties":false
                }),
                "v1",
            );
            sandboxed
                .save_sandboxed_component(&auth, &v1)
                .await
                .map_err(|error| error.to_string())?;
            sandboxed
                .publish_sandboxed_component(&auth, &v1.name)
                .await
                .map_err(|error| error.to_string())?;

            let components = PostgresComponentAdministration::new(
                pool.clone(),
                b"sandboxed-runtime-audit-key".to_vec(),
            )
            .map_err(|error| error.to_string())?;
            let generic = components
                .list_components(&auth)
                .await
                .map_err(|error| error.to_string())?;
            let governance = generic
                .components
                .iter()
                .find(|component| component.name == v1.name)
                .ok_or_else(|| "sandbox governance absent from shared list".to_owned())?;
            if governance.kind != CompiledComponentKind::Sandboxed
                || !governance.functions.is_empty()
                || !governance.published
            {
                return Err(format!("shared sandbox governance drift: {governance:?}"));
            }

            let scope = ComponentRuntimeScope {
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
                admin: true,
                agent_id: BotId::new("bot-1"),
            };
            let granted = sandboxed
                .list_sandboxed_components_for_agent(&scope)
                .await
                .map_err(|error| error.to_string())?;
            if granted.components.len() != 1
                || granted.components[0].name != v1.name
                || granted.components[0].description != v1.description
                || granted.components[0].argument_schema != object_value(&v1.argument_schema)
                || granted.components[0].revision != 1
            {
                return Err(format!("sandbox grant drift: {granted:?}"));
            }

            let lease = RunExecutionLease::new(
                RunId::new("run-1"),
                ThreadId::new("thread-1"),
                BotId::new("bot-1"),
                ActorId::new("actor-a"),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                Some(256),
            )
            .map_err(|error| error.to_string())?
            .with_sandboxed_components(sandboxed.clone());
            let provider = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if provider.tools.len() != 1
                || provider.tools[0].name != v1.name
                || provider.tools[0].description != v1.description
                || provider.tools[0].input_schema != object_value(&v1.argument_schema)
            {
                return Err(format!(
                    "provider sandbox definition drift: {:?}",
                    provider.tools
                ));
            }
            let allowed = sandboxed
                .authorize_sandboxed_component(&scope, &v1.name, &json!({"title":"ETA"}))
                .await
                .map_err(|error| error.to_string())?;
            if !allowed.allowed {
                return Err(format!("valid sandbox call refused: {allowed:?}"));
            }
            if !matches!(
                sandboxed
                    .authorize_sandboxed_component(&scope, &v1.name, &json!({}))
                    .await,
                Err(SandboxedComponentAdministrationError::InvalidInput {
                    field: "component_arguments"
                })
            ) {
                return Err("published JSON Schema did not reject invalid arguments".to_owned());
            }

            let mut v2 = draft(
                json!({
                    "type":"object",
                    "properties":{"count":{"type":"integer","minimum":1}},
                    "required":["count"],
                    "additionalProperties":false
                }),
                "v2",
            );
            v2.name = v1.name.clone();
            sandboxed
                .save_sandboxed_component(&auth, &v2)
                .await
                .map_err(|error| error.to_string())?;
            let before_publish = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if before_publish.tools[0].input_schema != object_value(&v1.argument_schema) {
                return Err("draft schema reached provider before publication".to_owned());
            }
            sandboxed
                .publish_sandboxed_component(&auth, &v2.name)
                .await
                .map_err(|error| error.to_string())?;
            let after_publish = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if after_publish.tools[0].input_schema != object_value(&v2.argument_schema) {
                return Err("published schema did not refresh provider context".to_owned());
            }
            if !sandboxed
                .authorize_sandboxed_component(&scope, &v2.name, &json!({"count":2}))
                .await
                .map_err(|error| error.to_string())?
                .allowed
            {
                return Err("new published schema refused matching arguments".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.component_exclusions(component_name,agent_id,withheld_by)
                     VALUES($1,'bot-1','actor-a')",
                    &[&v2.name],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if !context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?
                .tools
                .is_empty()
            {
                return Err("sandbox withholding did not remove provider definition".to_owned());
            }
            let refused = sandboxed
                .authorize_sandboxed_component(&scope, &v2.name, &json!({"count":2}))
                .await
                .map_err(|error| error.to_string())?;
            if refused.refusal != Some(ComponentDecisionRefusal::WithheldFromAgent) {
                return Err(format!("sandbox withholding decision drift: {refused:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "DELETE FROM public.component_exclusions
                       WHERE component_name='custom_delivery_eta' AND agent_id='bot-1';
                     INSERT INTO public.component_functions(component_name,function_name,granted_by)
                       VALUES('custom_delivery_eta','botActivity','actor-a');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if !matches!(
                components.list_components(&auth).await,
                Err(openbot_application::ComponentAdministrationError::Corrupt {
                    field: "sandboxed_component_functions"
                })
            ) {
                return Err("sandbox data-function row did not fail closed".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "DELETE FROM public.component_functions WHERE component_name=$1",
                    &[&v2.name],
                )
                .await
                .map_err(|error| error.to_string())?;
            let refusal_audits: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type='component.refused' AND target_id=$1
                        AND payload->>'error_code'='component_withheld'",
                    &[&v2.name],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if refusal_audits != 1 {
                return Err(format!("sandbox refusal audit drift: {refusal_audits}"));
            }
            drop(client);
            let external_ref = draft(
                json!({"type":"object","properties":{"x":{"$ref":"https://example.test/schema.json"}}}),
                "external-ref",
            );
            if !matches!(
                sandboxed.save_sandboxed_component(&auth, &external_ref).await,
                Err(SandboxedComponentAdministrationError::InvalidInput {
                    field: "argument_schema"
                })
            ) {
                return Err("external JSON Schema reference was not rejected before save".to_owned());
            }
            let still_v2 = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if still_v2.tools[0].input_schema != object_value(&v2.argument_schema) {
                return Err("rejected schema changed published provider definition".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

fn draft(schema: Value, version: &str) -> SandboxedComponentDraft {
    SandboxedComponentDraft {
        name: "custom_delivery_eta".to_owned(),
        title: "Delivery ETA".to_owned(),
        description: format!("Show a delivery estimate ({version})."),
        html: "<p id=\"value\"></p>".to_owned(),
        css: "p { color: currentColor; }".to_owned(),
        js_functions:
            "document.getElementById('value').textContent = JSON.stringify(window.__args);"
                .to_owned(),
        argument_schema: schema.as_object().unwrap().clone().into_iter().collect(),
        sample_arguments: BTreeMap::new(),
    }
}

fn object_value(object: &BTreeMap<String, Value>) -> Value {
    Value::Object(object.clone().into_iter().collect())
}
