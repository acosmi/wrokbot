//! PostgreSQL 17 evidence for compiled-component runtime grants and call-time refusal audit.

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    ComponentAdministration, ComponentRuntimeScope, call_component_function, decide_component,
    list_components_for_agent,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::components::{
    BOT_ACTIVITY_FUNCTION_NAME, ComponentDecision, ComponentDecisionRefusal,
    ComponentDecisionRequest, ComponentFunctionCallRequest, ComponentFunctionData,
    RECENT_REFUSALS_FUNCTION_NAME, SHOW_ACTIVITY_REPORT_COMPONENT_NAME, SHOW_NOTICE_COMPONENT_NAME,
    SHOW_QUOTE_COMPONENT_NAME, SHOW_RECORD_COMPONENT_NAME, compiled_component_manifest,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;

fn auth(actor: &str, roles: impl IntoIterator<Item = Role>) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("component-runtime-deployment"),
        TenantId::new("tenant-a"),
        ActorId::new(actor),
        AuthGeneration::new(0),
        false,
    )
    .with_roles(roles)
    .build()
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn runtime_grants_recheck_agent_component_function_and_refusal_audit_atomically() {
    let admin = admin_config(
        "runtime_grants_recheck_agent_component_function_and_refusal_audit_atomically",
    );
    with_temp_database(&admin, "componentruntime", |config| async move {
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
                       ('actor-a','a@example.test',0),('actor-b','b@example.test',0),
                       ('actor-admin','admin@example.test',0);
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES
                       ('tenant-a','/tenant-a','checksum-a'),
                       ('tenant-b','/tenant-b','checksum-b');
                     INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
                       ('agent-public','Public','built_in','{}',NULL),
                       ('agent-private-a','Private A','built_in','{}',NULL),
                       ('agent-private-b','Private B','built_in','{}',NULL),
                       ('agent-deleted','Deleted','built_in','{}',NULL),
                       ('agent-package-a','Package A','built_in','{}',
                        (SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-a')),
                       ('agent-package-b','Package B','built_in','{}',
                        (SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-b'));
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES
                       ('agent-public','actor-a','Public','Public','public','public',NULL),
                       ('agent-private-a','actor-a','Private A','Private A','private-a','private',NULL),
                       ('agent-private-b','actor-b','Private B','Private B','private-b','private',NULL),
                       ('agent-deleted','actor-a','Deleted','Deleted','deleted','public',now()),
                       ('agent-package-a',NULL,'Package A','Package A','package-a','public',NULL),
                       ('agent-package-b',NULL,'Package B','Package B','package-b','public',NULL);",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let actor = auth("actor-a", [Role::User]);
            let admin_actor = auth("actor-admin", [Role::User, Role::Admin]);
            let unconfigured = PostgresComponentAdministration::new(
                pool.clone(),
                b"component-runtime-audit-key".to_vec(),
            )
            .map_err(|error| error.to_string())?;
            unconfigured
                .sync_catalogue(&actor, &compiled_component_manifest())
                .await
                .map_err(|error| error.to_string())?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "UPDATE public.components SET published=false
                       WHERE name='showNotice';
                     UPDATE public.components SET published_description=NULL
                       WHERE name='showMetrics';
                     INSERT INTO public.component_exclusions(component_name,agent_id,withheld_by)
                       VALUES('showRecord','agent-public','actor-admin');
                     INSERT INTO public.component_functions(component_name,function_name,granted_by)
                       VALUES('showActivityReport','botActivity','actor-admin');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let components = PostgresComponentAdministration::new(
                pool.clone(),
                b"component-runtime-audit-key".to_vec(),
            )
            .map_err(|error| error.to_string())?
            .with_policy(PolicyStore::in_memory(Some(ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: Vec::new(),
                allow: vec![
                    "tool.name == \"component_data__botActivity\"".to_owned(),
                    "tool.name == \"component_data__recentRefusals\"".to_owned(),
                ],
            })));

            let initial = list_components_for_agent(
                &components,
                &actor,
                BotId::new("agent-public"),
            )
            .await
            .map_err(|error| error.to_string())?;
            let initial_names = initial
                .components
                .iter()
                .map(|component| component.name.as_str())
                .collect::<Vec<_>>();
            if initial_names.len() != 10
                || initial_names.contains(&SHOW_NOTICE_COMPONENT_NAME)
                || initial_names.contains(&SHOW_RECORD_COMPONENT_NAME)
                || initial_names.contains(&"showMetrics")
                || !initial_names.contains(&SHOW_QUOTE_COMPONENT_NAME)
            {
                return Err(format!("initial runtime grants drifted: {initial_names:?}"));
            }

            for invisible in ["agent-private-b", "agent-deleted", "agent-package-b"] {
                let error = list_components_for_agent(
                    &components,
                    &actor,
                    BotId::new(invisible),
                )
                .await
                .expect_err("invisible Agent must fail closed");
                if error.code().as_str() != "not_visible" {
                    return Err(format!("{invisible} returned the wrong error: {error}"));
                }
            }
            let admin_private = list_components_for_agent(
                &components,
                &admin_actor,
                BotId::new("agent-private-b"),
            )
            .await
            .map_err(|error| error.to_string())?;
            if admin_private.components.len() != 11 {
                return Err(format!(
                    "admin private-Agent grants drifted: {admin_private:?}"
                ));
            }

            let decide = |functions: Vec<String>| ComponentDecisionRequest {
                agent_id: BotId::new("agent-public"),
                functions,
            };
            if decide_component(
                &components,
                &actor,
                SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                decide(Vec::new()),
            )
            .await
            .map_err(|error| error.to_string())?
                != ComponentDecision::allowed()
            {
                return Err("published component was refused".to_owned());
            }

            let policy_refused = decide_component(
                &unconfigured,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                decide(vec![BOT_ACTIVITY_FUNCTION_NAME.to_owned()]),
            )
            .await
            .map_err(|error| error.to_string())?;
            if policy_refused
                != ComponentDecision::refused(ComponentDecisionRefusal::FunctionPolicyRefused {
                    function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                })
            {
                return Err(format!("default policy decision drifted: {policy_refused:?}"));
            }

            let actor_refused = decide_component(
                &components,
                &actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                decide(vec![BOT_ACTIVITY_FUNCTION_NAME.to_owned()]),
            )
            .await
            .map_err(|error| error.to_string())?;
            if actor_refused
                != ComponentDecision::refused(
                    ComponentDecisionRefusal::FunctionActorNotAuthorized {
                        function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                    },
                )
            {
                return Err(format!("actor ACL decision drifted: {actor_refused:?}"));
            }

            if decide_component(
                &components,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                decide(vec![BOT_ACTIVITY_FUNCTION_NAME.to_owned()]),
            )
            .await
            .map_err(|error| error.to_string())?
                != ComponentDecision::allowed()
            {
                return Err("admin+policy+function grant was refused".to_owned());
            }

            let missing_function = decide_component(
                &components,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                decide(vec![RECENT_REFUSALS_FUNCTION_NAME.to_owned()]),
            )
            .await
            .map_err(|error| error.to_string())?;
            if missing_function
                != ComponentDecision::refused(ComponentDecisionRefusal::FunctionNotGranted {
                    function: RECENT_REFUSALS_FUNCTION_NAME.to_owned(),
                })
            {
                return Err(format!(
                    "missing function decision drifted: {missing_function:?}"
                ));
            }
            let unpublished = decide_component(
                &components,
                &actor,
                SHOW_NOTICE_COMPONENT_NAME.to_owned(),
                decide(Vec::new()),
            )
            .await
            .map_err(|error| error.to_string())?;
            if unpublished
                != ComponentDecision::refused(ComponentDecisionRefusal::Unpublished)
            {
                return Err(format!("unpublished decision drifted: {unpublished:?}"));
            }
            let stale = decide_component(
                &components,
                &actor,
                "showStale".to_owned(),
                decide(Vec::new()),
            )
            .await
            .map_err(|error| error.to_string())?;
            if stale
                != ComponentDecision::refused(ComponentDecisionRefusal::UnknownComponent)
            {
                return Err(format!("stale renderer decision drifted: {stale:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.component_functions(component_name,function_name,granted_by)
                     VALUES('showActivityReport','recentRefusals','actor-admin')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let activity = call_component_function(
                &components,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                ComponentFunctionCallRequest {
                    agent_id: BotId::new("agent-public"),
                    function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                    args: serde_json::json!({"days": 120.9}),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            let Some(ComponentFunctionData::BotActivity(activity)) = activity.data else {
                return Err(format!("botActivity result drifted: {activity:?}"));
            };
            if activity.days != 90
                || activity.rows.len() != 1
                || activity.rows[0].bot != "agent-public"
                || activity.rows[0].actions != 5
            {
                return Err(format!("botActivity data drifted: {activity:?}"));
            }
            let refusals = call_component_function(
                &components,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                ComponentFunctionCallRequest {
                    agent_id: BotId::new("agent-public"),
                    function: RECENT_REFUSALS_FUNCTION_NAME.to_owned(),
                    args: serde_json::json!({"limit": 2}),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            let Some(ComponentFunctionData::RecentRefusals(refusals)) = refusals.data else {
                return Err(format!("recentRefusals result drifted: {refusals:?}"));
            };
            if refusals.rows.len() != 2
                || refusals.rows.iter().any(|row| {
                    row.bot.as_deref() != Some("agent-public")
                        || row.reason.as_deref().is_none_or(str::is_empty)
                })
            {
                return Err(format!("recentRefusals data drifted: {refusals:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.component_exclusions(component_name,agent_id,withheld_by)
                     VALUES($1,'agent-public','actor-admin')",
                    &[&SHOW_QUOTE_COMPONENT_NAME],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let after_revoke = decide_component(
                &components,
                &actor,
                SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                decide(Vec::new()),
            )
            .await
            .map_err(|error| error.to_string())?;
            if after_revoke
                != ComponentDecision::refused(ComponentDecisionRefusal::WithheldFromAgent)
            {
                return Err(format!("call-time revoke was ignored: {after_revoke:?}"));
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let audit_rows = client
                .query(
                    "SELECT event_type,target_id,payload
                       FROM public.audit_events
                      WHERE event_type IN ('component.refused','component.function_refused')
                   ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if audit_rows.len() != 6 {
                return Err(format!("runtime refusal audit count drifted: {}", audit_rows.len()));
            }
            for row in &audit_rows {
                let payload: serde_json::Value =
                    row.try_get("payload").map_err(|error| error.to_string())?;
                if payload.get("bot").and_then(serde_json::Value::as_str)
                    != Some("agent-public")
                    || payload.get("error_code").is_none()
                    || payload.get("reason").is_some()
                {
                    return Err(format!("runtime audit payload drifted: {payload}"));
                }
                let event_type: String = row.try_get("event_type").map_err(|error| error.to_string())?;
                if event_type == "component.function_refused" {
                    let function = payload.get("function").and_then(serde_json::Value::as_str);
                    if !matches!(
                        function,
                        Some(BOT_ACTIVITY_FUNCTION_NAME | RECENT_REFUSALS_FUNCTION_NAME)
                    ) {
                        return Err(format!("function refusal audit drifted: {payload}"));
                    }
                }
            }
            let called_rows = client
                .query(
                    "SELECT payload FROM public.audit_events
                      WHERE event_type='component.function_called' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if called_rows.len() != 2 {
                return Err(format!("function called audit count drifted: {}", called_rows.len()));
            }
            for row in called_rows {
                let payload: serde_json::Value =
                    row.try_get("payload").map_err(|error| error.to_string())?;
                if payload.get("reads").and_then(serde_json::Value::as_str)
                    != Some("the audit trail")
                    || payload.get("policy_version").is_none()
                    || payload.get("reason").is_some()
                {
                    return Err(format!("function called audit payload drifted: {payload}"));
                }
            }
            client
                .execute(
                    "INSERT INTO public.audit_events(
                       actor_user_id,event_type,target_type,target_id,payload,created_at,
                       prev_hash,row_hash
                     ) VALUES(
                       'actor-admin','component.function_called','component','showActivityReport',
                       jsonb_build_object('bot',repeat('x',300)),
                       clock_timestamp()+interval '1 second',
                       (SELECT row_hash FROM public.audit_events
                         ORDER BY created_at DESC,id DESC LIMIT 1),repeat('0',64)
                     )",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let failed = call_component_function(
                &components,
                &admin_actor,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME.to_owned(),
                ComponentFunctionCallRequest {
                    agent_id: BotId::new("agent-public"),
                    function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
                    args: serde_json::json!({"days": 90}),
                },
            )
            .await
            .map_err(|error| format!("corrupt component read application error: {error:?}"))?;
            if failed.error
                != Some(openbot_contracts::components::ComponentFunctionError::ReadFailed)
            {
                return Err(format!("corrupt data read did not return stable failure: {failed:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let failed_payload: serde_json::Value = client
                .query_one(
                    "SELECT payload FROM public.audit_events
                      WHERE event_type='component.function_failed'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get("payload")
                .map_err(|error| error.to_string())?;
            if failed_payload.get("error_code").and_then(serde_json::Value::as_str)
                != Some("component_function_read_failed")
                || failed_payload.to_string().contains(&"x".repeat(300))
            {
                return Err(format!("function failed audit drifted: {failed_payload}"));
            }
            let before_forced = audit_rows.len();
            client
                .batch_execute(
                    "CREATE FUNCTION public.reject_component_runtime_audit() RETURNS trigger
                       LANGUAGE plpgsql AS $$ BEGIN
                         IF NEW.event_type='component.refused' THEN
                           RAISE EXCEPTION 'forced component runtime audit failure';
                         END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER reject_component_runtime_audit
                       BEFORE INSERT ON public.audit_events FOR EACH ROW
                       EXECUTE FUNCTION public.reject_component_runtime_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let scope = ComponentRuntimeScope {
                tenant: actor.tenant().clone(),
                actor: actor.actor().clone(),
                admin: false,
                agent_id: BotId::new("agent-public"),
            };
            if components
                .decide_component(&scope, SHOW_RECORD_COMPONENT_NAME, true, &[])
                .await
                .is_ok()
            {
                return Err("forced refusal audit failure returned a decision".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let after_forced: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type IN ('component.refused','component.function_refused')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if usize::try_from(after_forced).ok() != Some(before_forced) {
                return Err(format!(
                    "failed refusal audit changed durable rows: before={before_forced} after={after_forced}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
