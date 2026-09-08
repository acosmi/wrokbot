//! Durable compiled-component human-decision request/answer/wait PostgreSQL evidence.

mod harness;

use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    COMPONENT_HUMAN_DECISION_TTL, ComponentAdministration, ComponentAdministrationError,
    ComponentHumanDecisionDraft, ComponentHumanDecisionScope, ComponentRuntimeScope,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_DESCRIPTION, ASK_APPROVAL_COMPONENT_NAME, ASK_APPROVAL_COMPONENT_TITLE,
    ASK_CHOICE_COMPONENT_DESCRIPTION, ASK_CHOICE_COMPONENT_NAME, ASK_CHOICE_COMPONENT_TITLE,
    ComponentApprovalAnswer, ComponentApprovalDecision, ComponentChoiceAnswer,
    ComponentHumanDecisionAnswer,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::tool::args::ToolArguments;
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::{baseline, native, pool};

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn decisions_are_actor_scoped_exactly_once_audited_and_cross_replica_resumable() {
    let admin =
        admin_config("decisions_are_actor_scoped_exactly_once_audited_and_cross_replica_resumable");
    with_temp_database(&admin, "componenthuman", |config| async move {
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
                .batch_execute(&format!(
                    "INSERT INTO public.users(id,email,auth_generation)
                       VALUES('actor-a','actor-a@example.test',0),
                             ('actor-b','actor-b@example.test',0);
                     INSERT INTO public.user_roles(user_id,role)
                       VALUES('actor-a','user'),('actor-b','user');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('tenant-a','/fixture',repeat('a',64));
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'bot-1','Bot 1','built_in','{{}}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant-a';
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                     ) VALUES('bot-1',NULL,'Bot 1','role','seed','public',NULL);
                     INSERT INTO public.components(
                       name,title,kind,draft_description,published_description,published,
                       published_at,updated_by,created_at,updated_at
                     ) VALUES
                       ('{ASK_APPROVAL_COMPONENT_NAME}','{ASK_APPROVAL_COMPONENT_TITLE}','decision',
                        '{ASK_APPROVAL_COMPONENT_DESCRIPTION}','{ASK_APPROVAL_COMPONENT_DESCRIPTION}',
                        true,clock_timestamp(),'the build',clock_timestamp(),clock_timestamp()),
                       ('{ASK_CHOICE_COMPONENT_NAME}','{ASK_CHOICE_COMPONENT_TITLE}','decision',
                        '{ASK_CHOICE_COMPONENT_DESCRIPTION}','{ASK_CHOICE_COMPONENT_DESCRIPTION}',
                        true,clock_timestamp(),'the build',clock_timestamp(),clock_timestamp());
                     INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES('thread-1','tenant-a','deployment-a','actor-a','direct_bot','bot-1',
                              'active',0,0,clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-1','actor-a');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at
                     ) VALUES('run-1','thread-1','bot-1','actor-a',true,'running',1,0,
                              clock_timestamp(),clock_timestamp());
                     INSERT INTO public.thread_leases(
                       thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                     ) VALUES('thread-1','fixture-owner',1,clock_timestamp(),
                              clock_timestamp()+interval '10 minutes',clock_timestamp());"
                ))
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let actor_auth = auth("actor-a", 0);
            let scope = ComponentHumanDecisionScope {
                deployment: DeploymentId::new("deployment-a"),
                tenant: TenantId::new("tenant-a"),
                actor: ActorId::new("actor-a"),
                auth_generation: AuthGeneration::new(0),
                admin: false,
                thread_id: ThreadId::new("thread-1"),
                run_id: RunId::new("run-1"),
                agent_id: BotId::new("bot-1"),
            };
            let arguments = serde_json::json!({
                "title":"Refund this order?",
                "summary":"The charge was duplicated."
            });
            let approval_draft = draft(
                "decision-1",
                "provider-call-1",
                ASK_APPROVAL_COMPONENT_NAME,
                arguments,
            );
            let requester = Arc::new(
                PostgresComponentAdministration::new(pool.clone(), vec![0x47; 32])
                    .map_err(|error| error.to_string())?,
            );
            let answerer = PostgresComponentAdministration::new(pool.clone(), vec![0x47; 32])
                .map_err(|error| error.to_string())?;

            let runtime_decision = requester
                .decide_component(
                    &ComponentRuntimeScope {
                        tenant: TenantId::new("tenant-a"),
                        actor: ActorId::new("actor-a"),
                        admin: false,
                        agent_id: BotId::new("bot-1"),
                    },
                    ASK_APPROVAL_COMPONENT_NAME,
                    true,
                    &[],
                )
                .await
                .map_err(|error| format!("preflight component decision: {error}"))?;
            if !runtime_decision.allowed {
                return Err(format!("preflight component refused: {runtime_decision:?}"));
            }

            let pending = requester
                .request_component_human_decision(&scope, &approval_draft)
                .await
                .map_err(|error| format!("first request: {error}"))?;
            if pending.decision_id != "decision-1"
                || pending.agent_id.as_str() != "bot-1"
                || pending.component_name != ASK_APPROVAL_COMPONENT_NAME
            {
                return Err(format!("pending decision drifted: {pending:?}"));
            }
            let replay = requester
                .request_component_human_decision(&scope, &approval_draft)
                .await
                .map_err(|error| format!("request replay: {error}"))?;
            if replay != pending {
                return Err("exact request replay changed pending projection".to_owned());
            }
            for (sql, expected_constraint) in [
                (
                    "UPDATE public.component_human_decisions SET arguments_hash='bad'
                      WHERE decision_id='decision-1'",
                    "component_human_decisions_arguments_hash_lower_hex",
                ),
                (
                    "UPDATE public.component_human_decisions
                        SET state='answered',answer='{\"choice\":\"x\",\"label\":\"X\"}'::jsonb,
                            resolved_at=clock_timestamp(),resolved_by=actor_id
                      WHERE decision_id='decision-1'",
                    "component_human_decisions_answer_shape",
                ),
                (
                    "UPDATE public.component_human_decisions
                        SET answer='{\"decision\":\"approved\"}'::jsonb
                      WHERE decision_id='decision-1'",
                    "component_human_decisions_resolution_shape",
                ),
            ] {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let error = client
                    .execute(sql, &[])
                    .await
                    .expect_err("invalid durable decision shape must hit a named constraint");
                if error
                    .as_db_error()
                    .and_then(tokio_postgres::error::DbError::constraint)
                    != Some(expected_constraint)
                {
                    return Err(format!("wrong decision constraint for {sql}: {error}"));
                }
            }
            let conflicting = ComponentHumanDecisionDraft {
                decision_id: "decision-other".to_owned(),
                ..approval_draft.clone()
            };
            if requester
                .request_component_human_decision(&scope, &conflicting)
                .await
                != Err(ComponentAdministrationError::Conflict)
            {
                return Err("same run/provider call with another identity must conflict".to_owned());
            }
            if !answerer
                .list_component_human_decisions(&auth("actor-b", 0))
                .await
                .map_err(|error| error.to_string())?
                .decisions
                .is_empty()
                || answerer
                    .list_component_human_decisions(&actor_auth)
                    .await
                    .map_err(|error| format!("actor pending list: {error}"))?
                    .decisions
                    .len()
                    != 1
            {
                return Err("pending list actor scope drifted".to_owned());
            }

            let waiter_port = requester.clone();
            let waiter_scope = scope.clone();
            let waiter = tokio::spawn(async move {
                waiter_port
                    .wait_component_human_decision(&waiter_scope, "decision-1")
                    .await
            });
            tokio::time::sleep(core::time::Duration::from_millis(100)).await;
            let answer = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Approved,
                note: Some("exact reason".to_owned()),
            });
            let resolved = answerer
                .resolve_component_human_decision(&actor_auth, "decision-1", &answer)
                .await
                .map_err(|error| format!("first answer: {error}"))?;
            if resolved.replayed || resolved.answer != answer {
                return Err(format!("first answer drifted: {resolved:?}"));
            }
            let waited = waiter
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            if waited.answer != answer {
                return Err(format!("cross-replica waiter drifted: {waited:?}"));
            }
            let replayed = answerer
                .resolve_component_human_decision(&actor_auth, "decision-1", &answer)
                .await
                .map_err(|error| format!("answer replay: {error}"))?;
            if !replayed.replayed {
                return Err("same answer must be an exact replay".to_owned());
            }
            let different = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Declined,
                note: None,
            });
            if answerer
                .resolve_component_human_decision(&actor_auth, "decision-1", &different)
                .await
                != Err(ComponentAdministrationError::Conflict)
            {
                return Err("different second answer must conflict".to_owned());
            }

            let choice_arguments = serde_json::json!({
                "title":"Where?",
                "options":[{"id":"staging","label":"Staging"}]
            });
            let choice = draft(
                "decision-2",
                "provider-call-2",
                ASK_CHOICE_COMPONENT_NAME,
                choice_arguments,
            );
            requester
                .request_component_human_decision(&scope, &choice)
                .await
                .map_err(|error| format!("choice request: {error}"))?;
            let forged = ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer {
                choice: "staging".to_owned(),
                label: "Production".to_owned(),
            });
            if answerer
                .resolve_component_human_decision(&actor_auth, "decision-2", &forged)
                .await
                != Err(ComponentAdministrationError::InvalidInput {
                    field: "component_answer",
                })
            {
                return Err("choice label must match stored option".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let audits = client
                .query(
                    "SELECT event_type,payload::text AS payload FROM public.audit_events
                      WHERE event_type LIKE 'component.human_%' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if audits.len() != 3
                || audits[0].get::<_, String>("event_type") != "component.human_requested"
                || audits[1].get::<_, String>("event_type") != "component.human_answered"
                || audits[2].get::<_, String>("event_type") != "component.human_requested"
                || audits.iter().any(|row| {
                    let payload: String = row.get("payload");
                    payload.contains("Refund")
                        || payload.contains("exact reason")
                        || payload.contains("Staging")
                })
            {
                return Err(format!("human decision audit drifted: {audits:?}"));
            }
            drop(client);

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION fail_human_decision_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN IF NEW.event_type='component.human_answered' THEN
                         RAISE EXCEPTION 'forced human audit failure'; END IF; RETURN NEW; END $$;
                     CREATE TRIGGER fail_human_decision_audit_trigger BEFORE INSERT ON public.audit_events
                       FOR EACH ROW EXECUTE FUNCTION fail_human_decision_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let exact_choice = ComponentHumanDecisionAnswer::Choice(ComponentChoiceAnswer {
                choice: "staging".to_owned(),
                label: "Staging".to_owned(),
            });
            if answerer
                .resolve_component_human_decision(&actor_auth, "decision-2", &exact_choice)
                .await
                != Err(ComponentAdministrationError::Unavailable)
            {
                return Err("forced answer audit failure must be unavailable".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let state: String = client
                .query_one(
                    "SELECT state FROM public.component_human_decisions WHERE decision_id='decision-2'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if state != "pending" {
                return Err("answer audit failure must roll decision back to pending".to_owned());
            }
            client
                .execute(
                    "UPDATE public.users SET auth_generation=1 WHERE id='actor-a'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if requester
                .wait_component_human_decision(&scope, "decision-2")
                .await
                != Err(ComponentAdministrationError::NotVisible)
            {
                return Err("generation change must stop the durable waiter".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let cancelled: String = client
                .query_one(
                    "SELECT state FROM public.component_human_decisions WHERE decision_id='decision-2'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if cancelled != "cancelled"
                || !answerer
                    .list_component_human_decisions(&actor_auth)
                    .await
                    .map_err(|error| error.to_string())?
                    .decisions
                    .is_empty()
            {
                return Err("generation invalidation must retire and hide pending state".to_owned());
            }
            client
                .batch_execute(
                    "DROP TRIGGER fail_human_decision_audit_trigger ON public.audit_events;
                     DROP FUNCTION fail_human_decision_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let scope_v2 = ComponentHumanDecisionScope {
                auth_generation: AuthGeneration::new(1),
                ..scope.clone()
            };
            let actor_auth_v2 = auth("actor-a", 1);
            let expiry = draft(
                "decision-3",
                "provider-call-3",
                ASK_APPROVAL_COMPONENT_NAME,
                serde_json::json!({"title":"Proceed?","summary":"Exact request"}),
            );
            requester
                .request_component_human_decision(&scope_v2, &expiry)
                .await
                .map_err(|error| format!("expiry request: {error}"))?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.component_human_decisions
                        SET created_at=clock.now-interval '2 hours',
                            requested_at=clock.now-interval '2 hours',
                            expires_at=clock.now-interval '1 hour',
                            updated_at=clock.now
                       FROM (SELECT clock_timestamp() AS now) clock
                      WHERE decision_id='decision-3'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if answerer
                .resolve_component_human_decision(&actor_auth_v2, "decision-3", &different)
                .await
                != Err(ComponentAdministrationError::NotVisible)
            {
                return Err("expired decision must not accept an answer".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let expired: String = client
                .query_one(
                    "SELECT state FROM public.component_human_decisions WHERE decision_id='decision-3'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if expired != "expired" {
                return Err("database-clock expiry must be durable".to_owned());
            }
            client
                .batch_execute(
                    "CREATE FUNCTION fail_human_decision_request_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN IF NEW.event_type='component.human_requested' THEN
                         RAISE EXCEPTION 'forced request audit failure'; END IF; RETURN NEW; END $$;
                     CREATE TRIGGER fail_human_decision_request_audit_trigger
                       BEFORE INSERT ON public.audit_events FOR EACH ROW
                       EXECUTE FUNCTION fail_human_decision_request_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let request_failure = draft(
                "decision-4",
                "provider-call-4",
                ASK_APPROVAL_COMPONENT_NAME,
                serde_json::json!({"title":"Proceed?","summary":"Exact request"}),
            );
            if requester
                .request_component_human_decision(&scope_v2, &request_failure)
                .await
                != Err(ComponentAdministrationError::Unavailable)
            {
                return Err("forced request audit failure must be unavailable".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let leaked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.component_human_decisions
                      WHERE decision_id='decision-4'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if leaked != 0 {
                return Err("request audit failure must roll the pending row back".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

fn auth(actor: &str, generation: u64) -> openbot_contracts::auth::AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("deployment-a"),
        TenantId::new("tenant-a"),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_roles([Role::User])
    .build()
}

fn draft(
    decision_id: &str,
    provider_call_id: &str,
    component_name: &str,
    arguments: serde_json::Value,
) -> ComponentHumanDecisionDraft {
    let arguments_hash = ToolArguments::new(arguments.clone())
        .unwrap()
        .canonical_hash();
    ComponentHumanDecisionDraft {
        decision_id: decision_id.to_owned(),
        provider_call_id: provider_call_id.to_owned(),
        component_name: component_name.to_owned(),
        arguments,
        arguments_hash,
        ttl: COMPONENT_HUMAN_DECISION_TTL,
    }
}
