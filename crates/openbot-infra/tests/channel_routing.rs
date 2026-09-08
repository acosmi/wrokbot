//! PostgreSQL evidence for Agent reach projection, candidate recheck, and secret-free audit.

mod harness;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    ChannelRoutingBackend, ChannelRoutingBackendError, ProviderAdapter, ProviderEvent,
    ProviderPortError, ProviderRequest, ProviderSession, RoutingAuditRecord, route_channel_message,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_domain::routing::RoutingReasonCode;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::PostgresAgentDirectory;
use openbot_infra::routing::PostgresChannelRouting;

struct EventSession {
    events: VecDeque<ProviderEvent>,
}

#[async_trait]
impl ProviderSession for EventSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.events.pop_front())
    }
}

struct RecordingProvider {
    requests: Arc<Mutex<Vec<ProviderRequest>>>,
}

#[async_trait]
impl ProviderAdapter for RecordingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.requests.lock().unwrap().push(request);
        Ok(Box::new(EventSession {
            events: vec![
                ProviderEvent::ResponseStarted {
                    response_id: "routing-response".to_owned(),
                },
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: r#"{"agentId":"knowledge","reason":"Drive lookup","confidence":0.9}"#
                        .to_owned(),
                },
                ProviderEvent::Completed,
            ]
            .into(),
        }))
    }
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new("actor"),
        AuthGeneration::new(1),
        false,
    )
    .with_role(Role::User)
    .build()
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn route_uses_active_reach_and_appends_one_hash_chained_message_free_audit() {
    let admin =
        admin_config("route_uses_active_reach_and_appends_one_hash_chained_message_free_audit");
    with_temp_database(&admin, "channelrouting", |config| async move {
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
                    "INSERT INTO public.users(id,email) VALUES
                       ('actor','actor@example.test'),('other','other@example.test');
                     INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                       VALUES('tenant','/tenant','checksum');
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'general','General','built_in','{}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant';
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       SELECT 'knowledge','Knowledge','built_in','{}',id
                         FROM public.deployment_packages WHERE tenant_id='tenant';
                     INSERT INTO public.agents(id,name,type,configuration,package_id)
                       VALUES('private-other','Private','built_in','{}',NULL);
                     INSERT INTO public.agent_profiles(
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                     ) VALUES
                       ('general',NULL,'General','everyday work','g','public'),
                       ('knowledge',NULL,'Knowledge','company knowledge','k','public'),
                       ('private-other','other','Private','private work','p','private');
                     INSERT INTO public.plugin_grants(
                       kind,ref,agent_id,state,catalog_generation,schema_hash,effect,
                       transport_fingerprint,credential_generation
                     ) VALUES(
                       'mcp','google-drive/search_files','knowledge','active',1,
                       repeat('a',64),'read',repeat('b',64),0
                     );",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let requests = Arc::new(Mutex::new(Vec::new()));
            let routing = PostgresChannelRouting::new(
                pool.clone(),
                vec![0x72; 32],
                Arc::new(RecordingProvider {
                    requests: requests.clone(),
                }),
            )
            .map_err(|error| error.to_string())?;
            let decision = route_channel_message(
                &PostgresAgentDirectory::new(pool.clone()),
                &routing,
                &auth(),
                "PRIVATE ROUTING MESSAGE CANARY".to_owned(),
                None,
            )
            .await
            .map_err(|error| error.to_string())?;
            if decision.agent_id.as_str() != "knowledge"
                || decision.name != "Knowledge"
                || decision.reason != "Drive lookup"
                || decision.fallback
                || decision.via_mention
            {
                return Err(format!("routing decision drifted: {decision:?}"));
            }
            let request_matches = {
                let requests = requests.lock().unwrap();
                requests.len() == 1
                    && requests[0].tools.is_empty()
                    && requests[0].max_output_tokens == Some(512)
                    && requests[0].messages[0]
                        .content
                        .contains("can reach: google-drive")
            };
            if !request_matches {
                return Err("routing request omitted bounded reach/model framing".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT actor_user_id,event_type,target_type,target_id,payload,
                            prev_hash,row_hash
                       FROM public.audit_events",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let payload: serde_json::Value = row.try_get("payload").map_err(|e| e.to_string())?;
            if row
                .try_get::<_, String>("actor_user_id")
                .map_err(|e| e.to_string())?
                != "actor"
                || row
                    .try_get::<_, String>("event_type")
                    .map_err(|e| e.to_string())?
                    != "channel.routed"
                || row
                    .try_get::<_, String>("target_type")
                    .map_err(|e| e.to_string())?
                    != "agent"
                || row
                    .try_get::<_, String>("target_id")
                    .map_err(|e| e.to_string())?
                    != "knowledge"
                || payload
                    != serde_json::json!({
                        "chosen":"knowledge",
                        "reason":"model_match",
                        "fallback":false,
                        "via_mention":false,
                        "candidates":["general","knowledge"]
                    })
                || row
                    .try_get::<_, Option<String>>("prev_hash")
                    .map_err(|e| e.to_string())?
                    .is_some()
                || row
                    .try_get::<_, Option<String>>("row_hash")
                    .map_err(|e| e.to_string())?
                    .is_none()
            {
                return Err(format!("routing audit drifted: {payload}"));
            }
            let audit_text: String = client
                .query_one(
                    "SELECT payload::text || coalesce(target_id,'') FROM public.audit_events",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if audit_text.contains("PRIVATE ROUTING MESSAGE CANARY")
                || audit_text.contains("Drive lookup")
            {
                return Err("routing audit retained message or model prose".to_owned());
            }
            client
                .execute(
                    "INSERT INTO public.agent_preferences(user_id,agent_id,hidden_at)
                     VALUES('actor','general',clock_timestamp())",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let stale = routing
                .record_routing(RoutingAuditRecord {
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("actor"),
                    admin: false,
                    roster: vec![BotId::new("general"), BotId::new("knowledge")],
                    chosen: BotId::new("knowledge"),
                    reason: RoutingReasonCode::ModelMatch,
                    fallback: false,
                    via_mention: false,
                    candidates: vec![BotId::new("general"), BotId::new("knowledge")],
                })
                .await;
            if stale != Err(ChannelRoutingBackendError::CandidateSetChanged) {
                return Err(format!("stale candidate set was not refused: {stale:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let count: i64 = client
                .query_one("SELECT count(*)::bigint FROM public.audit_events", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if count != 1 {
                return Err("candidate conflict appended a second audit row".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
