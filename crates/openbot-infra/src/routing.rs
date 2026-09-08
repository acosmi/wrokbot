//! Deployment-model routing completion, Agent reach hints, and hash-chained audit adapter.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use openbot_application::{
    AgentReachability, ChannelRoutingBackend, ChannelRoutingBackendError, ProviderAdapter,
    ProviderEvent, ProviderMessage, ProviderMessageRole, ProviderOutputKind, ProviderRequest,
    ProviderRoute, RoutingAuditRecord,
};
use openbot_contracts::ids::{AuditEventId, BotId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{
    AuditFact, AuditIdentifier, AuditIdentifierList, AuditLabel, AuditPayload,
};
use time::OffsetDateTime;
use tokio_postgres::IsolationLevel;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::repo::audit::append_event_in_transaction;

const ROUTING_DEADLINE: Duration = Duration::from_secs(10);
const ROUTING_MAX_OUTPUT_BYTES: usize = 16 * 1024;
const ROUTING_MAX_EVENTS: usize = 4096;
const ROUTING_MAX_OUTPUT_TOKENS: u32 = 512;

/// Production routing adapter. Provider failures are classified softly by application; audit fails hard.
#[derive(Clone)]
pub struct PostgresChannelRouting {
    pool: Pool,
    audit_key: Arc<Vec<u8>>,
    provider: Arc<dyn ProviderAdapter>,
}

impl PostgresChannelRouting {
    /// Construct with the deployment package Chat provider and audit-chain key.
    pub fn new(
        pool: Pool,
        audit_key: Vec<u8>,
        provider: Arc<dyn ProviderAdapter>,
    ) -> Result<Self, ChannelRoutingBackendError> {
        if audit_key.is_empty() {
            return Err(ChannelRoutingBackendError::Corrupt { field: "audit_key" });
        }
        Ok(Self {
            pool,
            audit_key: Arc::new(audit_key),
            provider,
        })
    }
}

impl core::fmt::Debug for PostgresChannelRouting {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresChannelRouting")
            .field("provider", &"[redacted-config]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ChannelRoutingBackend for PostgresChannelRouting {
    async fn complete(&self, prompt: &str) -> Result<String, ChannelRoutingBackendError> {
        let request = ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: prompt.to_owned(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            tools: Vec::new(),
            max_output_tokens: Some(ROUTING_MAX_OUTPUT_TOKENS),
            rate_card: None,
            cost_cap: None,
        };
        tokio::time::timeout(
            ROUTING_DEADLINE,
            collect_completion(self.provider.as_ref(), request),
        )
        .await
        .map_err(|_| {
            tracing::warn!("channel router model deadline exceeded");
            ChannelRoutingBackendError::Unavailable
        })?
    }

    async fn reachable_systems(
        &self,
        agents: &[BotId],
    ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
        if agents.is_empty() {
            return Ok(Vec::new());
        }
        let ids = agents.iter().map(BotId::as_str).collect::<Vec<_>>();
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "routing reach pool unavailable");
            ChannelRoutingBackendError::Unavailable
        })?;
        let rows = client
            .query(
                "SELECT g.agent_id,split_part(g.ref,'/',1) AS system \
                 FROM public.plugin_grants g \
                 WHERE g.kind='mcp' AND g.state='active' AND g.agent_id=ANY($1::text[]) \
                 ORDER BY g.agent_id,system",
                &[&ids],
            )
            .await
            .map_err(|error| routing_query("load Agent reach hints", error))?;
        let mut by_agent = agents
            .iter()
            .cloned()
            .map(|agent| (agent, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        for row in rows {
            let agent: String = row
                .try_get("agent_id")
                .map_err(|_| ChannelRoutingBackendError::Corrupt { field: "agent_id" })?;
            let system: String = row
                .try_get("system")
                .map_err(|_| ChannelRoutingBackendError::Corrupt { field: "system" })?;
            if system.is_empty() || system.len() > 256 || system.chars().any(char::is_control) {
                return Err(ChannelRoutingBackendError::Corrupt { field: "system" });
            }
            let Some(systems) = by_agent.get_mut(&BotId::new(agent)) else {
                return Err(ChannelRoutingBackendError::Corrupt { field: "agent_id" });
            };
            if systems.last() != Some(&system) {
                systems.push(system);
            }
        }
        Ok(by_agent
            .into_iter()
            .map(|(agent_id, systems)| AgentReachability { agent_id, systems })
            .collect())
    }

    async fn record_routing(
        &self,
        record: RoutingAuditRecord,
    ) -> Result<(), ChannelRoutingBackendError> {
        let chosen = audit_id(record.chosen.as_str(), "chosen")?;
        let candidates = AuditIdentifierList::new(
            record
                .candidates
                .iter()
                .map(|candidate| audit_id(candidate.as_str(), "candidates"))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| ChannelRoutingBackendError::Corrupt {
            field: "candidates",
        })?;
        let payload = AuditPayload::from_facts([
            AuditFact::RoutingChosen(chosen.clone()),
            AuditFact::RoutingReason(AuditLabel::new(record.reason.as_str())),
            AuditFact::RoutingFallback(record.fallback),
            AuditFact::RoutingViaMention(record.via_mention),
            AuditFact::RoutingCandidates(candidates),
        ])
        .map_err(|_| ChannelRoutingBackendError::Corrupt {
            field: "audit_payload",
        })?;
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "routing audit pool unavailable");
            ChannelRoutingBackendError::Unavailable
        })?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "begin routing audit transaction failed");
                ChannelRoutingBackendError::Unavailable
            })?;
        let current_candidates = transaction
            .query(
                "SELECT a.id
                 FROM public.agents a
                 JOIN public.agent_profiles p ON p.agent_id=a.id
                 LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
                 LEFT JOIN public.agent_preferences pref
                   ON pref.agent_id=a.id AND pref.user_id=$1
                 WHERE p.deleted_at IS NULL
                   AND (a.package_id IS NULL OR dp.tenant_id=$2)
                   AND ($3 OR p.visibility='public' OR p.owner_user_id=$1)
                   AND pref.hidden_at IS NULL
                 ORDER BY a.id
                 FOR SHARE OF a,p",
                &[
                    &record.actor.as_str(),
                    &record.tenant.as_str(),
                    &record.admin,
                ],
            )
            .await
            .map_err(|error| routing_query("recheck routing candidate set", error))?
            .into_iter()
            .map(|row| {
                row.try_get::<_, String>(0)
                    .map(BotId::new)
                    .map_err(|_| ChannelRoutingBackendError::Corrupt { field: "candidate" })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if current_candidates != record.roster {
            return Err(ChannelRoutingBackendError::CandidateSetChanged);
        }
        let created_at: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(|error| routing_query("read routing audit clock", error))?
            .try_get(0)
            .map_err(|_| ChannelRoutingBackendError::Corrupt {
                field: "database_clock",
            })?;
        let event = AuditEvent {
            id: AuditEventId::new(Uuid::now_v7().to_string()),
            actor: Some(record.actor),
            event_type: AuditEventType::CHANNEL_ROUTED,
            target_kind: AuditLabel::new("agent"),
            target_id: Some(chosen),
            payload,
            created_at,
        };
        append_event_in_transaction(&transaction, &event, self.audit_key.as_slice())
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "append routing audit failed");
                ChannelRoutingBackendError::Unavailable
            })?;
        transaction.commit().await.map_err(|error| {
            if error.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) {
                return ChannelRoutingBackendError::CandidateSetChanged;
            }
            tracing::error!(error = %error, "commit routing audit failed");
            ChannelRoutingBackendError::Unavailable
        })?;
        Ok(())
    }
}

async fn collect_completion(
    provider: &dyn ProviderAdapter,
    request: ProviderRequest,
) -> Result<String, ChannelRoutingBackendError> {
    let mut session = provider
        .start(request)
        .await
        .map_err(|_| ChannelRoutingBackendError::Unavailable)?;
    let mut output = String::new();
    for _ in 0..ROUTING_MAX_EVENTS {
        match session
            .next_event()
            .await
            .map_err(|_| ChannelRoutingBackendError::Unavailable)?
        {
            Some(ProviderEvent::TextDelta { delta, .. }) => {
                if output.len().saturating_add(delta.len()) > ROUTING_MAX_OUTPUT_BYTES {
                    return Err(ChannelRoutingBackendError::Corrupt {
                        field: "provider_output",
                    });
                }
                output.push_str(&delta);
            }
            Some(ProviderEvent::OutputItemAdded {
                kind: ProviderOutputKind::FunctionCall,
                ..
            })
            | Some(
                ProviderEvent::ToolCallStarted { .. }
                | ProviderEvent::ToolArgumentsDelta { .. }
                | ProviderEvent::ToolCallCompleted { .. },
            ) => {
                return Err(ChannelRoutingBackendError::Corrupt {
                    field: "provider_output",
                });
            }
            Some(ProviderEvent::Completed) => {
                return if output.trim().is_empty() {
                    Err(ChannelRoutingBackendError::Corrupt {
                        field: "provider_output",
                    })
                } else {
                    Ok(output)
                };
            }
            Some(ProviderEvent::Failed(_) | ProviderEvent::Interrupted(_)) | None => {
                return Err(ChannelRoutingBackendError::Unavailable);
            }
            Some(
                ProviderEvent::ResponseStarted { .. }
                | ProviderEvent::OutputItemAdded { .. }
                | ProviderEvent::ReasoningDelta { .. }
                | ProviderEvent::RemoteProjection(_)
                | ProviderEvent::Usage(_),
            ) => {}
        }
    }
    Err(ChannelRoutingBackendError::Corrupt {
        field: "provider_events",
    })
}

fn audit_id(
    value: &str,
    field: &'static str,
) -> Result<AuditIdentifier, ChannelRoutingBackendError> {
    AuditIdentifier::new(value).map_err(|_| ChannelRoutingBackendError::Corrupt { field })
}

fn routing_query(
    context: &'static str,
    error: tokio_postgres::Error,
) -> ChannelRoutingBackendError {
    tracing::error!(context, error = %error, "channel routing query failed");
    ChannelRoutingBackendError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use openbot_application::{ProviderPortError, ProviderSession};

    use super::*;

    type EventQueue = VecDeque<Result<Option<ProviderEvent>, ProviderPortError>>;

    struct EventSession {
        events: VecDeque<Result<Option<ProviderEvent>, ProviderPortError>>,
    }

    #[async_trait]
    impl ProviderSession for EventSession {
        async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
            self.events.pop_front().unwrap_or(Ok(None))
        }
    }

    struct EventProvider {
        events: Mutex<Option<EventQueue>>,
        requests: Mutex<Vec<ProviderRequest>>,
    }

    #[async_trait]
    impl ProviderAdapter for EventProvider {
        async fn start(
            &self,
            request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            self.requests.lock().unwrap().push(request);
            Ok(Box::new(EventSession {
                events: self.events.lock().unwrap().take().unwrap_or_default(),
            }))
        }
    }

    fn provider(events: Vec<ProviderEvent>) -> EventProvider {
        EventProvider {
            events: Mutex::new(Some(
                events.into_iter().map(|event| Ok(Some(event))).collect(),
            )),
            requests: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn completion_collects_only_bounded_text_until_explicit_completed() {
        let provider = provider(vec![
            ProviderEvent::ResponseStarted {
                response_id: "response-1".to_owned(),
            },
            ProviderEvent::TextDelta {
                index: 0,
                delta: "{\"agentId\":".to_owned(),
            },
            ProviderEvent::TextDelta {
                index: 0,
                delta: "\"a\"}".to_owned(),
            },
            ProviderEvent::Completed,
        ]);
        let output = collect_completion(
            &provider,
            ProviderRequest {
                route: ProviderRoute::PackageOpenAi,
                messages: vec![ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "prompt".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                }],
                tools: Vec::new(),
                max_output_tokens: Some(ROUTING_MAX_OUTPUT_TOKENS),
                rate_card: None,
                cost_cap: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(output, r#"{"agentId":"a"}"#);
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].max_output_tokens, Some(512));
        assert!(requests[0].tools.is_empty());
    }

    #[tokio::test]
    async fn completion_rejects_tool_output_empty_terminal_and_event_exhaustion() {
        for events in [
            vec![
                ProviderEvent::ToolCallStarted {
                    index: 0,
                    call_id: "call-1".to_owned(),
                    name: Some("tool".to_owned()),
                },
                ProviderEvent::Completed,
            ],
            vec![ProviderEvent::Completed],
        ] {
            let provider = provider(events);
            assert!(
                collect_completion(
                    &provider,
                    ProviderRequest {
                        route: ProviderRoute::PackageOpenAi,
                        messages: Vec::new(),
                        tools: Vec::new(),
                        max_output_tokens: Some(1),
                        rate_card: None,
                        cost_cap: None,
                    },
                )
                .await
                .is_err()
            );
        }
    }
}
