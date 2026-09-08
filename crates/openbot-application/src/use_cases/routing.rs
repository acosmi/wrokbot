//! Current-roster recipient routing and durable audit orchestration.

use openbot_contracts::agent::{AgentProfile, AgentVisibility};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::{ChannelRoutingDecision, MAX_THREAD_MESSAGE_BYTES};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;
use openbot_contracts::text::trim_ecmascript;
use openbot_domain::routing::{
    RoutingCandidate, RoutingCompletion, RoutingDecision, RoutingReasonCode, decide,
    needs_completion, routing_prompt,
};

use crate::ports::{
    AgentDirectory, AgentReadScope, ChannelRoutingBackend, PortError, RoutingAuditRecord,
};

/// Maximum candidate count that can be fully represented in one routing audit row.
pub const MAX_ROUTING_CANDIDATES: usize = 256;

/// Explicitly validate or infer a recipient and durably record why, never the source message.
pub async fn route_channel_message(
    agents: &dyn AgentDirectory,
    backend: &dyn ChannelRoutingBackend,
    auth: &AuthContext,
    text: String,
    agent_id: Option<BotId>,
) -> Result<ChannelRoutingDecision, AppError> {
    let text = trim_ecmascript(&text);
    if text.is_empty() || text.len() > MAX_THREAD_MESSAGE_BYTES || text.as_bytes().contains(&0) {
        return Err(AppError::MalformedPayload { field: "text" });
    }
    let roster = agents
        .list_visible_agents(
            &AgentReadScope {
                tenant: auth.tenant().clone(),
                actor: auth.actor().clone(),
                admin: auth.has_role(Role::Admin),
            },
            false,
        )
        .await
        .map_err(PortError::into_app_error)?;
    if roster.is_empty() {
        return Err(AppError::RequestConflict {
            resource: "routing_roster",
        });
    }
    if roster.len() > MAX_ROUTING_CANDIDATES {
        return Err(AppError::DependencyUnavailable {
            dependency: "routing_roster",
        });
    }
    let roster_snapshot = roster
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();

    let named = agent_id
        .map(|id| trim_ecmascript(id.as_str()).to_owned())
        .filter(|id| !id.is_empty());
    let (decision, via_mention, candidates) = if let Some(named) = named {
        if named.len() > 512 || named.chars().any(char::is_control) {
            return Err(AppError::MalformedPayload { field: "agent_id" });
        }
        let chosen = roster
            .iter()
            .find(|profile| profile.id.as_str() == named)
            .ok_or(AppError::NotVisible)?;
        (
            RoutingDecision {
                agent_id: chosen.id.clone(),
                name: chosen.name.clone(),
                reason: "named by the person asking".to_owned(),
                fallback: false,
                reason_code: RoutingReasonCode::ExplicitChoice,
            },
            true,
            vec![chosen.id.clone()],
        )
    } else {
        let agent_ids = roster
            .iter()
            .map(|profile| profile.id.clone())
            .collect::<Vec<_>>();
        let reaches = backend
            .reachable_systems(&agent_ids)
            .await
            .unwrap_or_default();
        let mut routing_candidates = profiles_to_candidates(&roster);
        for reachability in reaches {
            if let Some(candidate) = routing_candidates
                .iter_mut()
                .find(|candidate| candidate.id == reachability.agent_id)
            {
                candidate.reaches = reachability.systems;
            }
        }
        let preferred = roster
            .iter()
            .find(|profile| profile.visibility == AgentVisibility::Public)
            .unwrap_or(&roster[0]);
        let answer = if needs_completion(&routing_candidates) {
            backend
                .complete(&routing_prompt(text, &routing_candidates))
                .await
                .ok()
        } else {
            None
        };
        let completion = answer
            .as_deref()
            .map(RoutingCompletion::Answer)
            .unwrap_or(RoutingCompletion::Unavailable);
        let decision = decide(&routing_candidates, &preferred.id, completion);
        (decision, false, agent_ids)
    };

    backend
        .record_routing(RoutingAuditRecord {
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            admin: auth.has_role(Role::Admin),
            roster: roster_snapshot,
            chosen: decision.agent_id.clone(),
            reason: decision.reason_code,
            fallback: decision.fallback,
            via_mention,
            candidates,
        })
        .await
        .map_err(|error| match error {
            crate::ports::ChannelRoutingBackendError::CandidateSetChanged => {
                AppError::RequestConflict {
                    resource: "routing_candidates",
                }
            }
            crate::ports::ChannelRoutingBackendError::Unavailable
            | crate::ports::ChannelRoutingBackendError::Corrupt { .. } => {
                AppError::DependencyUnavailable {
                    dependency: "channel_routing_audit",
                }
            }
        })?;
    Ok(ChannelRoutingDecision {
        agent_id: decision.agent_id,
        name: decision.name,
        reason: decision.reason,
        fallback: decision.fallback,
        via_mention,
    })
}

fn profiles_to_candidates(profiles: &[AgentProfile]) -> Vec<RoutingCandidate> {
    profiles
        .iter()
        .map(|profile| RoutingCandidate {
            id: profile.id.clone(),
            name: profile.name.clone(),
            role_description: profile.role_description.clone(),
            reaches: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::agent::AgentVisibility;
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

    use super::*;
    use crate::ports::{AgentReachability, ChannelRoutingBackendError, PortError};

    struct FakeAgents {
        profiles: Vec<AgentProfile>,
        scopes: Mutex<Vec<AgentReadScope>>,
    }

    #[async_trait]
    impl AgentDirectory for FakeAgents {
        async fn list_visible_agents(
            &self,
            scope: &AgentReadScope,
            hidden: bool,
        ) -> Result<Vec<AgentProfile>, PortError> {
            assert!(!hidden);
            self.scopes.lock().unwrap().push(scope.clone());
            Ok(self.profiles.clone())
        }

        async fn get_visible_agent(
            &self,
            _scope: &AgentReadScope,
            _agent_id: &BotId,
        ) -> Result<Option<AgentProfile>, PortError> {
            unreachable!("routing uses one authoritative roster query")
        }
    }

    struct FakeBackend {
        answer: Option<String>,
        record_error: Option<ChannelRoutingBackendError>,
        complete_prompts: Mutex<Vec<String>>,
        reach_calls: Mutex<Vec<Vec<BotId>>>,
        audits: Mutex<Vec<RoutingAuditRecord>>,
    }

    impl FakeBackend {
        fn answering(answer: &str) -> Self {
            Self {
                answer: Some(answer.to_owned()),
                record_error: None,
                complete_prompts: Mutex::new(Vec::new()),
                reach_calls: Mutex::new(Vec::new()),
                audits: Mutex::new(Vec::new()),
            }
        }

        fn unavailable() -> Self {
            Self {
                answer: None,
                ..Self::answering("")
            }
        }
    }

    #[async_trait]
    impl ChannelRoutingBackend for FakeBackend {
        async fn complete(&self, prompt: &str) -> Result<String, ChannelRoutingBackendError> {
            self.complete_prompts
                .lock()
                .unwrap()
                .push(prompt.to_owned());
            self.answer
                .clone()
                .ok_or(ChannelRoutingBackendError::Unavailable)
        }

        async fn reachable_systems(
            &self,
            agents: &[BotId],
        ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
            self.reach_calls.lock().unwrap().push(agents.to_vec());
            Ok(agents
                .iter()
                .cloned()
                .map(|agent_id| AgentReachability {
                    systems: if agent_id.as_str() == "knowledge" {
                        vec!["google-drive".to_owned()]
                    } else {
                        Vec::new()
                    },
                    agent_id,
                })
                .collect())
        }

        async fn record_routing(
            &self,
            record: RoutingAuditRecord,
        ) -> Result<(), ChannelRoutingBackendError> {
            if let Some(error) = self.record_error {
                return Err(error);
            }
            self.audits.lock().unwrap().push(record);
            Ok(())
        }
    }

    fn profile(id: &str, visibility: AgentVisibility) -> AgentProfile {
        AgentProfile {
            id: BotId::new(id),
            name: match id {
                "general" => "General",
                "knowledge" => "Knowledge",
                _ => "Private",
            }
            .to_owned(),
            title: "Title".to_owned(),
            role_description: format!("{id} purpose"),
            avatar_seed: id.to_owned(),
            visibility,
            endpoint: None,
            has_auth: false,
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: false,
            mine: false,
        }
    }

    fn agents() -> FakeAgents {
        FakeAgents {
            profiles: vec![
                profile("private", AgentVisibility::Private),
                profile("general", AgentVisibility::Public),
                profile("knowledge", AgentVisibility::Public),
            ],
            scopes: Mutex::new(Vec::new()),
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(7),
            false,
        )
    }

    #[tokio::test]
    async fn a_named_coworker_is_recorded_as_the_person_s_own_choice() {
        let agents = agents();
        let backend = FakeBackend::answering("must not be used");
        let decision = route_channel_message(
            &agents,
            &backend,
            &auth(),
            "what is the deadline".to_owned(),
            Some(BotId::new("knowledge")),
        )
        .await
        .unwrap();
        assert_eq!(decision.agent_id.as_str(), "knowledge");
        assert!(decision.via_mention);
        assert!(!decision.fallback);
        assert_eq!(decision.reason, "named by the person asking");
        assert!(backend.complete_prompts.lock().unwrap().is_empty());
        assert!(backend.reach_calls.lock().unwrap().is_empty());
        assert_eq!(
            backend.audits.lock().unwrap().as_slice(),
            [RoutingAuditRecord {
                tenant: TenantId::new("tenant"),
                actor: ActorId::new("actor"),
                admin: false,
                roster: vec![
                    BotId::new("private"),
                    BotId::new("general"),
                    BotId::new("knowledge"),
                ],
                chosen: BotId::new("knowledge"),
                reason: RoutingReasonCode::ExplicitChoice,
                fallback: false,
                via_mention: true,
                candidates: vec![BotId::new("knowledge")],
            }]
        );
        assert_eq!(
            agents.scopes.lock().unwrap().as_slice(),
            [AgentReadScope {
                tenant: TenantId::new("tenant"),
                actor: ActorId::new("actor"),
                admin: false,
            }]
        );
    }

    #[tokio::test]
    async fn naming_a_coworker_never_asks_the_model_and_unknown_is_refused() {
        let agents = agents();
        let backend = FakeBackend::answering("must not be used");
        assert_eq!(
            route_channel_message(
                &agents,
                &backend,
                &auth(),
                "hello".to_owned(),
                Some(BotId::new("not-on-roster")),
            )
            .await,
            Err(AppError::NotVisible)
        );
        assert!(backend.complete_prompts.lock().unwrap().is_empty());
        assert!(backend.audits.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_inferred_choice_is_recorded_with_reach_but_not_the_message() {
        let agents = agents();
        let backend = FakeBackend::answering(
            r#"{"agentId":"knowledge","reason":"drive lookup","confidence":0.9}"#,
        );
        let decision = route_channel_message(
            &agents,
            &backend,
            &auth(),
            "PRIVATE MESSAGE CANARY".to_owned(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(decision.agent_id.as_str(), "knowledge");
        assert!(!decision.via_mention);
        let prompt = backend.complete_prompts.lock().unwrap()[0].clone();
        assert!(prompt.contains("can reach: google-drive"));
        assert!(prompt.contains("PRIVATE MESSAGE CANARY"));
        let audit = backend.audits.lock().unwrap()[0].clone();
        assert_eq!(audit.reason, RoutingReasonCode::ModelMatch);
        assert_eq!(audit.chosen.as_str(), "knowledge");
        assert!(!format!("{audit:?}").contains("PRIVATE MESSAGE CANARY"));
    }

    #[tokio::test]
    async fn blank_agent_id_is_inference_and_provider_failure_falls_back() {
        let agents = agents();
        let backend = FakeBackend::unavailable();
        let decision = route_channel_message(
            &agents,
            &backend,
            &auth(),
            "hello".to_owned(),
            Some(BotId::new("   ")),
        )
        .await
        .unwrap();
        assert_eq!(decision.agent_id.as_str(), "general");
        assert!(decision.fallback);
        assert!(!decision.via_mention);
        assert_eq!(
            backend.audits.lock().unwrap()[0].reason,
            RoutingReasonCode::RouterUnavailable
        );
    }

    #[tokio::test]
    async fn routing_audit_failure_never_returns_an_unrecorded_decision() {
        let agents = agents();
        let backend = FakeBackend {
            record_error: Some(ChannelRoutingBackendError::Unavailable),
            ..FakeBackend::answering(r#"{"agentId":"knowledge","reason":"match","confidence":0.9}"#)
        };
        assert_eq!(
            route_channel_message(&agents, &backend, &auth(), "hello".to_owned(), None).await,
            Err(AppError::DependencyUnavailable {
                dependency: "channel_routing_audit"
            })
        );
    }

    #[tokio::test]
    async fn changed_candidate_set_is_a_stable_request_conflict() {
        let agents = agents();
        let backend = FakeBackend {
            record_error: Some(ChannelRoutingBackendError::CandidateSetChanged),
            ..FakeBackend::answering("unused")
        };
        assert_eq!(
            route_channel_message(
                &agents,
                &backend,
                &auth(),
                "hello".to_owned(),
                Some(BotId::new("knowledge")),
            )
            .await,
            Err(AppError::RequestConflict {
                resource: "routing_candidates"
            })
        );
    }
}
