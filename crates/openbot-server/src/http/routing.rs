//! Native channel-recipient routing HTTP framing.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue};
use openbot_contracts::command::{
    AppCommand, AppReply, ChannelRoutingDecision, RouteChannelRequest,
};
use openbot_contracts::error::AppError;

use crate::auth::OriginAuthenticated;
use crate::error::HttpError;
use crate::http::ServerState;

/// `POST /api/route`; same-origin authentication is resolved before untrusted JSON is parsed.
pub async fn choose(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<RouteChannelRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ChannelRoutingDecision>), HttpError> {
    let Json(body) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "channel routing body parsing failed");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::RouteChannelMessage {
                text: body.text,
                agent_id: body.agent_id,
            },
        )
        .await?
    {
        AppReply::ChannelRouting(decision) => {
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((headers, Json(decision)))
        }
        _ => {
            tracing::error!("RouteChannelMessage received a non-routing application reply");
            Err(AppError::DependencyUnavailable {
                dependency: "application",
            }
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request, StatusCode};
    use openbot_application::{
        AgentDirectory, AgentReachability, AgentReadScope, ChannelCursor, ChannelReader,
        ChannelRoutingBackend, ChannelRoutingBackendError, OpenBotApplication, PortError,
        RoutingAuditRecord,
    };
    use openbot_contracts::agent::{AgentProfile, AgentVisibility};
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
    use openbot_domain::identity::session::TrustedOrigins;
    use openbot_infra::auth::config::default_session_lifetime;
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{FixedAuthResolver, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

    #[derive(Clone, Copy)]
    struct EmptyChannels;

    #[async_trait]
    impl ChannelReader for EmptyChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone)]
    struct FakeAgents {
        profiles: Vec<AgentProfile>,
        calls: Arc<Mutex<Vec<AgentReadScope>>>,
    }

    #[async_trait]
    impl AgentDirectory for FakeAgents {
        async fn list_visible_agents(
            &self,
            scope: &AgentReadScope,
            hidden: bool,
        ) -> Result<Vec<AgentProfile>, PortError> {
            assert!(!hidden);
            self.calls.lock().expect("agent calls").push(scope.clone());
            Ok(self.profiles.clone())
        }

        async fn get_visible_agent(
            &self,
            _scope: &AgentReadScope,
            _agent_id: &BotId,
        ) -> Result<Option<AgentProfile>, PortError> {
            unreachable!("routing performs one roster read")
        }
    }

    #[derive(Clone)]
    struct FakeRouting {
        answer: String,
        record_error: Option<ChannelRoutingBackendError>,
        prompts: Arc<Mutex<Vec<String>>>,
        audits: Arc<Mutex<Vec<RoutingAuditRecord>>>,
    }

    impl FakeRouting {
        fn answering(answer: &str) -> Self {
            Self {
                answer: answer.to_owned(),
                record_error: None,
                prompts: Arc::new(Mutex::new(Vec::new())),
                audits: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl ChannelRoutingBackend for FakeRouting {
        async fn complete(&self, prompt: &str) -> Result<String, ChannelRoutingBackendError> {
            self.prompts
                .lock()
                .expect("routing prompts")
                .push(prompt.to_owned());
            Ok(self.answer.clone())
        }

        async fn reachable_systems(
            &self,
            agents: &[BotId],
        ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
            Ok(agents
                .iter()
                .cloned()
                .map(|agent_id| AgentReachability {
                    agent_id,
                    systems: Vec::new(),
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
            self.audits.lock().expect("routing audits").push(record);
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
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    fn app(agents: FakeAgents, routing: FakeRouting, resolver: FixedAuthResolver) -> Router {
        let application = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_agent_directory(Arc::new(agents))
                .with_channel_routing(Arc::new(routing)),
        );
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .into_router()
    }

    async fn post(
        router: Router,
        origin: Option<&str>,
        body: &str,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/route")
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router
            .oneshot(
                request
                    .body(Body::from(body.to_owned()))
                    .expect("route request"),
            )
            .await
            .expect("route response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("route body");
        let body = serde_json::from_slice(&bytes).expect("route json");
        (status, headers, body)
    }

    #[tokio::test]
    async fn a_named_coworker_is_recorded_as_the_person_s_own_choice() {
        let agents = agents();
        let routing = FakeRouting::answering("must not be called");
        let visible = routing.clone();
        let (status, headers, body) = post(
            app(agents, routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"deadline?","agentId":"knowledge"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(body["agentId"], "knowledge");
        assert_eq!(body["name"], "Knowledge");
        assert_eq!(body["viaMention"], true);
        assert_eq!(body.as_object().unwrap().len(), 5);
        assert!(visible.prompts.lock().unwrap().is_empty());
        assert_eq!(visible.audits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn naming_a_coworker_never_asks_the_model() {
        let routing = FakeRouting::answering("must not be called");
        let visible = routing.clone();
        let (status, _, _) = post(
            app(agents(), routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"hello","agentId":"knowledge"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(visible.prompts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_inferred_choice_is_still_recorded_as_inferred() {
        let routing = FakeRouting::answering(
            r#"{"agentId":"knowledge","reason":"policy lookup","confidence":0.9}"#,
        );
        let visible = routing.clone();
        let (status, _, body) = post(
            app(agents(), routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"find the policy","agentId":null}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["agentId"], "knowledge");
        assert_eq!(body["viaMention"], false);
        assert_eq!(visible.prompts.lock().unwrap().len(), 1);
        assert!(!visible.audits.lock().unwrap()[0].via_mention);
    }

    #[tokio::test]
    async fn a_coworker_who_is_not_on_the_roster_is_refused_not_redirected() {
        let routing = FakeRouting::answering("must not be called");
        let visible = routing.clone();
        let (status, _, body) = post(
            app(agents(), routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"hello","agentId":"outside"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"code":"not_visible"}));
        assert!(visible.prompts.lock().unwrap().is_empty());
        assert!(visible.audits.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_blank_agentid_is_a_message_with_no_mention_not_a_broken_one() {
        let routing =
            FakeRouting::answering(r#"{"agentId":"knowledge","reason":"lookup","confidence":0.9}"#);
        let visible = routing.clone();
        let (status, _, body) = post(
            app(agents(), routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"hello","agentId":"   "}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["viaMention"], false);
        assert_eq!(visible.prompts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn auth_origin_and_json_precede_roster_and_candidate_changes_are_409() {
        let first_agents = agents();
        let calls = first_agents.calls.clone();
        let (status, _, _) = post(
            app(
                first_agents,
                FakeRouting::answering("unused"),
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            None,
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(calls.lock().unwrap().is_empty());

        let second_agents = agents();
        let calls = second_agents.calls.clone();
        let (status, _, _) = post(
            app(
                second_agents,
                FakeRouting::answering("unused"),
                FixedAuthResolver::granting(auth()),
            ),
            Some("https://app.example.test"),
            r#"{"text":"hello","actor":"forged"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(calls.lock().unwrap().is_empty());

        let mut routing = FakeRouting::answering("unused");
        routing.record_error = Some(ChannelRoutingBackendError::CandidateSetChanged);
        let (status, _, body) = post(
            app(agents(), routing, FixedAuthResolver::granting(auth())),
            Some("https://app.example.test"),
            r#"{"text":"hello","agentId":"knowledge"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, serde_json::json!({"code":"request_conflict"}));
    }
}
