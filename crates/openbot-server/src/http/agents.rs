//! Remote Agent callback-token HTTP framing; authorization and mutation remain in application/infra.

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use http::header::CACHE_CONTROL;
use http::{HeaderMap, HeaderValue, StatusCode};
use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentMutationRequest, AgentProfileResponse,
    AgentProfilesResponse, CallbackTokenIssued,
};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;
use serde::Deserialize;

use crate::auth::{Authenticated, FreshOriginAuthenticated, SensitiveAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// Closed Agent roster query.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentListQuery {
    /// True selects this actor's hidden roster instead of the default roster.
    pub hidden: Option<bool>,
}

/// `GET /api/agents`.
pub async fn list_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    query: Result<Query<AgentListQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<AgentProfilesResponse>), HttpError> {
    let Query(query) = query.map_err(|error| {
        tracing::debug!(error = %error, "agent list query rejected");
        AppError::MalformedPayload { field: "query" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::ListVisibleAgents {
                hidden: query.hidden.unwrap_or(false),
            },
        )
        .await?
    {
        AppReply::Agents(agents) => {
            Ok((no_store_headers(), Json(AgentProfilesResponse { agents })))
        }
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/agents/{agent_id}`.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(agent_id): Path<String>,
) -> Result<(HeaderMap, Json<AgentProfileResponse>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetVisibleAgent {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::Agent(agent) => Ok((no_store_headers(), Json(AgentProfileResponse { agent }))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/agents`; fresh same-origin member creates one caller-owned Agent.
pub async fn create_post(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    body: Result<Json<AgentMutationRequest>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<AgentProfileResponse>), HttpError> {
    let Json(request) = agent_body(body)?;
    match state
        .application()
        .execute(auth, AppCommand::CreateAgent(request))
        .await?
    {
        AppReply::Agent(agent) => Ok((
            StatusCode::CREATED,
            no_store_headers(),
            Json(AgentProfileResponse { agent }),
        )),
        _ => Err(application_contract_error()),
    }
}

/// `PATCH /api/agents/{agent_id}`.
pub async fn update_patch(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    Path(agent_id): Path<String>,
    body: Result<Json<AgentMutationRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<AgentProfileResponse>), HttpError> {
    let Json(request) = agent_body(body)?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::UpdateAgent {
                agent_id: BotId::new(agent_id),
                request,
            },
        )
        .await?
    {
        AppReply::Agent(agent) => Ok((no_store_headers(), Json(AgentProfileResponse { agent }))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/agents/{agent_id}/duplicate`.
pub async fn duplicate_post(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    Path(agent_id): Path<String>,
) -> Result<(StatusCode, HeaderMap, Json<AgentProfileResponse>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::DuplicateAgent {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::Agent(agent) => Ok((
            StatusCode::CREATED,
            no_store_headers(),
            Json(AgentProfileResponse { agent }),
        )),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/agents/{agent_id}/hide`.
pub async fn hide_post(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, HttpError> {
    set_hidden(state, auth, agent_id, true).await
}

/// `POST /api/agents/{agent_id}/unhide`.
pub async fn unhide_post(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, HttpError> {
    set_hidden(state, auth, agent_id, false).await
}

/// `DELETE /api/agents/{agent_id}`.
pub async fn delete_agent(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::DeleteAgent {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::AgentLifecycle(_) => Ok(StatusCode::NO_CONTENT),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/agents/test-connection`; a failed endpoint verdict is still HTTP 200.
pub async fn test_connection_post(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    body: Result<Json<AgentConnectionTestRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<AgentConnectionVerdict>), HttpError> {
    let Json(request) = body.map_err(|error| {
        tracing::debug!(error = %error, "agent connection test body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::TestAgentConnection(request))
        .await?
    {
        AppReply::AgentConnectionVerdict(verdict) => Ok((no_store_headers(), Json(verdict))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/agents/{agent_id}/callback-token`; cleartext appears in this response once.
pub async fn callback_token_post(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<(StatusCode, Json<CallbackTokenIssued>), HttpError> {
    state
        .authorize_fresh_origin_write(&resolved, request_origin(&headers))
        .await?;
    match state
        .application()
        .execute(
            resolved.into_context(),
            AppCommand::IssueAgentCallbackToken {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::AgentCallbackToken(token) => Ok((StatusCode::CREATED, Json(token))),
        _ => Err(application_contract_error()),
    }
}

/// `DELETE /api/agents/{agent_id}/callback-token`.
pub async fn callback_token_delete(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, HttpError> {
    state
        .authorize_fresh_origin_write(&resolved, request_origin(&headers))
        .await?;
    match state
        .application()
        .execute(
            resolved.into_context(),
            AppCommand::RevokeAgentCallbackToken {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::AgentCallbackTokenRevoked(_) => Ok(StatusCode::NO_CONTENT),
        _ => Err(application_contract_error()),
    }
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::ORIGIN)
        .map(|value| value.to_str().unwrap_or(""))
}

async fn set_hidden(
    state: ServerState,
    auth: openbot_contracts::auth::AuthContext,
    agent_id: String,
    hidden: bool,
) -> Result<StatusCode, HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::SetAgentHidden {
                agent_id: BotId::new(agent_id),
                hidden,
            },
        )
        .await?
    {
        AppReply::AgentLifecycle(_) => Ok(StatusCode::NO_CONTENT),
        _ => Err(application_contract_error()),
    }
}

fn agent_body(
    body: Result<Json<AgentMutationRequest>, JsonRejection>,
) -> Result<Json<AgentMutationRequest>, HttpError> {
    body.map_err(|error| {
        tracing::debug!(error = %error, "agent mutation body rejected");
        AppError::MalformedPayload { field: "body" }.into()
    })
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn application_contract_error() -> HttpError {
    tracing::error!("agent command 收到不匹配 reply");
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request};
    use openbot_application::{
        AgentAdministration, AgentAdministrationError, AgentAdministrationScope,
        AgentCallbackTokenAdministration, AgentCallbackTokenError, AgentDirectory, AgentReadScope,
        ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    };
    use openbot_contracts::agent::{
        AgentConnectionTestRequest, AgentConnectionVerdict, AgentLifecycleReceipt,
        AgentLifecycleState, AgentMutationRequest, AgentProfile, AgentVisibility,
        CallbackTokenIssued, CallbackTokenRevoked,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_domain::identity::session::{
        SessionLifetimePolicy, SessionState, TrustedOrigins, evaluate_session,
    };
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::{ServerBuilder, router};

    type AgentDirectoryCall = (AgentReadScope, Option<BotId>, bool);

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
    struct FakeAgentDirectory {
        profiles: Arc<Vec<AgentProfile>>,
        calls: Arc<Mutex<Vec<AgentDirectoryCall>>>,
        unavailable: bool,
    }

    impl FakeAgentDirectory {
        fn new() -> Self {
            Self {
                profiles: Arc::new(vec![AgentProfile {
                    id: BotId::new("agent-1"),
                    name: "Agent One".to_owned(),
                    title: "Operations".to_owned(),
                    role_description: "Handle operations".to_owned(),
                    avatar_seed: "seed".to_owned(),
                    visibility: AgentVisibility::Public,
                    endpoint: None,
                    has_auth: false,
                    has_callback_token: false,
                    hidden: false,
                    system_owned: true,
                    can_manage: false,
                    mine: false,
                }]),
                calls: Arc::new(Mutex::new(Vec::new())),
                unavailable: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                unavailable: true,
                ..Self::new()
            }
        }
    }

    #[async_trait]
    impl AgentDirectory for FakeAgentDirectory {
        async fn list_visible_agents(
            &self,
            scope: &AgentReadScope,
            hidden: bool,
        ) -> Result<Vec<AgentProfile>, PortError> {
            self.calls
                .lock()
                .unwrap()
                .push((scope.clone(), None, hidden));
            if self.unavailable {
                return Err(PortError::Unavailable {
                    dependency: "database",
                });
            }
            Ok(self.profiles.as_ref().clone())
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
            if self.unavailable {
                return Err(PortError::Unavailable {
                    dependency: "database",
                });
            }
            Ok(self
                .profiles
                .iter()
                .find(|profile| &profile.id == agent_id)
                .cloned())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Issue(ActorId, BotId),
        Revoke(ActorId, BotId),
    }

    #[derive(Clone, Default)]
    struct FakeTokens {
        calls: Arc<Mutex<Vec<Call>>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum LifecycleCall {
        Create(AgentAdministrationScope),
        Update(AgentAdministrationScope, BotId),
        Duplicate(AgentAdministrationScope, BotId),
        Hidden(AgentAdministrationScope, BotId, bool),
        Delete(AgentAdministrationScope, BotId),
        Probe(AgentAdministrationScope),
    }

    #[derive(Clone, Default)]
    struct FakeLifecycle {
        calls: Arc<Mutex<Vec<LifecycleCall>>>,
        failure: Arc<Mutex<Option<AgentAdministrationError>>>,
    }

    impl FakeLifecycle {
        fn failing(error: AgentAdministrationError) -> Self {
            Self {
                calls: Arc::default(),
                failure: Arc::new(Mutex::new(Some(error))),
            }
        }
    }

    #[async_trait]
    impl AgentAdministration for FakeLifecycle {
        async fn create_agent(
            &self,
            scope: &AgentAdministrationScope,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Create(scope.clone()));
            if let Some(error) = *self.failure.lock().unwrap() {
                return Err(error);
            }
            Ok(lifecycle_profile("created", request))
        }

        async fn update_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
            request: AgentMutationRequest,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Update(scope.clone(), agent_id.clone()));
            Ok(lifecycle_profile(agent_id.as_str(), request))
        }

        async fn duplicate_agent(
            &self,
            scope: &AgentAdministrationScope,
            agent_id: &BotId,
        ) -> Result<AgentProfile, AgentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Duplicate(scope.clone(), agent_id.clone()));
            Ok(lifecycle_profile(
                "copy",
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
            self.calls.lock().unwrap().push(LifecycleCall::Hidden(
                scope.clone(),
                agent_id.clone(),
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
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Delete(scope.clone(), agent_id.clone()));
            Ok(AgentLifecycleReceipt {
                agent_id: agent_id.clone(),
                state: AgentLifecycleState::Deleted,
            })
        }

        async fn test_agent_connection(
            &self,
            scope: &AgentAdministrationScope,
            _request: AgentConnectionTestRequest,
        ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Probe(scope.clone()));
            Ok(AgentConnectionVerdict::working(vec![
                "RUN_STARTED".to_owned(),
            ]))
        }
    }

    fn lifecycle_profile(id: &str, request: AgentMutationRequest) -> AgentProfile {
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
    impl AgentCallbackTokenAdministration for FakeTokens {
        async fn issue(
            &self,
            auth: &AuthContext,
            agent: &BotId,
        ) -> Result<CallbackTokenIssued, AgentCallbackTokenError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Issue(auth.actor().clone(), agent.clone()));
            CallbackTokenIssued::new("obot_agt_one-time-response".to_owned())
                .map_err(|_| AgentCallbackTokenError::Corrupt { field: "token" })
        }

        async fn revoke(
            &self,
            auth: &AuthContext,
            agent: &BotId,
        ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Revoke(auth.actor().clone(), agent.clone()));
            Ok(CallbackTokenRevoked)
        }
    }

    fn lifetime() -> SessionLifetimePolicy {
        SessionLifetimePolicy::new(Duration::hours(8), Duration::days(7), Duration::minutes(15))
            .unwrap()
    }

    fn app(tokens: FakeTokens, session_age: Duration) -> axum::Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("owner"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let live = evaluate_session(
            lifetime(),
            SessionState::rehydrate(now - session_age, now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        router(
            ServerBuilder::new(
                Arc::new(OpenBotApplication::new(EmptyChannels).with_agent_callback_tokens(tokens)),
                Arc::new(resolver),
            )
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .build(),
        )
    }

    fn lifecycle_app(lifecycle: FakeLifecycle, session_age: Duration) -> axum::Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("owner"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let live = evaluate_session(
            lifetime(),
            SessionState::rehydrate(now - session_age, now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        router(
            ServerBuilder::new(
                Arc::new(
                    OpenBotApplication::new(EmptyChannels)
                        .with_agent_administration(Arc::new(lifecycle)),
                ),
                Arc::new(resolver),
            )
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .build(),
        )
    }

    fn lifecycle_request(method: Method, path: &str, body: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::ORIGIN, "https://app.example.test");
        if body.is_some() {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(Body::from(body.unwrap_or_default().to_owned()))
            .unwrap()
    }

    fn request(method: Method, origin: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri("/api/agents/remote-1/callback-token");
        if let Some(origin) = origin {
            builder = builder.header(http::header::ORIGIN, origin);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn send_full(
        router: axum::Router,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    async fn send(router: axum::Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = send_full(router, request).await;
        (status, body)
    }

    fn read_app(agents: FakeAgentDirectory, resolver: FixedAuthResolver) -> axum::Router {
        router(
            ServerBuilder::new(
                Arc::new(
                    OpenBotApplication::new(EmptyChannels).with_agent_directory(Arc::new(agents)),
                ),
                Arc::new(resolver),
            )
            .build(),
        )
    }

    fn read_auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("reader"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn agent_list_and_detail_use_authenticated_scope_and_exact_envelopes() {
        let agents = FakeAgentDirectory::new();
        let visible = agents.clone();
        let (status, headers, body) = send_full(
            read_app(agents, FixedAuthResolver::granting(read_auth())),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents?hidden=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["agents"][0]["id"], "agent-1");
        assert_eq!(value["agents"][0]["systemOwned"], true);
        assert!(value["agents"][0].get("ownerUserId").is_none());
        assert_eq!(
            visible.calls.lock().unwrap().as_slice(),
            [(
                AgentReadScope {
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("reader"),
                    admin: false,
                },
                None,
                true,
            )]
        );

        let (status, headers, body) = send_full(
            read_app(
                FakeAgentDirectory::new(),
                FixedAuthResolver::granting(read_auth()),
            ),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents/agent-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["agent"]["name"], "Agent One");
    }

    #[tokio::test]
    async fn agent_reads_authenticate_first_reject_unknown_query_and_collapse_missing_to_404() {
        let agents = FakeAgentDirectory::new();
        let untouched = agents.clone();
        let (status, _) = send(
            read_app(
                agents,
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents?principal=admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(untouched.calls.lock().unwrap().is_empty());

        let agents = FakeAgentDirectory::new();
        let untouched = agents.clone();
        let (status, _) = send(
            read_app(agents, FixedAuthResolver::granting(read_auth())),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents?principal=admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(untouched.calls.lock().unwrap().is_empty());

        let (status, body) = send(
            read_app(
                FakeAgentDirectory::new(),
                FixedAuthResolver::granting(read_auth()),
            ),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"code":"not_visible"})
        );

        let (status, _) = send(
            read_app(
                FakeAgentDirectory::new(),
                FixedAuthResolver::granting(read_auth()),
            ),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents/%0A")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = send(
            read_app(
                FakeAgentDirectory::unavailable(),
                FixedAuthResolver::granting(read_auth()),
            ),
            Request::builder()
                .method(Method::GET)
                .uri("/api/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn lifecycle_origin_and_freshness_precede_body_then_all_routes_use_typed_application() {
        let lifecycle = FakeLifecycle::default();
        let malformed_without_origin = Request::builder()
            .method(Method::POST)
            .uri("/api/agents")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        let (status, _) = send(
            lifecycle_app(lifecycle.clone(), Duration::minutes(1)),
            malformed_without_origin,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(
            lifecycle_app(lifecycle.clone(), Duration::minutes(16)),
            lifecycle_request(
                Method::POST,
                "/api/agents",
                Some(
                    r#"{"name":"Agent","title":"Title","roleDescription":"Role","visibility":"private"}"#,
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(lifecycle.calls.lock().unwrap().is_empty());

        for malformed in [
            "[]",
            "{}",
            r#"{"name":"Agent","title":"Title","roleDescription":"Role","visibility":"private","ownerUserId":"forged"}"#,
            r#"{"name":" ","title":"Title","roleDescription":"Role","visibility":"private"}"#,
        ] {
            let (status, _) = send(
                lifecycle_app(lifecycle.clone(), Duration::minutes(1)),
                lifecycle_request(Method::POST, "/api/agents", Some(malformed)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body={malformed}");
        }
        assert!(lifecycle.calls.lock().unwrap().is_empty());

        let router = lifecycle_app(lifecycle.clone(), Duration::minutes(1));
        let body =
            r#"{"name":"Agent","title":"Title","roleDescription":"Role","visibility":"private"}"#;
        let (status, headers, response) = send_full(
            router.clone(),
            lifecycle_request(Method::POST, "/api/agents", Some(body)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response).unwrap()["agent"]["id"],
            "created"
        );
        assert_eq!(
            send(
                router.clone(),
                lifecycle_request(Method::PATCH, "/api/agents/created", Some(body)),
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                router.clone(),
                lifecycle_request(Method::POST, "/api/agents/created/duplicate", None),
            )
            .await
            .0,
            StatusCode::CREATED
        );
        for path in ["/api/agents/created/hide", "/api/agents/created/unhide"] {
            assert_eq!(
                send(router.clone(), lifecycle_request(Method::POST, path, None),)
                    .await
                    .0,
                StatusCode::NO_CONTENT
            );
        }
        let (status, _, response) = send_full(
            router.clone(),
            lifecycle_request(
                Method::POST,
                "/api/agents/test-connection",
                Some(r#"{"endpoint":"https://agent.example/ag-ui"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response).unwrap(),
            serde_json::json!({"ok":true,"events":["RUN_STARTED"]})
        );
        assert_eq!(
            send(
                router,
                lifecycle_request(Method::DELETE, "/api/agents/created", None),
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let calls = lifecycle.calls.lock().unwrap();
        assert_eq!(calls.len(), 7);
        assert!(calls.iter().all(|call| match call {
            LifecycleCall::Create(scope)
            | LifecycleCall::Update(scope, _)
            | LifecycleCall::Duplicate(scope, _)
            | LifecycleCall::Hidden(scope, _, _)
            | LifecycleCall::Delete(scope, _) => {
                scope.actor == ActorId::new("owner")
                    && !scope.admin
                    && scope.auth_generation == AuthGeneration::new(1)
            }
            LifecycleCall::Probe(scope) => {
                scope.actor == ActorId::new("owner")
                    && !scope.admin
                    && scope.auth_generation == AuthGeneration::new(1)
            }
        }));
    }

    #[tokio::test]
    async fn lifecycle_errors_are_closed_and_missing_adapter_stays_mounted_fail_closed() {
        let body =
            r#"{"name":"Agent","title":"Title","roleDescription":"Role","visibility":"private"}"#;
        for (error, expected) in [
            (AgentAdministrationError::NotVisible, StatusCode::NOT_FOUND),
            (AgentAdministrationError::Forbidden, StatusCode::FORBIDDEN),
            (AgentAdministrationError::Protected, StatusCode::FORBIDDEN),
            (
                AgentAdministrationError::InvalidInput { field: "endpoint" },
                StatusCode::BAD_REQUEST,
            ),
            (
                AgentAdministrationError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AgentAdministrationError::Corrupt { field: "profile" },
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AgentAdministrationError::CommitUnknown,
                StatusCode::ACCEPTED,
            ),
        ] {
            let (status, _) = send(
                lifecycle_app(FakeLifecycle::failing(error), Duration::minutes(1)),
                lifecycle_request(Method::POST, "/api/agents", Some(body)),
            )
            .await;
            assert_eq!(status, expected, "error={error:?}");
        }

        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("owner"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let live = evaluate_session(
            lifetime(),
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        let app = router(
            ServerBuilder::new(
                Arc::new(OpenBotApplication::new(EmptyChannels)),
                Arc::new(resolver),
            )
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .build(),
        );
        let (status, _) = send(
            app,
            lifecycle_request(Method::POST, "/api/agents", Some(body)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn callback_token_write_requires_origin_and_freshness_before_application() {
        let tokens = FakeTokens::default();
        let (status, _) = send(
            app(tokens.clone(), Duration::minutes(1)),
            request(Method::POST, None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(
            app(tokens.clone(), Duration::minutes(1)),
            request(Method::POST, Some("https://evil.example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(
            app(tokens.clone(), Duration::minutes(16)),
            request(Method::POST, Some("https://app.example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(tokens.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn callback_token_cleartext_is_once_and_delete_has_no_body() {
        let tokens = FakeTokens::default();
        let router = app(tokens.clone(), Duration::minutes(1));
        let (status, body) = send(
            router.clone(),
            request(Method::POST, Some("https://app.example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["token"], "obot_agt_one-time-response");

        let (status, body) = send(
            router,
            request(Method::DELETE, Some("https://app.example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        assert_eq!(
            tokens.calls.lock().unwrap().as_slice(),
            [
                Call::Issue(ActorId::new("owner"), BotId::new("remote-1")),
                Call::Revoke(ActorId::new("owner"), BotId::new("remote-1")),
            ]
        );
    }
}
