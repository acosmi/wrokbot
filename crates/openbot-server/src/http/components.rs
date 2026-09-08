//! Compiled-component list and additive build-catalogue HTTP framing.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use http::{HeaderMap, HeaderValue};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::components::{
    ComponentAgentGrantRequest, ComponentCatalogueAdded, ComponentCatalogueRequest,
    ComponentDataFunctions, ComponentDecision, ComponentDecisionRequest, ComponentDraftRequest,
    ComponentFunctionCall, ComponentFunctionCallRequest, ComponentFunctionGrantRequest,
    ComponentGovernanceMutation, ComponentGovernanceReceipt, ComponentHumanDecisionAnswer,
    ComponentHumanDecisionResolved, ComponentPublicationRequest, ComponentRecords,
    GrantedCompiledComponents, PendingComponentHumanDecisions,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;

use crate::auth::{Authenticated, OriginAuthenticated, SensitiveOriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// `GET /api/components`; any authenticated person may inspect deployment governance facts.
pub async fn list_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<ComponentRecords>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::ListComponents)
        .await?
    {
        AppReply::Components(components) => Ok((no_store(), Json(components))),
        _ => Err(application_contract_error()),
    }
}

/// `PUT /api/components/catalogue`; the application accepts only byte-exact build manifest rows.
pub async fn catalogue_put(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<ComponentCatalogueRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentCatalogueAdded>), HttpError> {
    let Json(request) = body.map_err(|error| {
        tracing::debug!(error = %error, "component catalogue body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(auth, AppCommand::SyncComponentCatalogue(request))
        .await?
    {
        AppReply::ComponentCatalogueAdded(added) => Ok((no_store(), Json(added))),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/components/for-agent/{agent_id}`; returns only current-build grants for a runnable Agent.
pub async fn for_agent_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(agent_id): Path<String>,
) -> Result<(HeaderMap, Json<GrantedCompiledComponents>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::ListComponentsForAgent {
                agent_id: BotId::new(agent_id),
            },
        )
        .await?
    {
        AppReply::GrantedComponents(components) => Ok((no_store(), Json(components))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/components/{name}/decision`; mandatory re-authorization for one exact tool call.
pub async fn decision_post(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentDecisionRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentDecision>), HttpError> {
    let Json(request) = body.map_err(|error| {
        tracing::debug!(error = %error, "component decision body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::DecideComponent {
                component_name: name,
                request,
            },
        )
        .await?
    {
        AppReply::ComponentDecision(decision) => Ok((no_store(), Json(decision))),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/components/functions`; exact build-owned data-function registry.
pub async fn functions_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<ComponentDataFunctions>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::ListComponentDataFunctions)
        .await?
    {
        AppReply::ComponentDataFunctions(functions) => Ok((no_store(), Json(functions))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/components/{name}/functions`; fresh admin grants one build-owned data function.
pub async fn functions_post(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentFunctionGrantRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    let Json(request) = component_body(body, "component function grant body rejected")?;
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SetFunctionGrant {
            component_name: name,
            function: request.function,
            granted: true,
        },
    )
    .await
}

/// `DELETE /api/components/{name}/functions/{function}`; fresh admin revokes one data function.
pub async fn functions_delete(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path((name, function)): Path<(String, String)>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SetFunctionGrant {
            component_name: name,
            function,
            granted: false,
        },
    )
    .await
}

/// `POST /api/components/{name}/grants`; fresh admin removes one Agent withholding.
pub async fn grants_post(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentAgentGrantRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    let Json(request) = component_body(body, "component Agent grant body rejected")?;
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SetAgentGrant {
            component_name: name,
            agent_id: request.agent_id,
            granted: true,
        },
    )
    .await
}

/// `DELETE /api/components/{name}/grants/{agent_id}`; fresh admin creates one withholding.
pub async fn grants_delete(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path((name, agent_id)): Path<(String, String)>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SetAgentGrant {
            component_name: name,
            agent_id: BotId::new(agent_id),
            granted: false,
        },
    )
    .await
}

/// `POST /api/components/{name}/publication`; fresh admin publishes or withdraws one compiled row.
pub async fn publication_post(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentPublicationRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    let Json(request) = component_body(body, "component publication body rejected")?;
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SetPublication {
            component_name: name,
            published: request.published,
        },
    )
    .await
}

/// `PUT /api/components/{name}/draft`; fresh admin saves a compiled description draft only.
pub async fn draft_put(
    State(state): State<ServerState>,
    SensitiveOriginAuthenticated(auth): SensitiveOriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentDraftRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    let Json(request) = component_body(body, "component draft body rejected")?;
    execute_governance(
        &state,
        auth,
        ComponentGovernanceMutation::SaveDraft {
            component_name: name,
            description: request.description,
        },
    )
    .await
}

/// `POST /api/components/{name}/call`; authorized, policy-governed component data read.
pub async fn call_post(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(name): Path<String>,
    body: Result<Json<ComponentFunctionCallRequest>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<ComponentFunctionCall>), HttpError> {
    let Json(request) = body.map_err(|error| {
        tracing::debug!(error = %error, "component function body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::CallComponentFunction {
                component_name: name,
                request,
            },
        )
        .await?
    {
        AppReply::ComponentFunctionCall(result) => {
            let status = if result.error.is_some() {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::OK
            };
            Ok((status, no_store(), Json(result)))
        }
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/components/human-decisions`; current actor's pending surface/HITL requests.
pub async fn human_decisions_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<PendingComponentHumanDecisions>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::ListPendingComponentHumanDecisions)
        .await?
    {
        AppReply::PendingComponentHumanDecisions(decisions) => Ok((no_store(), Json(decisions))),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/components/human-decisions/{decision_id}/answer`; answer body carries no bindings.
pub async fn human_decision_answer_post(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(decision_id): Path<String>,
    body: Result<Json<ComponentHumanDecisionAnswer>, JsonRejection>,
) -> Result<(HeaderMap, Json<ComponentHumanDecisionResolved>), HttpError> {
    let Json(answer) = body.map_err(|error| {
        tracing::debug!(error = %error, "component human decision body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::ResolveComponentHumanDecision {
                decision_id,
                answer,
            },
        )
        .await?
    {
        AppReply::ComponentHumanDecisionResolved(resolved) => Ok((no_store(), Json(resolved))),
        _ => Err(application_contract_error()),
    }
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn component_body<T>(
    body: Result<Json<T>, JsonRejection>,
    message: &'static str,
) -> Result<Json<T>, HttpError> {
    body.map_err(|error| {
        tracing::debug!(error = %error, "{message}");
        AppError::MalformedPayload { field: "body" }.into()
    })
}

async fn execute_governance(
    state: &ServerState,
    auth: openbot_contracts::auth::AuthContext,
    mutation: ComponentGovernanceMutation,
) -> Result<(HeaderMap, Json<ComponentGovernanceReceipt>), HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::UpdateComponentGovernance(mutation))
        .await?
    {
        AppReply::ComponentGovernanceUpdated(receipt) => Ok((no_store(), Json(receipt))),
        _ => Err(application_contract_error()),
    }
}

fn application_contract_error() -> HttpError {
    tracing::error!("component command received mismatched reply");
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        ApplicationService, ChannelReader, ComponentAdministration, ComponentAdministrationError,
        ComponentFunctionArguments, ComponentFunctionCallPlan, ComponentRuntimeScope,
        OpenBotApplication, PortError,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::components::{
        BOT_ACTIVITY_FUNCTION_NAME, BotActivityReport, CompiledComponentKind,
        CompiledComponentManifestEntry, ComponentApprovalAnswer, ComponentApprovalDecision,
        ComponentDecision, ComponentFunctionCall, ComponentFunctionData,
        ComponentHumanDecisionAnswer, ComponentHumanDecisionResolved, ComponentRecord,
        GrantedCompiledComponent, GrantedCompiledComponents, PendingComponentHumanDecision,
        PendingComponentHumanDecisions, SHOW_QUOTE_COMPONENT_NAME, compiled_component_manifest,
    };
    use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use time::OffsetDateTime;
    use tower::ServiceExt as _;

    use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

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

    #[derive(Clone, Default)]
    struct FakeComponents {
        syncs: Arc<Mutex<Vec<Vec<CompiledComponentManifestEntry>>>>,
        runtime: Arc<Mutex<Vec<String>>>,
        mutations: Arc<Mutex<Vec<ComponentGovernanceMutation>>>,
    }

    #[async_trait]
    impl ComponentAdministration for FakeComponents {
        async fn list_components(
            &self,
            _auth: &AuthContext,
        ) -> Result<ComponentRecords, ComponentAdministrationError> {
            Ok(ComponentRecords {
                components: vec![ComponentRecord {
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    title: "Quotation".to_owned(),
                    kind: CompiledComponentKind::Card,
                    draft_description: "quote".to_owned(),
                    published_description: Some("quote".to_owned()),
                    published: true,
                    published_at: Some(OffsetDateTime::UNIX_EPOCH),
                    updated_by: Some("the build".to_owned()),
                    updated_at: OffsetDateTime::UNIX_EPOCH,
                    has_unpublished_changes: false,
                    withheld_from: Vec::new(),
                    functions: Vec::new(),
                }],
            })
        }

        async fn sync_catalogue(
            &self,
            _auth: &AuthContext,
            entries: &[CompiledComponentManifestEntry],
        ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
            self.syncs.lock().unwrap().push(entries.to_vec());
            Ok(ComponentCatalogueAdded {
                added: entries.iter().map(|entry| entry.name.clone()).collect(),
            })
        }

        async fn update_component_governance(
            &self,
            _auth: &AuthContext,
            mutation: &ComponentGovernanceMutation,
        ) -> Result<ComponentRecord, ComponentAdministrationError> {
            self.mutations.lock().unwrap().push(mutation.clone());
            let mut record = ComponentRecord {
                name: mutation.component_name().to_owned(),
                title: "Quotation".to_owned(),
                kind: CompiledComponentKind::Card,
                draft_description: "quote".to_owned(),
                published_description: Some("quote".to_owned()),
                published: true,
                published_at: Some(OffsetDateTime::UNIX_EPOCH),
                updated_by: Some("actor".to_owned()),
                updated_at: OffsetDateTime::UNIX_EPOCH,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: Vec::new(),
            };
            match mutation {
                ComponentGovernanceMutation::SetAgentGrant {
                    agent_id, granted, ..
                } => {
                    if !granted {
                        record.withheld_from.push(agent_id.as_str().to_owned());
                    }
                }
                ComponentGovernanceMutation::SetFunctionGrant {
                    function, granted, ..
                } => {
                    if *granted {
                        record.functions.push(function.clone());
                    }
                }
                ComponentGovernanceMutation::SetPublication { published, .. } => {
                    record.published = *published;
                }
                ComponentGovernanceMutation::SaveDraft { description, .. } => {
                    record.draft_description = description.clone();
                    record.has_unpublished_changes = true;
                }
            }
            Ok(record)
        }

        async fn list_components_for_agent(
            &self,
            scope: &ComponentRuntimeScope,
            _renderer_names: &[String],
        ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
            self.runtime
                .lock()
                .unwrap()
                .push(format!("list:{}", scope.agent_id));
            Ok(GrantedCompiledComponents {
                components: vec![GrantedCompiledComponent {
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    description: "published quote".to_owned(),
                }],
            })
        }

        async fn decide_component(
            &self,
            scope: &ComponentRuntimeScope,
            component_name: &str,
            build_has_renderer: bool,
            functions: &[String],
        ) -> Result<ComponentDecision, ComponentAdministrationError> {
            self.runtime.lock().unwrap().push(format!(
                "decide:{}:{component_name}:{build_has_renderer}:{}",
                scope.agent_id,
                functions.join(",")
            ));
            Ok(ComponentDecision::allowed())
        }

        async fn call_component_function(
            &self,
            scope: &ComponentRuntimeScope,
            component_name: &str,
            build_has_renderer: bool,
            plan: &ComponentFunctionCallPlan,
        ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
            self.runtime.lock().unwrap().push(format!(
                "call:{}:{component_name}:{build_has_renderer}:{}",
                scope.agent_id, plan.function
            ));
            let days = match plan.arguments {
                Some(ComponentFunctionArguments::BotActivity { days }) => days,
                _ => return Err(ComponentAdministrationError::Corrupt { field: "arguments" }),
            };
            if days == 13 {
                return Ok(ComponentFunctionCall::failed(
                    openbot_contracts::components::ComponentFunctionError::ReadFailed,
                ));
            }
            Ok(ComponentFunctionCall::succeeded(
                ComponentFunctionData::BotActivity(BotActivityReport {
                    days,
                    rows: Vec::new(),
                }),
            ))
        }

        async fn list_component_human_decisions(
            &self,
            _auth: &AuthContext,
        ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
            Ok(PendingComponentHumanDecisions {
                decisions: vec![PendingComponentHumanDecision {
                    decision_id: "decision-1".to_owned(),
                    run_id: RunId::new("run-1"),
                    provider_call_id: "provider-call-1".to_owned(),
                    agent_id: BotId::new("bot-1"),
                    component_name: "askApproval".to_owned(),
                    arguments: serde_json::json!({"title":"Refund?","summary":"Duplicate"}),
                    requested_at: OffsetDateTime::UNIX_EPOCH,
                    expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
                }],
            })
        }

        async fn resolve_component_human_decision(
            &self,
            _auth: &AuthContext,
            decision_id: &str,
            answer: &ComponentHumanDecisionAnswer,
        ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
            Ok(ComponentHumanDecisionResolved {
                decision_id: decision_id.to_owned(),
                answer: answer.clone(),
                replayed: false,
            })
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

    fn app(components: FakeComponents) -> axum::Router {
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_component_administration(Arc::new(components)),
        );
        crate::router(
            ServerBuilder::new(application, Arc::new(FixedAuthResolver::granting(auth())))
                .with_sensitive_write_security(SensitiveWriteSecurity::new(
                    default_session_lifetime(),
                    TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                ))
                .build(),
        )
    }

    fn admin_app(components: FakeComponents) -> axum::Router {
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_component_administration(Arc::new(components)),
        );
        crate::router(
            ServerBuilder::new(
                application,
                Arc::new(crate::auth::SingleUserAuthResolver::new(
                    DeploymentId::new("dep"),
                    TenantId::new("tenant"),
                    ActorId::new(crate::SINGLE_USER_ACTOR_ID),
                    default_session_lifetime(),
                )),
            )
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .build(),
        )
    }

    fn member_app(components: FakeComponents) -> axum::Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("member"),
            [Role::User],
            generation,
            true,
        );
        let now = OffsetDateTime::now_utc();
        let live = evaluate_session(
            default_session_lifetime(),
            SessionState::rehydrate(now, now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_component_administration(Arc::new(components)),
        );
        crate::router(
            ServerBuilder::new(application, Arc::new(resolver))
                .with_sensitive_write_security(SensitiveWriteSecurity::new(
                    default_session_lifetime(),
                    TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                ))
                .build(),
        )
    }

    async fn send(
        router: axum::Router,
        method: Method,
        uri: &str,
        origin: Option<&str>,
        body: Body,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        request = request.header(http::header::CONTENT_TYPE, "application/json");
        router.oneshot(request.body(body).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn list_and_catalogue_are_typed_no_store_and_origin_precedes_body() {
        let components = FakeComponents::default();
        let list = send(
            app(components.clone()),
            Method::GET,
            "/api/components",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(list.headers()[CACHE_CONTROL], "no-store");
        let list_body = to_bytes(list.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&list_body).contains("secret"));

        let rejected = send(
            app(components.clone()),
            Method::PUT,
            "/api/components/catalogue",
            None,
            Body::from("{"),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
        assert!(components.syncs.lock().unwrap().is_empty());

        let body = serde_json::to_vec(&ComponentCatalogueRequest {
            components: compiled_component_manifest(),
        })
        .unwrap();
        let accepted = send(
            app(components.clone()),
            Method::PUT,
            "/api/components/catalogue",
            Some("https://app.example.test"),
            Body::from(body),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(accepted.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(components.syncs.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn six_governance_routes_require_fresh_admin_origin_and_return_authoritative_rows() {
        let components = FakeComponents::default();
        let no_origin = send(
            admin_app(components.clone()),
            Method::PUT,
            "/api/components/showQuote/draft",
            None,
            Body::from("{"),
        )
        .await;
        assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);
        assert!(components.mutations.lock().unwrap().is_empty());

        let member = send(
            member_app(components.clone()),
            Method::PUT,
            "/api/components/showQuote/draft",
            Some("https://app.example.test"),
            Body::from(r#"{"description":"member edit"}"#),
        )
        .await;
        assert_eq!(member.status(), StatusCode::FORBIDDEN);
        assert!(components.mutations.lock().unwrap().is_empty());

        let requests = [
            (
                Method::POST,
                "/api/components/showQuote/functions",
                serde_json::json!({"function":BOT_ACTIVITY_FUNCTION_NAME}),
            ),
            (
                Method::DELETE,
                "/api/components/showQuote/functions/botActivity",
                serde_json::Value::Null,
            ),
            (
                Method::POST,
                "/api/components/showQuote/grants",
                serde_json::json!({"agentId":"agent-one"}),
            ),
            (
                Method::DELETE,
                "/api/components/showQuote/grants/agent-one",
                serde_json::Value::Null,
            ),
            (
                Method::POST,
                "/api/components/showQuote/publication",
                serde_json::json!({"published":false}),
            ),
            (
                Method::PUT,
                "/api/components/showQuote/draft",
                serde_json::json!({"description":"edited quote"}),
            ),
        ];
        for (method, path, body) in requests {
            let body = if body.is_null() {
                Body::empty()
            } else {
                Body::from(serde_json::to_vec(&body).unwrap())
            };
            let response = send(
                admin_app(components.clone()),
                method,
                path,
                Some("https://app.example.test"),
                body,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let receipt = serde_json::from_slice::<ComponentGovernanceReceipt>(
                &to_bytes(response.into_body(), 128 * 1024).await.unwrap(),
            )
            .unwrap();
            assert_eq!(receipt.component.name, SHOW_QUOTE_COMPONENT_NAME);
        }
        assert_eq!(components.mutations.lock().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn runtime_grants_and_decision_are_typed_no_store_and_fail_before_port_without_origin() {
        let components = FakeComponents::default();
        let grants = send(
            app(components.clone()),
            Method::GET,
            "/api/components/for-agent/agent-one",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(grants.status(), StatusCode::OK);
        assert_eq!(grants.headers()[CACHE_CONTROL], "no-store");
        let grants_body = to_bytes(grants.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<GrantedCompiledComponents>(&grants_body)
                .unwrap()
                .components[0]
                .name,
            SHOW_QUOTE_COMPONENT_NAME
        );

        let body = serde_json::to_vec(&ComponentDecisionRequest {
            agent_id: BotId::new("agent-one"),
            functions: Vec::new(),
        })
        .unwrap();
        let no_origin = send(
            app(components.clone()),
            Method::POST,
            "/api/components/showQuote/decision",
            None,
            Body::from(body.clone()),
        )
        .await;
        assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);
        assert_eq!(components.runtime.lock().unwrap().len(), 1);

        let decision = send(
            app(components.clone()),
            Method::POST,
            "/api/components/showQuote/decision",
            Some("https://app.example.test"),
            Body::from(body),
        )
        .await;
        assert_eq!(decision.status(), StatusCode::OK);
        assert_eq!(decision.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentDecision>(
                &to_bytes(decision.into_body(), 4096).await.unwrap()
            )
            .unwrap(),
            ComponentDecision::allowed()
        );
        assert_eq!(components.runtime.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn function_registry_and_call_are_typed_no_store_and_origin_precedes_read() {
        let components = FakeComponents::default();
        let functions = send(
            app(components.clone()),
            Method::GET,
            "/api/components/functions",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(functions.status(), StatusCode::OK);
        assert_eq!(functions.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentDataFunctions>(
                &to_bytes(functions.into_body(), 4096).await.unwrap()
            )
            .unwrap()
            .functions[0]
                .name,
            BOT_ACTIVITY_FUNCTION_NAME
        );

        let body = serde_json::to_vec(&ComponentFunctionCallRequest {
            agent_id: BotId::new("agent-one"),
            function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
            args: serde_json::json!({"days": 30}),
        })
        .unwrap();
        let no_origin = send(
            app(components.clone()),
            Method::POST,
            "/api/components/showActivityReport/call",
            None,
            Body::from(body.clone()),
        )
        .await;
        assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);
        assert!(components.runtime.lock().unwrap().is_empty());

        let called = send(
            app(components.clone()),
            Method::POST,
            "/api/components/showActivityReport/call",
            Some("https://app.example.test"),
            Body::from(body),
        )
        .await;
        assert_eq!(called.status(), StatusCode::OK);
        assert_eq!(called.headers()[CACHE_CONTROL], "no-store");
        let result = serde_json::from_slice::<ComponentFunctionCall>(
            &to_bytes(called.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert!(matches!(
            result.data,
            Some(ComponentFunctionData::BotActivity(BotActivityReport {
                days: 30,
                ..
            }))
        ));
        assert_eq!(components.runtime.lock().unwrap().len(), 1);

        let failed_body = serde_json::to_vec(&ComponentFunctionCallRequest {
            agent_id: BotId::new("agent-one"),
            function: BOT_ACTIVITY_FUNCTION_NAME.to_owned(),
            args: serde_json::json!({"days": 13}),
        })
        .unwrap();
        let failed = send(
            app(components.clone()),
            Method::POST,
            "/api/components/showActivityReport/call",
            Some("https://app.example.test"),
            Body::from(failed_body),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(failed.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentFunctionCall>(
                &to_bytes(failed.into_body(), 4096).await.unwrap()
            )
            .unwrap()
            .error,
            Some(openbot_contracts::components::ComponentFunctionError::ReadFailed)
        );
        assert_eq!(components.runtime.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn human_decisions_are_actor_scoped_no_store_and_origin_precedes_answer_body() {
        let components = FakeComponents::default();
        let pending = send(
            app(components.clone()),
            Method::GET,
            "/api/components/human-decisions",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(pending.status(), StatusCode::OK);
        assert_eq!(pending.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<PendingComponentHumanDecisions>(
                &to_bytes(pending.into_body(), 4096).await.unwrap()
            )
            .unwrap()
            .decisions[0]
                .decision_id,
            "decision-1"
        );

        let no_origin = send(
            app(components.clone()),
            Method::POST,
            "/api/components/human-decisions/decision-1/answer",
            None,
            Body::from("{"),
        )
        .await;
        assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);

        let body = serde_json::to_vec(&ComponentHumanDecisionAnswer::Approval(
            ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Declined,
                note: Some(" because no ".to_owned()),
            },
        ))
        .unwrap();
        let answered = send(
            app(components),
            Method::POST,
            "/api/components/human-decisions/decision-1/answer",
            Some("https://app.example.test"),
            Body::from(body),
        )
        .await;
        assert_eq!(answered.status(), StatusCode::OK);
        assert_eq!(answered.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<ComponentHumanDecisionResolved>(
                &to_bytes(answered.into_body(), 4096).await.unwrap()
            )
            .unwrap()
            .answer,
            ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Declined,
                note: Some("because no".to_owned()),
            })
        );
    }
}
