//! Deployment-wide computer policy HTTP framing；不含 Bot path/access 规则。

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use http::HeaderMap;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::policy::{ActionPolicyDocument, ActionPolicyMode, ActionPolicyResponse};
use serde::Deserialize;

use crate::auth::{Authenticated, SensitiveAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// PUT body；缺失或 null 的规则列表按固定上游语义成为空表，mode 不得缺省。
#[derive(Debug, Deserialize)]
pub struct PolicyBody {
    /// enforce / dry-run。
    pub mode: ActionPolicyMode,
    /// deny 表达式；缺失/null = []。
    pub deny: Option<Vec<String>>,
    /// allow 表达式；缺失/null = []。
    pub allow: Option<Vec<String>>,
}

/// `GET /api/computers/policy`。
pub async fn policy_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<Json<ActionPolicyResponse>, HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::GetActionPolicy)
        .await?
    {
        AppReply::ActionPolicy { policy } => Ok(Json(ActionPolicyResponse { policy })),
        _ => Err(application_contract_error()),
    }
}

/// `PUT /api/computers/policy`；fresh admin + trusted Origin 先于 body 解析。
pub async fn policy_put(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    body: Result<Json<PolicyBody>, JsonRejection>,
) -> Result<Json<ActionPolicyResponse>, HttpError> {
    state
        .authorize_sensitive_write(&resolved, request_origin(&headers))
        .await?;
    let Json(body) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "policy body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    let policy = ActionPolicyDocument {
        mode: body.mode,
        deny: body.deny.unwrap_or_default(),
        allow: body.allow.unwrap_or_default(),
    };
    match state
        .application()
        .execute(
            resolved.into_context(),
            AppCommand::SetActionPolicy { policy },
        )
        .await?
    {
        AppReply::ActionPolicy { policy } => Ok(Json(ActionPolicyResponse { policy })),
        _ => Err(application_contract_error()),
    }
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::ORIGIN)
        .map(|value| value.to_str().unwrap_or(""))
}

fn application_contract_error() -> HttpError {
    tracing::error!("policy command 收到不匹配 reply");
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
    use axum::http::{Request, StatusCode};
    use openbot_application::{
        ChannelCursor, ChannelReader, OpenBotApplication, PolicyAdministration,
        PolicyAdministrationError, PortError,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_domain::identity::session::{
        SessionLifetimePolicy, SessionState, TrustedOrigins, evaluate_session,
    };
    use openbot_domain::policy::{ActionPolicy, PolicyMode};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use crate::SINGLE_USER_ACTOR_ID;
    use crate::auth::{
        FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity, SingleUserAuthResolver,
    };
    use crate::http::{ServerBuilder, router};

    #[derive(Clone, Default)]
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
    struct FakePolicies {
        current: Arc<Mutex<Option<ActionPolicy>>>,
        actors: Arc<Mutex<Vec<ActorId>>>,
    }

    impl FakePolicies {
        fn configured() -> Self {
            Self {
                current: Arc::new(Mutex::new(Some(ActionPolicy {
                    mode: PolicyMode::Enforce,
                    deny: Vec::new(),
                    allow: vec!["true".to_owned()],
                }))),
                actors: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PolicyAdministration for FakePolicies {
        async fn current_policy(&self) -> Result<Option<ActionPolicy>, PolicyAdministrationError> {
            Ok(self.current.lock().unwrap().clone())
        }

        async fn set_policy(
            &self,
            updated_by: &ActorId,
            policy: ActionPolicy,
        ) -> Result<(), PolicyAdministrationError> {
            self.actors.lock().unwrap().push(updated_by.clone());
            *self.current.lock().unwrap() = Some(policy);
            Ok(())
        }
    }

    fn lifetime() -> SessionLifetimePolicy {
        SessionLifetimePolicy::new(Duration::hours(8), Duration::days(7), Duration::minutes(15))
            .unwrap()
    }

    fn security() -> SensitiveWriteSecurity {
        SensitiveWriteSecurity::new(
            lifetime(),
            TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
        )
    }

    fn application(policies: FakePolicies) -> Arc<dyn openbot_application::ApplicationService> {
        Arc::new(OpenBotApplication::new(EmptyChannels).with_policy(policies))
    }

    fn admin_router(policies: FakePolicies) -> axum::Router {
        let resolver = SingleUserAuthResolver::new(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new(SINGLE_USER_ACTOR_ID),
            lifetime(),
        );
        router(
            ServerBuilder::new(application(policies), Arc::new(resolver))
                .with_sensitive_write_security(security())
                .build(),
        )
    }

    fn member_router(policies: FakePolicies) -> axum::Router {
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
            lifetime(),
            SessionState::rehydrate(now, now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        router(
            ServerBuilder::new(application(policies), Arc::new(resolver))
                .with_sensitive_write_security(security())
                .build(),
        )
    }

    async fn send(router: axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, value)
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    fn put(path: &str, origin: Option<&str>, body: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        request.body(Body::from(body.to_owned())).unwrap()
    }

    #[tokio::test]
    async fn administrator_can_read_policy_without_any_bot_access() {
        let policies = FakePolicies::configured();
        let (status, body) = send(admin_router(policies), get("/api/computers/policy")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["policy"]["mode"], "enforce");
    }

    #[tokio::test]
    async fn administrator_can_write_policy_only_after_sensitive_guard() {
        let policies = FakePolicies::configured();
        let path = "/api/computers/policy";
        let (status, body) = send(
            admin_router(policies.clone()),
            put(path, None, r#"{"mode":"enforce","deny":"bad"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "identity_sensitive_write_origin_missing");
        assert!(policies.actors.lock().unwrap().is_empty());

        let (status, body) = send(
            admin_router(policies.clone()),
            put(
                path,
                Some("https://app.example.test"),
                r#"{"mode":"dry-run","deny":["false"],"allow":["true"]}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["policy"]["mode"], "dry-run");
        assert_eq!(body["policy"]["deny"], serde_json::json!(["false"]));
        assert_eq!(
            policies.actors.lock().unwrap().as_slice(),
            [ActorId::new(SINGLE_USER_ACTOR_ID)]
        );
    }

    #[tokio::test]
    async fn policy_write_remains_administrator_only_after_sensitive_guard() {
        let policies = FakePolicies::configured();
        let (status, body) = send(
            member_router(policies.clone()),
            put(
                "/api/computers/policy",
                Some("https://app.example.test"),
                r#"{"mode":"enforce","deny":[],"allow":[]}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "identity_sensitive_write_role_insufficient");
        assert!(policies.actors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn policy_is_an_exact_deployment_route_not_a_wildcard_exemption() {
        let router = admin_router(FakePolicies::configured());
        let (status, _) = send(router.clone(), get("/api/computers/policy")).await;
        assert_eq!(status, StatusCode::OK);
        for path in [
            "/api/computers/some-bot/status",
            "/api/computers/policy/status",
        ] {
            let (status, body) = send(router.clone(), get(path)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(body, serde_json::Value::Null, "{path}");
        }
    }
}
