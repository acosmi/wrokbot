//! Authenticated actor-scoped per-run provider cost-budget HTTP framing.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use http::HeaderMap;
use http::header::{CACHE_CONTROL, HeaderValue};
use openbot_contracts::budget::RunCostBudgetPreference;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// `GET /api/me/run-cost-budget`; actor scope comes only from the authenticated context.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<RunCostBudgetPreference>), HttpError> {
    let budget = budget_reply(
        state
            .application()
            .execute(auth, AppCommand::GetRunCostBudget)
            .await?,
    )?;
    Ok((no_store(), Json(budget)))
}

/// `PUT /api/me/run-cost-budget`; same-origin validation precedes closed body parsing.
pub async fn put(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<RunCostBudgetPreference>, JsonRejection>,
) -> Result<(HeaderMap, Json<RunCostBudgetPreference>), HttpError> {
    let Json(preference) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "run cost budget body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    let budget = budget_reply(
        state
            .application()
            .execute(auth, AppCommand::ReplaceRunCostBudget(preference))
            .await?,
    )?;
    Ok((no_store(), Json(budget)))
}

fn budget_reply(reply: AppReply) -> Result<RunCostBudgetPreference, HttpError> {
    match reply {
        AppReply::RunCostBudget(budget) => Ok(budget),
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use http::{Method, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        ChannelReader, OpenBotApplication, PortError, RunCostBudgetAdministration,
        RunCostBudgetAdministrationError, RunCostCap,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::budget::RunCostCapInput;
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};
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
    struct FakeBudgets {
        stored: Arc<Mutex<Option<RunCostCap>>>,
        replacements: Arc<Mutex<Vec<Option<RunCostCap>>>>,
    }

    #[async_trait]
    impl RunCostBudgetAdministration for FakeBudgets {
        async fn get(
            &self,
            _auth: &AuthContext,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            Ok(self.stored.lock().unwrap().clone())
        }

        async fn replace(
            &self,
            _auth: &AuthContext,
            cap: Option<RunCostCap>,
        ) -> Result<Option<RunCostCap>, RunCostBudgetAdministrationError> {
            self.replacements.lock().unwrap().push(cap.clone());
            *self.stored.lock().unwrap() = cap.clone();
            Ok(cap)
        }
    }

    fn router(budgets: FakeBudgets) -> Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let lifetime = default_session_lifetime();
        let live = evaluate_session(
            lifetime,
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        let application = Arc::new(
            OpenBotApplication::new(EmptyChannels).with_run_cost_budgets(Arc::new(budgets)),
        );
        let trusted = TrustedOrigins::from_configured(["https://app.example.test"]).unwrap();
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(lifetime, trusted))
            .with_login_security(
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                true,
            )
            .into_router()
    }

    async fn send(
        router: Router,
        method: Method,
        origin: Option<&str>,
        body: &'static str,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method(method)
            .uri("/api/me/run-cost-budget");
        if !body.is_empty() {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
        }
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        router
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn budget_is_closed_no_store_and_origin_precedes_body_parsing() {
        let budgets = FakeBudgets::default();
        let blocked = send(router(budgets.clone()), Method::PUT, None, "{").await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        assert!(budgets.replacements.lock().unwrap().is_empty());

        let smuggled = send(
            router(budgets.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            r#"{"cap":{"currency":"USD","maxCostMicroUnits":"250000","actor":"admin"}}"#,
        )
        .await;
        assert_eq!(smuggled.status(), StatusCode::BAD_REQUEST);
        assert!(budgets.replacements.lock().unwrap().is_empty());

        let saved = send(
            router(budgets.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            r#"{"cap":{"currency":"USD","maxCostMicroUnits":"250000"}}"#,
        )
        .await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(saved.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            serde_json::from_slice::<RunCostBudgetPreference>(
                &to_bytes(saved.into_body(), 1024).await.unwrap()
            )
            .unwrap(),
            RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: "250000".to_owned(),
                }),
            }
        );

        let disabled = send(
            router(budgets.clone()),
            Method::PUT,
            Some("https://app.example.test"),
            r#"{"cap":null}"#,
        )
        .await;
        assert_eq!(disabled.status(), StatusCode::OK);
        assert_eq!(budgets.replacements.lock().unwrap().len(), 2);
        let get = send(router(budgets), Method::GET, None, "").await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()[CACHE_CONTROL], "no-store");
    }
}
