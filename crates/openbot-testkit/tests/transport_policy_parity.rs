//! W-5 batch 4：Policy GET/PUT 经 Axum 与 typed in-process 的同实例对拍。

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PolicyAdministration,
    PolicyAdministrationError, PortError,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::policy::{ActionPolicyDocument, ActionPolicyMode};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::{SessionLifetimePolicy, TrustedOrigins};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_server::{
    SINGLE_USER_ACTOR_ID, SensitiveWriteSecurity, ServerBuilder, SingleUserAuthResolver, router,
};
use time::Duration;
use tower::ServiceExt as _;

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
    fn new() -> Self {
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

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        [Role::Admin],
        openbot_contracts::auth::AuthGeneration::new(0),
        true,
    )
}

#[tokio::test]
async fn policy_get_and_put_match_between_http_and_typed_in_process_on_the_same_arc() {
    let policies = FakePolicies::new();
    let service: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_policy(policies.clone()));
    let transport = InProcessTransport::new(Arc::clone(&service));
    let resolver = SingleUserAuthResolver::new(
        DeploymentId::new("dep"),
        TenantId::new("tenant"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        lifetime(),
    );
    let security = SensitiveWriteSecurity::new(
        lifetime(),
        TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
    );
    let state = ServerBuilder::new(Arc::clone(&service), Arc::new(resolver))
        .with_sensitive_write_security(security)
        .build();
    assert!(core::ptr::addr_eq(
        Arc::as_ptr(&service),
        state.application()
    ));
    assert!(Arc::ptr_eq(&service, transport.service()));
    let router = router(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/computers/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let AppReply::ActionPolicy { policy: typed } = transport
        .execute(auth(), AppCommand::GetActionPolicy)
        .await
        .unwrap()
    else {
        panic!("typed get policy reply 不符");
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["policy"],
        serde_json::to_value(typed).unwrap(),
    );

    let policy = ActionPolicyDocument {
        mode: ActionPolicyMode::DryRun,
        deny: vec!["false".to_owned()],
        allow: vec!["true".to_owned()],
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/computers/policy")
                .header(axum::http::header::ORIGIN, "https://app.example.test")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&policy).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let AppReply::ActionPolicy { policy: typed } = transport
        .execute(
            auth(),
            AppCommand::SetActionPolicy {
                policy: policy.clone(),
            },
        )
        .await
        .unwrap()
    else {
        panic!("typed set policy reply 不符");
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["policy"],
        serde_json::to_value(typed).unwrap(),
    );
    assert_eq!(
        policies.actors.lock().unwrap().as_slice(),
        [
            ActorId::new(SINGLE_USER_ACTOR_ID),
            ActorId::new(SINGLE_USER_ACTOR_ID),
        ]
    );
}
