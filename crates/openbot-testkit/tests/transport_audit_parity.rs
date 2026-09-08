//! W-5 batch 3：audit query 经 Axum 与 typed in-process 的同实例对拍。

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use openbot_application::{
    ApplicationService, AuditPageRequest, AuditReadError, AuditReader, ChannelCursor,
    ChannelReader, OpenBotApplication, PortError,
};
use openbot_contracts::audit::{AuditEventView, AuditPage};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::ids::{ActorId, AuditEventId, DeploymentId, TenantId};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::SessionLifetimePolicy;
use openbot_server::{SINGLE_USER_ACTOR_ID, ServerBuilder, SingleUserAuthResolver, router};
use time::{Duration, OffsetDateTime};
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
struct FakeAudit {
    calls: Arc<Mutex<Vec<AuditPageRequest>>>,
    page: AuditPage,
}

impl FakeAudit {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            page: AuditPage {
                events: vec![AuditEventView {
                    id: AuditEventId::new("event-1"),
                    actor_user_id: Some(ActorId::new(SINGLE_USER_ACTOR_ID)),
                    event_type: "connector.sync_succeeded".to_owned(),
                    target_type: "connector".to_owned(),
                    target_id: Some("drive-1".to_owned()),
                    payload: serde_json::json!({"output_bytes": 3}),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                }],
                next_cursor: Some("next-page".to_owned()),
            },
        }
    }
}

#[async_trait]
impl AuditReader for FakeAudit {
    async fn list_audit_events(
        &self,
        request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError> {
        self.calls.lock().unwrap().push(request);
        Ok(self.page.clone())
    }
}

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(Duration::hours(8), Duration::days(7), Duration::minutes(15))
        .unwrap()
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-1"),
        TenantId::new("tenant-1"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        [Role::Admin],
        openbot_contracts::auth::AuthGeneration::new(0),
        true,
    )
}

#[tokio::test]
async fn audit_page_matches_between_http_and_typed_in_process_on_the_same_arc() {
    let audit = FakeAudit::new();
    let service: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_audit(audit.clone()));
    let transport = InProcessTransport::new(Arc::clone(&service));
    let resolver = SingleUserAuthResolver::new(
        DeploymentId::new("dep-1"),
        TenantId::new("tenant-1"),
        ActorId::new(SINGLE_USER_ACTOR_ID),
        lifetime(),
    );
    let state = ServerBuilder::new(Arc::clone(&service), Arc::new(resolver)).build();
    assert!(core::ptr::addr_eq(
        Arc::as_ptr(&service),
        state.application()
    ));
    assert!(Arc::ptr_eq(&service, transport.service()));

    let request = Request::builder()
        .uri("/api/admin/audit-events?eventType=one,two&targetType=connector&limit=10")
        .body(Body::empty())
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();

    let command = AppCommand::ListAuditEvents {
        cursor: None,
        event_type: Some("one,two".to_owned()),
        actor_user_id: None,
        target_type: Some("connector".to_owned()),
        target_id: None,
        from: None,
        to: None,
        limit: Some(10),
    };
    let AppReply::AuditEvents(typed) = transport.execute(auth(), command).await.unwrap() else {
        panic!("typed audit reply 不符");
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::to_value(typed).unwrap(),
    );

    let calls = audit.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].event_types, ["one", "two"]);
    assert_eq!(calls[0].target_type.as_deref(), Some("connector"));
    assert_eq!(calls[0].limit, 10);
}
