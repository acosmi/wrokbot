//! Rust-only Application/InProcess/host consumers stay sealed and unavailable without a producer.
//! Controlled test identities here are not PostgreSQL Session or actual Local canary acceptance;
//! those positive chains execute in the separately registered Server/Desktop owned fixtures.

use async_trait::async_trait;
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::ChannelSummary;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_desktop::InProcessTransport;
use std::sync::Arc;

struct UnusedChannels;
#[async_trait]
impl ChannelReader for UnusedChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("artifact first-chunk consumer must not use the channel-listing port")
    }
}
fn controlled_unbound_auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("artifact-read-parity"),
        TenantId::new("artifact-read-tenant"),
        ActorId::new("artifact-read-actor"),
        [Role::User],
        AuthGeneration::new(0),
        false,
    )
}
const ARTIFACT: &str = "019a32cc-7e00-7000-8000-000000000008";

#[tokio::test]
async fn actual_application_and_same_typed_transport_keep_missing_binding_closed() {
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(UnusedChannels));
    let transport = InProcessTransport::new(application.clone());
    assert!(Arc::ptr_eq(transport.service(), &application));
    let direct = application
        .read_current_artifact_chunk(controlled_unbound_auth(), ARTIFACT.to_owned())
        .await
        .err();
    let forwarded = transport
        .read_current_artifact_chunk(controlled_unbound_auth(), ARTIFACT.to_owned())
        .await
        .err();
    assert_eq!(
        direct,
        Some(AppError::DependencyUnavailable {
            dependency: "host_request_binding"
        })
    );
    assert_eq!(forwarded, direct);
}

#[tokio::test]
async fn actual_application_and_same_typed_transport_keep_selector_validation_order() {
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(UnusedChannels));
    let transport = InProcessTransport::new(application.clone());
    let direct = application
        .read_current_artifact_chunk(
            controlled_unbound_auth(),
            "not-a-valid-artifact-selector".to_owned(),
        )
        .await
        .err();
    let forwarded = transport
        .read_current_artifact_chunk(
            controlled_unbound_auth(),
            "not-a-valid-artifact-selector".to_owned(),
        )
        .await
        .err();
    assert_eq!(
        direct,
        Some(AppError::MalformedPayload {
            field: "artifactId"
        })
    );
    assert_eq!(forwarded, direct);
}

#[tokio::test]
async fn actual_closed_inprocess_transport_cannot_start_a_current_read() {
    let application: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(UnusedChannels));
    let transport = InProcessTransport::new(application);
    let shutdown = transport.shutdown().await;
    assert!(shutdown.within_deadline);
    assert_eq!(
        transport
            .read_current_artifact_chunk(controlled_unbound_auth(), ARTIFACT.to_owned())
            .await
            .err(),
        Some(AppError::DependencyUnavailable {
            dependency: "desktop_transport"
        })
    );
}
