//! Current host-binding capability; Desktop owns no revocable Server session row.

use openbot_contracts::ui::SessionStatus;

use super::{
    AppError, DesktopTauriProtocol, Method, Request, Response, StatusCode, WindowAuthority,
    empty_response, error_response, json_response,
};

impl DesktopTauriProtocol {
    pub(super) fn session_status(
        &self,
        label: &str,
        request: &mut Request<Vec<u8>>,
        admitted: &WindowAuthority,
    ) -> Response<Vec<u8>> {
        if let Err(error) = self.session_binding_current(label, admitted) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.uri().query().is_some() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        if !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        if let Err(error) = self.session_binding_current(label, admitted) {
            return error_response(error);
        }
        // This describes the host's actual lack of a revocable session handle. It neither mints
        // authentication nor grants sensitive-write freshness, and does not infer revocability
        // from a renderer field, role, or the AuthContext single-user flag.
        json_response(&SessionStatus { revocable: false })
    }

    fn session_binding_current(
        &self,
        label: &str,
        admitted: &WindowAuthority,
    ) -> Result<(), AppError> {
        match self.authority(label) {
            Ok(Some(current))
                if current.binding_id == admitted.binding_id && !admitted.closed.is_cancelled() =>
            {
                Ok(())
            }
            Ok(_) => Err(AppError::Unauthenticated),
            Err(_) => Err(AppError::DependencyUnavailable {
                dependency: "desktop_window_authority",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use async_trait::async_trait;
    use openbot_application::{AppEventStream, ApplicationService};
    use openbot_contracts::{
        auth::{AuthContext, AuthGeneration, Role},
        command::{AppCommand, AppReply, SubscriptionRequest},
        ids::{ActorId, DeploymentId, TenantId},
    };
    use serde_json::json;

    use super::*;

    struct UnusedApplication;

    #[async_trait]
    impl ApplicationService for UnusedApplication {
        async fn execute(&self, _: AuthContext, _: AppCommand) -> Result<AppReply, AppError> {
            panic!("host session capability must not create/read a Server session or business data")
        }

        async fn subscribe(
            &self,
            _: AuthContext,
            _: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            panic!("session status is not a subscription")
        }
    }

    struct Fixture {
        protocol: DesktopTauriProtocol,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("wrok-desktop-session-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").unwrap();
            std::fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
            let transport = Arc::new(crate::InProcessTransport::new(Arc::new(UnusedApplication)));
            let protocol = DesktopTauriProtocol::open(&root, transport).unwrap();
            protocol.bind_window("main", auth(7, true), None).unwrap();
            Self { protocol, root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn auth(generation: u64, single_user: bool) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("host-deployment"),
            TenantId::new("host-tenant"),
            ActorId::new("host-actor"),
            [Role::User],
            AuthGeneration::new(generation),
            single_user,
        )
    }

    fn request(method: Method, path: &str, body: Vec<u8>) -> Request<Vec<u8>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(body)
            .unwrap()
    }

    fn assert_status(response: &Response<Vec<u8>>) {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(response.body(), br#"{"revocable":false}"#);
        let status: SessionStatus = serde_json::from_slice(response.body()).unwrap();
        assert!(!status.revocable);
    }

    #[tokio::test]
    async fn exact_session_route_returns_existing_capability_without_freshness_or_application() {
        let fixture = Fixture::new();
        assert!(
            !fixture
                .protocol
                .authority("main")
                .unwrap()
                .unwrap()
                .is_fresh()
        );
        assert_status(
            &fixture
                .protocol
                .handle("main", request(Method::GET, "/api/me/session", vec![]))
                .await,
        );
        assert!(
            !fixture
                .protocol
                .authority("main")
                .unwrap()
                .unwrap()
                .is_fresh()
        );
        // A role/flag is not a concrete revocable session. This adapter still owns no Server
        // session handle, even when a trusted caller supplied a non-single-user AuthContext.
        fixture
            .protocol
            .bind_window("other", auth(9, false), None)
            .unwrap();
        assert_status(
            &fixture
                .protocol
                .handle("other", request(Method::GET, "/api/me/session", vec![]))
                .await,
        );
    }

    #[tokio::test]
    async fn method_query_body_and_unknown_subpaths_are_closed_and_buffers_are_cleared() {
        let fixture = Fixture::new();
        let admitted = fixture.protocol.authority("main").unwrap().unwrap();
        for (method, path, body, status) in [
            (
                Method::POST,
                "/api/me/session",
                b"{}".to_vec(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::PUT,
                "/api/me/session",
                vec![],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::DELETE,
                "/api/me/session",
                vec![],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::HEAD,
                "/api/me/session",
                vec![],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::GET,
                "/api/me/session?",
                vec![],
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/api/me/session?revocable=true",
                b"SECRET_BUFFER".to_vec(),
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/api/me/session",
                b"{}".to_vec(),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = fixture
                .protocol
                .handle("main", request(method.clone(), path, body.clone()))
                .await;
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let mut request = request(method, path, body);
            assert_eq!(
                fixture
                    .protocol
                    .session_status("main", &mut request, &admitted)
                    .status(),
                status
            );
            assert!(request.body().iter().all(|byte| *byte == 0));
        }
        for path in [
            "/api/me/session/",
            "/api/me/session/revoke",
            "/api/me/session-other",
        ] {
            assert_eq!(
                fixture
                    .protocol
                    .handle("main", request(Method::GET, path, vec![]))
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn renderer_fields_and_headers_cannot_mint_window_or_revocable_authority() {
        let fixture = Fixture::new();
        for field in [
            "actor",
            "tenant",
            "deployment",
            "window",
            "bindingId",
            "authGeneration",
            "freshFor",
            "revocable",
            "sessionId",
        ] {
            let body = serde_json::to_vec(&json!({field: "renderer-choice"})).unwrap();
            assert_eq!(
                fixture
                    .protocol
                    .handle("main", request(Method::GET, "/api/me/session", body))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                fixture
                    .protocol
                    .handle(
                        "main",
                        request(
                            Method::GET,
                            &format!("/api/me/session?{field}=renderer-choice"),
                            vec![]
                        )
                    )
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut forged = request(Method::GET, "/api/me/session", vec![]);
        forged
            .headers_mut()
            .insert("x-window-label", "main".parse().unwrap());
        forged
            .headers_mut()
            .insert("authorization", "Bearer RENDERER_CANARY".parse().unwrap());
        let response = fixture.protocol.handle("unbound", forged).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.body(), br#"{"code":"unauthenticated"}"#);
    }

    #[tokio::test]
    async fn closed_or_replaced_window_cannot_use_admitted_status_request() {
        let fixture = Fixture::new();
        let old = fixture.protocol.authority("main").unwrap().unwrap();
        fixture.protocol.unbind_window("main").unwrap();
        assert_eq!(
            fixture
                .protocol
                .handle("main", request(Method::GET, "/api/me/session", vec![]))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        fixture
            .protocol
            .bind_window("main", auth(8, true), None)
            .unwrap();
        let mut stale_request = request(Method::GET, "/api/me/session", b"SECRET_BUFFER".to_vec());
        let response = fixture
            .protocol
            .session_status("main", &mut stale_request, &old);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(stale_request.body().iter().all(|byte| *byte == 0));
        assert_status(
            &fixture
                .protocol
                .handle("main", request(Method::GET, "/api/me/session", vec![]))
                .await,
        );
    }
}
