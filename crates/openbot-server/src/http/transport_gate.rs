//! Request-level transport admission before every authentication or application handler (R394).
//! Only the server's socket `ConnectInfo` establishes the peer. Proxy headers are evidence only
//! after the configured same-machine secret, HTTPS marker and exact authority all match.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use openbot_domain::vault::SecretBytes;

use crate::config::transport::{TrustedTransportMode, TrustedTransportPolicy};
use crate::readiness::ReadinessStatus;

const PROXY_SECRET: &str = "x-wrok-bot-proxy-secret";
const FORWARDED_PROTO: &str = "x-forwarded-proto";
const FORWARDED_HOST: &str = "x-forwarded-host";

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a [u8]> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(value.as_bytes())
}

fn accepted(policy: &TrustedTransportPolicy, request: &Request) -> bool {
    #[cfg(any(test, feature = "testkit"))]
    if matches!(policy.mode, TrustedTransportMode::TestOnlyUnchecked) {
        return true;
    }
    let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return false;
    };
    if !peer.ip().is_loopback() {
        return false;
    }
    match &policy.mode {
        TrustedTransportMode::Deny => false,
        TrustedTransportMode::LoopbackSingleUser => true,
        TrustedTransportMode::LoopbackHttpsProxy { authority, secret } => {
            if single_header(request.headers(), FORWARDED_PROTO) != Some(b"https")
                || single_header(request.headers(), FORWARDED_HOST) != Some(authority.as_bytes())
            {
                return false;
            }
            let Some(provided) = single_header(request.headers(), PROXY_SECRET) else {
                return false;
            };
            if provided.len() != 64 {
                return false;
            }
            // Reuse the domain's audited subtle wrapper. Both temporary allocations zeroize;
            // comparison results and stable response codes are the only observable outputs.
            SecretBytes::new(secret.expose().as_bytes().to_vec())
                .ct_eq(&SecretBytes::new(provided.to_vec()))
        }
        #[cfg(any(test, feature = "testkit"))]
        TrustedTransportMode::TestOnlyUnchecked => true,
    }
}

fn remove_proxy_headers(headers: &mut HeaderMap) {
    for name in [
        PROXY_SECRET,
        FORWARDED_PROTO,
        FORWARDED_HOST,
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-port",
        "x-real-ip",
    ] {
        headers.remove(name);
    }
}

pub(super) async fn enforce(
    State(policy): State<TrustedTransportPolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    let trusted = accepted(&policy, &request);
    remove_proxy_headers(request.headers_mut());
    if trusted {
        return next.run(request).await;
    }
    let diagnostic_method = matches!(*request.method(), Method::GET | Method::HEAD);
    if diagnostic_method && request.uri().path() == "/health" {
        return next.run(request).await;
    }
    let mut response = if diagnostic_method && request.uri().path() == "/readiness" {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(super::health::ReadinessBody {
                status: ReadinessStatus::NotReady,
                insecure_transport: true,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"code": "transport_untrusted"})),
        )
            .into_response()
    };
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use openbot_application::{AppEventStream, ApplicationService};
    use openbot_contracts::auth::AuthContext;
    use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
    use openbot_contracts::error::AppError;
    use tower::ServiceExt as _;

    use crate::auth::AuthResolver;
    use crate::config::{EnvMap, ServerConfig};
    use crate::{FnReadinessProbe, ReadinessVerdict, ServerBuilder};

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn proxy_policy() -> TrustedTransportPolicy {
        let env = EnvMap::from([
            (
                "OPENBOT_PUBLIC_URL".into(),
                "https://public.example:8443".into(),
            ),
            ("OPENBOT_TLS_PROXY_SECRET".into(), SECRET.into()),
        ]);
        ServerConfig::from_env_map(&env)
            .unwrap()
            .transport_policy(false)
    }

    fn request(path: &str, peer: Option<&str>, with_proxy: bool) -> Request {
        let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        if with_proxy {
            let headers = request.headers_mut();
            headers.insert(PROXY_SECRET, HeaderValue::from_static(SECRET));
            headers.insert(FORWARDED_PROTO, HeaderValue::from_static("https"));
            headers.insert(
                FORWARDED_HOST,
                HeaderValue::from_static("public.example:8443"),
            );
        }
        request
    }

    #[test]
    fn peer_is_a_socket_fact_and_each_proxy_header_is_exact_and_single() {
        let policy = proxy_policy();
        assert!(accepted(
            &policy,
            &request("/api/me", Some("127.0.0.1:12345"), true)
        ));
        assert!(accepted(
            &policy,
            &request("/api/me", Some("[::1]:12345"), true)
        ));
        for peer in [None, Some("192.168.1.2:12345"), Some("203.0.113.2:12345")] {
            let mut forged = request("/api/me", peer, true);
            forged
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
            assert!(!accepted(&policy, &forged));
        }
        for name in [PROXY_SECRET, FORWARDED_PROTO, FORWARDED_HOST] {
            let mut missing = request("/api/me", Some("127.0.0.1:12345"), true);
            missing.headers_mut().remove(name);
            assert!(!accepted(&policy, &missing));
            let mut duplicate = request("/api/me", Some("127.0.0.1:12345"), true);
            let value = duplicate.headers().get(name).unwrap().clone();
            duplicate.headers_mut().append(name, value);
            assert!(!accepted(&policy, &duplicate));
        }
        for (name, bad) in [
            (PROXY_SECRET, "wrong"),
            (
                PROXY_SECRET,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee",
            ),
            (FORWARDED_PROTO, "http"),
            (FORWARDED_PROTO, "HTTPS"),
            (FORWARDED_PROTO, "https,https"),
            (FORWARDED_HOST, "public.example"),
            (FORWARDED_HOST, "public.example:8443,public.example:8443"),
            (FORWARDED_HOST, "public.example:8443 "),
        ] {
            let mut forged = request("/api/me", Some("127.0.0.1:12345"), true);
            forged
                .headers_mut()
                .insert(name, HeaderValue::from_str(bad).unwrap());
            assert!(!accepted(&policy, &forged), "accepted malformed {name}");
        }
        let local = ServerConfig::from_env_map(&EnvMap::new())
            .unwrap()
            .transport_policy(true);
        assert!(accepted(
            &local,
            &request("/api/me", Some("127.0.0.1:12345"), false)
        ));
        assert!(!accepted(&local, &request("/api/me", None, true)));
        assert!(!accepted(
            &local,
            &request("/api/me", Some("192.168.1.2:12345"), true)
        ));
    }

    struct Spy(AtomicUsize);

    #[async_trait]
    impl AuthResolver for Spy {
        async fn resolve(&self, parts: &http::request::Parts) -> Result<AuthContext, AppError> {
            for name in [
                PROXY_SECRET,
                FORWARDED_PROTO,
                FORWARDED_HOST,
                "forwarded",
                "x-forwarded-for",
            ] {
                assert!(
                    !parts.headers.contains_key(name),
                    "proxy header reached auth"
                );
            }
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Unauthenticated)
        }
    }

    #[async_trait]
    impl ApplicationService for Spy {
        async fn execute(&self, _: AuthContext, _: AppCommand) -> Result<AppReply, AppError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Unauthenticated)
        }
        async fn subscribe(
            &self,
            _: AuthContext,
            _: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Unauthenticated)
        }
    }

    fn router(policy: TrustedTransportPolicy, spy: Arc<Spy>) -> axum::Router {
        ServerBuilder::new(spy.clone(), spy)
            .with_transport_policy(policy)
            .with_readiness_probe(Arc::new(FnReadinessProbe::new("test_ready", || async {
                ReadinessVerdict::Ready
            })))
            .into_router()
    }

    #[tokio::test]
    async fn every_registered_business_route_is_denied_before_authentication_or_application() {
        let spy = Arc::new(Spy(AtomicUsize::new(0)));
        let app = router(proxy_policy(), spy.clone());
        let mut paths = std::collections::BTreeSet::new();
        for route in include_str!("mod.rs").split(".route(").skip(1) {
            let Some(path) = route.split('"').nth(1).filter(|path| path.starts_with('/')) else {
                continue;
            };
            if ["/health", "/readiness"].contains(&path) {
                continue;
            }
            let mut concrete = path.to_owned();
            while let Some(start) = concrete.find('{') {
                let end = concrete[start..].find('}').unwrap() + start;
                concrete.replace_range(start..=end, "example-id");
            }
            paths.insert(concrete);
        }
        assert!(
            paths.len() > 40,
            "route coverage extraction must not silently become empty"
        );
        paths.insert("/unmatched-static-or-api-path".into());
        for path in paths {
            for method in [
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ] {
                let mut incoming = request(&path, Some("127.0.0.1:12345"), false);
                *incoming.method_mut() = method;
                incoming.headers_mut().insert(
                    http::header::COOKIE,
                    HeaderValue::from_static("openbot_session=existing-session"),
                );
                let response = app.clone().oneshot(incoming).await.unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
                assert_eq!(
                    response.headers().get(http::header::CACHE_CONTROL).unwrap(),
                    "no-store"
                );
                assert!(!response.headers().contains_key(http::header::SET_COOKIE));
                let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                assert_eq!(bytes.as_ref(), br#"{"code":"transport_untrusted"}"#);
            }
        }
        assert_eq!(spy.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn only_diagnostics_survive_untrusted_transport_and_readiness_cannot_be_green() {
        let spy = Arc::new(Spy(AtomicUsize::new(0)));
        let app = router(proxy_policy(), spy.clone());
        assert_eq!(
            app.clone()
                .oneshot(request("/health", None, false))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let response = app
            .clone()
            .oneshot(request("/readiness", None, false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("not_ready"));
        assert_eq!(
            app.clone()
                .oneshot(request("/readiness", Some("127.0.0.1:12345"), true))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let mut accepted_request = request("/api/me", Some("127.0.0.1:12345"), true);
        accepted_request.headers_mut().insert(
            "forwarded",
            HeaderValue::from_static("for=127.0.0.1;proto=https"),
        );
        assert_eq!(
            app.oneshot(accepted_request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(spy.0.load(Ordering::SeqCst), 1);
        let denied = router(TrustedTransportPolicy::deny(), spy);
        assert_eq!(
            denied
                .oneshot(request("/api/me", Some("127.0.0.1:12345"), true))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn real_loopback_socket_requires_proxy_proof_before_reaching_auth() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let spy = Arc::new(Spy(AtomicUsize::new(0)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = router(proxy_policy(), spy.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
        });
        for trusted in [false, true] {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let headers = if trusted {
                format!(
                    "x-wrok-bot-proxy-secret: {SECRET}\r\nx-forwarded-proto: https\r\nx-forwarded-host: public.example:8443\r\n"
                )
            } else {
                String::new()
            };
            stream.write_all(format!("GET /api/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n").as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read_to_end(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            let response = std::str::from_utf8(&bytes).unwrap();
            assert!(response.starts_with(if trusted {
                "HTTP/1.1 401"
            } else {
                "HTTP/1.1 503"
            }));
            assert!(!response.contains(SECRET));
        }
        assert_eq!(spy.0.load(Ordering::SeqCst), 1);
        stop.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
