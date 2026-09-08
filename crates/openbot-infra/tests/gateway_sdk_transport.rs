//! Actual SDK4 -> production gateway transport -> owned TLS. No real tokens, PG authority or login.
use acosmi::{
    AuthorityResult, AuthorityState, ChatRequest, Client, Config, StrictTokenAuthority,
    TokenAuthorityError, TokenSet, TokenStore,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use openbot_infra::gateway_transport::*;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
include!("gateway_sdk_transport/tls.rs");
include!("gateway_sdk_transport/authority.rs");

// In-memory test fixture only. The production module intentionally has no authority implementation.
#[derive(Default)]
struct Fence {
    calls: AtomicUsize,
    permits: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    refused: AtomicBool,
    fail_release: AtomicBool,
    revoke_after_model: AtomicBool,
    model_calls: AtomicUsize,
}
struct Permit {
    active: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    fail: bool,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl GatewayHttpPermit for Permit {
    async fn release_after_headers(self: Box<Self>) -> Result<(), GatewayFenceError> {
        if self.fail {
            return Err(GatewayFenceError::CleanupUnknown);
        }
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[async_trait]
impl GatewayHttpAuthority for Fence {
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        _: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.kind() == GatewayRequestKind::Model
            && self.revoke_after_model.load(Ordering::SeqCst)
            && self.model_calls.fetch_add(1, Ordering::SeqCst) > 0
        {
            return Err(GatewayFenceError::Refused);
        }
        if self.refused.load(Ordering::SeqCst) {
            return Err(GatewayFenceError::Refused);
        }
        self.permits.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Permit {
            active: self.permits.clone(),
            releases: self.releases.clone(),
            fail: self.fail_release.load(Ordering::SeqCst),
        }))
    }
}
#[derive(Default)]
struct Outcomes(Mutex<Vec<GatewayAttempt>>);
impl GatewayHttpOutcomes for Outcomes {
    fn started(&self, a: GatewayAttempt) {
        let mut entries = self.0.lock().unwrap();
        assert!(entries.len() < 32);
        entries.push(a);
    }
}
impl Outcomes {
    fn snapshots(&self) -> Vec<GatewayAttemptSnapshot> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(GatewayAttempt::snapshot)
            .collect()
    }
}
fn transport(
    f: &TlsFixture,
    wire: GatewayModelWire,
    fence: Arc<Fence>,
    outcomes: Arc<Outcomes>,
    limit: usize,
    timeout: Duration,
    allow: bool,
) -> Arc<dyn acosmi::HttpTransport> {
    let base = f.endpoint();
    let oauth = GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Desktop,
        &format!("{base}/register"),
        &format!("{base}/token"),
        Some(&format!("{base}/revoke")),
    )
    .unwrap();
    GatewayTransportFactory::new(
        f.dialer_with(false, allow),
        VerifiedGatewayEndpoints::new(&base, Some(("qa-model", wire)), Some(oauth)).unwrap(),
        GatewayTransportLimits::new(timeout, limit).unwrap(),
    )
    .for_operation(
        fence,
        outcomes,
        Instant::now() + Duration::from_secs(8),
        Duration::from_millis(250),
    )
    .unwrap()
}
async fn client(f: &TlsFixture, t: Arc<dyn acosmi::HttpTransport>) -> Client {
    Client::create_with_authority(
        config(&f.endpoint()),
        t,
        Authority::new(&f.endpoint(), false),
        None,
    )
    .await
    .unwrap()
}
fn catalogue(wire: GatewayModelWire) -> String {
    json!({"code":0,"data":[{"id":"qa-model","name":"QA","provider":if wire==GatewayModelWire::OpenAi {"openai"}else{"anthropic"},"modelId":"qa-upstream","maxTokens":256,"isEnabled":true,"capabilities":{"supports_thinking":false,"supports_adaptive_thinking":false,"supports_isp":false,"supports_web_search":false,"supports_tool_search":false,"supports_structured_output":false,"supports_effort":false,"supports_max_effort":false,"supports_fast_mode":false,"supports_auto_mode":false,"supports_1m_context":false,"supports_prompt_cache":false,"supports_cache_editing":false,"supports_token_efficient":false,"supports_redact_thinking":false,"max_input_tokens":2048,"max_output_tokens":256}}]}).to_string()
}
fn request() -> ChatRequest {
    ChatRequest {
        messages: Some(vec![acosmi::ChatMessage {
            role: "user".into(),
            content: "owned test prompt".into(),
        }]),
        max_tokens: Some(32),
        ..Default::default()
    }
}
fn model_response(wire: GatewayModelWire) -> String {
    match wire {
    GatewayModelWire::OpenAi => chat_text(),
    GatewayModelWire::Anthropic => "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"owned answer\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".into()
}
}
async fn stream_result(c: &Client) -> Vec<acosmi::Result<acosmi::StreamEvent>> {
    let stream = c.chat_stream("qa-model", &request(), None);
    futures_util::pin_mut!(stream);
    let mut out = vec![];
    while let Some(event) = stream.next().await {
        out.push(event);
    }
    out
}

#[tokio::test]
async fn actual_sdk_catalog_and_both_model_wires_preserve_headers_and_release_before_body() {
    for wire in [GatewayModelWire::OpenAi, GatewayModelWire::Anthropic] {
        let mut answer = ResponsePlan::ok(model_response(wire));
        answer.extra_headers = "X-Acosmi-Request-Id: one\r\nX-Acosmi-Request-Id: two\r\n".into();
        let f = TlsFixture::new(vec![ResponsePlan::ok(catalogue(wire)), answer]).await;
        let fence = Arc::new(Fence::default());
        let out = Arc::new(Outcomes::default());
        let t = transport(
            &f,
            wire,
            fence.clone(),
            out.clone(),
            64 * 1024,
            Duration::from_secs(2),
            true,
        );
        let c = client(&f, t).await;
        let ids = Arc::new(AtomicUsize::new(0));
        let ids_copy = ids.clone();
        let stream = c.chat_stream_with_options(
            "qa-model",
            &request(),
            None,
            acosmi::ChatOptions {
                on_gateway_request_id: Some(Arc::new(move |_| {
                    ids_copy.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            },
        );
        futures_util::pin_mut!(stream);
        let mut n = 0;
        while let Some(event) = stream.next().await {
            assert!(event.is_ok());
            n += 1;
            assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
        }
        assert!(n > 0);
        assert_eq!(
            ids.load(Ordering::SeqCst),
            0,
            "duplicate billing ID must not become a single value"
        );
        assert_eq!(f.count(), 2);
        let captures = f.captures.lock().unwrap().clone();
        assert_eq!(captures[0].method, "GET");
        assert_eq!(captures[0].path, "/api/v4/managed-models");
        assert_eq!(captures[1].method, "POST");
        assert_eq!(captures[1].headers["accept"], "text/event-stream");
        assert_eq!(captures[1].headers["content-type"], "application/json");
        assert_eq!(
            captures[1].headers["authorization"],
            "Bearer QA_FAKE_ACCESS"
        );
        assert!(
            serde_json::from_slice::<Value>(&captures[1].body)
                .unwrap()
                .is_object()
        );
        drop(captures);
        assert_eq!(fence.releases.load(Ordering::SeqCst), 2);
        assert!(out.snapshots().iter().all(|s| s.permit_released()));
        f.stop().await;
    }
}

#[tokio::test]
async fn actual_sdk_redirect_private_and_current_refusal_send_no_followup() {
    for status in [303, 307] {
        let target = TlsFixture::new(vec![]).await;
        let mut response = ResponsePlan::ok("{}".into());
        response.status = status;
        response.location = Some(format!("{}/leak", target.endpoint()));
        let f = TlsFixture::new(vec![response]).await;
        let out = Arc::new(Outcomes::default());
        let c = client(
            &f,
            transport(
                &f,
                GatewayModelWire::OpenAi,
                Arc::new(Fence::default()),
                out.clone(),
                65536,
                Duration::from_secs(2),
                true,
            ),
        )
        .await;
        assert!(c.list_models(None, false).await.is_err());
        assert_eq!(f.count(), 1);
        assert_eq!(target.count(), 0);
        assert_eq!(out.snapshots()[0].response_status(), Some(status));
        f.stop().await;
        target.stop().await;
    }
    for refuse in [false, true] {
        let f = TlsFixture::new(vec![]).await;
        let fence = Arc::new(Fence::default());
        fence.refused.store(refuse, Ordering::SeqCst);
        let out = Arc::new(Outcomes::default());
        let c = client(
            &f,
            transport(
                &f,
                GatewayModelWire::OpenAi,
                fence.clone(),
                out.clone(),
                65536,
                Duration::from_secs(2),
                refuse,
            ),
        )
        .await;
        assert!(c.list_models(None, false).await.is_err());
        assert_eq!(f.count(), 0);
        assert_eq!(fence.calls.load(Ordering::SeqCst), 1);
        assert_eq!(out.snapshots().len(), 1);
        f.stop().await;
    }
}
fn metadata(base: &str) -> String {
    json!({"issuer":base,"authorization_endpoint":format!("{base}/authorize"),"token_endpoint":format!("{base}/token"),"registration_endpoint":format!("{base}/register"),"revocation_endpoint":format!("{base}/revoke"),"scopes_supported":["ai"]}).to_string()
}
fn token_response() -> String {
    json!({"access_token":"QA_ROTATED_ACCESS","refresh_token":"QA_ROTATED_REFRESH","token_type":"Bearer","expires_in":3600,"scope":"ai"}).to_string()
}
#[tokio::test]
async fn actual_sdk_oauth_discovery_registration_code_refresh_and_revoke_are_closed() {
    use acosmi::auth::*;
    let mut revoke = ResponsePlan::ok("unread revoke body".into());
    revoke.body_gate = Some(Arc::new(Semaphore::new(0)));
    let f = TlsFixture::new(vec![
        ResponsePlan::ok(metadata("OWNED_ORIGIN")),
        ResponsePlan::ok("{\"client_id\":\"qa-client\"}".into()),
        ResponsePlan::ok(token_response()),
        ResponsePlan::ok(token_response()),
        revoke,
    ])
    .await;
    let out = Arc::new(Outcomes::default());
    let fence = Arc::new(Fence::default());
    let http = acosmi::core::HttpClient::new(transport(
        &f,
        GatewayModelWire::OpenAi,
        fence.clone(),
        out.clone(),
        65536,
        Duration::from_secs(2),
        true,
    ));
    let meta = discover_with_transport(&http, &f.endpoint()).await.unwrap();
    let registration = register_with_transport(&http, &meta, "Owned fixture")
        .await
        .unwrap();
    let _code = exchange_code_with_transport(
        &http,
        &meta,
        &registration.client_id,
        "QA_CODE",
        "http://127.0.0.1/callback",
        "QA_VERIFIER",
    )
    .await
    .unwrap();
    let _refresh =
        refresh_token_with_transport(&http, &meta, &registration.client_id, "QA_REFRESH &plus+")
            .await
            .unwrap();
    revoke_token_with_transport(&http, &meta, "QA_ACCESS")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.closed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.count(), 5);
    let captures = f.captures.lock().unwrap().clone();
    assert!(
        captures
            .iter()
            .all(|c| !c.headers.contains_key("authorization"))
    );
    assert_eq!(
        captures[0].path,
        "/.well-known/oauth-authorization-server/desktop"
    );
    assert_eq!(captures[1].headers["content-type"], "application/json");
    assert!(String::from_utf8_lossy(&captures[3].body).contains("grant_type=refresh_token"));
    assert!(String::from_utf8_lossy(&captures[3].body).contains("%26plus%2B"));
    assert_eq!(captures[4].body, b"token=QA_ACCESS");
    drop(captures);
    assert_eq!(fence.releases.load(Ordering::SeqCst), 5);
    f.stop().await;
}
#[tokio::test]
async fn actual_sdk_401_refresh_rechecks_fence_and_refuses_second_model_post() {
    let mut denied = ResponsePlan::ok("{}".into());
    denied.status = 401;
    let f = TlsFixture::new(vec![
        ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi)),
        denied,
        ResponsePlan::ok(metadata("OWNED_ORIGIN")),
        ResponsePlan::ok(token_response()),
    ])
    .await;
    let fence = Arc::new(Fence::default());
    fence.revoke_after_model.store(true, Ordering::SeqCst);
    let out = Arc::new(Outcomes::default());
    let c = client(
        &f,
        transport(
            &f,
            GatewayModelWire::OpenAi,
            fence.clone(),
            out.clone(),
            65536,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;
    let events = stream_result(&c).await;
    assert!(events.iter().any(Result::is_err));
    assert_eq!(f.count(), 4);
    assert_eq!(
        f.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.ends_with("/chat"))
            .count(),
        1
    );
    assert_eq!(fence.model_calls.load(Ordering::SeqCst), 2);
    let facts = out.snapshots();
    assert_eq!(facts.len(), 5);
    assert_eq!(facts[1].response_status(), Some(401));
    assert!(facts[1].permit_released());
    assert!(!facts[4].may_have_sent());
    assert_eq!(facts[4].failure(), Some(GatewayFailure::Rejected));
    f.stop().await;
}
#[tokio::test]
async fn actual_sdk_response_budgets_header_limits_and_cleanup_unknown_are_not_retried() {
    for mode in 0..4 {
        let mut response = ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi));
        if mode == 1 {
            response.extra_headers = (0..65).map(|i| format!("X-Value-{i}: a\r\n")).collect();
        }
        if mode == 2 {
            response.extra_headers = format!("X-Value: {}\r\n", "a".repeat(8193));
        }
        let f = TlsFixture::new(vec![response]).await;
        let fence = Arc::new(Fence::default());
        fence.fail_release.store(mode == 3, Ordering::SeqCst);
        let out = Arc::new(Outcomes::default());
        let c = client(
            &f,
            transport(
                &f,
                GatewayModelWire::OpenAi,
                fence.clone(),
                out.clone(),
                if mode == 0 { 32 } else { 65536 },
                Duration::from_secs(2),
                true,
            ),
        )
        .await;
        assert!(c.list_models(None, false).await.is_err());
        assert_eq!(f.count(), 1);
        assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
        let facts = out.snapshots();
        assert_eq!(facts.len(), 1);
        assert!(facts[0].may_have_sent());
        assert!(facts[0].failure().is_some());
        if mode == 3 {
            assert_eq!(facts[0].failure(), Some(GatewayFailure::CleanupUnknown));
            assert!(!facts[0].permit_released());
        }
        f.stop().await;
    }
}
#[tokio::test]
async fn actual_sdk_cancellation_at_headers_and_body_closes_connection() {
    for headers in [true, false] {
        let mut response = ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi));
        let gate = Arc::new(Semaphore::new(0));
        if headers {
            response.header_gate = Some(gate);
        } else {
            response.body_gate = Some(gate);
        }
        let f = TlsFixture::new(vec![response]).await;
        let fence = Arc::new(Fence::default());
        let out = Arc::new(Outcomes::default());
        let c = client(
            &f,
            transport(
                &f,
                GatewayModelWire::OpenAi,
                fence.clone(),
                out.clone(),
                65536,
                Duration::from_secs(2),
                true,
            ),
        )
        .await;
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(async move { c.list_models(Some(token), false).await });
        f.wait_count(1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        assert!(task.await.unwrap().is_err());
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.closed.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
        assert_eq!(f.count(), 1);
        assert!(out.snapshots()[0].failure().is_some());
        f.stop().await;
    }
}
#[tokio::test]
async fn actual_sdk_body_stall_and_operation_outcomes_remain_isolated() {
    let mut stalled = ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi));
    stalled.body_gate = Some(Arc::new(Semaphore::new(0)));
    let f = TlsFixture::new(vec![
        stalled,
        ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi)),
    ])
    .await;
    let bad = Arc::new(Outcomes::default());
    let good = Arc::new(Outcomes::default());
    let fence = Arc::new(Fence::default());
    let a = client(
        &f,
        transport(
            &f,
            GatewayModelWire::OpenAi,
            fence.clone(),
            bad.clone(),
            65536,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;
    let b = client(
        &f,
        transport(
            &f,
            GatewayModelWire::OpenAi,
            fence.clone(),
            good.clone(),
            65536,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;
    let first = tokio::spawn(async move { a.list_models(None, false).await });
    f.wait_count(1).await;
    assert_eq!(b.list_models(None, false).await.unwrap().len(), 1);
    assert!(first.await.unwrap().is_err());
    assert_eq!(bad.snapshots()[0].failure(), Some(GatewayFailure::Timeout));
    assert!(good.snapshots()[0].complete());
    assert_eq!(good.snapshots()[0].failure(), None);
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    f.stop().await;
}
fn raw_catalogue(base: &str) -> acosmi::HttpRequest {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer QA_FAKE_ACCESS"),
    );
    acosmi::HttpRequest {
        method: http::Method::GET,
        url: format!("{base}/api/v4/managed-models").parse().unwrap(),
        headers,
        body: vec![],
        context: acosmi::HttpContext::default(),
    }
}
#[tokio::test]
async fn malformed_direct_frames_never_reach_fence_or_socket() {
    let f = TlsFixture::new(vec![]).await;
    let fence = Arc::new(Fence::default());
    let out = Arc::new(Outcomes::default());
    let t = transport(
        &f,
        GatewayModelWire::OpenAi,
        fence.clone(),
        out.clone(),
        65536,
        Duration::from_secs(2),
        true,
    );
    for mode in 0..13 {
        let mut r = raw_catalogue(&f.endpoint());
        match mode {
            0 => {
                r.headers
                    .insert(http::header::COOKIE, http::HeaderValue::from_static("x=y"));
            }
            1 => {
                r.headers.append(
                    http::header::AUTHORIZATION,
                    http::HeaderValue::from_static("Bearer duplicate"),
                );
            }
            2 => {
                r.headers.insert(
                    http::header::HOST,
                    http::HeaderValue::from_static("other.invalid"),
                );
            }
            3 => {
                r.url.set_query(Some("picker=1&x=2"));
            }
            4 => {
                r.url.set_path("/api/v4/managed-models/qa-model/chat/other");
            }
            5 => {
                r.method = http::Method::DELETE;
            }
            6 => {
                r.body.push(b'x');
            }
            7 => {
                r.context.purpose = acosmi::HttpPurpose::Transfer;
            }
            8 => {
                r.context.response_mode = acosmi::HttpResponseMode::Streaming;
            }
            9 => {
                r.headers.insert(
                    http::header::AUTHORIZATION,
                    http::HeaderValue::from_str(&format!("Bearer {}", "x".repeat(16384))).unwrap(),
                );
            }
            10 => {
                r.headers
                    .insert(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
            }
            11 => {
                r.url.set_fragment(Some("hidden"));
            }
            _ => {
                r.context.timeout = Duration::ZERO;
            }
        }
        assert!(t.execute(r, CancellationToken::new()).await.is_err());
    }
    for body in [
        b"grant_type=refresh_token&client_id=qa&refresh_token=x&client_secret=bad".as_slice(),
        b"grant_type=refresh_token&client_id=qa&refresh_token=x&refresh_token=y",
        b"grant_type=refresh_token&client_id=qa&refresh_token=%GG",
        b"grant_type=client_credentials&client_id=qa&client_secret=x",
    ] {
        let mut r = raw_catalogue(&f.endpoint());
        r.url = format!("{}/token", f.endpoint()).parse().unwrap();
        r.method = http::Method::POST;
        r.headers.clear();
        r.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        r.body = body.to_vec();
        r.context.purpose = acosmi::HttpPurpose::OAuthToken;
        assert!(t.execute(r, CancellationToken::new()).await.is_err());
    }
    assert_eq!(fence.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.count(), 0);
    assert_eq!(out.snapshots().len(), 17);
    assert!(out.snapshots().iter().all(|s| !s.may_have_sent()));
    f.stop().await;
}
#[tokio::test]
async fn unpolled_response_drop_releases_driver_without_reading_body() {
    let mut response = ResponsePlan::ok("unread body".into());
    response.body_gate = Some(Arc::new(Semaphore::new(0)));
    let f = TlsFixture::new(vec![response]).await;
    let fence = Arc::new(Fence::default());
    let out = Arc::new(Outcomes::default());
    let t = transport(
        &f,
        GatewayModelWire::OpenAi,
        fence.clone(),
        out.clone(),
        65536,
        Duration::from_secs(2),
        true,
    );
    let response = t
        .execute(raw_catalogue(&f.endpoint()), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    assert_eq!(f.closed.load(Ordering::SeqCst), 0);
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.closed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        out.snapshots()[0].failure(),
        Some(GatewayFailure::Cancelled)
    );
    assert!(out.snapshots()[0].permit_released());
    f.stop().await;
}
#[test]
fn verified_endpoints_and_limits_reject_unbounded_or_ambiguous_configuration() {
    for base in [
        "http://example.test",
        " https://example.test",
        "https://user@example.test",
        "https://example.test/?x=y",
        "https://example.test/#f",
        "https://example.test/\n",
    ] {
        assert!(VerifiedGatewayEndpoints::new(base, None, None).is_err());
    }
    assert!(
        VerifiedGatewayEndpoints::new(
            "https://example.test",
            Some(("..", GatewayModelWire::OpenAi)),
            None
        )
        .is_err()
    );
    let oauth = GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Desktop,
        "https://other.test/reg",
        "https://other.test/token",
        None,
    )
    .unwrap();
    assert!(VerifiedGatewayEndpoints::new("https://example.test", None, Some(oauth)).is_err());
    assert!(GatewayTransportLimits::new(Duration::ZERO, 1).is_err());
    assert!(GatewayTransportLimits::new(Duration::from_secs(31), 1).is_err());
    assert!(GatewayTransportLimits::new(Duration::from_secs(1), 0).is_err());
    assert!(GatewayTransportLimits::new(Duration::from_secs(1), 64 * 1024 * 1024 + 1).is_err());
    let endpoints =
        VerifiedGatewayEndpoints::new("https://example.test/private", None, None).unwrap();
    assert!(!format!("{endpoints:?}").contains("private"));
}
#[tokio::test]
async fn actual_sdk_buffered_model_and_request_budget() {
    let answer=json!({"id":"owned-id","model":"qa-upstream","created":1,"object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"owned answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}).to_string();
    let f = TlsFixture::new(vec![
        ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi)),
        ResponsePlan::ok(answer),
    ])
    .await;
    let fence = Arc::new(Fence::default());
    let out = Arc::new(Outcomes::default());
    let c = client(
        &f,
        transport(
            &f,
            GatewayModelWire::OpenAi,
            fence.clone(),
            out.clone(),
            65536,
            Duration::from_secs(2),
            true,
        ),
    )
    .await;
    let result = c.chat("qa-model", &request(), None).await;
    assert!(
        result.is_ok(),
        "owned fixture result {result:?}, requests {}, outcomes {:?}",
        f.count(),
        out.snapshots()
    );
    assert_eq!(f.count(), 2);
    assert_eq!(
        f.captures.lock().unwrap()[1].headers["accept"],
        "application/json"
    );
    let mut huge = request();
    huge.messages.as_mut().unwrap()[0].content = "a".repeat(8 * 1024 * 1024);
    assert!(c.chat("qa-model", &huge, None).await.is_err());
    assert_eq!(f.count(), 2);
    assert_eq!(fence.calls.load(Ordering::SeqCst), 2);
    let facts = out.snapshots();
    assert_eq!(facts.len(), 3);
    assert!(!facts[2].may_have_sent());
    f.stop().await;
}
#[tokio::test]
async fn actual_sdk_absolute_operation_deadline_bounds_buffered_body() {
    let mut response = ResponsePlan::ok(catalogue(GatewayModelWire::OpenAi));
    response.body_gate = Some(Arc::new(Semaphore::new(0)));
    let f = TlsFixture::new(vec![response]).await;
    let fence = Arc::new(Fence::default());
    let out = Arc::new(Outcomes::default());
    let t = GatewayTransportFactory::new(
        f.dialer_with(false, true),
        VerifiedGatewayEndpoints::new(&f.endpoint(), None, None).unwrap(),
        GatewayTransportLimits::new(Duration::from_secs(2), 65536).unwrap(),
    )
    .for_operation(
        fence.clone(),
        out.clone(),
        Instant::now() + Duration::from_millis(100),
        Duration::from_secs(5),
    )
    .unwrap();
    let c = client(&f, t).await;
    assert!(c.list_models(None, false).await.is_err());
    assert_eq!(out.snapshots()[0].failure(), Some(GatewayFailure::Timeout));
    assert_eq!(fence.permits.load(Ordering::SeqCst), 0);
    assert_eq!(f.count(), 1);
    f.stop().await;
}
