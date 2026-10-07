//! Finite wire counterexamples for the private MCP selected-target boundary.
//!
//! The task-local probe receives the actual production backend and completed RMCP config from
//! `SafeRmcpClient::connect`. Only this test wrapper substitutes one `tools/call` URI. The pinned
//! RMCP client itself preserves its configured URI; this is explicit synthetic fault injection.

use super::*;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::net::safe_http::{DnsResolver, DnsUnavailable};
use async_trait::async_trait;
use axum::response::IntoResponse as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{CallToolResponse, CallToolResult, ServerCapabilities, ServerInfo, Tool};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const TARGET_PATH: &str = "/vendor/team-one/mcp";
const TARGET_QUERY: &str = "tenant=a&opaque=x%2Fy&tenant=b";
const DRIFT_PATH: &str = "/shadow/vendor/team-one/mcp";
const TOOL_NAME: &str = "selected_target_probe";
const SYNTHETIC_BEARER: &str = "synthetic-selected-target-token";
const SESSION_ID: &str = "selected-target-session";
const LAST_EVENT_ID: &str = "selected-target-event";

// Existing non-production idp.test certificate fixture from tests/mcp_protocol.rs. No certificate
// generation or external trust configuration is needed for these owned listeners.
const TLS_CA_DER: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TLS_LEAF_DER: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TLS_LEAF_KEY_DER: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

tokio::task_local! {
    static CONNECT_PROBE: Arc<ConnectProbe>;
}

#[derive(Default)]
struct ConnectProbe {
    backend: Mutex<Option<SafeRmcpHttpClient>>,
    configs: Mutex<Vec<Value>>,
    forwards: Mutex<Vec<Value>>,
    drift_target: Option<Arc<str>>,
    drift_once: AtomicBool,
}

#[derive(Clone)]
pub(super) struct InstrumentedHttp {
    inner: SafeRmcpHttpClient,
    probe: Option<Arc<ConnectProbe>>,
}

pub(super) fn instrument_http(
    inner: SafeRmcpHttpClient,
    config: &StreamableHttpClientTransportConfig,
) -> InstrumentedHttp {
    let probe = CONNECT_PROBE.try_with(Arc::clone).ok();
    if let Some(probe) = &probe {
        *probe.backend.lock().expect("probe backend mutex") = Some(inner.clone());
        probe
            .configs
            .lock()
            .expect("probe config mutex")
            .push(json!({
                "uri": config.uri.as_ref(),
                "allow_stateless": config.allow_stateless,
                "reinit_on_expired_session": config.reinit_on_expired_session,
                "max_sse_event_size": config.max_sse_event_size,
            }));
    }
    InstrumentedHttp { inner, probe }
}

impl InstrumentedHttp {
    fn forwarded_uri(
        &self,
        entry: &str,
        uri: Arc<str>,
        message: Option<&ClientJsonRpcMessage>,
    ) -> Arc<str> {
        let Some(probe) = &self.probe else {
            return uri;
        };
        let body = message.map(|message| serde_json::to_vec(message).expect("typed MCP body"));
        let is_call = body
            .as_ref()
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .is_some_and(|value| value["method"] == "tools/call");
        let drift = is_call
            && probe.drift_target.is_some()
            && !probe.drift_once.swap(true, Ordering::AcqRel);
        let target = if drift {
            probe.drift_target.as_ref().expect("chosen drift").clone()
        } else {
            uri.clone()
        };
        probe
            .forwards
            .lock()
            .expect("probe forward mutex")
            .push(json!({
                "entry": entry,
                "original_uri": uri.as_ref(),
                "forwarded_uri": target.as_ref(),
                "synthetic_drift": drift,
                "body": body.map(|bytes| String::from_utf8(bytes).expect("JSON UTF8")),
            }));
        target
    }
}

impl StreamableHttpClient for InstrumentedHttp {
    type Error = SafeRmcpHttpError;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let uri = self.forwarded_uri("post_message", uri, Some(&message));
        self.inner
            .post_message(uri, message, session_id, auth_header, custom_headers)
            .await
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let uri = self.forwarded_uri("post_message_with_max_sse_event_size", uri, Some(&message));
        self.inner
            .post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        let uri = self.forwarded_uri("get_stream", uri, None);
        self.inner
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        let uri = self.forwarded_uri("get_stream_with_max_sse_event_size", uri, None);
        self.inner
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let uri = self.forwarded_uri("delete_session", uri, None);
        self.inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    host: String,
    body: Vec<u8>,
    authorization_present: bool,
    authorization_matches_synthetic: bool,
    protocol: Option<String>,
    session_id: Option<String>,
    last_event_id: Option<String>,
}

impl CapturedRequest {
    fn json(&self) -> Value {
        json!({
            "method": self.method,
            "target": self.target,
            "host": self.host,
            "body": String::from_utf8_lossy(&self.body),
            "authorization_present": self.authorization_present,
            "authorization_matches_synthetic": self.authorization_matches_synthetic,
            "protocol": self.protocol,
            "session_id": self.session_id,
            "last_event_id": self.last_event_id,
        })
    }
}

#[derive(Clone)]
struct WireServer {
    calls: Arc<Mutex<Vec<Value>>>,
}

impl ServerHandler for WireServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("selected-target-test", "3.1.4"))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            TOOL_NAME,
            "Selected target wire probe.",
            json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]})
                .as_object()
                .expect("schema object")
                .clone(),
        )]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        if request.name != TOOL_NAME {
            return Err(rmcp::ErrorData::invalid_params("unknown probe tool", None));
        }
        self.calls
            .lock()
            .expect("server calls mutex")
            .push(Value::Object(request.arguments.unwrap_or_default()));
        Ok(CallToolResponse::Complete(CallToolResult::success(vec![
            ContentBlock::text("selected target response"),
        ])))
    }
}

struct OwnedServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    calls: Arc<Mutex<Vec<Value>>>,
    raw_mode: Arc<AtomicBool>,
    redirect: Arc<Mutex<Option<(String, String)>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OwnedServer {
    async fn start(path: &'static str) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let raw_mode = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(Mutex::new(None::<(String, String)>));
        let handler = WireServer {
            calls: calls.clone(),
        };
        let service = StreamableHttpService::new(
            move || Ok::<_, std::io::Error>(handler.clone()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default().with_allowed_hosts(["idp.test"]),
        );
        let captured = requests.clone();
        let raw_response = raw_mode.clone();
        let redirected_response = redirect.clone();
        let router =
            axum::Router::new()
                .nest_service(path, service)
                .layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let captured = captured.clone();
                        let raw_response = raw_response.clone();
                        let redirected_response = redirected_response.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let Ok(body) = axum::body::to_bytes(body, 1024 * 1024).await else {
                                return StatusCode::BAD_REQUEST.into_response();
                            };
                            let target = parts
                                .uri
                                .path_and_query()
                                .expect("request target")
                                .as_str()
                                .to_owned();
                            let header = |name: &'static str| {
                                parts
                                    .headers
                                    .get(name)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned)
                            };
                            captured
                                .lock()
                                .expect("wire request mutex")
                                .push(CapturedRequest {
                                    method: parts.method.to_string(),
                                    target: target.clone(),
                                    host: parts
                                        .headers
                                        .get(http::header::HOST)
                                        .expect("host")
                                        .to_str()
                                        .expect("host UTF8")
                                        .to_owned(),
                                    body: body.to_vec(),
                                    authorization_present: parts
                                        .headers
                                        .contains_key(http::header::AUTHORIZATION),
                                    authorization_matches_synthetic: header("authorization")
                                        .is_some_and(|value| {
                                            value == format!("Bearer {SYNTHETIC_BEARER}")
                                        }),
                                    protocol: header("mcp-protocol-version"),
                                    session_id: header("mcp-session-id"),
                                    last_event_id: header("last-event-id"),
                                });
                            let redirect =
                                redirected_response.lock().expect("redirect mutex").clone();
                            if let Some((from, to)) = redirect
                                && target == from
                            {
                                return (
                                    StatusCode::TEMPORARY_REDIRECT,
                                    [(http::header::LOCATION, to)],
                                )
                                    .into_response();
                            }
                            if raw_response.load(Ordering::Acquire) {
                                return if parts.method == http::Method::GET {
                                    StatusCode::METHOD_NOT_ALLOWED.into_response()
                                } else {
                                    StatusCode::NO_CONTENT.into_response()
                                };
                            }
                            next.run(axum::extract::Request::from_parts(
                                parts,
                                axum::body::Body::from(body),
                            ))
                            .await
                        }
                    },
                ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned listener");
        let address = listener.local_addr().expect("owned address");
        let (shutdown, receive) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = receive.await;
                })
                .await
                .expect("owned HTTP serve");
        });
        Self {
            address,
            requests,
            calls,
            raw_mode,
            redirect,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    fn url(&self, path: &str, query: &str) -> String {
        format!("http://idp.test:{}{path}?{query}", self.address.port())
    }

    async fn stop(mut self) -> bool {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let mut task = self.task.take().expect("owned task");
        let stopped = matches!(
            tokio::time::timeout(Duration::from_secs(5), &mut task).await,
            Ok(Ok(()))
        );
        if !stopped {
            task.abort();
            let _ = task.await;
        }
        stopped
    }
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct LocalResolver {
    addresses: Vec<SocketAddr>,
    calls: Mutex<Vec<(String, u16)>>,
}

#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls
            .lock()
            .expect("resolver mutex")
            .push((host.to_owned(), port));
        if host != "idp.test" {
            return Err(DnsUnavailable);
        }
        self.addresses
            .iter()
            .find(|address| address.port() == port)
            .map(|address| vec![*address])
            .ok_or(DnsUnavailable)
    }
}

async fn composed_case(inject_drift: bool) {
    let server_a = OwnedServer::start(TARGET_PATH).await;
    let server_b = OwnedServer::start(DRIFT_PATH).await;
    let selected_a = server_a.url(TARGET_PATH, TARGET_QUERY);
    let injected_b = server_b.url(DRIFT_PATH, "tenant=other");
    let resolver = Arc::new(LocalResolver {
        addresses: vec![server_a.address, server_b.address],
        calls: Mutex::new(Vec::new()),
    });
    let client = SafeRmcpClient::new(
        SafeDialer::with_resolver(
            EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("exact CIDR")),
            resolver.clone(),
        ),
        SchemePolicy::HttpOrHttps,
        Some(Duration::from_secs(2)),
    );
    let probe = Arc::new(ConnectProbe {
        drift_target: inject_drift.then(|| Arc::from(injected_b.as_str())),
        ..ConnectProbe::default()
    });
    let result = CONNECT_PROBE
        .scope(
            probe.clone(),
            client.call_tool(
                &selected_a,
                Some(McpBearerToken::new(SYNTHETIC_BEARER.to_owned()).expect("synthetic token")),
                TOOL_NAME,
                json!({"query":"independent wire fixture"}),
            ),
        )
        .await;
    // No assertions until the controlled servers are shut down and awaited, including RED.
    let a_requests = server_a.requests.lock().expect("A requests mutex").clone();
    let b_requests = server_b.requests.lock().expect("B requests mutex").clone();
    let a_calls = server_a.calls.lock().expect("A calls mutex").clone();
    let b_calls = server_b.calls.lock().expect("B calls mutex").clone();
    let port_a = server_a.address.port();
    let port_b = server_b.address.port();
    let a_stopped = server_a.stop().await;
    let b_stopped = server_b.stop().await;
    let configs = probe.configs.lock().expect("probe configs mutex").clone();
    let forwards = probe.forwards.lock().expect("probe forwards mutex").clone();
    let resolver_calls = resolver
        .calls
        .lock()
        .expect("resolver observations mutex")
        .clone();
    eprintln!(
        "MCP_SELECTED_TARGET_COMPOSED {}",
        json!({
            "selected_a": selected_a, "injected_b": injected_b,
            "synthetic_injection": inject_drift, "actual_connect_configs": configs,
            "actual_rmcp_forwards": forwards,
            "a_requests": a_requests.iter().map(CapturedRequest::json).collect::<Vec<_>>(),
            "b_requests": b_requests.iter().map(CapturedRequest::json).collect::<Vec<_>>(),
            "a_calls": a_calls, "b_calls": b_calls,
            "resolver_calls": resolver_calls,
            "public_result": format!("{result:?}"), "a_stopped": a_stopped, "b_stopped": b_stopped,
        })
    );
    assert!(
        a_stopped && b_stopped,
        "owned servers must stop even on RED"
    );
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0]["uri"], selected_a);
    assert_eq!(configs[0]["allow_stateless"], true);
    assert_eq!(configs[0]["reinit_on_expired_session"], false);
    assert_eq!(configs[0]["max_sse_event_size"], MAX_MCP_SSE_EVENT_BYTES);
    assert!(
        probe
            .backend
            .lock()
            .expect("captured backend mutex")
            .is_some()
    );
    let a_target = format!("{TARGET_PATH}?{TARGET_QUERY}");
    assert!(!a_requests.is_empty());
    assert!(a_requests.iter().all(|request| request.target == a_target));
    assert!(
        a_requests
            .iter()
            .all(|request| request.host == format!("idp.test:{port_a}"))
    );
    assert!(
        a_requests
            .iter()
            .all(|request| request.authorization_matches_synthetic)
    );
    assert!(a_requests.iter().any(|request| {
        serde_json::from_slice::<Value>(&request.body)
            .is_ok_and(|value| value["method"] == "tools/list")
    }));
    if inject_drift {
        let drifted = forwards
            .iter()
            .filter(|forward| forward["synthetic_drift"] == true)
            .collect::<Vec<_>>();
        assert_eq!(drifted.len(), 1, "exactly one synthetic URI substitution");
        assert_eq!(drifted[0]["original_uri"], selected_a);
        assert_eq!(drifted[0]["forwarded_uri"], injected_b);
        let body: Value = serde_json::from_str(drifted[0]["body"].as_str().expect("typed body"))
            .expect("JSON body");
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], TOOL_NAME);
        assert_eq!(
            body["params"]["arguments"],
            json!({"query":"independent wire fixture"})
        );
        // Measure actual B frames before applying the zero-send contract oracle.
        for request in &b_requests {
            assert_eq!(request.method, "POST");
            assert_eq!(request.target, format!("{DRIFT_PATH}?tenant=other"));
            assert_eq!(
                request.body,
                drifted[0]["body"].as_str().expect("typed body").as_bytes()
            );
            assert!(request.authorization_present);
            assert!(request.authorization_matches_synthetic);
            assert_eq!(request.host, format!("idp.test:{port_b}"));
        }
        assert!(
            b_requests.is_empty(),
            "selected A must reject synthetic passed B before wire send"
        );
        assert!(
            resolver_calls
                .iter()
                .all(|(host, port)| host == "idp.test" && *port == port_a)
        );
        assert!(b_calls.is_empty());
        assert!(a_calls.is_empty());
        assert!(result.is_err());
    } else {
        assert!(b_requests.is_empty());
        assert_eq!(a_calls, [json!({"query":"independent wire fixture"})]);
        assert_eq!(
            result.expect("same selected A succeeds").text,
            "selected target response"
        );
    }
    assert!(
        CONNECT_PROBE.try_with(|_| ()).is_err(),
        "task-local injection released"
    );
}

#[tokio::test]
async fn selected_target_real_rmcp_synthetic_call_drift_rejects_before_b_wire() {
    composed_case(true).await;
}

#[tokio::test]
async fn selected_target_real_rmcp_same_a_preserves_prefix_query_and_call_body() {
    composed_case(false).await;
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Post,
    CappedPost,
    Get,
    CappedGet,
    Delete,
}

const ENTRIES: [Entry; 5] = [
    Entry::Post,
    Entry::CappedPost,
    Entry::Get,
    Entry::CappedGet,
    Entry::Delete,
];

impl Entry {
    fn name(self) -> &'static str {
        match self {
            Self::Post => "post_message",
            Self::CappedPost => "post_message_with_max_sse_event_size",
            Self::Get => "get_stream",
            Self::CappedGet => "get_stream_with_max_sse_event_size",
            Self::Delete => "delete_session",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Post | Self::CappedPost => "POST",
            Self::Get | Self::CappedGet => "GET",
            Self::Delete => "DELETE",
        }
    }
}

fn call_message() -> ClientJsonRpcMessage {
    serde_json::from_value(json!({
        "jsonrpc":"2.0", "id":71, "method":"tools/call",
        "params":{"name":TOOL_NAME,"arguments":{"query":"independent wire fixture"}},
    }))
    .expect("known typed tools/call message")
}

fn protocol_headers(entry: Entry) -> HashMap<HeaderName, HeaderValue> {
    let mut headers = HashMap::from([(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_static("2026-07-28"),
    )]);
    if matches!(entry, Entry::Post | Entry::CappedPost) {
        headers.insert(
            HeaderName::from_static("mcp-method"),
            HeaderValue::from_static("tools/call"),
        );
    }
    headers
}

async fn invoke_entry(
    backend: &SafeRmcpHttpClient,
    entry: Entry,
    uri: &str,
) -> Result<(), StreamableHttpError<SafeRmcpHttpError>> {
    let uri = Arc::from(uri);
    let session = Some(Arc::from(SESSION_ID));
    let headers = protocol_headers(entry);
    match entry {
        Entry::Post => backend
            .post_message(uri, call_message(), session, None, headers)
            .await
            .map(drop),
        Entry::CappedPost => backend
            .post_message_with_max_sse_event_size(
                uri,
                call_message(),
                session,
                None,
                headers,
                MAX_MCP_SSE_EVENT_BYTES,
            )
            .await
            .map(drop),
        Entry::Get => backend
            .get_stream(uri, session, Some(LAST_EVENT_ID.to_owned()), None, headers)
            .await
            .map(drop),
        Entry::CappedGet => backend
            .get_stream_with_max_sse_event_size(
                uri,
                session,
                Some(LAST_EVENT_ID.to_owned()),
                None,
                headers,
                MAX_MCP_SSE_EVENT_BYTES,
            )
            .await
            .map(drop),
        Entry::Delete => {
            backend
                .delete_session(uri, Arc::from(SESSION_ID), None, headers)
                .await
        }
    }
}

fn is_transport_rejection(result: &Result<(), StreamableHttpError<SafeRmcpHttpError>>) -> bool {
    matches!(
        result,
        Err(StreamableHttpError::Client(SafeRmcpHttpError::Transport))
    )
}

struct FailResolver(Mutex<Vec<(String, u16)>>);

#[async_trait]
impl DnsResolver for FailResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.0
            .lock()
            .expect("fail resolver mutex")
            .push((host.to_owned(), port));
        Err(DnsUnavailable)
    }
}

async fn capture_from_actual_connect(
    client: &SafeRmcpClient,
    selected: &str,
) -> (SafeRmcpHttpClient, Vec<Value>, String) {
    let probe = Arc::new(ConnectProbe::default());
    let connection = CONNECT_PROBE
        .scope(
            probe.clone(),
            client.connect(
                selected,
                Some(McpBearerToken::new(SYNTHETIC_BEARER.to_owned()).expect("synthetic token")),
                None,
            ),
        )
        .await;
    let description = match connection {
        Ok(mut running) => {
            let closed = running.close_with_timeout(MCP_CLOSE_TIMEOUT).await;
            format!("connected; close={closed:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    let configs = probe.configs.lock().expect("actual config mutex").clone();
    let backend = probe
        .backend
        .lock()
        .expect("actual backend mutex")
        .as_ref()
        .expect("production connect supplies backend")
        .clone();
    assert!(
        CONNECT_PROBE.try_with(|_| ()).is_err(),
        "task-local capture released"
    );
    (backend, configs, description)
}

async fn dns_matrix(selected: &str, canonical: &str, alternatives: &[(&str, String)]) {
    let resolver = Arc::new(FailResolver(Mutex::new(Vec::new())));
    let client = SafeRmcpClient::new(
        SafeDialer::with_resolver(EgressPolicy::default(), resolver.clone()),
        SchemePolicy::HttpOrHttps,
        None,
    );
    let (backend, configs, bootstrap) = capture_from_actual_connect(&client, selected).await;
    let initial = std::mem::take(&mut *resolver.0.lock().expect("initial resolver mutex"));
    let mut rows = Vec::new();
    let mut outcomes = Vec::new();
    for entry in ENTRIES {
        // The exact same valid body/session/headers calibrate every entry before its negatives.
        let result = invoke_entry(&backend, entry, canonical).await;
        let calls = std::mem::take(&mut *resolver.0.lock().expect("exact resolver mutex"));
        rows.push(json!({"entry":entry.name(),"case":"same_a","uri":canonical,"resolver":calls,"result":format!("{result:?}")}));
        outcomes.push((
            entry.name(),
            "same_a",
            is_transport_rejection(&result),
            calls.len() == 1,
        ));
        for (name, target) in alternatives {
            // Clone the actual production-created owner; never construct a test-only URL pin.
            let result = invoke_entry(&backend.clone(), entry, target).await;
            let calls = std::mem::take(&mut *resolver.0.lock().expect("matrix resolver mutex"));
            rows.push(json!({"entry":entry.name(),"case":name,"uri":target,"resolver":calls,"result":format!("{result:?}")}));
            outcomes.push((
                entry.name(),
                *name,
                is_transport_rejection(&result),
                calls.is_empty(),
            ));
        }
    }
    eprintln!(
        "MCP_SELECTED_TARGET_DNS_MATRIX {}",
        json!({
            "input_selected":selected,"actual_connect_configs":configs,"bootstrap_result":bootstrap,
            "bootstrap_resolver":initial,"rows":rows,
        })
    );
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0]["uri"], canonical);
    assert_eq!(
        initial.len(),
        1,
        "actual config A enters one resolver, NeverRetry remains"
    );
    let url = Url::parse(canonical).expect("canonical target");
    assert_eq!(
        initial[0],
        (
            url.host_str().expect("host").to_owned(),
            url.port_or_known_default().expect("port")
        )
    );
    for (entry, name, closed_error, count_matches) in outcomes {
        assert!(
            closed_error && count_matches,
            "entry {entry}, case {name}: selected target boundary drift"
        );
    }
}

#[tokio::test]
async fn selected_target_all_five_entries_reject_full_identity_drift_before_dns() {
    let canonical = "https://mcp.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b";
    let targets = [
        (
            "prefix",
            "https://mcp.test:7443/shadow/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "suffix",
            "https://mcp.test:7443/vendor/team%2Fone/mcp/other?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "default_route",
            "https://mcp.test:7443/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "trailing_slash",
            "https://mcp.test:7443/vendor/team%2Fone/mcp/?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "encoded_slash",
            "https://mcp.test:7443/vendor/team/one/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "other_host",
            "https://other.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "other_port",
            "https://mcp.test:7444/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "other_scheme",
            "http://mcp.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b",
        ),
        (
            "query_removed",
            "https://mcp.test:7443/vendor/team%2Fone/mcp",
        ),
        (
            "query_reordered",
            "https://mcp.test:7443/vendor/team%2Fone/mcp?tenant=b&opaque=x%2Fy&tenant=a",
        ),
        (
            "query_encoding",
            "https://mcp.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x/y&tenant=b",
        ),
        (
            "duplicate_query_removed",
            "https://mcp.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy",
        ),
        (
            "query_added",
            "https://mcp.test:7443/vendor/team%2Fone/mcp?tenant=a&opaque=x%2Fy&tenant=b&other=1",
        ),
    ]
    .map(|(name, target)| (name, target.to_owned()));
    dns_matrix(canonical, canonical, &targets).await;
}

#[tokio::test]
async fn selected_target_all_five_entries_keep_empty_query_identity_and_parser_normalization() {
    let canonical = "https://mcp.test/mcp?";
    let input = "HTTPS://MCP.TEST:443/vendor/../mcp?";
    dns_matrix(
        input,
        canonical,
        &[
            ("empty_query_removed", "https://mcp.test/mcp".to_owned()),
            (
                "empty_query_replaced",
                "https://mcp.test/mcp?a=1".to_owned(),
            ),
        ],
    )
    .await;
    let resolver = Arc::new(FailResolver(Mutex::new(Vec::new())));
    let client = SafeRmcpClient::new(
        SafeDialer::with_resolver(EgressPolicy::default(), resolver.clone()),
        SchemePolicy::HttpsOnly,
        None,
    );
    let (backend, configs, bootstrap) = capture_from_actual_connect(&client, input).await;
    resolver
        .0
        .lock()
        .expect("normalized resolver mutex")
        .clear();
    let mut rows = Vec::new();
    let mut valid = Vec::new();
    for entry in ENTRIES {
        let result = invoke_entry(&backend, entry, input).await;
        let calls = std::mem::take(&mut *resolver.0.lock().expect("normalized resolver mutex"));
        rows.push(json!({"entry":entry.name(),"resolver":calls,"result":format!("{result:?}")}));
        valid.push(is_transport_rejection(&result) && calls == [("mcp.test".to_owned(), 443)]);
    }
    eprintln!(
        "MCP_SELECTED_TARGET_NORMALIZATION {}",
        json!({
            "input_selected":input,"canonical_selected":canonical,"actual_connect_configs":configs,
            "bootstrap_result":bootstrap,"rows":rows,
        })
    );
    assert!(
        valid.into_iter().all(|value| value),
        "parsed-equivalent spelling reaches the same host/port in all entries"
    );
}

struct OwnedTlsProxy {
    address: SocketAddr,
    root: CertificateDer<'static>,
    accepted: Arc<AtomicUsize>,
    handshakes: Arc<AtomicUsize>,
    joined: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OwnedTlsProxy {
    async fn start(backend: SocketAddr) -> Self {
        let decode = |value: &str| BASE64_STANDARD.decode(value).expect("existing TLS fixture");
        let root = CertificateDer::from(decode(TLS_CA_DER));
        let leaf = CertificateDer::from(decode(TLS_LEAF_DER));
        let key = PrivateKeyDer::try_from(decode(TLS_LEAF_KEY_DER))
            .expect("existing private key fixture");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("fixture certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned TLS listener");
        let address = listener.local_addr().expect("TLS address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let joined = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let cancellation = CancellationToken::new();
        let ct = cancellation.clone();
        let tcp_count = accepted.clone();
        let tls_count = handshakes.clone();
        let joined_count = joined.clone();
        let failure_count = failed.clone();
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = ct.cancelled() => break,
                    result = workers.join_next(), if !workers.is_empty() => {
                        if result.is_some() {
                            joined_count.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        tcp_count.fetch_add(1, Ordering::AcqRel);
                        let acceptor = acceptor.clone();
                        let child_ct = ct.clone();
                        let tls_count = tls_count.clone();
                        let failure_count = failure_count.clone();
                        workers.spawn(async move {
                            let handshake = acceptor.accept(stream);
                            let mut stream = tokio::select! {
                                _ = child_ct.cancelled() => return,
                                result = handshake => match result {
                                    Ok(stream) => stream,
                                    Err(_) => { failure_count.fetch_add(1, Ordering::AcqRel); return; }
                                },
                            };
                            tls_count.fetch_add(1, Ordering::AcqRel);
                            let mut connection = match tokio::net::TcpStream::connect(backend).await {
                                Ok(connection) => connection,
                                Err(_) => { failure_count.fetch_add(1, Ordering::AcqRel); return; }
                            };
                            tokio::select! {
                                _ = child_ct.cancelled() => {},
                                _ = tokio::io::copy_bidirectional(&mut stream, &mut connection) => {},
                            }
                        });
                    }
                }
            }
            ct.cancel();
            while workers.join_next().await.is_some() {
                joined_count.fetch_add(1, Ordering::AcqRel);
            }
        });
        Self {
            address,
            root,
            accepted,
            handshakes,
            joined,
            failed,
            cancellation,
            task: Some(task),
        }
    }

    async fn stop(mut self) -> Value {
        self.cancellation.cancel();
        let mut task = self.task.take().expect("owned TLS task");
        let stopped = matches!(
            tokio::time::timeout(Duration::from_secs(5), &mut task).await,
            Ok(Ok(()))
        );
        if !stopped {
            task.abort();
            let _ = task.await;
        }
        json!({
            "stopped":stopped,"accepted_tcp":self.accepted.load(Ordering::Acquire),
            "handshakes":self.handshakes.load(Ordering::Acquire),
            "joined_children":self.joined.load(Ordering::Acquire),"failures":self.failed.load(Ordering::Acquire),
        })
    }
}

impl Drop for OwnedTlsProxy {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct OwnedEndpoint {
    server: Option<OwnedServer>,
    tls: Option<OwnedTlsProxy>,
}

impl OwnedEndpoint {
    async fn start(path: &'static str, tls: bool) -> Self {
        let server = OwnedServer::start(path).await;
        let tls = if tls {
            Some(OwnedTlsProxy::start(server.address).await)
        } else {
            None
        };
        Self {
            server: Some(server),
            tls,
        }
    }

    fn address(&self) -> SocketAddr {
        self.tls
            .as_ref()
            .map_or_else(|| self.server().address, |tls| tls.address)
    }

    fn server(&self) -> &OwnedServer {
        self.server.as_ref().expect("owned server")
    }

    fn url(&self, path: &str, query: &str) -> String {
        format!(
            "{}://idp.test:{}{path}?{query}",
            if self.tls.is_some() { "https" } else { "http" },
            self.address().port()
        )
    }

    async fn stop(mut self) -> Value {
        let tls = match self.tls.take() {
            Some(tls) => Some(tls.stop().await),
            None => None,
        };
        let http_stopped = self.server.take().expect("owned server").stop().await;
        json!({"http_stopped":http_stopped,"tls":tls})
    }
}

fn fixture_dialer(resolver: Arc<LocalResolver>, endpoint: &OwnedEndpoint) -> SafeDialer {
    let policy =
        EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("exact CIDR"));
    match &endpoint.tls {
        Some(tls) => SafeDialer::with_extra_roots(policy, resolver, [tls.root.clone()])
            .expect("existing test CA"),
        None => SafeDialer::with_resolver(policy, resolver),
    }
}

async fn all_five_wire(tls: bool) {
    let server_a = OwnedEndpoint::start(TARGET_PATH, tls).await;
    let server_b = OwnedEndpoint::start(DRIFT_PATH, tls).await;
    let selected_a = server_a.url(TARGET_PATH, TARGET_QUERY);
    let target_b = server_b.url(DRIFT_PATH, "tenant=other");
    let address_a = server_a.address();
    let address_b = server_b.address();
    let resolver = Arc::new(LocalResolver {
        addresses: vec![address_a, address_b],
        calls: Mutex::new(Vec::new()),
    });
    let client = SafeRmcpClient::new(
        fixture_dialer(resolver.clone(), &server_a),
        if tls {
            SchemePolicy::HttpsOnly
        } else {
            SchemePolicy::HttpOrHttps
        },
        Some(Duration::from_secs(2)),
    );
    let probe = Arc::new(ConnectProbe::default());
    let calibration = CONNECT_PROBE
        .scope(
            probe.clone(),
            client.call_tool(
                &selected_a,
                Some(McpBearerToken::new(SYNTHETIC_BEARER.to_owned()).expect("synthetic token")),
                TOOL_NAME,
                json!({"query":"independent wire fixture"}),
            ),
        )
        .await;
    let backend = probe
        .backend
        .lock()
        .expect("actual backend mutex")
        .as_ref()
        .expect("captured production owner")
        .clone();
    let configs = probe.configs.lock().expect("actual config mutex").clone();
    let calibration_requests = std::mem::take(
        &mut *server_a
            .server()
            .requests
            .lock()
            .expect("calibration requests mutex"),
    );
    server_a.server().raw_mode.store(true, Ordering::Release);
    server_b.server().raw_mode.store(true, Ordering::Release);
    resolver.calls.lock().expect("resolver mutex").clear();
    let mut rows = Vec::new();
    let mut positives = Vec::new();
    let mut negatives = Vec::new();
    for entry in ENTRIES {
        let result = invoke_entry(&backend, entry, &selected_a).await;
        let requests = std::mem::take(
            &mut *server_a
                .server()
                .requests
                .lock()
                .expect("A matrix request mutex"),
        );
        let calls = std::mem::take(&mut *resolver.calls.lock().expect("A matrix resolver mutex"));
        rows.push(json!({"entry":entry.name(),"case":"same_a","resolver":calls,
            "requests":requests.iter().map(CapturedRequest::json).collect::<Vec<_>>(),"result":format!("{result:?}")}));
        positives.push((entry, result, requests, calls));
        let result = invoke_entry(&backend.clone(), entry, &target_b).await;
        let requests_a = std::mem::take(
            &mut *server_a
                .server()
                .requests
                .lock()
                .expect("A negative request mutex"),
        );
        let requests_b = std::mem::take(
            &mut *server_b
                .server()
                .requests
                .lock()
                .expect("B negative request mutex"),
        );
        let calls = std::mem::take(&mut *resolver.calls.lock().expect("B negative resolver mutex"));
        rows.push(json!({"entry":entry.name(),"case":"passed_b","resolver":calls,
            "a_requests":requests_a.iter().map(CapturedRequest::json).collect::<Vec<_>>(),
            "b_requests":requests_b.iter().map(CapturedRequest::json).collect::<Vec<_>>(),"result":format!("{result:?}")}));
        negatives.push((entry, result, requests_a, requests_b, calls));
    }
    let a_stop = server_a.stop().await;
    let b_stop = server_b.stop().await;
    eprintln!(
        "MCP_SELECTED_TARGET_ALL_FIVE_WIRE {}",
        json!({
            "tls":tls,"selected_a":selected_a,"target_b":target_b,"actual_connect_configs":configs,
            "public_calibration":format!("{calibration:?}"),
            "calibration_requests":calibration_requests.iter().map(CapturedRequest::json).collect::<Vec<_>>(),
            "rows":rows,"a_stop":a_stop,"b_stop":b_stop,
        })
    );
    assert_eq!(a_stop["http_stopped"], true);
    assert_eq!(b_stop["http_stopped"], true);
    if tls {
        for stop in [&a_stop, &b_stop] {
            assert_eq!(stop["tls"]["stopped"], true);
            assert_eq!(stop["tls"]["accepted_tcp"], stop["tls"]["joined_children"]);
            assert_eq!(stop["tls"]["failures"], 0);
        }
        assert_eq!(a_stop["tls"]["accepted_tcp"], a_stop["tls"]["handshakes"]);
        assert!(
            a_stop["tls"]["handshakes"]
                .as_u64()
                .expect("handshake count")
                >= 5
        );
        assert_eq!(b_stop["tls"]["accepted_tcp"], 0);
    }
    assert_eq!(
        calibration.expect("public selected A calibration").text,
        "selected target response"
    );
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0]["uri"], selected_a);
    assert!(calibration_requests.iter().any(|request| {
        serde_json::from_slice::<Value>(&request.body).is_ok_and(|value| {
            value["method"] == "tools/call"
                && value["params"]["name"] == TOOL_NAME
                && value["params"]["arguments"] == json!({"query":"independent wire fixture"})
        })
    }));
    let expected_body = serde_json::to_vec(&call_message()).expect("independent typed body");
    for (entry, result, requests, calls) in positives {
        assert_eq!(
            calls,
            [("idp.test".to_owned(), address_a.port())],
            "same A resolver calibration in {}",
            entry.name()
        );
        assert_eq!(
            requests.len(),
            1,
            "same A wire calibration in {}",
            entry.name()
        );
        let request = &requests[0];
        assert_eq!(request.method, entry.method());
        assert_eq!(request.target, format!("{TARGET_PATH}?{TARGET_QUERY}"));
        assert_eq!(request.host, format!("idp.test:{}", address_a.port()));
        assert!(request.authorization_present && request.authorization_matches_synthetic);
        assert_eq!(request.protocol.as_deref(), Some("2026-07-28"));
        assert_eq!(request.session_id.as_deref(), Some(SESSION_ID));
        if matches!(entry, Entry::Post | Entry::CappedPost) {
            assert_eq!(request.body, expected_body);
            assert!(result.is_ok());
        } else {
            assert!(request.body.is_empty());
            if matches!(entry, Entry::Get | Entry::CappedGet) {
                assert_eq!(request.last_event_id.as_deref(), Some(LAST_EVENT_ID));
                assert!(matches!(
                    result,
                    Err(StreamableHttpError::ServerDoesNotSupportSse)
                ));
            } else {
                assert!(result.is_ok());
            }
        }
    }
    for (entry, result, requests_a, requests_b, calls) in negatives {
        assert!(
            is_transport_rejection(&result),
            "closed drift rejection in {}",
            entry.name()
        );
        assert!(
            calls.is_empty() && requests_a.is_empty() && requests_b.is_empty(),
            "zero network drift in {}",
            entry.name()
        );
    }
    assert!(CONNECT_PROBE.try_with(|_| ()).is_err());
}

#[tokio::test]
async fn selected_target_all_five_http_entries_have_real_positive_and_zero_b_controls() {
    all_five_wire(false).await;
}

#[tokio::test]
async fn selected_target_all_five_tls_entries_have_real_positive_and_zero_b_controls() {
    all_five_wire(true).await;
}

#[tokio::test]
async fn selected_target_admitted_post_keeps_explicit_same_origin_redirect_policy() {
    let server = OwnedEndpoint::start(TARGET_PATH, false).await;
    let selected = server.url(TARGET_PATH, TARGET_QUERY);
    let address = server.address();
    let resolver = Arc::new(LocalResolver {
        addresses: vec![address],
        calls: Mutex::new(Vec::new()),
    });
    let client = SafeRmcpClient::new(
        fixture_dialer(resolver.clone(), &server),
        SchemePolicy::HttpOrHttps,
        None,
    );
    let (backend, configs, bootstrap) = capture_from_actual_connect(&client, &selected).await;
    server.server().raw_mode.store(true, Ordering::Release);
    let target_a = format!("{TARGET_PATH}?{TARGET_QUERY}");
    let redirected_target = "/redirected/mcp?source=explicit-policy";
    *server
        .server()
        .redirect
        .lock()
        .expect("redirect setting mutex") = Some((target_a.clone(), redirected_target.to_owned()));
    server
        .server()
        .requests
        .lock()
        .expect("old requests mutex")
        .clear();
    resolver.calls.lock().expect("old resolver mutex").clear();
    let result = invoke_entry(&backend, Entry::CappedPost, &selected).await;
    let requests = server
        .server()
        .requests
        .lock()
        .expect("redirect observations mutex")
        .clone();
    let calls = resolver
        .calls
        .lock()
        .expect("redirect resolver mutex")
        .clone();
    let stopped = server.stop().await;
    eprintln!(
        "MCP_SELECTED_TARGET_EXPLICIT_REDIRECT {}",
        json!({
            "selected":selected,"actual_connect_configs":configs,"bootstrap_result":bootstrap,
            "requests":requests.iter().map(CapturedRequest::json).collect::<Vec<_>>(),
            "resolver":calls,"result":format!("{result:?}"),"stopped":stopped,
        })
    );
    assert_eq!(stopped["http_stopped"], true);
    assert_eq!(configs[0]["uri"], selected);
    assert!(
        bootstrap.starts_with("connected;"),
        "production connect actually initialized at selected A"
    );
    assert!(result.is_ok());
    assert_eq!(
        calls,
        [
            ("idp.test".to_owned(), address.port()),
            ("idp.test".to_owned(), address.port())
        ]
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, target_a);
    assert_eq!(requests[1].target, redirected_target);
    let expected_body = serde_json::to_vec(&call_message()).expect("independent typed body");
    for request in requests {
        assert_eq!(request.method, "POST");
        assert_eq!(request.host, format!("idp.test:{}", address.port()));
        assert_eq!(request.body, expected_body);
        assert!(request.authorization_matches_synthetic);
        assert_eq!(request.session_id.as_deref(), Some(SESSION_ID));
    }
}
