//! Owned wire fixtures for the delivered Remote composition. These ports are not PostgreSQL.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use openbot_agent::{
    BuiltInAgentConfig, BuiltInAgentRuntime, NoAgentToolInvoker, RemoteAguiProvider,
};
use openbot_application::{
    AgentContextError, AgentContextSource, ClaimedRunDispatch, NoAgentAudit, ProviderAdapter,
    ProviderMessage, ProviderMessageRole, ProviderPortError, ProviderRemoteInterruptBatch,
    ProviderRemoteResume, ProviderRemoteResumeEntry, ProviderRemoteResumeStatus, ProviderRequest,
    ProviderRoute, ProviderSession, ProviderToolCall, ProviderToolDefinition,
    RemoteAguiAuthorization, RemoteAguiEventStream, RemoteAguiRoute, RemoteAguiTransport,
    RemoteAguiTransportError, RemoteInterruptCoordinator, RemoteInterruptError,
    RemoteInterruptPending, RemoteInterruptResolutionReceipt, RunDispatchDecision,
    RunExecutionLease, RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel,
    RunTerminal, RunWriteReceipt,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId};
use openbot_domain::{thread::FencingToken, vault::SecretBytes};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer, SafeHttpBudget,
    SchemePolicy,
};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

pub const THREAD: &str = "550e8400-e29b-41d4-a716-446655440000";
pub const LOCAL_RUN: &str = "run-remote-selected";
pub const BOT: &str = "bot-selected";
pub const RESUMED_RUN: &str = "protocol-resumed-selected";
pub const INTERRUPT: &str = "interrupt-selected";
pub const A_TARGET: &str = "/vendor/team-one/agent/run?tenant=a&opaque=x%2Fy&tenant=b";
pub const B_TARGET: &str = "/shadow/vendor/team-one/agent/run?tenant=other";
const AUTHORIZATION: &str = "Bearer synthetic-remote-target";
const ASSERTION: &str = "selected-run-assertion";
const WAIT: Duration = Duration::from_secs(4);

pub fn request(endpoint: &str) -> ProviderRequest {
    let message = |role, content: &str| ProviderMessage {
        role,
        content: content.to_owned(),
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    };
    let mut assistant = message(ProviderMessageRole::Assistant, "");
    assistant.tool_calls.push(ProviderToolCall {
        call_id: "historical-call".to_owned(),
        name: "inspect".to_owned(),
        arguments: json!({"path":"report.txt"}),
    });
    let mut tool = message(ProviderMessageRole::Tool, "historical result");
    tool.tool_call_id = Some("historical-call".to_owned());
    tool.tool_name = Some("inspect".to_owned());
    ProviderRequest {
        route: ProviderRoute::RemoteAgUi(
            RemoteAguiRoute::new(
                endpoint.to_owned(),
                THREAD.to_owned(),
                LOCAL_RUN.to_owned(),
                BOT.to_owned(),
                Some(ASSERTION.to_owned()),
            )
            .expect("typed fixture route")
            .with_authorization(
                RemoteAguiAuthorization::new(SecretBytes::new(AUTHORIZATION.as_bytes().to_vec()))
                    .expect("synthetic authorization"),
            ),
        ),
        messages: vec![
            message(ProviderMessageRole::System, "trusted fixture"),
            message(ProviderMessageRole::User, "Compare"),
            assistant,
            tool,
            message(ProviderMessageRole::User, "fresh request"),
        ],
        tools: vec![ProviderToolDefinition {
            name: "inspect".to_owned(),
            description: "Inspect fixture".to_owned(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},
                "required":["path"],"additionalProperties":false}),
        }],
        // Production remote_ag_ui context also has no local token cap. This actual AG-UI
        // fixture emits no Usage, so Some(cap) would correctly fail the Runtime usage gate
        // before an interrupt can reach the coordinator (preflight01 preserves that setup).
        max_output_tokens: None,
        rate_card: None,
        cost_cap: None,
    }
}

pub fn resume() -> ProviderRemoteResume {
    ProviderRemoteResume::new(
        LOCAL_RUN.to_owned(),
        RESUMED_RUN.to_owned(),
        vec![
            ProviderRemoteResumeEntry::new(
                INTERRUPT.to_owned(),
                ProviderRemoteResumeStatus::Resolved,
                Some(json!({"approved":true})),
            )
            .expect("typed answer"),
        ],
    )
    .expect("typed resume")
}

/// This oracle is independent of the encoder, transport observations, and remote response.
pub fn expected_body(resumed: bool) -> Value {
    let protocol = if resumed { RESUMED_RUN } else { LOCAL_RUN };
    let mut body = json!({
        "threadId":THREAD,"runId":protocol,"state":{},
        "messages":[
            {"id":format!("openbot:{protocol}:message:0"),"role":"system","content":"trusted fixture"},
            {"id":format!("openbot:{protocol}:message:1"),"role":"user","content":"Compare"},
            {"id":format!("openbot:{protocol}:message:2"),"role":"assistant","toolCalls":[
                {"id":"historical-call","type":"function","function":{
                    "name":"inspect","arguments":"{\"path\":\"report.txt\"}"}}]},
            {"id":format!("openbot:{protocol}:message:3"),"role":"tool","content":"historical result",
                "toolCallId":"historical-call","name":"inspect"},
            {"id":format!("openbot:{protocol}:message:4"),"role":"user","content":"fresh request"}
        ],
        "tools":[{"name":"inspect","description":"Inspect fixture","parameters":{
            "type":"object","properties":{"path":{"type":"string"}},"required":["path"],
            "additionalProperties":false}}],
        "context":[],"forwardedProps":{"openbotBotId":BOT,"openbotDeploymentTools":["inspect"],
            "openbotRun":ASSERTION}
    });
    if resumed {
        body["parentRunId"] = json!(LOCAL_RUN);
        body["resume"] =
            json!([{"interruptId":INTERRUPT,"status":"resolved","payload":{"approved":true}}]);
    }
    body
}

#[derive(Clone, Debug)]
pub struct WireRequest {
    pub method: String,
    pub target: String,
    pub host: String,
    pub authorization_matches: bool,
    pub content_type: String,
    pub accept: String,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct WireState {
    pub tcp: AtomicUsize,
    pub requests: Mutex<Vec<WireRequest>>,
    pub responses: Mutex<Vec<String>>,
}

pub struct OwnedServer {
    pub address: SocketAddr,
    pub state: Arc<WireState>,
    cancel: CancellationToken,
    join: JoinHandle<Result<(), String>>,
}

impl OwnedServer {
    pub async fn start(interrupt_first: bool) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("owned loopback");
        let address = listener.local_addr().expect("owned port");
        let state = Arc::new(WireState::default());
        let worker_state = state.clone();
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let join = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    () = worker_cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.map_err(|error| error.to_string())?;
                        worker_state.tcp.fetch_add(1, Ordering::SeqCst);
                        let state = worker_state.clone();
                        handlers.spawn(async move {
                            tokio::time::timeout(WAIT, serve(stream, state, interrupt_first)).await
                                .map_err(|_| "owned handler timeout".to_owned())?
                        });
                    }
                }
            }
            drop(listener);
            while let Some(result) = handlers.join_next().await {
                result.map_err(|error| error.to_string())??;
            }
            Ok(())
        });
        Self {
            address,
            state,
            cancel,
            join,
        }
    }

    pub fn endpoint(&self, target: &str) -> String {
        format!("http://remote.test:{}{target}", self.address.port())
    }

    pub async fn stop(self) -> Result<(), String> {
        self.cancel.cancel();
        self.join.await.map_err(|error| error.to_string())?
    }
}

async fn serve(
    mut stream: TcpStream,
    state: Arc<WireState>,
    interrupt_first: bool,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let (header_end, length) = loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("incomplete owned request".to_owned());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 64 * 1024 {
            return Err("oversized owned request".to_owned());
        }
        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            let end = end + 4;
            let headers = std::str::from_utf8(&bytes[..end]).map_err(|error| error.to_string())?;
            let length = header(headers, "content-length")
                .parse::<usize>()
                .map_err(|error| error.to_string())?;
            if length > 64 * 1024 {
                return Err("oversized owned body".to_owned());
            }
            break (end, length);
        }
    };
    while bytes.len() < header_end + length {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("incomplete owned body".to_owned());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|error| error.to_string())?;
    let mut line = headers
        .lines()
        .next()
        .ok_or("missing request line")?
        .split_whitespace();
    let request = WireRequest {
        method: line.next().ok_or("missing method")?.to_owned(),
        target: line.next().ok_or("missing target")?.to_owned(),
        host: header(headers, "host"),
        authorization_matches: header(headers, "authorization") == AUTHORIZATION,
        content_type: header(headers, "content-type"),
        accept: header(headers, "accept"),
        body: bytes[header_end..header_end + length].to_vec(),
    };
    // Response identity is echoed only to exercise the real decoder. The request oracle never
    // derives its expected identity or body from this response or the observed request.
    let input: Value = serde_json::from_slice(&request.body).map_err(|error| error.to_string())?;
    let ordinal = {
        let mut requests = state.requests.lock().expect("wire lock");
        requests.push(request);
        requests.len()
    };
    let mut events =
        vec![json!({"type":"RUN_STARTED","threadId":input["threadId"],"runId":input["runId"]})];
    if interrupt_first && ordinal == 1 {
        events.push(
            json!({"type":"RUN_FINISHED","threadId":input["threadId"],"runId":input["runId"],
            "outcome":{"type":"interrupt","interrupts":[{"id":INTERRUPT,"reason":"confirmation",
                "message":"Choose","responseSchema":{"type":"object"}}]}}),
        );
    } else {
        events.extend([
            json!({"type":"TEXT_MESSAGE_START","messageId":"answer","role":"assistant"}),
            json!({"type":"TEXT_MESSAGE_CONTENT","messageId":"answer","delta":"resumed answer"}),
            json!({"type":"TEXT_MESSAGE_END","messageId":"answer"}),
            json!({"type":"RUN_FINISHED","threadId":input["threadId"],"runId":input["runId"]}),
        ]);
    }
    let response: String = events
        .into_iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect();
    state
        .responses
        .lock()
        .expect("response lock")
        .push(response.clone());
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())
}

fn header(headers: &str, name: &str) -> String {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| {
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_default()
}

#[derive(Default)]
pub struct OwnedResolver {
    pub calls: Mutex<Vec<(String, u16)>>,
}

#[async_trait]
impl DnsResolver for OwnedResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls
            .lock()
            .expect("resolver lock")
            .push((host.to_owned(), port));
        if host != "remote.test" {
            return Err(DnsUnavailable);
        }
        Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
    }
}

#[derive(Clone, Debug)]
pub struct TransportObservation {
    pub endpoint: String,
    pub authorization_matches: bool,
    pub body: Vec<u8>,
}

pub struct ForwardingTransport {
    inner: SafeRemoteAguiTransport,
    pub observations: Mutex<Vec<TransportObservation>>,
}

impl ForwardingTransport {
    pub fn new(resolver: Arc<OwnedResolver>) -> Self {
        Self {
            inner: SafeRemoteAguiTransport::new(
                SafeDialer::with_resolver(
                    EgressPolicy::new(
                        CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("owned CIDR"),
                    ),
                    resolver,
                ),
                SafeHttpBudget::new(64 * 1024, WAIT).expect("finite budget"),
                Some(WAIT),
                SchemePolicy::HttpOrHttps,
            )
            .expect("explicit test HTTP policy"),
            observations: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RemoteAguiTransport for ForwardingTransport {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.inner.validate_endpoint(endpoint).await
    }

    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.observations
            .lock()
            .expect("transport lock")
            .push(TransportObservation {
                endpoint: endpoint.to_owned(),
                authorization_matches: authorization.and_then(|value| value.expose().ok())
                    == Some(AUTHORIZATION),
                body: body.clone(),
            });
        // Preserve the original owned body and all production parameters; no routing injection.
        self.inner.start(endpoint, authorization, body).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteObservation {
    pub endpoint: String,
    pub thread: String,
    pub local_run: String,
    pub protocol_run: String,
    pub bot: String,
    pub parent: Option<String>,
}

pub struct ForwardingProvider {
    inner: RemoteAguiProvider,
    pub starts: Mutex<Vec<RouteObservation>>,
}

impl ForwardingProvider {
    pub fn new(transport: Arc<ForwardingTransport>) -> Self {
        Self {
            inner: RemoteAguiProvider::new(transport),
            starts: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ProviderAdapter for ForwardingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        if let ProviderRoute::RemoteAgUi(route) = &request.route {
            self.starts
                .lock()
                .expect("provider lock")
                .push(RouteObservation {
                    endpoint: route.endpoint().to_owned(),
                    thread: route.thread_id().to_owned(),
                    local_run: route.local_run_id().to_owned(),
                    protocol_run: route.run_id().to_owned(),
                    bot: route.bot_id().to_owned(),
                    parent: route.parent_protocol_run_id().map(str::to_owned),
                });
        }
        self.inner.start(request).await
    }
}

pub struct ControlledContext {
    pub endpoints: [String; 2],
    pub loads: Mutex<Vec<ProviderRequest>>,
}

#[async_trait]
impl AgentContextSource for ControlledContext {
    async fn load(&self, _lease: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError> {
        let mut loads = self.loads.lock().expect("context lock");
        // The only changed fresh-context input in the drift case is this endpoint selection.
        let value = request(&self.endpoints[usize::from(!loads.is_empty())]);
        loads.push(value.clone());
        Ok(value)
    }
}

#[derive(Default)]
pub struct ControlledCoordinator {
    pub arrived: Notify,
    pub release: Notify,
    pub batches: Mutex<Vec<ProviderRemoteInterruptBatch>>,
}

#[async_trait]
impl RemoteInterruptCoordinator for ControlledCoordinator {
    async fn list_pending(
        &self,
        _auth: &AuthContext,
    ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
        Err(RemoteInterruptError::Unavailable)
    }

    async fn resolve(
        &self,
        _auth: &AuthContext,
        _request_id: &str,
        _status: ProviderRemoteResumeStatus,
        _payload: Option<Value>,
    ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
        Err(RemoteInterruptError::Unavailable)
    }

    async fn persist_and_wait(
        &self,
        _lease: &RunExecutionLease,
        batch: &ProviderRemoteInterruptBatch,
    ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
        self.batches.lock().expect("batch lock").push(batch.clone());
        self.arrived.notify_one();
        self.release.notified().await;
        // Synthetic human answer only. No database persistence, receipt, or authority proof.
        Ok(resume())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeCall {
    Chunk(u64, RunSemanticChannel, String),
    Finish(u64, RunTerminal),
}

#[derive(Default)]
pub struct ControlledRuntime {
    pub calls: Mutex<Vec<RuntimeCall>>,
    pub terminal: Notify,
}

#[async_trait]
impl RunRuntime for ControlledRuntime {
    async fn claim_dispatch(&self) -> Result<Option<ClaimedRunDispatch>, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn acknowledge_dispatch(
        &self,
        _claim: &ClaimedRunDispatch,
    ) -> Result<RunExecutionLease, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn retry_dispatch(&self, _claim: &ClaimedRunDispatch) -> Result<(), RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn reject_dispatch(
        &self,
        _claim: &ClaimedRunDispatch,
        _code: RunFailureCode,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn renew_lease(&self, _lease: &RunExecutionLease) -> Result<(), RunRuntimeError> {
        Ok(())
    }
    async fn append_semantic_chunk(
        &self,
        _lease: &RunExecutionLease,
        sequence: u64,
        channel: RunSemanticChannel,
        chunk: &str,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.calls
            .lock()
            .expect("runtime lock")
            .push(RuntimeCall::Chunk(sequence, channel, chunk.to_owned()));
        Ok(receipt(sequence))
    }
    async fn finish_run(
        &self,
        _lease: &RunExecutionLease,
        sequence: u64,
        terminal: RunTerminal,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.calls
            .lock()
            .expect("runtime lock")
            .push(RuntimeCall::Finish(sequence, terminal));
        self.terminal.notify_one();
        Ok(receipt(sequence))
    }
    async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError> {
        Ok(None)
    }
}

const fn receipt(sequence: u64) -> RunWriteReceipt {
    RunWriteReceipt {
        run_event_sequence: sequence,
        thread_event_sequence: sequence,
        message_sequence: None,
        replayed: false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectCounts {
    pub provider: usize,
    pub transport: usize,
    pub resolver: usize,
    pub tcp: usize,
    pub http: usize,
    pub b_http: usize,
}

pub fn counts(
    provider: &ForwardingProvider,
    transport: &ForwardingTransport,
    resolver: &OwnedResolver,
    wire: &WireState,
) -> EffectCounts {
    let requests = wire.requests.lock().expect("wire lock");
    EffectCounts {
        provider: provider.starts.lock().expect("provider lock").len(),
        transport: transport.observations.lock().expect("transport lock").len(),
        resolver: resolver.calls.lock().expect("resolver lock").len(),
        tcp: wire.tcp.load(Ordering::SeqCst),
        http: requests.len(),
        b_http: requests
            .iter()
            .filter(|request| request.target == B_TARGET)
            .count(),
    }
}

pub struct RuntimeEvidence {
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub port: u16,
    pub accepted: RunDispatchDecision,
    pub activated: bool,
    pub arrived: bool,
    pub completed: bool,
    pub before: EffectCounts,
    pub after: EffectCounts,
    pub starts: Vec<RouteObservation>,
    pub transport: Vec<TransportObservation>,
    pub dns: Vec<(String, u16)>,
    pub wire: Vec<WireRequest>,
    pub responses: Vec<String>,
    pub loads: Vec<ProviderRequest>,
    pub batches: Vec<ProviderRemoteInterruptBatch>,
    pub runtime: Vec<RuntimeCall>,
    pub stopped: Result<(), String>,
}

pub async fn runtime_evidence(drift: bool) -> RuntimeEvidence {
    let server = OwnedServer::start(true).await;
    let port = server.address.port();
    let endpoint_a = server.endpoint(A_TARGET);
    let endpoint_b = if drift {
        server.endpoint(B_TARGET)
    } else {
        endpoint_a.clone()
    };
    let resolver = Arc::new(OwnedResolver::default());
    let transport = Arc::new(ForwardingTransport::new(resolver.clone()));
    let provider = Arc::new(ForwardingProvider::new(transport.clone()));
    let context = Arc::new(ControlledContext {
        endpoints: [endpoint_a.clone(), endpoint_b.clone()],
        loads: Mutex::new(Vec::new()),
    });
    let coordinator = Arc::new(ControlledCoordinator::default());
    let runtime = Arc::new(ControlledRuntime::default());
    let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
        runtime.clone(),
        context.clone(),
        provider.clone(),
        Arc::new(NoAgentToolInvoker),
        Arc::new(NoAgentAudit),
        coordinator.clone(),
        BuiltInAgentConfig {
            queue_capacity: 4,
            max_concurrency: 2,
            max_tool_concurrency: 2,
            lease_renew_interval: Duration::from_secs(10),
            run_deadline: Some(Duration::from_secs(12)),
        },
    )
    .expect("valid finite runtime configuration");
    let lease = RunExecutionLease::new(
        RunId::new(LOCAL_RUN),
        ThreadId::new(THREAD),
        BotId::new(BOT),
        ActorId::new("actor-selected"),
        FencingToken::new(1).expect("fence"),
        1,
    )
    .expect("lease");
    let consumer = agent.consumer();
    let accepted = consumer.dispatch(lease.clone()).await;
    let activated = consumer.activate(&lease).await.is_ok();
    let arrived = tokio::time::timeout(WAIT, coordinator.arrived.notified())
        .await
        .is_ok();
    let before = counts(&provider, &transport, &resolver, &server.state);
    coordinator.release.notify_one();
    let completed = tokio::time::timeout(WAIT, runtime.terminal.notified())
        .await
        .is_ok();
    agent.stop().await;
    let after = counts(&provider, &transport, &resolver, &server.state);
    let wire = server.state.requests.lock().expect("wire lock").clone();
    let responses = server
        .state
        .responses
        .lock()
        .expect("response lock")
        .clone();
    let stopped = server.stop().await;
    let starts = provider.starts.lock().expect("provider lock").clone();
    let transport = transport
        .observations
        .lock()
        .expect("transport lock")
        .clone();
    let dns = resolver.calls.lock().expect("resolver lock").clone();
    let loads = context.loads.lock().expect("context lock").clone();
    let batches = coordinator.batches.lock().expect("batch lock").clone();
    let runtime = runtime.calls.lock().expect("runtime lock").clone();
    RuntimeEvidence {
        endpoint_a,
        endpoint_b,
        port,
        accepted,
        activated,
        arrived,
        completed,
        before,
        after,
        starts,
        transport,
        dns,
        wire,
        responses,
        loads,
        batches,
        runtime,
        stopped,
    }
}

pub fn assert_wire(
    wire: &WireRequest,
    observation: &TransportObservation,
    endpoint: &str,
    port: u16,
    resumed: bool,
) {
    assert_eq!(wire.method, "POST");
    assert_eq!(wire.target, A_TARGET);
    assert_eq!(wire.host, format!("remote.test:{port}"));
    assert_eq!(wire.content_type, "application/json");
    assert_eq!(wire.accept, "text/event-stream, application/json");
    assert!(wire.authorization_matches);
    assert!(observation.authorization_matches);
    assert_eq!(observation.endpoint, endpoint);
    assert_eq!(wire.body, observation.body);
    assert_eq!(
        Sha256::digest(&wire.body),
        Sha256::digest(&observation.body)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&wire.body).expect("actual JSON"),
        expected_body(resumed)
    );
}

pub fn assert_baseline(evidence: &RuntimeEvidence) {
    println!(
        "remote runtime diagnostic: accepted={:?} activated={} arrived={} completed={} before={:?} after={:?} starts={:?} dns={:?} runtime={:?} loads={} batches={} stopped={:?}",
        evidence.accepted,
        evidence.activated,
        evidence.arrived,
        evidence.completed,
        evidence.before,
        evidence.after,
        evidence.starts,
        evidence.dns,
        evidence.runtime,
        evidence.loads.len(),
        evidence.batches.len(),
        evidence.stopped
    );
    for (index, wire) in evidence.wire.iter().enumerate() {
        println!(
            "remote actual wire[{index}]: method={} target={} host={} body={}",
            wire.method,
            wire.target,
            wire.host,
            String::from_utf8_lossy(&wire.body)
        );
    }
    for (index, response) in evidence.responses.iter().enumerate() {
        println!("remote owned SSE[{index}]: {response}");
    }
    assert!(
        evidence.stopped.is_ok(),
        "owned listener joined: {:?}",
        evidence.stopped
    );
    assert_eq!(evidence.accepted, RunDispatchDecision::Accepted);
    assert!(evidence.activated && evidence.arrived && evidence.completed);
    assert_eq!(
        evidence.before,
        EffectCounts {
            provider: 1,
            transport: 1,
            resolver: 1,
            tcp: 1,
            http: 1,
            b_http: 0
        }
    );
    assert_eq!(evidence.loads.len(), 2);
    assert_eq!(evidence.batches.len(), 1);
    assert_eq!(evidence.batches[0].protocol_run_id(), LOCAL_RUN);
    assert_eq!(evidence.batches[0].interrupts().len(), 1);
    assert_eq!(evidence.batches[0].interrupts()[0].id(), INTERRUPT);
    assert_wire(
        &evidence.wire[0],
        &evidence.transport[0],
        &evidence.endpoint_a,
        evidence.port,
        false,
    );
    assert_eq!(
        evidence.starts[0],
        RouteObservation {
            endpoint: evidence.endpoint_a.clone(),
            thread: THREAD.to_owned(),
            local_run: LOCAL_RUN.to_owned(),
            protocol_run: LOCAL_RUN.to_owned(),
            bot: BOT.to_owned(),
            parent: None
        }
    );
    // Full typed-input equality after substituting ONLY the endpoint is stronger than a route
    // identity subset. Authorization exposes only a private synthetic comparison here.
    assert_eq!(evidence.loads[0], request(&evidence.endpoint_a));
    assert_eq!(evidence.loads[1], request(&evidence.endpoint_b));
    let mut first = evidence.loads[0].clone();
    first.route = request(&evidence.endpoint_b).route;
    assert_eq!(first, evidence.loads[1]);
}
