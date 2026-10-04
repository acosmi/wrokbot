//! Strict finite owned TLS replies: one real 200 SSE, then one real held 401.
//! Request capture, writes, shutdown attempts and child joins remain distinct observations.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct RawRequest {
    pub request_ordinal: usize,
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub header_counts: BTreeMap<String, usize>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct Counts {
    pub dns: usize,
    pub tcp: usize,
    pub http: usize,
}

pub struct WireRecord {
    pub counts: Counts,
    pub requests: Vec<RawRequest>,
    pub joined: usize,
    pub failed: usize,
    pub state: Value,
}

#[derive(Clone, Default)]
struct Gate {
    request_captured: bool,
    request_ordinal: Option<usize>,
    header_held: bool,
    release_sent: bool,
}

impl Gate {
    fn value(&self) -> Value {
        json!({"requestCaptured":self.request_captured,"requestOrdinal":self.request_ordinal,
            "headerHeld":self.header_held,"releaseSent":self.release_sent})
    }
}

#[derive(Default)]
struct PositiveStreamGate {
    armed: bool,
    subscription_observed: bool,
    body_release_sent: bool,
    thread_id: Option<String>,
    run_id: Option<String>,
    actor_id: Option<String>,
    session_id: Option<String>,
    auth_generation: Option<i64>,
    subscription_sequence: Option<u64>,
    subscription_status: Option<u16>,
    error: Option<&'static str>,
}

impl PositiveStreamGate {
    fn value(&self) -> Value {
        json!({"armed":self.armed,"subscriptionObserved":self.subscription_observed,
            "bodyReleaseSent":self.body_release_sent,"threadId":self.thread_id,"runId":self.run_id,
            "actorId":self.actor_id,"sessionId":self.session_id,"authGeneration":self.auth_generation,
            "subscriptionSequence":self.subscription_sequence,"subscriptionStatus":self.subscription_status,
            "error":self.error})
    }
}

pub struct PositiveSubscription {
    pub thread_id: String,
    pub run_id: String,
    pub actor_id: String,
    pub session_id: String,
    pub auth_generation: i64,
    /// The original HTTP middleware sequence, never a business event cursor.
    pub sequence: u64,
    pub status: u16,
}

#[derive(Clone)]
pub struct PositiveStreamWitness {
    shared: Arc<Mutex<Shared>>,
}

impl PositiveStreamWitness {
    pub fn observe(&self, subscription: PositiveSubscription) -> Result<(), &'static str> {
        if subscription.status != 200
            || subscription.sequence == 0
            || subscription.auth_generation < 0
        {
            return Err("owned_tls_positive_subscription_invalid");
        }
        let mut shared = locked(&self.shared)?;
        let gate = &mut shared.positive;
        if gate.error.is_some() {
            return Err("owned_tls_positive_already_failed");
        }
        if gate.subscription_observed {
            if gate.thread_id.as_deref() != Some(subscription.thread_id.as_str())
                || gate.run_id.as_deref() != Some(subscription.run_id.as_str())
                || gate.actor_id.as_deref() != Some(subscription.actor_id.as_str())
                || gate.session_id.as_deref() != Some(subscription.session_id.as_str())
                || gate.auth_generation != Some(subscription.auth_generation)
            {
                return Err("owned_tls_positive_subscription_identity");
            }
            return Ok(());
        }
        gate.subscription_observed = true;
        gate.thread_id = Some(subscription.thread_id);
        gate.run_id = Some(subscription.run_id);
        gate.actor_id = Some(subscription.actor_id);
        gate.session_id = Some(subscription.session_id);
        gate.auth_generation = Some(subscription.auth_generation);
        gate.subscription_sequence = Some(subscription.sequence);
        gate.subscription_status = Some(subscription.status);
        release_positive_if_ready(&mut shared)
    }

    pub fn fail(&self, code: &'static str) {
        if let Ok(mut shared) = locked(&self.shared)
            && shared.positive.error.is_none()
        {
            shared.positive.error = Some(code);
        }
    }
}

#[derive(Clone)]
struct Connection {
    connection_ordinal: usize,
    request_ordinal: Option<usize>,
    status: Option<u16>,
    tls_accepted: bool,
    request_captured: bool,
    headers_written: bool,
    body_written: bool,
    shutdown_attempted: bool,
    shutdown_returned: bool,
    error: Option<&'static str>,
}

impl Connection {
    fn value(&self) -> Value {
        json!({"connectionOrdinal":self.connection_ordinal,"requestOrdinal":self.request_ordinal,
            "status":self.status,"tlsAccepted":self.tls_accepted,"requestCaptured":self.request_captured,
            "headersWritten":self.headers_written,"bodyWritten":self.body_written,
            "shutdownAttempted":self.shutdown_attempted,"shutdownReturned":self.shutdown_returned,
            "error":self.error})
    }
}

struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
}

struct Shared {
    requests: Vec<RawRequest>,
    connections: Vec<Connection>,
    replies: VecDeque<Reply>,
    gate: Gate,
    positive: PositiveStreamGate,
    release: Option<oneshot::Sender<()>>,
    released: Option<oneshot::Receiver<()>>,
    positive_release: Option<oneshot::Sender<()>>,
    positive_released: Option<oneshot::Receiver<()>>,
    listener_errors: Vec<&'static str>,
}

fn release_positive_if_ready(shared: &mut Shared) -> Result<(), &'static str> {
    if shared.positive.armed
        && shared.positive.subscription_observed
        && !shared.positive.body_release_sent
        && shared.positive.error.is_none()
    {
        let sent = shared
            .positive_release
            .take()
            .ok_or("owned_tls_positive_release_missing")?
            .send(())
            .map_err(|_| "owned_tls_positive_receiver_closed");
        if let Err(code) = sent {
            shared.positive.error = Some(code);
            return Err(code);
        }
        shared.positive.body_release_sent = true;
    }
    Ok(())
}

fn locked(shared: &Mutex<Shared>) -> Result<MutexGuard<'_, Shared>, &'static str> {
    shared.lock().map_err(|_| "owned_tls_observation_poisoned")
}

fn update_connection(
    shared: &Mutex<Shared>,
    index: usize,
    update: impl FnOnce(&mut Connection),
) -> Result<(), &'static str> {
    let mut state = locked(shared)?;
    let connection = state
        .connections
        .get_mut(index)
        .ok_or("owned_tls_connection_missing")?;
    update(connection);
    Ok(())
}

struct Resolver {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if host != "idp.test" || port != self.address.port() {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}

pub struct OwnedWire {
    address: SocketAddr,
    root: CertificateDer<'static>,
    dns: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
    http: Arc<AtomicUsize>,
    shared: Arc<Mutex<Shared>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<(usize, usize)>>,
}

impl OwnedWire {
    pub async fn new(positive_sse: String, certificate: [&str; 3]) -> Result<Self, &'static str> {
        let root = CertificateDer::from(
            STANDARD
                .decode(certificate[0])
                .map_err(|_| "owned_tls_root")?,
        );
        let leaf = CertificateDer::from(
            STANDARD
                .decode(certificate[1])
                .map_err(|_| "owned_tls_leaf")?,
        );
        let key = PrivateKeyDer::try_from(
            STANDARD
                .decode(certificate[2])
                .map_err(|_| "owned_tls_key")?,
        )
        .map_err(|_| "owned_tls_key")?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| "owned_tls_protocol")?
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .map_err(|_| "owned_tls_certificate")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "owned_tls_bind")?;
        let address = listener.local_addr().map_err(|_| "owned_tls_address")?;
        if [39025, 39027].contains(&address.port()) {
            return Err("owned_tls_protected_port");
        }
        let (release, released) = oneshot::channel();
        let (positive_release, positive_released) = oneshot::channel();
        let shared = Arc::new(Mutex::new(Shared {
            requests: Vec::new(),
            connections: Vec::new(),
            replies: VecDeque::from([
                Reply {
                    status: 200,
                    content_type: "text/event-stream",
                    body: positive_sse,
                },
                Reply {
                    status: 401,
                    content_type: "application/json",
                    body: "{\"error\":\"owned_c2_authentication\"}".to_owned(),
                },
            ]),
            gate: Gate::default(),
            positive: PositiveStreamGate::default(),
            release: Some(release),
            released: Some(released),
            positive_release: Some(positive_release),
            positive_released: Some(positive_released),
            listener_errors: Vec::new(),
        }));
        let dns = Arc::new(AtomicUsize::new(0));
        let tcp = Arc::new(AtomicUsize::new(0));
        let http = Arc::new(AtomicUsize::new(0));
        let accepted = tcp.clone();
        let captured = http.clone();
        let observations = shared.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            let mut joined = 0;
            let mut failed = 0;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    connection = listener.accept() => {
                        let (stream, _) = match connection {
                            Ok(value) => value,
                            Err(_) => {
                                if let Ok(mut state) = locked(&observations) {
                                    state.listener_errors.push("owned_tls_accept");
                                }
                                break;
                            }
                        };
                        let ordinal = accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        let index = match locked(&observations) {
                            Ok(mut state) => {
                                let index = state.connections.len();
                                state.connections.push(Connection {
                                    connection_ordinal: ordinal, request_ordinal: None, status: None,
                                    tls_accepted: false, request_captured: false, headers_written: false,
                                    body_written: false, shutdown_attempted: false, shutdown_returned: false,
                                    error: None,
                                });
                                index
                            }
                            Err(_) => { failed += 1; break; }
                        };
                        let tls = acceptor.clone();
                        let shared = observations.clone();
                        let captured = captured.clone();
                        children.spawn(async move {
                            let result = tokio::time::timeout(Duration::from_secs(8),
                                serve_connection(stream, tls, shared.clone(), captured, index)).await
                                .unwrap_or(Err("owned_tls_connection_deadline"));
                            if let Err(code) = result {
                                let _ = update_connection(&shared, index, |row| row.error = Some(code));
                                if let Ok(mut state)=locked(&shared)
                                    && state.connections.get(index).is_some_and(|row|row.request_ordinal==Some(1))
                                    && state.positive.error.is_none()
                                { state.positive.error=Some(code); }
                            }
                            result
                        });
                    }
                    result = children.join_next(), if !children.is_empty() => {
                        joined += 1;
                        match result {
                            Some(Ok(Ok(()))) => {},
                            Some(Ok(Err(_))) => failed += 1,
                            _ => {
                                failed += 1;
                                if let Ok(mut state) = locked(&observations) {
                                    state.listener_errors.push("owned_tls_child_join");
                                }
                            }
                        }
                    }
                }
            }
            drop(listener);
            // Every child owns an eight-second deadline. Stop accepting and join, never abort.
            while let Some(result) = children.join_next().await {
                joined += 1;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => failed += 1,
                    Err(_) => {
                        failed += 1;
                        if let Ok(mut state) = locked(&observations) {
                            state.listener_errors.push("owned_tls_child_join");
                        }
                    }
                }
            }
            (joined, failed)
        });
        Ok(Self {
            address,
            root,
            dns,
            tcp,
            http,
            shared,
            stop: Some(stop),
            task: Some(task),
        })
    }

    pub fn origin(&self) -> String {
        format!("https://idp.test:{}", self.address.port())
    }

    pub fn dialer(&self) -> SafeDialer {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).expect("fixed owned CIDR"),
            ),
            Arc::new(Resolver {
                address: self.address,
                calls: self.dns.clone(),
            }),
            [self.root.clone()],
        )
        .expect("fixed owned root and policy")
    }

    pub fn counts(&self) -> Counts {
        Counts {
            dns: self.dns.load(Ordering::SeqCst),
            tcp: self.tcp.load(Ordering::SeqCst),
            http: self.http.load(Ordering::SeqCst),
        }
    }

    pub fn requests(&self) -> Result<Vec<RawRequest>, &'static str> {
        Ok(locked(&self.shared)?.requests.clone())
    }

    pub fn positive_witness(&self) -> PositiveStreamWitness {
        PositiveStreamWitness {
            shared: self.shared.clone(),
        }
    }

    pub fn state(&self) -> Result<Value, &'static str> {
        let shared = locked(&self.shared)?;
        let connections: Vec<Value> = shared.connections.iter().map(Connection::value).collect();
        Ok(
            json!({"gate":shared.gate.value(),"remainingReplies":shared.replies.len(),
            "connections":connections,"listenerErrors":shared.listener_errors,
            "positiveStreamGate":shared.positive.value()}),
        )
    }

    pub fn gate(&self) -> Result<Value, &'static str> {
        Ok(locked(&self.shared)?.gate.value())
    }

    pub async fn wait_held(&self, timeout: Duration) -> Result<bool, &'static str> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let state = locked(&self.shared)?;
                if state.gate.request_captured && state.gate.header_held && !state.gate.release_sent
                {
                    return Ok(true);
                }
                if state.gate.release_sent {
                    return Err("owned_tls_gate_already_released");
                }
                if state.connections.iter().any(|row| row.error.is_some()) {
                    return Err("owned_tls_connection_failed");
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn release401(&self) -> Result<(), &'static str> {
        let mut shared = locked(&self.shared)?;
        if !shared.gate.request_captured || !shared.gate.header_held || shared.gate.release_sent {
            return Err("owned_tls_gate_not_held_once");
        }
        shared
            .release
            .take()
            .ok_or("owned_tls_release_missing")?
            .send(())
            .map_err(|_| "owned_tls_release_receiver_closed")?;
        // Sender acknowledgement does not mean that headers, body or shutdown completed.
        shared.gate.release_sent = true;
        Ok(())
    }

    pub async fn finish(mut self) -> WireRecord {
        if self
            .stop
            .take()
            .is_none_or(|sender| sender.send(()).is_err())
            && let Ok(mut state) = locked(&self.shared)
        {
            state.listener_errors.push("owned_tls_stop_sender");
        }
        // Closing an unreleased gate is a failed child, never a synthetic successful 401 release.
        if let Ok(mut state) = locked(&self.shared) {
            state.release.take();
            state.positive_release.take();
        }
        let (joined, failed) = match self.task.take() {
            Some(task) => match task.await {
                Ok(value) => value,
                Err(_) => {
                    if let Ok(mut state) = locked(&self.shared) {
                        state.listener_errors.push("owned_tls_listener_join");
                    }
                    (0, 1)
                }
            },
            None => {
                if let Ok(mut state) = locked(&self.shared) {
                    state.listener_errors.push("owned_tls_listener_missing");
                }
                (0, 1)
            }
        };
        // Preserve the actual captured contents even after a poisoned observation lock.
        // Poisoning remains an explicit closure error and never supplies zero/fabricated facts.
        let (requests, state) = {
            let shared = match self.shared.lock() {
                Ok(value) => value,
                Err(poisoned) => {
                    let mut value = poisoned.into_inner();
                    value.listener_errors.push("owned_tls_observation_poisoned");
                    value
                }
            };
            let connections: Vec<Value> =
                shared.connections.iter().map(Connection::value).collect();
            (
                shared.requests.clone(),
                json!({"gate":shared.gate.value(),
                "remainingReplies":shared.replies.len(),"connections":connections,
                "listenerErrors":shared.listener_errors,"positiveStreamGate":shared.positive.value()}),
            )
        };
        WireRecord {
            counts: self.counts(),
            requests,
            joined,
            failed,
            state,
        }
    }
}

impl Drop for OwnedWire {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Ok(mut state) = locked(&self.shared) {
            state.release.take();
            state.positive_release.take();
        }
        // The normal owner always calls finish and awaits the listener. Drop grants no join fact.
        // It deliberately does not abort children or fabricate a gate release.
    }
}

async fn serve_connection(
    stream: TcpStream,
    tls: TlsAcceptor,
    shared: Arc<Mutex<Shared>>,
    captured: Arc<AtomicUsize>,
    index: usize,
) -> Result<(), &'static str> {
    let mut stream = tls
        .accept(stream)
        .await
        .map_err(|_| "owned_tls_handshake")?;
    update_connection(&shared, index, |row| row.tls_accepted = true)?;
    let mut request = read_request(&mut stream).await?;
    let (reply, release, positive_release) = {
        let mut state = locked(&shared)?;
        request.request_ordinal = state.requests.len() + 1;
        let ordinal = request.request_ordinal;
        state.requests.push(request);
        captured.fetch_add(1, Ordering::SeqCst);
        let row = state
            .connections
            .get_mut(index)
            .ok_or("owned_tls_connection_missing")?;
        row.request_ordinal = Some(ordinal);
        row.request_captured = true;
        let reply = state
            .replies
            .pop_front()
            .ok_or("owned_tls_unexpected_request")?;
        state.connections[index].status = Some(reply.status);
        let release = if reply.status == 401 {
            if ordinal != 2 {
                return Err("owned_tls_gate_request_identity");
            }
            state.gate.request_captured = true;
            state.gate.request_ordinal = Some(ordinal);
            state.gate.header_held = true;
            Some(
                state
                    .released
                    .take()
                    .ok_or("owned_tls_gate_receiver_missing")?,
            )
        } else {
            None
        };
        let positive_release = if reply.status == 200 {
            Some(
                state
                    .positive_released
                    .take()
                    .ok_or("owned_tls_positive_receiver_missing")?,
            )
        } else {
            None
        };
        (reply, release, positive_release)
    };
    if let Some(release) = release {
        release.await.map_err(|_| "owned_tls_gate_not_released")?;
    }
    let reason = if reply.status == 200 {
        "OK"
    } else {
        "Unauthorized"
    };
    let header = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.content_type,
        reply.body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|_| "owned_tls_header_write")?;
    update_connection(&shared, index, |row| row.headers_written = true)?;
    if let Some(positive_release) = positive_release {
        {
            let mut state = locked(&shared)?;
            state.positive.armed = true;
            release_positive_if_ready(&mut state)?;
        }
        positive_release
            .await
            .map_err(|_| "owned_tls_positive_not_released")?;
    }
    stream
        .write_all(reply.body.as_bytes())
        .await
        .map_err(|_| "owned_tls_body_write")?;
    update_connection(&shared, index, |row| row.body_written = true)?;
    update_connection(&shared, index, |row| row.shutdown_attempted = true)?;
    stream.shutdown().await.map_err(|_| "owned_tls_shutdown")?;
    update_connection(&shared, index, |row| row.shutdown_returned = true)?;
    Ok(())
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<RawRequest, &'static str> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let split = loop {
        let n = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "owned_tls_header_read")?;
        if n == 0 {
            return Err("owned_tls_header_eof");
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("owned_tls_request_limit");
        }
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if pos >= 64 * 1024 {
                return Err("owned_tls_header_limit");
            }
            break pos + 4;
        }
        if bytes.len() > 64 * 1024 {
            return Err("owned_tls_header_limit");
        }
    };
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| "owned_tls_header_utf8")?;
    let mut lines = head.lines();
    let parts: Vec<_> = lines
        .next()
        .ok_or("owned_tls_request_line")?
        .split_whitespace()
        .collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err("owned_tls_request_line");
    }
    let method = parts[0].to_owned();
    let target = parts[1].to_owned();
    let mut headers = BTreeMap::new();
    let mut header_counts = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("owned_tls_header_shape")?;
        let name = name.to_ascii_lowercase();
        *header_counts.entry(name.clone()).or_insert(0) += 1;
        headers.insert(name, value.trim().to_owned());
    }
    if headers.contains_key("transfer-encoding") || header_counts.get("content-length") != Some(&1)
    {
        return Err("owned_tls_body_framing");
    }
    let length = headers
        .get("content-length")
        .ok_or("owned_tls_body_framing")?
        .parse::<usize>()
        .map_err(|_| "owned_tls_body_framing")?;
    if length > 8 * 1024 * 1024 - split {
        return Err("owned_tls_body_limit");
    }
    while bytes.len() < split + length {
        let n = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "owned_tls_body_read")?;
        if n == 0 {
            return Err("owned_tls_body_eof");
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > split + length {
            return Err("owned_tls_extra_request_bytes");
        }
    }
    if bytes.len() != split + length {
        return Err("owned_tls_extra_request_bytes");
    }
    Ok(RawRequest {
        request_ordinal: 0,
        method,
        target,
        headers,
        header_counts,
        body: bytes[split..].to_vec(),
    })
}
