//! Strict finite owned TLS waveforms: positive SSE, then one scoped failure boundary.
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

/// Finite registered reply plan; these modes schedule only real owned TLS bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaseMode {
    Completed,
    Failed,
    Cancelled,
    HeadersUnknown,
    AuditUnknown,
    Reconnect,
    Remount,
}
impl CaseMode {
    pub fn parse(id: &str) -> Option<Self> {
        match id {
            "C6.current-empty-partial-completed" => Some(Self::Completed),
            "C6.current-partial-failed" => Some(Self::Failed),
            "C6.current-partial-cancelled-no-tools" => Some(Self::Cancelled),
            "C6.current-post-unknown-no-output" => Some(Self::HeadersUnknown),
            "C6.current-partial-unknown-stream-stalled-audit" => Some(Self::AuditUnknown),
            "C6.live-reconnect-terminal-replay" => Some(Self::Reconnect),
            "C6.remount-missed-terminal-snapshot" => Some(Self::Remount),
            _ => None,
        }
    }
    pub fn tail_releasable(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Reconnect | Self::Remount
        )
    }
}

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

#[derive(Default)]
struct Gate {
    request_captured: bool,
    request_ordinal: Option<usize>,
    held: bool,
    release_sent: bool,
    receiver_returned: bool,
    receiver_dropped: bool,
}
impl Gate {
    fn value(&self, phase: &str) -> Value {
        json!({"requestCaptured":self.request_captured,"requestOrdinal":self.request_ordinal,
            "phase":phase,"held":self.held,"releaseSent":self.release_sent,
            "receiverReturned":self.receiver_returned,"receiverDropped":self.receiver_dropped})
    }
    fn receiver_pending(&self) -> bool {
        self.held && !self.receiver_returned && !self.receiver_dropped
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
    shutdown_returned: Option<bool>,
    error: Option<&'static str>,
    prefix_written: bool,
    peer_close_observed: bool,
    unsent_tail: bool,
    header_flush_returned: Option<bool>,
    prefix_flush_returned: Option<bool>,
    tail_written: bool,
    tail_flush_returned: Option<bool>,
    natural_child_join: bool,
    forced_abort: bool,
    prefix_written_at_ms: Option<u128>,
}
impl Connection {
    fn value(&self) -> Value {
        json!({"connectionOrdinal":self.connection_ordinal,"requestOrdinal":self.request_ordinal,
            "status":self.status,"tlsAccepted":self.tls_accepted,"requestCaptured":self.request_captured,
            "headersWritten":self.headers_written,"bodyWritten":self.body_written,
            "shutdownAttempted":self.shutdown_attempted,"shutdownReturned":self.shutdown_returned,
            "error":self.error,"prefixWritten":self.prefix_written,
            "peerCloseObserved":self.peer_close_observed,"unsentTail":self.unsent_tail,
            "headerFlushReturned":self.header_flush_returned,"prefixFlushReturned":self.prefix_flush_returned,
            "tailWritten":self.tail_written,"tailFlushReturned":self.tail_flush_returned,
            "naturalChildJoin":self.natural_child_join,"forcedAbort":self.forced_abort,
            "prefixWrittenAtMs":self.prefix_written_at_ms})
    }
}

#[derive(Clone, Copy)]
enum GateKind {
    Headers,
    Tail,
    Positive,
}
struct GateReceiver {
    shared: Arc<Mutex<Shared>>,
    kind: GateKind,
    receiver: Option<oneshot::Receiver<()>>,
    returned: bool,
}
impl GateReceiver {
    fn new(
        shared: &Arc<Mutex<Shared>>,
        kind: GateKind,
        receiver: Option<oneshot::Receiver<()>>,
    ) -> Option<Self> {
        receiver.map(|receiver| Self {
            shared: shared.clone(),
            kind,
            receiver: Some(receiver),
            returned: false,
        })
    }
    fn mark(&self, returned: bool) -> Result<(), &'static str> {
        let mut state = locked(&self.shared)?;
        match self.kind {
            GateKind::Headers => {
                state.headers.receiver_returned = returned;
                state.headers.receiver_dropped = !returned;
            }
            GateKind::Tail => {
                state.tail.receiver_returned = returned;
                state.tail.receiver_dropped = !returned;
            }
            GateKind::Positive => {
                state.positive_receiver_pending = false;
            }
        }
        Ok(())
    }
    async fn wait(mut self) -> Result<bool, &'static str> {
        let returned = self
            .receiver
            .as_mut()
            .ok_or("owned_tls_receiver_missing")?
            .await
            .is_ok();
        // Taking this exact receiver closes it even if the recording step fails.
        self.receiver.take();
        self.returned = returned;
        self.mark(returned)?;
        Ok(returned)
    }
}
impl Drop for GateReceiver {
    fn drop(&mut self) {
        if self.receiver.take().is_some() && !self.returned {
            // An unchanged child timeout may cancel the future before wait returns.
            // This is the actual owned receiver Drop, never a fabricated release ACK.
            let _ = self.mark(false);
        }
    }
}

struct Reply {
    positive: bool,
    body: String,
    prefix: Option<String>,
}
struct Shared {
    mode: CaseMode,
    started: tokio::time::Instant,
    requests: Vec<RawRequest>,
    connections: Vec<Connection>,
    replies: VecDeque<Reply>,
    headers: Gate,
    tail: Gate,
    positive: PositiveStreamGate,
    header_release: Option<oneshot::Sender<()>>,
    header_released: Option<oneshot::Receiver<()>>,
    tail_release: Option<oneshot::Sender<()>>,
    tail_released: Option<oneshot::Receiver<()>>,
    positive_release: Option<oneshot::Sender<()>>,
    positive_released: Option<oneshot::Receiver<()>>,
    positive_receiver_pending: bool,
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

// All bytes and gate lifetimes below belong to this finite owned TLS fixture.

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

fn shared_value(shared: &Shared) -> Value {
    let pending_headers = shared.header_release.is_some()
        || shared.header_released.is_some()
        || shared.headers.receiver_pending();
    let pending_tail = shared.tail_release.is_some()
        || shared.tail_released.is_some()
        || shared.tail.receiver_pending();
    let pending_positive = shared.positive_release.is_some()
        || shared.positive_released.is_some()
        || shared.positive_receiver_pending;
    json!({"headersGate":shared.headers.value("headers"),"tailGate":shared.tail.value("tail"),
        "remainingReplies":shared.replies.len(),
        "remainingGates":usize::from(pending_headers)+usize::from(pending_tail)+usize::from(pending_positive),
        "remainingChildren":shared.connections.iter().filter(|row|!row.natural_child_join).count(),
        "connections":shared.connections.iter().map(Connection::value).collect::<Vec<_>>(),
        "listenerErrors":shared.listener_errors,"positiveStreamGate":shared.positive.value()})
}

impl OwnedWire {
    pub async fn new(
        positive: String,
        prefix: String,
        tail: String,
        mode: CaseMode,
        certificate: [&str; 3],
    ) -> Result<Self, &'static str> {
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
        let (header_release, header_released) = oneshot::channel();
        let (tail_release, tail_released) = oneshot::channel();
        let (positive_release, positive_released) = oneshot::channel();
        let shared = Arc::new(Mutex::new(Shared {
            mode,
            started: tokio::time::Instant::now(),
            requests: Vec::new(),
            connections: Vec::new(),
            replies: VecDeque::from([
                Reply {
                    positive: true,
                    body: positive,
                    prefix: None,
                },
                Reply {
                    positive: false,
                    body: format!("{prefix}{tail}"),
                    prefix: Some(prefix),
                },
            ]),
            headers: Gate::default(),
            tail: Gate::default(),
            positive: PositiveStreamGate::default(),
            header_release: Some(header_release),
            header_released: Some(header_released),
            tail_release: Some(tail_release),
            tail_released: Some(tail_released),
            positive_release: Some(positive_release),
            positive_released: Some(positive_released),
            positive_receiver_pending: false,
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
                    _=&mut stopped=>break,
                    connection=listener.accept()=> {
                        let (stream,_)=match connection {Ok(value)=>value,Err(_)=>{if let Ok(mut state)=locked(&observations){state.listener_errors.push("owned_tls_accept");}break;}};
                        let ordinal=accepted.fetch_add(1,Ordering::SeqCst)+1;
                        let index=match locked(&observations) {
                            Ok(mut state)=>{let index=state.connections.len();state.connections.push(Connection {
                                connection_ordinal:ordinal,request_ordinal:None,status:None,tls_accepted:false,request_captured:false,
                                headers_written:false,body_written:false,shutdown_attempted:false,shutdown_returned:None,error:None,
                                prefix_written:false,peer_close_observed:false,unsent_tail:false,header_flush_returned:None,
                                prefix_flush_returned:None,tail_written:false,tail_flush_returned:None,natural_child_join:false,
                                forced_abort:false,prefix_written_at_ms:None,
                            });index},Err(_)=>{failed+=1;break;}
                        };
                        let tls=acceptor.clone();let shared=observations.clone();let captured=captured.clone();
                        children.spawn(async move {
                            let result=tokio::time::timeout(Duration::from_secs(8),serve_connection(stream,tls,shared.clone(),captured,index)).await
                                .unwrap_or(Err("owned_tls_connection_deadline"));
                            if let Err(code)=result {let _=update_connection(&shared,index,|row|row.error=Some(code));}
                            (index,result)
                        });
                    },
                    result=children.join_next(),if !children.is_empty()=> {
                        joined+=1;
                        match result {Some(Ok((index,result)))=>{
                            if result.is_err(){failed+=1;}
                            if update_connection(&observations,index,|row|row.natural_child_join=true).is_err(){failed+=1;}
                        },_=>{failed+=1;if let Ok(mut state)=locked(&observations){state.listener_errors.push("owned_tls_child_join");}}}
                    }
                }
            }
            drop(listener);
            // Every child already has its unchanged eight-second bound. No child is aborted.
            while let Some(result) = children.join_next().await {
                joined += 1;
                match result {
                    Ok((index, result)) => {
                        if result.is_err() {
                            failed += 1;
                        }
                        if update_connection(&observations, index, |row| {
                            row.natural_child_join = true
                        })
                        .is_err()
                        {
                            failed += 1;
                        }
                    }
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
        .expect("fixed owned CA and policy")
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
    pub fn state(&self) -> Result<Value, &'static str> {
        Ok(shared_value(&locked(&self.shared)?))
    }
    pub fn positive_witness(&self) -> PositiveStreamWitness {
        PositiveStreamWitness {
            shared: self.shared.clone(),
        }
    }
    pub async fn wait_captured(&self, timeout: Duration) -> Result<bool, &'static str> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let captured = {
                let state = locked(&self.shared)?;
                state.headers.request_captured
            };
            if captured {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub fn release(&self, phase: &str) -> Result<(), &'static str> {
        let mut state = locked(&self.shared)?;
        if phase == "headers" {
            if state.mode == CaseMode::HeadersUnknown {
                return Err("owned_tls_headers_never_releasable");
            }
            if !state.headers.request_captured || !state.headers.held || state.headers.release_sent
            {
                return Err("owned_tls_header_gate_state");
            }
            state
                .header_release
                .take()
                .ok_or("owned_tls_header_sender_missing")?
                .send(())
                .map_err(|_| "owned_tls_header_receiver_closed")?;
            state.headers.release_sent = true;
        } else if phase == "tail" {
            if !state.mode.tail_releasable() {
                return Err("owned_tls_tail_never_releasable");
            }
            if !state.tail.request_captured || !state.tail.held || state.tail.release_sent {
                return Err("owned_tls_tail_gate_state");
            }
            state
                .tail_release
                .take()
                .ok_or("owned_tls_tail_sender_missing")?
                .send(())
                .map_err(|_| "owned_tls_tail_receiver_closed")?;
            state.tail.release_sent = true;
        } else {
            return Err("owned_tls_unknown_phase");
        }
        Ok(())
    }
    pub async fn finish(mut self) -> WireRecord {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Ok(mut state) = locked(&self.shared) {
            state.header_release.take();
            state.tail_release.take();
            state.positive_release.take();
            if state.header_released.take().is_some() {
                state.headers.receiver_dropped = true;
            }
            if state.tail_released.take().is_some() {
                state.tail.receiver_dropped = true;
            }
            state.positive_released.take();
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
        let (requests, state) = match self.shared.lock() {
            Ok(shared) => (shared.requests.clone(), shared_value(&shared)),
            Err(poisoned) => {
                let mut shared = poisoned.into_inner();
                shared
                    .listener_errors
                    .push("owned_tls_observation_poisoned");
                (shared.requests.clone(), shared_value(&shared))
            }
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
            state.header_release.take();
            state.tail_release.take();
            state.positive_release.take();
        }
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
    let (reply, mode, header_rx, tail_rx, positive_rx) = {
        let mut state = locked(&shared)?;
        request.request_ordinal = state.requests.len() + 1;
        let ordinal = request.request_ordinal;
        state.requests.push(request);
        captured.fetch_add(1, Ordering::SeqCst);
        state.connections[index].request_ordinal = Some(ordinal);
        state.connections[index].request_captured = true;
        let reply = state
            .replies
            .pop_front()
            .ok_or("owned_tls_unexpected_request")?;
        if reply.positive != (ordinal == 1) {
            return Err("owned_tls_reply_identity");
        }
        let positive_rx = if reply.positive {
            state.positive_receiver_pending = true;
            state.positive_released.take()
        } else {
            None
        };
        let header_rx = if ordinal == 2 {
            state.headers.request_captured = true;
            state.headers.request_ordinal = Some(2);
            state.headers.held = true;
            state.header_released.take()
        } else {
            None
        };
        let tail_rx = if ordinal == 2 {
            state.tail_released.take()
        } else {
            None
        };
        (reply, state.mode, header_rx, tail_rx, positive_rx)
    };
    let header_rx = GateReceiver::new(&shared, GateKind::Headers, header_rx);
    let tail_rx = GateReceiver::new(&shared, GateKind::Tail, tail_rx);
    let positive_rx = GateReceiver::new(&shared, GateKind::Positive, positive_rx);
    let result=async {
        if !reply.positive && mode==CaseMode::HeadersUnknown {
            drop(header_rx);drop(tail_rx);
            update_connection(&shared,index,|row|row.unsent_tail=true)?;
            observe_peer_close(&mut stream,&shared,index).await?;
        } else {
            if let Some(receiver)=header_rx {
                let returned=receiver.wait().await?;
                if !returned{return Err("owned_tls_header_gate_not_released");}
            }
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.body.len());
            stream.write_all(header.as_bytes()).await.map_err(|_|"owned_tls_header_write")?;
            update_connection(&shared,index,|row|{row.headers_written=true;row.status=Some(200);})?;
            let flushed=stream.flush().await.is_ok();update_connection(&shared,index,|row|row.header_flush_returned=Some(flushed))?;
            if !flushed{return Err("owned_tls_header_flush");}
            if let Some(receiver)=positive_rx {
                {let mut state=locked(&shared)?;state.positive.armed=true;release_positive_if_ready(&mut state)?;}
                let returned=receiver.wait().await?;
                if !returned{return Err("owned_tls_positive_not_released");}
            }
            if let Some(prefix)=reply.prefix {
                stream.write_all(prefix.as_bytes()).await.map_err(|_|"owned_tls_prefix_write")?;
                {let mut state=locked(&shared)?;let elapsed=state.started.elapsed().as_millis();
                    let row=&mut state.connections[index];row.prefix_written=true;row.unsent_tail=true;row.prefix_written_at_ms=Some(elapsed);
                    state.tail.request_captured=true;state.tail.request_ordinal=Some(2);state.tail.held=true;}
                let flushed=stream.flush().await.is_ok();update_connection(&shared,index,|row|row.prefix_flush_returned=Some(flushed))?;
                if !flushed{return Err("owned_tls_prefix_flush");}
                if mode.tail_releasable() {
                    let receiver=tail_rx.ok_or("owned_tls_tail_receiver_missing")?;
                    let returned=receiver.wait().await?;
                    if !returned{return Err("owned_tls_tail_not_released");}
                    stream.write_all(&reply.body.as_bytes()[prefix.len()..]).await.map_err(|_|"owned_tls_tail_write")?;
                    update_connection(&shared,index,|row|{row.tail_written=true;row.body_written=true;row.unsent_tail=false;})?;
                    let flushed=stream.flush().await.is_ok();update_connection(&shared,index,|row|row.tail_flush_returned=Some(flushed))?;
                    if !flushed{return Err("owned_tls_tail_flush");}
                } else {
                    drop(tail_rx);
                    observe_peer_close(&mut stream,&shared,index).await?;
                }
            } else {
                stream.write_all(reply.body.as_bytes()).await.map_err(|_|"owned_tls_body_write")?;
                update_connection(&shared,index,|row|row.body_written=true)?;
                let flushed=stream.flush().await.is_ok();update_connection(&shared,index,|row|row.tail_flush_returned=Some(flushed))?;
                if !flushed{return Err("owned_tls_body_flush");}
            }
        }
        Ok(())
    }.await;
    // Even an original write/flush/gate error attempts this child's shutdown before returning.
    update_connection(&shared, index, |row| row.shutdown_attempted = true)?;
    let shutdown = stream.shutdown().await.is_ok();
    update_connection(&shared, index, |row| row.shutdown_returned = Some(shutdown))?;
    match (result, shutdown) {
        (Err(code), _) => Err(code),
        (Ok(()), false) => Err("owned_tls_shutdown"),
        (Ok(()), true) => Ok(()),
    }
}

async fn observe_peer_close(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    shared: &Mutex<Shared>,
    index: usize,
) -> Result<(), &'static str> {
    // Only connection lifetime is observed here, after the complete original request.
    // B remains silent; the client owns its unchanged timeout and may send TLS close bytes.
    // A genuine TCP EOF is not a provider result, journal terminal or client receipt.
    let mut bytes = [0_u8; 1024];
    let mut received = 0_usize;
    loop {
        let count = stream
            .get_mut()
            .0
            .read(&mut bytes)
            .await
            .map_err(|_| "owned_tls_peer_read")?;
        if count == 0 {
            update_connection(shared, index, |row| row.peer_close_observed = true)?;
            return Ok(());
        }
        received += count;
        if received > 4096 {
            return Err("owned_tls_peer_close_bytes_limit");
        }
    }
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
