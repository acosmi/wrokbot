//! New, strictly owned TLS fixture for the original finite Agent connection probe.
//! Authorization is compared only in memory. It is never serialized or hashed.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const IO_BUDGET: Duration = Duration::from_secs(12);
pub(super) const STARTED: &str = "C5.normal-run-started-probe";
pub(super) const RUN_ERROR: &str = "C5.normal-run-error-probe";
pub(super) const AUTH: &str = "C5.normal-upstream-authentication-rejection";
pub(super) const UNREACHABLE: &str = "C5.normal-unreachable-endpoint";
pub(super) const INVALID: &str = "C5.normal-invalid-finite-event-stream";
pub(super) const ENDPOINT_LATE: &str = "C5.same-editor-endpoint-change-late-probe";
pub(super) const AUTH_LATE: &str = "C5.same-editor-authorization-change-late-probe";
pub(super) const CLOSE_LATE: &str = "C5.close-reopen-late-probe";
pub(super) const CASES: [&str; 8] = [
    STARTED,
    RUN_ERROR,
    AUTH,
    UNREACHABLE,
    INVALID,
    ENDPOINT_LATE,
    AUTH_LATE,
    CLOSE_LATE,
];
pub(super) const ERROR_MESSAGE: &str = "owned C5 RUN_ERROR message must stay upstream";
pub(super) const ERROR_CODE: &str = "owned_c5_run_error_code_must_stay_upstream";

pub(super) fn late(mode: &str) -> bool {
    [ENDPOINT_LATE, AUTH_LATE, CLOSE_LATE].contains(&mode)
}

pub(super) type ProbeObservations = Arc<Mutex<Vec<Value>>>;
type OwnedListenerOutcome = (usize, usize, usize, Vec<String>);
type OwnedChildOutcome = (u64, Result<u64, String>);

#[derive(Clone)]
pub(super) struct WireView {
    shared: Arc<Shared>,
}

struct Shared {
    mode: String,
    address: SocketAddr,
    root: CertificateDer<'static>,
    key_a: String,
    key_b: String,
    dns: AtomicU64,
    tcp: AtomicU64,
    resolver: Mutex<Vec<Value>>,
    requests: Mutex<Vec<Value>>,
    observations: ProbeObservations,
    gate: Mutex<Option<oneshot::Sender<bool>>>,
    released: AtomicU64,
    gate_closed: AtomicU64,
}

struct Resolver {
    shared: Arc<Shared>,
}

#[async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        let started = std::time::Instant::now();
        let ordinal = self.shared.dns.fetch_add(1, Ordering::SeqCst) + 1;
        let matched = host == "idp.test" && port == self.shared.address.port();
        self.shared.resolver.lock().map_err(|_| DnsUnavailable)?.push(json!({
            "ordinal":ordinal,"hostMatched":matched,"portMatched":port==self.shared.address.port(),
            "elapsedMicros":u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),"returnedOwnedAddress":matched,
            "observationBoundary":"actual owned pinned resolver; separate from execute_stream 30s"
        }));
        if !matched {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.shared.address])
    }
}

pub(super) struct OwnedWire {
    view: WireView,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<OwnedListenerOutcome>>,
    listener_closed_before_test: bool,
}

pub(super) struct WireRecord {
    pub counts: Value,
    pub requests: Vec<Value>,
    pub summary: Value,
    pub joined: usize,
    pub failed: usize,
}

fn error_code(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::TimedOut => "timed_out",
        _ => "other_io",
    }
}

fn update(shared: &Shared, index: usize, key: &str, value: Value) -> Result<(), String> {
    let mut records = shared.requests.lock().map_err(|_| "wire_record_lock")?;
    let row = records.get_mut(index).ok_or("wire_record_missing")?;
    row[key] = value;
    Ok(())
}

impl WireView {
    pub(super) fn origin(&self) -> String {
        format!("https://idp.test:{}", self.shared.address.port())
    }
    pub(super) fn keys(&self) -> (String, String) {
        (self.shared.key_a.clone(), self.shared.key_b.clone())
    }
    pub(super) fn dialer(&self) -> Result<SafeDialer, String> {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|_| "owned_allowlist")?,
            ),
            Arc::new(Resolver {
                shared: self.shared.clone(),
            }),
            [self.shared.root.clone()],
        )
        .map_err(|_| "owned_actual_dialer".to_owned())
    }
    pub(super) fn counts(&self) -> Value {
        json!({"dns":self.shared.dns.load(Ordering::SeqCst),"tcp":self.shared.tcp.load(Ordering::SeqCst),
            "http":self.shared.requests.lock().map(|r|r.iter().filter(|v|v["requestCaptured"]==true).count()).unwrap_or(0)})
    }
    pub(super) fn requests(&self) -> Result<Vec<Value>, String> {
        Ok(self
            .shared
            .requests
            .lock()
            .map_err(|_| "wire_record_lock")?
            .clone())
    }
    pub(super) fn resolver(&self) -> Result<Vec<Value>, String> {
        Ok(self
            .shared
            .resolver
            .lock()
            .map_err(|_| "resolver_record_lock")?
            .clone())
    }
    pub(super) fn release(&self) -> Result<Value, String> {
        if !late(&self.shared.mode) || self.shared.released.load(Ordering::SeqCst) != 0 {
            return Err("held_probe_release_not_registered_or_reused".to_owned());
        }
        let records = self.requests()?;
        if records.first().is_none_or(|r| {
            r["requestCaptured"] != true || r["headersWriteReturned"] != Value::Null
        }) {
            return Err("held_probe_original_capture_not_observed".to_owned());
        }
        let sender = self
            .shared
            .gate
            .lock()
            .map_err(|_| "held_probe_gate_lock")?
            .take()
            .ok_or("held_probe_gate_not_armed")?;
        sender
            .send(true)
            .map_err(|_| "held_probe_release_receiver_closed")?;
        self.shared.released.store(1, Ordering::SeqCst);
        Ok(json!({"released":true,"requestOrdinal":1}))
    }
    pub(super) fn close_held(&self) -> Result<(), String> {
        if let Some(sender) = self
            .shared
            .gate
            .lock()
            .map_err(|_| "held_probe_gate_lock")?
            .take()
        {
            self.shared.gate_closed.store(1, Ordering::SeqCst);
            sender
                .send(false)
                .map_err(|_| "held_probe_close_receiver_closed")?;
        }
        Ok(())
    }
}

impl OwnedWire {
    pub(super) async fn new(
        mode: &str,
        certificate: [&str; 3],
        observations: ProbeObservations,
    ) -> Result<Self, String> {
        if !CASES.contains(&mode) {
            return Err("unknown_owned_waveform".to_owned());
        }
        let root = CertificateDer::from(STANDARD.decode(certificate[0]).map_err(|_| "owned_ca")?);
        let leaf = CertificateDer::from(STANDARD.decode(certificate[1]).map_err(|_| "owned_leaf")?);
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
        .map_err(|_| "owned_tls_versions")?
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .map_err(|_| "owned_tls_config")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "owned_tls_bind")?;
        let address = listener.local_addr().map_err(|_| "owned_tls_address")?;
        let shared = Arc::new(Shared {
            mode: mode.to_owned(),
            address,
            root,
            key_a: format!("Bearer OWNED_C5_A_{}", Uuid::new_v4()),
            key_b: format!("Bearer OWNED_C5_B_{}", Uuid::new_v4()),
            dns: AtomicU64::new(0),
            tcp: AtomicU64::new(0),
            resolver: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            observations,
            gate: Mutex::new(None),
            released: AtomicU64::new(0),
            gate_closed: AtomicU64::new(0),
        });
        let view = WireView {
            shared: shared.clone(),
        };
        if mode == UNREACHABLE {
            // This exact newly bound own listener is really closed before any Test.
            drop(listener);
            return Ok(Self {
                view,
                stop: None,
                task: None,
                listener_closed_before_test: true,
            });
        }
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            let mut joined = 0;
            let mut failed = 0;
            let mut errors = Vec::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    accepted=listener.accept()=>match accepted {
                        Ok((socket,_))=>{
                            let ordinal=shared.tcp.fetch_add(1,Ordering::SeqCst)+1;
                            let own=shared.clone();let tls=acceptor.clone();
                            children.spawn(async move {
                                let deadline=tokio::time::Instant::now()+IO_BUDGET;
                                let result=match tokio::time::timeout_at(deadline, connection(socket,tls,own.clone(),ordinal,deadline)).await {
                                    Ok(value)=>value,
                                    Err(_)=>Err("owned_child_io_gate_deadline".to_owned()),
                                };
                                (ordinal,result)
                            });
                        },
                        Err(_)=>{errors.push("owned_listener_accept".to_owned());break;}
                    },
                    result=children.join_next(),if !children.is_empty()=>{
                        joined+=1; collect_join(result, &shared, &mut failed, &mut errors);
                    }
                }
            }
            drop(listener);
            while let Some(result) = children.join_next().await {
                joined += 1;
                collect_join(Some(result), &shared, &mut failed, &mut errors);
            }
            (joined, failed, children.len(), errors)
        });
        Ok(Self {
            view,
            stop: Some(stop),
            task: Some(task),
            listener_closed_before_test: false,
        })
    }
    pub(super) fn view(&self) -> WireView {
        self.view.clone()
    }
    pub(super) async fn finish(mut self) -> Result<WireRecord, String> {
        let mut preliminary_errors = Vec::new();
        if let Err(error) = self.view.close_held() {
            preliminary_errors.push(error);
        }
        let mut listener_stop_sent = false;
        if let Some(stop) = self.stop.take() {
            listener_stop_sent = true;
            if stop.send(()).is_err() {
                preliminary_errors.push("owned_listener_stop_receiver".to_owned());
            }
        }
        let (joined, failed, remaining_children, mut errors, listener_joined) =
            if let Some(task) = self.task.take() {
                match task.await {
                    Ok((joined, failed, remaining, errors)) => {
                        (joined, failed, remaining, errors, Some(true))
                    }
                    Err(_) => (
                        0,
                        1,
                        1,
                        vec!["owned_listener_natural_join".to_owned()],
                        Some(false),
                    ),
                }
            } else {
                (0, 0, 0, Vec::new(), None)
            };
        errors.extend(preliminary_errors);
        let requests = self.view.requests()?;
        let original = self
            .view
            .shared
            .observations
            .lock()
            .map_err(|_| "probe_observation_lock")?
            .clone();
        let mut any_cancellation = false;
        for request in &requests {
            let source = original
                .iter()
                .find(|r| r["threadId"] == request["threadId"] && r["runId"] == request["runId"]);
            let causal = source.is_some_and(|r| {
                r["startReturn"] == "authentication"
                    || (r["wrapperStreamDropObserved"] == true
                        && (r["firstEventType"] == "RUN_STARTED"
                            || r["firstEventType"] == "RUN_ERROR"
                            || r["eofObserved"] == true))
                    || (self.view.shared.mode == CLOSE_LATE && r["startFutureDropObserved"] == true)
            });
            let cancellation = request["shutdownErrorCode"] != Value::Null
                || request["peerCloseErrorCode"] != Value::Null;
            if cancellation {
                let allowed_codes = [
                    "broken_pipe",
                    "connection_reset",
                    "connection_aborted",
                    "unexpected_eof",
                ];
                let code_ok = ["shutdownErrorCode", "peerCloseErrorCode"]
                    .iter()
                    .all(|key| {
                        request[*key].is_null()
                            || request[*key]
                                .as_str()
                                .is_some_and(|v| allowed_codes.contains(&v))
                    });
                if causal
                    && code_ok
                    && request["headersWriteReturned"] == true
                    && request["bodyWriteReturned"] == true
                    && request["flushReturned"] == true
                    && request["peerCloseObserved"] == true
                    && request["naturalChildJoin"] == true
                {
                    any_cancellation = true;
                } else {
                    errors.push("owned_unqualified_tls_cancel_or_shutdown_error".to_owned());
                }
            }
        }
        let tls_positive = if requests.is_empty() {
            Value::Null
        } else {
            json!(
                !any_cancellation
                    && errors.is_empty()
                    && failed == 0
                    && requests.iter().all(|r| r["shutdownReturned"] == true
                        && r["peerCloseObserved"] == true
                        && r["naturalChildJoin"] == true
                        && r["headersWriteReturned"] == true
                        && r["bodyWriteReturned"] == true
                        && r["flushReturned"] == true)
            )
        };
        let summary = json!({"listenerBound":true,"listenerClosedBeforeTest":self.listener_closed_before_test,
            "listenerStopSent":listener_stop_sent,"listenerJoined":listener_joined,"childrenSpawned":self.view.shared.tcp.load(Ordering::SeqCst),
            "childrenJoined":joined,"childrenFailed":failed,"remainingChildren":remaining_children,"remainingReplies":remaining_children,
            "remainingGates":usize::from(self.view.shared.gate.lock().map_err(|_|"held_probe_gate_lock")?.is_some())+remaining_children,
            "gateCaptured":requests.first().is_some_and(|r|r["requestCaptured"]==true) && late(&self.view.shared.mode),
            "gateReleaseSent":self.view.shared.released.load(Ordering::SeqCst)==1,
            "gateClosedForShutdown":self.view.shared.gate_closed.load(Ordering::SeqCst)==1,
            "forcedAbort":false,"unexpectedErrors":errors,"tlsPositive":tls_positive,
            "qualifiedFiniteCancellation":any_cancellation,"originalTransportDriverJoinObserved":null});
        Ok(WireRecord {
            counts: self.view.counts(),
            requests,
            summary,
            joined,
            failed,
        })
    }
}

fn collect_join(
    result: Option<Result<OwnedChildOutcome, tokio::task::JoinError>>,
    shared: &Shared,
    failed: &mut usize,
    errors: &mut Vec<String>,
) {
    match result {
        Some(Ok((ordinal, result))) => {
            if let Ok(mut records) = shared.requests.lock() {
                if let Some(row) = records.iter_mut().find(|r| r["ordinal"] == ordinal) {
                    row["naturalChildJoin"] = json!(true);
                } else {
                    *failed += 1;
                    errors.push("owned_child_receipt_missing".to_owned());
                }
            } else {
                *failed += 1;
                errors.push("owned_child_receipt_lock".to_owned());
            }
            if let Err(error) = result {
                *failed += 1;
                errors.push(error);
            }
        }
        _ => {
            *failed += 1;
            errors.push("owned_child_task_join_error".to_owned());
        }
    }
}

async fn connection(
    socket: tokio::net::TcpStream,
    tls: TlsAcceptor,
    shared: Arc<Shared>,
    ordinal: u64,
    deadline: tokio::time::Instant,
) -> Result<u64, String> {
    let mut stream = tls.accept(socket).await.map_err(|_| "owned_tls_accept")?;
    let (method, target, headers, body) = read_request(&mut stream).await?;
    if !["/ag-ui/a", "/ag-ui/b"].contains(&target.as_str()) || method != "POST" {
        return Err("owned_request_target_or_method".to_owned());
    }
    let is_b = late(&shared.mode) && ordinal == 2;
    if ordinal > if late(&shared.mode) { 2 } else { 1 } {
        return Err("owned_request_count_exceeded".to_owned());
    }
    let auth = headers.get("authorization").map_or(&[][..], Vec::as_slice);
    let expected = if is_b { &shared.key_b } else { &shared.key_a };
    // Test A has already taken and cleared the secret. The endpoint-only edit
    // does not also alter authorization: its genuine B request has no header.
    let auth_matches = if is_b && shared.mode == ENDPOINT_LATE {
        auth.is_empty()
    } else {
        auth.len() == 1 && auth[0] == *expected
    };
    let value: Value = serde_json::from_slice(&body).map_err(|_| "owned_probe_json")?;
    let (thread, run, message, structural) = probe_body(&value);
    let no_secret = !body
        .windows(shared.key_a.len())
        .any(|b| b == shared.key_a.as_bytes())
        && !body
            .windows(shared.key_b.len())
            .any(|b| b == shared.key_b.as_bytes());
    let status = if shared.mode == AUTH || is_b {
        401
    } else {
        200
    };
    let index = {
        let mut records = shared.requests.lock().map_err(|_| "wire_record_lock")?;
        if records.len() >= 8 {
            return Err("owned_wire_receipt_limit".to_owned());
        }
        let index = records.len();
        records.push(json!({"ordinal":ordinal,"listenerId":"owned-probe-listener","method":method,"path":target,"query":null,
        "host":headers.get("host").and_then(|v|v.first()).cloned(),"bodyBytes":body.len(),
        "bodySha256":if structural && no_secret {Some(Sha256Digest::of(&body).to_hex())}else{None},
        "authorizationCount":auth.len(),"authorizationExpectedMatch":auth_matches,"probeBodyStructuralMatch":structural && no_secret,
        "threadId":thread,"runId":run,"messageId":message,"tlsAccepted":true,"requestCaptured":true,"intendedStatus":status,
        "headersWriteReturned":null,"bodyWriteReturned":null,"flushReturned":null,"shutdownAttempted":false,"shutdownReturned":null,
        "shutdownErrorCode":null,"peerCloseObserved":false,"peerCloseKind":null,"peerCloseErrorCode":null,"naturalChildJoin":false,"forcedAbort":false}));
        index
    };
    if !auth_matches
        || !structural
        || !no_secret
        || headers
            .get("host")
            .is_none_or(|v| v.len() != 1 || v[0] != format!("idp.test:{}", shared.address.port()))
    {
        return Err("owned_original_probe_structure_or_auth".to_owned());
    }
    if late(&shared.mode) && ordinal == 1 {
        let (send, receive) = oneshot::channel();
        *shared.gate.lock().map_err(|_| "held_probe_gate_lock")? = Some(send);
        let release = tokio::time::timeout_at(deadline, receive)
            .await
            .map_err(|_| "held_probe_gate_deadline")?
            .map_err(|_| "held_probe_gate_sender_closed")?;
        if !release {
            update(&shared, index, "shutdownAttempted", json!(true))?;
            let result = stream.shutdown().await;
            update(&shared, index, "shutdownReturned", json!(result.is_ok()))?;
            if let Err(error) = result {
                update(
                    &shared,
                    index,
                    "shutdownErrorCode",
                    json!(error_code(&error)),
                )?;
            }
            return Ok(ordinal);
        }
    }
    let body = if status == 401 {
        String::new()
    } else if shared.mode == RUN_ERROR {
        format!(
            "data: {}\n\n",
            json!({"type":"RUN_ERROR","message":ERROR_MESSAGE,"code":ERROR_CODE})
        )
    } else if shared.mode == INVALID {
        "data: {\"type\":\"run_started\"}\n\n".to_owned()
    } else {
        format!(
            "data: {}\n\n",
            json!({"type":"RUN_STARTED","threadId":thread,"runId":run})
        )
    };
    let header = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if status == 401 { "Unauthorized" } else { "OK" },
        body.len()
    );
    let result = stream.write_all(header.as_bytes()).await;
    update(
        &shared,
        index,
        "headersWriteReturned",
        json!(result.is_ok()),
    )?;
    result.map_err(|_| "owned_header_write_error")?;
    let result = stream.write_all(body.as_bytes()).await;
    update(&shared, index, "bodyWriteReturned", json!(result.is_ok()))?;
    result.map_err(|_| "owned_finite_body_write_error")?;
    let result = stream.flush().await;
    update(&shared, index, "flushReturned", json!(result.is_ok()))?;
    result.map_err(|_| "owned_flush_error")?;
    update(&shared, index, "shutdownAttempted", json!(true))?;
    let result = stream.shutdown().await;
    update(&shared, index, "shutdownReturned", json!(result.is_ok()))?;
    if let Err(error) = result {
        update(
            &shared,
            index,
            "shutdownErrorCode",
            json!(error_code(&error)),
        )?;
    }
    let mut byte = [0u8; 1];
    match stream.read(&mut byte).await {
        Ok(0) => {
            update(&shared, index, "peerCloseObserved", json!(true))?;
            update(&shared, index, "peerCloseKind", json!("async_read_eof"))?;
        }
        Ok(_) => return Err("owned_unexpected_peer_data_after_reply".to_owned()),
        Err(error) => {
            let code = error_code(&error);
            update(&shared, index, "peerCloseErrorCode", json!(code))?;
            if [
                "unexpected_eof",
                "connection_reset",
                "connection_aborted",
                "broken_pipe",
            ]
            .contains(&code)
            {
                update(&shared, index, "peerCloseObserved", json!(true))?;
                update(
                    &shared,
                    index,
                    "peerCloseKind",
                    json!("actual_transport_close_error"),
                )?;
            } else {
                return Err("owned_unqualified_peer_close_error".to_owned());
            }
        }
    }
    Ok(ordinal)
}

fn probe_body(value: &Value) -> (Option<String>, Option<String>, Option<String>, bool) {
    let thread = value
        .get("threadId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let run = value
        .get("runId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let messages = value.get("messages").and_then(Value::as_array);
    let message = messages
        .and_then(|v| v.first())
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let ephemeral = |id: &Option<String>| {
        id.as_deref()
            .and_then(|s| s.strip_prefix("openbot-connection-test-"))
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some()
    };
    let keys = [
        "threadId",
        "runId",
        "messages",
        "tools",
        "context",
        "state",
        "forwardedProps",
    ];
    let exact = value
        .as_object()
        .is_some_and(|v| v.len() == keys.len() && keys.iter().all(|key| v.contains_key(*key)))
        && ephemeral(&thread)
        && ephemeral(&run)
        && thread != run
        && message
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some()
        && messages.is_some_and(|v| {
            v.len() == 1
                && v[0].as_object().is_some_and(|m| {
                    m.len() == 3
                        && m.contains_key("id")
                        && m.get("role") == Some(&json!("user"))
                        && m.get("content")
                            == Some(&json!("OpenBot connection test. Reply briefly."))
                })
        })
        && value["tools"] == json!([])
        && value["context"] == json!([])
        && value["state"] == json!({})
        && value["forwardedProps"] == json!({});
    (thread, run, message, exact)
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(String, String, BTreeMap<String, Vec<String>>, Vec<u8>), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    let end = loop {
        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() > 32768 {
            return Err("owned_header_limit".to_owned());
        }
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "owned_header_read")?;
        if count == 0 {
            return Err("owned_header_eof".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| "owned_header_utf8")?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next().ok_or("owned_request_line")?.split_whitespace();
    let method = request.next().ok_or("owned_request_method")?.to_owned();
    let target = request.next().ok_or("owned_request_target")?.to_owned();
    if request.next() != Some("HTTP/1.1") || request.next().is_some() {
        return Err("owned_request_version".to_owned());
    }
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in lines.filter(|v| !v.is_empty()) {
        let (key, value) = line.split_once(':').ok_or("owned_header_shape")?;
        headers
            .entry(key.to_ascii_lowercase())
            .or_default()
            .push(value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .filter(|v| v.len() == 1)
        .and_then(|v| v[0].parse::<usize>().ok())
        .ok_or("owned_content_length")?;
    if length > 65536 || headers.contains_key("transfer-encoding") {
        return Err("owned_body_framing_limit".to_owned());
    }
    let mut body = bytes[end..].to_vec();
    while body.len() < length {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "owned_body_read")?;
        if count == 0 {
            return Err("owned_body_eof".to_owned());
        }
        body.extend_from_slice(&buffer[..count]);
    }
    if body.len() != length {
        return Err("owned_body_trailing_bytes".to_owned());
    }
    Ok((method, target, headers, body))
}
