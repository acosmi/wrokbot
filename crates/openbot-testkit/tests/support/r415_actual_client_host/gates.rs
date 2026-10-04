use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State as ExtractState};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify};

use super::{Case, State, control, observe, read_fault};

const HELD_TAIL_NOT_STARTED: u8 = 0;
const HELD_TAIL_ACTIVE: u8 = 1;
const HELD_TAIL_FINALIZED: u8 = 2;
const HELD_TAIL_DROPPED: u8 = 3;
const HELD_TAIL_FAILED_DEADLINE: u8 = 4;

pub(super) struct Gate {
    id: String,
    case: Case,
    method: String,
    path: String,
    mode: String,
    baseline: Value,
    state: Mutex<GateState>,
    held_tail: AtomicU8,
    changed: Notify,
}

struct GateState {
    phase: &'static str,
    arrival: Option<Value>,
    disposition: Option<&'static str>,
    requested_disposition: Option<&'static str>,
    error: Option<&'static str>,
    request_sequence: Option<u64>,
    producer_status: Option<u16>,
}

// This guard covers only the held tail after the real producer and independent
// committed observer have established arrival. Earlier cancellation is unobserved.
struct HeldTailGuard {
    gate: Arc<Gate>,
}

impl HeldTailGuard {
    fn new(gate: Arc<Gate>) -> Self {
        gate.held_tail.store(HELD_TAIL_ACTIVE, Ordering::Release);
        Self { gate }
    }

    fn finish(&self, observation: u8) {
        self.gate.held_tail.store(observation, Ordering::Release);
    }
}

impl Drop for HeldTailGuard {
    fn drop(&mut self) {
        if self
            .gate
            .held_tail
            .compare_exchange(
                HELD_TAIL_ACTIVE,
                HELD_TAIL_DROPPED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // Synchronous observation only: no worker, asynchronous Drop or timeout inference.
            self.gate.changed.notify_waiters();
        }
    }
}

fn held_tail_observation(gate: &Gate) -> &'static str {
    match gate.held_tail.load(Ordering::Acquire) {
        HELD_TAIL_ACTIVE => "active",
        HELD_TAIL_FINALIZED => "handler-finalized",
        HELD_TAIL_DROPPED => "dropped-after-commit",
        HELD_TAIL_FAILED_DEADLINE => "failed-owned-deadline",
        _ => "not-started",
    }
}

fn observe_dropped_tail(gate: &Gate, guard: &mut GateState) -> bool {
    if gate.held_tail.load(Ordering::Acquire) == HELD_TAIL_DROPPED
        && matches!(guard.phase, "arrived" | "releasing")
        && guard.arrival.is_some()
        && guard.producer_status.is_some()
        && guard.request_sequence.is_some()
        && guard.error.is_none()
    {
        guard.phase = "disposed-after-commit";
        guard.disposition = Some("observed-held-tail-drop-after-commit");
        true
    } else {
        false
    }
}

fn dropped_result(gate: &Gate) -> Value {
    json!({"gateId":gate.id,"caseId":gate.case.id,
        "completion":"held-tail-dropped-after-commit",
        "disposition":"observed-held-tail-drop-after-commit",
        "limitation":"actual held future dropped after real producer and independent committed arrival; body not finalized, HTTP receipt and browser consumption unobserved"})
}

pub(super) async fn arm(state: &State, message: &Value) -> Result<Value, String> {
    let id = control::text(message, "gateId")?;
    if id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid_gate_id".to_owned());
    }
    state.reserve_control_id(id).await?;
    let current = control::case(state, control::text(message, "caseId")?, true).await?;
    let method = control::text(message, "method")?;
    let path = control::text(message, "path")?;
    let mode = control::text(message, "mode")?;
    if method != current.method()
        || path != current.update_path()?
        || !["hold", "lose-body"].contains(&mode)
    {
        return Err("gate_binding_mismatch".to_owned());
    }
    if read_fault::open_count(state).await != 0 {
        return Err("read_control_already_live".to_owned());
    }
    let mut gates = state.gates.lock().await;
    if gates.contains_key(id) {
        return Err("gate_id_reused".to_owned());
    }
    if gates.len() >= 512 {
        return Err("gate_limit".to_owned());
    }
    for gate in gates.values() {
        if !terminal(gate.state.lock().await.phase) {
            return Err("gate_already_live".to_owned());
        }
    }
    let baseline = observe::probe(&state.observer, &current).await?;
    let gate = Arc::new(Gate {
        id: id.to_owned(),
        case: current,
        method: method.to_owned(),
        path: path.to_owned(),
        mode: mode.to_owned(),
        baseline: baseline.clone(),
        state: Mutex::new(GateState {
            phase: "armed",
            arrival: None,
            disposition: None,
            requested_disposition: None,
            error: None,
            request_sequence: None,
            producer_status: None,
        }),
        held_tail: AtomicU8::new(HELD_TAIL_NOT_STARTED),
        changed: Notify::new(),
    });
    gates.insert(id.to_owned(), gate);
    Ok(json!({"gateId":id,"armed":true,"baseline":baseline}))
}

async fn lookup(state: &State, message: &Value) -> Result<Arc<Gate>, String> {
    let case_id = control::text(message, "caseId")?;
    control::case(state, case_id, true).await?;
    let gate = state
        .gates
        .lock()
        .await
        .get(control::text(message, "gateId")?)
        .cloned()
        .ok_or("unknown_gate")?;
    if gate.case.id != case_id {
        return Err("gate_case_mismatch".to_owned());
    }
    Ok(gate)
}

pub(super) async fn wait(state: &State, message: &Value) -> Result<Value, String> {
    let gate = lookup(state, message).await?;
    let timeout = match message.get("timeoutMs") {
        None => 10_000,
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=15_000).contains(n))
            .ok_or("invalid_gate_timeout")?,
    };
    tokio::time::timeout(Duration::from_millis(timeout), async {
        loop {
            let notified = gate.changed.notified();
            let guard = gate.state.lock().await;
            if guard.phase == "arrived" {
                return guard
                    .arrival
                    .clone()
                    .ok_or_else(|| "gate_missing_arrival".to_owned());
            }
            if !["armed", "producing"].contains(&guard.phase) {
                return Err("gate_terminal_or_failed".to_owned());
            }
            drop(guard);
            notified.await;
        }
    })
    .await
    .map_err(|_| "gate_wait_timeout".to_owned())?
}

pub(super) async fn release(state: &State, message: &Value, lose: bool) -> Result<Value, String> {
    let gate = lookup(state, message).await?;
    let disposition = if lose {
        "lose-real-producer-body"
    } else {
        "release-real-producer-response"
    };
    {
        let mut guard = gate.state.lock().await;
        if guard.phase != "arrived" {
            return Err("gate_not_arrived_or_terminal".to_owned());
        }
        if lose && gate.mode != "lose-body" {
            return Err("gate_mode_mismatch".to_owned());
        }
        guard.requested_disposition = Some(disposition);
        if observe_dropped_tail(&gate, &mut guard) {
            return if lose {
                Err("gate_disposed_before_loss".to_owned())
            } else {
                Ok(dropped_result(&gate))
            };
        }
        guard.disposition = Some(disposition);
        guard.phase = "releasing";
    }
    gate.changed.notify_waiters();
    // Normal completion requires actual body finalization. A synchronous post-arrival
    // Drop has a separate typed outcome and can never be accepted as successful loss.
    tokio::time::timeout(Duration::from_secs(4),async {
        loop {
            let notified=gate.changed.notified(); let mut guard=gate.state.lock().await;
            if guard.phase=="completed" {
                if gate.held_tail.load(Ordering::Acquire)!=HELD_TAIL_FINALIZED {return Err("gate_handler_completion_unobserved".to_owned());}
                return Ok(json!({"gateId":gate.id,"caseId":gate.case.id,"disposition":disposition,"completion":"handler-finalized",
                "limitation":if lose {"actual producer response body replaced empty after committed observer; not TCP drop or browser delivery"} else {"handler finalized real response; browser completion requires separate observation"}}));}
            if guard.phase=="failed" {return Err("gate_handler_failed".to_owned());}
            if observe_dropped_tail(&gate,&mut guard) {
                return if lose {Err("gate_disposed_before_loss".to_owned())} else {Ok(dropped_result(&gate))};
            }
            drop(guard); notified.await;
        }
    }).await.map_err(|_|"gate_release_join_timeout".to_owned())?
}

fn terminal(phase: &str) -> bool {
    matches!(
        phase,
        "completed" | "failed" | "closed" | "disposed-after-commit"
    )
}

pub(super) async fn open_count(state: &State) -> usize {
    let gates = state
        .gates
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut n = 0;
    for gate in gates {
        if !terminal(gate.state.lock().await.phase) {
            n += 1;
        }
    }
    n
}

pub(super) async fn case_open_count(state: &State, id: &str) -> usize {
    let gates = state
        .gates
        .lock()
        .await
        .values()
        .filter(|g| g.case.id == id)
        .cloned()
        .collect::<Vec<_>>();
    let mut n = 0;
    for gate in gates {
        if !terminal(gate.state.lock().await.phase) {
            n += 1;
        }
    }
    n
}

pub(super) async fn records(state: &State) -> Vec<Value> {
    let gates = state
        .gates
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    for gate in gates {
        let guard = gate.state.lock().await;
        records.push(json!({"gateId":gate.id,"caseId":gate.case.id,"object":gate.case.object,
            "method":gate.method,"path":gate.path,"mode":gate.mode,"phase":guard.phase,
            "error":guard.error,"disposition":guard.disposition,
            "requestedDisposition":guard.requested_disposition,"heldTailObservation":held_tail_observation(&gate),
            "producerObserved":guard.producer_status.is_some(),"producerStatus":guard.producer_status,
            "requestSequence":guard.request_sequence}));
    }
    records
}

pub(super) async fn failed_count(state: &State) -> usize {
    let gates = state
        .gates
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut count = 0;
    for gate in gates {
        if gate.state.lock().await.error.is_some() {
            count += 1;
        }
    }
    count
}

pub(super) async fn close_all(state: &State) {
    let gates = state
        .gates
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for gate in gates {
        let mut guard = gate.state.lock().await;
        if !terminal(guard.phase) {
            if guard.requested_disposition.is_none() {
                guard.requested_disposition = Some("teardown-owned-gate");
            }
            if observe_dropped_tail(&gate, &mut guard) {
                drop(guard);
                gate.changed.notify_waiters();
                continue;
            }
            if guard.disposition.is_none() {
                guard.disposition = Some("teardown-owned-gate");
            }
            if guard.phase == "armed" {
                guard.phase = "closed";
            } else {
                guard.phase = "releasing";
            }
        }
        drop(guard);
        gate.changed.notify_waiters();
    }
}

async fn fail(gate: &Gate, reason: &'static str) {
    let mut guard = gate.state.lock().await;
    guard.error = Some(reason);
    guard.phase = "failed";
    if guard.disposition.is_none() {
        guard.disposition = Some("fixture-failed-handler");
    }
    drop(guard);
    gate.changed.notify_waiters();
}

pub(super) async fn observe_response(
    ExtractState(state): ExtractState<Arc<State>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    // Snapshot header text before awaiting; no &Request/!Sync Body enters a child future.
    // Cookie bytes stay owned in fixture memory and never bypass real resolver/authentication.
    let cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .map(str::trim)
                .find_map(|s| s.strip_prefix("openbot_session="))
        })
        .map(str::to_owned);
    let sequence = state.sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let metadata = json!({"sequence":sequence,"method":method,"path":path,"query":query,
        "status":null,"producerReturned":false});
    let is_api = path.starts_with("/api/");
    if is_api {
        let mut requests = state.requests.lock().await;
        state.api_ingress_count.fetch_add(1, Ordering::Relaxed);
        if requests.len() < 2048 {
            requests.push(metadata.clone());
        } else {
            state.fail_collection("http_request_record_limit").await;
        }
    }
    let selected_read = read_fault::select(
        &state,
        &method,
        &path,
        query.as_deref(),
        cookie.as_deref(),
        sequence,
    )
    .await;
    let candidates = state
        .gates
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut selected = None;
    for gate in candidates {
        if gate.method == method
            && gate.path == path
            && query.is_none()
            && cookie
                .as_deref()
                .is_some_and(|token| token == gate.case.token_a || token == gate.case.token_b)
        {
            let mut guard = gate.state.lock().await;
            if guard.phase == "armed" {
                guard.phase = "producing";
                guard.request_sequence = Some(sequence);
                selected = Some(gate.clone());
                break;
            }
        }
    }
    // Preserve genuine origin/auth/body extraction order. No business request is fabricated.
    let response = next.run(request).await;
    let status = response.status();
    let metadata = json!({"sequence":sequence,"method":method,"path":path,"query":query,
        "status":status.as_u16(),"producerReturned":true});
    if is_api {
        let mut requests = state.requests.lock().await;
        if let Some(record) = requests
            .iter_mut()
            .find(|value| value["sequence"].as_u64() == Some(sequence))
        {
            *record = metadata.clone();
        }
    }
    if let Some(read_control) = selected_read {
        return read_fault::apply(&state, &read_control, response, metadata).await;
    }
    let Some(gate) = selected else {
        return response;
    };
    gate.state.lock().await.producer_status = Some(status.as_u16());
    let (mut parts, body) = response.into_parts();
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            fail(&gate, "real_producer_body_read").await;
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("fixed response");
        }
    };
    let body_value = match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            fail(&gate, "real_producer_body_not_json").await;
            return Response::from_parts(parts, Body::from(bytes));
        }
    };
    if String::from_utf8_lossy(&bytes).contains("R415_PRIVATE_") {
        fail(&gate, "real_producer_private_canary_leak").await;
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("fixed response");
    }
    let committed = match observe::probe(&state.observer, &gate.case).await {
        Ok(value) => value,
        Err(_) => {
            fail(&gate, "independent_committed_observer_failed").await;
            return Response::from_parts(parts, Body::from(bytes));
        }
    };
    let old = gate.baseline["revision"].as_i64().unwrap_or(0);
    if !status.is_success() || committed["revision"].as_i64() != old.checked_add(1) {
        fail(&gate, "producer_did_not_commit_selected_revision").await;
        return Response::from_parts(parts, Body::from(bytes));
    }
    let held_tail = {
        let mut guard = gate.state.lock().await;
        // Teardown may have happened during the real producer; never re-arm a disposed gate.
        if guard.phase != "producing" {
            guard.phase = "completed";
            drop(guard);
            gate.changed.notify_waiters();
            return Response::from_parts(parts, Body::from(bytes));
        }
        guard.arrival = Some(
            json!({"gateId":gate.id,"caseId":gate.case.id,"object":gate.case.object,"arrived":true,
            "request":metadata,"producerResponse":{"status":status.as_u16(),"body":body_value},"committed":committed,"held":true}),
        );
        guard.phase = "arrived";
        HeldTailGuard::new(gate.clone())
    };
    gate.changed.notify_waiters();
    let disposition = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let notified = gate.changed.notified();
            let guard = gate.state.lock().await;
            if guard.phase == "releasing" {
                return guard.disposition;
            }
            drop(guard);
            notified.await;
        }
    })
    .await;
    let body = match disposition {
        Ok(Some("lose-real-producer-body")) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            Body::empty()
        }
        Ok(Some(_)) => Body::from(bytes),
        _ => {
            // A deadline is a failure observation, not evidence of future disposal.
            held_tail.finish(HELD_TAIL_FAILED_DEADLINE);
            fail(&gate, "owned_gate_deadline").await;
            return Response::from_parts(parts, Body::from(bytes));
        }
    };
    {
        let mut guard = gate.state.lock().await;
        guard.phase = "completed";
        held_tail.finish(HELD_TAIL_FINALIZED);
    }
    gate.changed.notify_waiters();
    Response::from_parts(parts, body)
}
