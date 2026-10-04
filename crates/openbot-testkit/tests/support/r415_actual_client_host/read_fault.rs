//! A named read-transport fault after the unchanged production GET and independent PG observation.
//! The real and altered public bytes are retained separately. This never writes a business row.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use openbot_contracts::mcp::McpAdminPage;
use openbot_contracts::model_connections::ModelConnection;
use openbot_contracts::sandboxed::SandboxedComponents;
use openbot_contracts::ui::UiPreferences;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, Notify};

use super::{Case, State, control, gates, observe};

const BODY_LIMIT: usize = 65_536;
const MODE: &str = "same-revision-public-field";

pub(super) struct ReadControl {
    id: String,
    case: Case,
    path: String,
    expected_revision: i64,
    baseline: Value,
    state: Mutex<ReadState>,
    changed: Notify,
}

struct ReadState {
    phase: &'static str,
    arrival: Option<Value>,
    error: Option<&'static str>,
    disposition: Option<&'static str>,
    evidence_read: bool,
    request_sequence: Option<u64>,
}

fn read_path(case: &Case) -> Result<String, String> {
    match case.object.as_str() {
        "models" => case.update_path(),
        "sandbox" => Ok("/api/sandboxed".to_owned()),
        "skills" => Ok("/api/plugins".to_owned()),
        "preferences" => Ok("/api/me/preferences".to_owned()),
        _ => Err("invalid_object".to_owned()),
    }
}

pub(super) async fn arm(state: &State, message: &Value) -> Result<Value, String> {
    let id = control::text(message, "corruptionId")?;
    if id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid_corruption_id".to_owned());
    }
    state.reserve_control_id(id).await?;
    let current = control::case(state, control::text(message, "caseId")?, true).await?;
    let path = control::text(message, "path")?;
    let expected_revision = message["expectedRevision"]
        .as_i64()
        .filter(|n| *n > 0)
        .ok_or("invalid_corruption_revision")?;
    if control::text(message, "method")? != "GET"
        || control::text(message, "session")? != "a"
        || control::text(message, "mode")? != MODE
        || path != read_path(&current)?
        || current.fault_enabled
    {
        return Err("read_control_binding_mismatch".to_owned());
    }
    if gates::open_count(state).await != 0 || open_count(state).await != 0 {
        return Err("transport_control_already_live".to_owned());
    }
    let baseline = observe::probe(&state.observer, &current).await?;
    if baseline["revision"].as_i64() != Some(expected_revision) || !baseline["row"].is_object() {
        return Err("read_control_requires_existing_current_revision".to_owned());
    }
    let read = Arc::new(ReadControl {
        id: id.to_owned(),
        case: current.clone(),
        path: path.to_owned(),
        expected_revision,
        baseline: baseline.clone(),
        state: Mutex::new(ReadState {
            phase: "armed",
            arrival: None,
            error: None,
            disposition: None,
            evidence_read: false,
            request_sequence: None,
        }),
        changed: Notify::new(),
    });
    state.read_controls.lock().await.insert(id.to_owned(), read);
    Ok(json!({"caseId":current.id,"corruptionId":id,"armed":true,"baseline":baseline}))
}

async fn lookup(state: &State, message: &Value) -> Result<Arc<ReadControl>, String> {
    let case_id = control::text(message, "caseId")?;
    control::case(state, case_id, true).await?;
    let read = state
        .read_controls
        .lock()
        .await
        .get(control::text(message, "corruptionId")?)
        .cloned()
        .ok_or("unknown_read_control")?;
    if read.case.id != case_id {
        return Err("read_control_case_mismatch".to_owned());
    }
    Ok(read)
}

pub(super) async fn wait(state: &State, message: &Value) -> Result<Value, String> {
    let read = lookup(state, message).await?;
    let timeout = match message.get("timeoutMs") {
        None => 10_000,
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=15_000).contains(n))
            .ok_or("invalid_read_control_timeout")?,
    };
    tokio::time::timeout(Duration::from_millis(timeout), async {
        loop {
            let notified = read.changed.notified();
            let mut guard = read.state.lock().await;
            if guard.phase == "applied" && !guard.evidence_read {
                let result = guard
                    .arrival
                    .clone()
                    .ok_or("read_control_missing_evidence")?;
                guard.evidence_read = true;
                return Ok(result);
            }
            if !matches!(guard.phase, "armed" | "producing") {
                return Err("read_control_terminal_failed_or_evidence_consumed".to_owned());
            }
            drop(guard);
            notified.await;
        }
    })
    .await
    .map_err(|_| "read_control_wait_timeout".to_owned())?
}

pub(super) async fn cancel(state: &State, message: &Value) -> Result<Value, String> {
    let read = lookup(state, message).await?;
    let mut guard = read.state.lock().await;
    if guard.phase != "armed" {
        return Err("read_control_not_armed_or_terminal".to_owned());
    }
    guard.phase = "closed";
    guard.disposition = Some("cancelled-unconsumed-read-control");
    drop(guard);
    read.changed.notify_waiters();
    Ok(
        json!({"caseId":read.case.id,"corruptionId":read.id,"phase":"closed",
        "disposition":"cancelled-unconsumed-read-control"}),
    )
}

pub(super) async fn select(
    state: &State,
    method: &str,
    path: &str,
    query: Option<&str>,
    cookie: Option<&str>,
    sequence: u64,
) -> Option<Arc<ReadControl>> {
    if method != "GET" || query.is_some() {
        return None;
    }
    let candidates = state
        .read_controls
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for read in candidates {
        if path == read.path && cookie == Some(read.case.token_a.as_str()) {
            let mut guard = read.state.lock().await;
            if guard.phase == "armed" {
                guard.phase = "producing";
                guard.request_sequence = Some(sequence);
                drop(guard);
                return Some(read);
            }
        }
    }
    None
}

fn same_finite_state(baseline: &Value, probe: &Value) -> bool {
    baseline["business"].is_object()
        && baseline["audit"].is_object()
        && baseline["business"] == probe["business"]
        && baseline["audit"] == probe["audit"]
        && baseline["row"] == probe["row"]
        && baseline["revision"] == probe["revision"]
        && baseline["faultHits"] == probe["faultHits"]
}

fn instant(value: &Value) -> Result<OffsetDateTime, &'static str> {
    OffsetDateTime::parse(value.as_str().ok_or("read_timestamp_type")?, &Rfc3339)
        .map_err(|_| "read_timestamp_parse")
}

fn fields_equal(dto: &Value, row: &Value, pairs: &[(&str, &str)]) -> bool {
    pairs.iter().all(|(wire, sql)| {
        dto.get(*wire).is_some() && row.get(*sql).is_some() && dto[*wire] == row[*sql]
    })
}

fn unique_index(rows: &[Value], field: &str, id: &str) -> Result<usize, &'static str> {
    let selected = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row[field].as_str() == Some(id))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err("read_selected_identity_not_unique");
    }
    Ok(selected[0])
}

// Decode with the existing closed production DTOs, then bind the selected public fields to SQL.
// Agent-grant projections and derived flags stay byte-for-byte semantic values in the cloned DTO.
fn selected_pointer(
    case: &Case,
    body: &Value,
    probe: &Value,
    n: i64,
) -> Result<String, &'static str> {
    let row = &probe["row"];
    let id = case.object_id.as_deref().ok_or("read_unbound_identity")?;
    if probe["revision"].as_i64() != Some(n) {
        return Err("read_revision_drift");
    }
    let (selected, pointer) = match case.object.as_str() {
        "models" => {
            let parsed: ModelConnection =
                serde_json::from_value(body.clone()).map_err(|_| "read_model_dto")?;
            if parsed.id != id
                || row["owner_user_id"].as_str() != Some(case.actor.as_str())
                || row["deployment_id"] != super::DEPLOYMENT
                || row["tenant_id"] != super::TENANT
                || body["source"] != "custom"
                || !fields_equal(
                    body,
                    row,
                    &[
                        ("id", "id"),
                        ("name", "name"),
                        ("protocol", "protocol"),
                        ("endpoint", "endpoint"),
                        ("model", "model"),
                        ("enabled", "enabled"),
                        ("revision", "revision"),
                    ],
                )
                || parsed.created_at != instant(&row["created_at"])?
            {
                return Err("read_model_row_mismatch");
            }
            (body, "/name".to_owned())
        }
        "skills" => {
            let _: McpAdminPage =
                serde_json::from_value(body.clone()).map_err(|_| "read_skill_page_dto")?;
            let index = unique_index(
                body["skills"].as_array().ok_or("read_skill_array")?,
                "id",
                id,
            )?;
            let selected = &body["skills"][index];
            let expected_owner = if case.scope == "global" {
                Value::Null
            } else {
                json!(case.actor)
            };
            if selected["slug"].as_str() != Some(case.slug.as_str())
                || selected["ownerUserId"] != expected_owner
                || !fields_equal(
                    selected,
                    row,
                    &[
                        ("id", "id"),
                        ("slug", "slug"),
                        ("ownerUserId", "owner_user_id"),
                        ("title", "title"),
                        ("summary", "summary"),
                        ("instructions", "instructions"),
                        ("origin", "origin"),
                        ("installedBy", "installed_by"),
                        ("revision", "revision"),
                    ],
                )
            {
                return Err("read_skill_row_mismatch");
            }
            (selected, format!("/skills/{index}/title"))
        }
        "sandbox" => {
            let parsed: SandboxedComponents =
                serde_json::from_value(body.clone()).map_err(|_| "read_sandbox_dto")?;
            let index = unique_index(
                body["components"].as_array().ok_or("read_sandbox_array")?,
                "name",
                id,
            )?;
            let selected = &body["components"][index];
            let published_at = if row["published_at"].is_null() {
                None
            } else {
                Some(instant(&row["published_at"])?)
            };
            if !fields_equal(
                selected,
                row,
                &[
                    ("name", "name"),
                    ("title", "title"),
                    ("draftDescription", "draft_description"),
                    ("draftHtml", "draft_html"),
                    ("draftCss", "draft_css"),
                    ("draftJsFunctions", "draft_js_functions"),
                    ("draftArgumentSchema", "draft_argument_schema"),
                    ("publishedHtml", "published_html"),
                    ("publishedCss", "published_css"),
                    ("publishedJsFunctions", "published_js_functions"),
                    ("publishedArgumentSchema", "published_argument_schema"),
                    ("sampleArguments", "sample_arguments"),
                    ("revision", "revision"),
                    ("editingRevision", "editing_revision"),
                    ("published", "published"),
                    ("authoredBy", "authored_by"),
                ],
            ) || parsed.components[index].published_at != published_at
            {
                return Err("read_sandbox_row_mismatch");
            }
            (selected, format!("/components/{index}/title"))
        }
        "preferences" => {
            let _: UiPreferences =
                serde_json::from_value(body.clone()).map_err(|_| "read_preferences_dto")?;
            if row["actor_user_id"].as_str() != Some(case.actor.as_str())
                || row["deployment_id"] != super::DEPLOYMENT
                || row["tenant_id"] != super::TENANT
                || !fields_equal(
                    body,
                    row,
                    &[
                        ("theme", "theme"),
                        ("locale", "locale"),
                        ("revision", "revision"),
                    ],
                )
            {
                return Err("read_preferences_row_mismatch");
            }
            (body, "/theme".to_owned())
        }
        _ => return Err("read_invalid_object"),
    };
    let revision = if case.object == "sandbox" {
        &selected["editingRevision"]
    } else {
        &selected["revision"]
    };
    if revision.as_i64() != Some(n)
        || instant(&selected["updatedAt"])? != instant(&row["updated_at"])?
    {
        return Err("read_current_metadata_mismatch");
    }
    Ok(pointer)
}

fn validate_fault(case: &Case, body: &Value) -> Result<(), &'static str> {
    match case.object.as_str() {
        "models" => serde_json::from_value::<ModelConnection>(body.clone())
            .map(|_| ())
            .map_err(|_| "fault_model_dto"),
        "skills" => serde_json::from_value::<McpAdminPage>(body.clone())
            .map(|_| ())
            .map_err(|_| "fault_skill_dto"),
        "sandbox" => serde_json::from_value::<SandboxedComponents>(body.clone())
            .map(|_| ())
            .map_err(|_| "fault_sandbox_dto"),
        "preferences" => serde_json::from_value::<UiPreferences>(body.clone())
            .map(|_| ())
            .map_err(|_| "fault_preferences_dto"),
        _ => Err("fault_invalid_object"),
    }
}

fn public_headers(headers: &HeaderMap) -> Value {
    json!({"cacheControl":headers.get(header::CACHE_CONTROL).and_then(|v|v.to_str().ok()),
        "contentType":headers.get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok())})
}

async fn fail(read: &ReadControl, reason: &'static str) {
    let mut guard = read.state.lock().await;
    guard.error = Some(reason);
    guard.phase = "failed";
    guard.disposition = Some("unchanged-real-response-after-control-failure");
    drop(guard);
    read.changed.notify_waiters();
}

pub(super) async fn apply(
    state: &State,
    read: &ReadControl,
    response: Response,
    metadata: Value,
) -> Response {
    let (mut parts, body) = response.into_parts();
    let bytes = match tokio::time::timeout(super::TIMEOUT, to_bytes(body, BODY_LIMIT)).await {
        Ok(Ok(bytes)) => bytes,
        _ => {
            fail(read, "real_read_body_limit_or_timeout").await;
            // Body collection failed; there is no assertion that the original bytes were preserved.
            read.state.lock().await.disposition = Some("fixture-failed-no-complete-producer-body");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("fixed response");
        }
    };
    let original = Body::from(bytes.clone());
    if read.state.lock().await.phase != "producing" {
        let mut guard = read.state.lock().await;
        guard.phase = "closed";
        guard.disposition = Some("teardown-before-read-fault-application");
        drop(guard);
        read.changed.notify_waiters();
        return Response::from_parts(parts, original);
    }
    let candidate=async {
        if parts.status!=StatusCode::OK {return Err("real_read_producer_status");}
        let raw=std::str::from_utf8(&bytes).map_err(|_|"real_read_body_utf8")?;
        if raw.contains("R415_PRIVATE_") {return Err("real_read_private_canary_leak");}
        let body:Value=serde_json::from_slice(&bytes).map_err(|_|"real_read_body_json")?;
        let before=observe::probe(&state.observer,&read.case).await.map_err(|_|"read_observer_before")?;
        if !same_finite_state(&read.baseline,&before) {return Err("read_finite_state_changed_before");}
        let pointer=selected_pointer(&read.case,&body,&before,read.expected_revision)?;
        let previous=body.pointer(&pointer).cloned().ok_or("read_pointer_missing")?;
        let replacement=if read.case.object=="preferences" {
            if previous=="dark" {json!("light")} else {json!("dark")}
        } else if previous=="R415 controlled contradictory value" {json!("R415 other contradictory value")}
        else {json!("R415 controlled contradictory value")};
        let mut faulty=body.clone();
        *faulty.pointer_mut(&pointer).ok_or("read_pointer_missing")?=replacement.clone();
        validate_fault(&read.case,&faulty)?;
        let fault_bytes=serde_json::to_vec(&faulty).map_err(|_|"fault_body_encode")?;
        if fault_bytes.len()>BODY_LIMIT {return Err("fault_body_limit");}
        let fault_raw=std::str::from_utf8(&fault_bytes).map_err(|_|"fault_body_utf8")?;
        let after=observe::probe(&state.observer,&read.case).await.map_err(|_|"read_observer_after")?;
        if !same_finite_state(&read.baseline,&after) {return Err("read_finite_state_changed_after");}
        let headers=public_headers(&parts.headers);
        let evidence=json!({"caseId":read.case.id,"corruptionId":read.id,"object":read.case.object,
            "phase":"applied","classification":"CONTROLLED_READ_TRANSPORT_CORRUPTION_AFTER_REAL_PRODUCER",
            "request":metadata,"expectedRevision":read.expected_revision,
            "producerResponse":{"status":parts.status.as_u16(),"headers":headers,"body":body,
                "rawBodyUtf8":raw,"bodyBytes":bytes.len()},
            "faultResponse":{"status":parts.status.as_u16(),"headers":headers,"body":faulty,
                "rawBodyUtf8":fault_raw,"bodyBytes":fault_bytes.len()},
            "difference":{"jsonPointer":pointer,"before":previous,"after":replacement,"semanticChangedPaths":[pointer]},
            "independent":{"baseline":read.baseline,"before":before,"after":after,"finiteBusinessAuditUnchanged":true},
            "disposition":"finalized-fault-body","deliveryBoundary":"handler finalized; browser receipt separate"});
        Ok::<_,&'static str>((fault_bytes,evidence))
    }.await;
    let (fault_bytes, evidence) = match candidate {
        Ok(value) => value,
        Err(reason) => {
            fail(read, reason).await;
            return Response::from_parts(parts, original);
        }
    };
    {
        let mut guard = read.state.lock().await;
        // Shutdown can dispose this control during either independent observer transaction.
        if guard.phase != "producing" {
            guard.phase = "closed";
            guard.disposition = Some("teardown-before-read-fault-application");
            drop(guard);
            read.changed.notify_waiters();
            return Response::from_parts(parts, original);
        }
        guard.arrival = Some(evidence);
        guard.phase = "applied";
        guard.disposition = Some("finalized-fault-body");
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    read.changed.notify_waiters();
    Response::from_parts(parts, Body::from(fault_bytes))
}

fn terminal(phase: &str) -> bool {
    matches!(phase, "applied" | "failed" | "closed")
}

pub(super) async fn open_count(state: &State) -> usize {
    let reads = state
        .read_controls
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut count = 0;
    for read in reads {
        if !terminal(read.state.lock().await.phase) {
            count += 1;
        }
    }
    count
}

pub(super) async fn case_open_count(state: &State, id: &str) -> usize {
    let reads = state
        .read_controls
        .lock()
        .await
        .values()
        .filter(|r| r.case.id == id)
        .cloned()
        .collect::<Vec<_>>();
    let mut count = 0;
    for read in reads {
        if !terminal(read.state.lock().await.phase) {
            count += 1;
        }
    }
    count
}

pub(super) async fn failed_count(state: &State) -> usize {
    let reads = state
        .read_controls
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut count = 0;
    for read in reads {
        if read.state.lock().await.error.is_some() {
            count += 1;
        }
    }
    count
}

pub(super) async fn records(state: &State) -> Vec<Value> {
    let reads = state
        .read_controls
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    for read in reads {
        let guard = read.state.lock().await;
        records.push(
            json!({"corruptionId":read.id,"caseId":read.case.id,"object":read.case.object,
            "method":"GET","path":read.path,"mode":MODE,"expectedRevision":read.expected_revision,
            "phase":guard.phase,"error":guard.error,"disposition":guard.disposition,
            "evidenceRead":guard.evidence_read,"requestSequence":guard.request_sequence}),
        );
    }
    records
}

pub(super) async fn close_all(state: &State) {
    let reads = state
        .read_controls
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for read in reads {
        let mut guard = read.state.lock().await;
        if !terminal(guard.phase) {
            let armed = guard.phase == "armed";
            guard.phase = if armed { "closed" } else { "closing" };
            guard.disposition = Some("teardown-owned-read-control");
        }
        drop(guard);
        read.changed.notify_waiters();
    }
}
