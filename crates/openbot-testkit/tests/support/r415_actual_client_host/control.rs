use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{Case, State, gates, observe, read_fault};

pub(super) fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("protocol_invalid_{name}"))
}

fn closed_fields(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("protocol_object_required")?;
    if object.keys().any(|name| !fields.contains(&name.as_str())) || value["schemaVersion"] != 1 {
        return Err("protocol_unknown_field_or_version".to_owned());
    }
    Ok(())
}

pub(super) async fn case(state: &State, id: &str, bound: bool) -> Result<Case, String> {
    state
        .cases
        .lock()
        .await
        .get(id)
        .filter(|c| !c.closed && (!bound || c.bound))
        .cloned()
        .ok_or_else(|| "case_unknown_closed_or_unbound".to_owned())
}

pub(super) async fn execute(state: &State, message: &Value) -> Result<Value, String> {
    let command = text(message, "command")?;
    let fields: &[&str] = match command {
        "prepare" => &[
            "schemaVersion",
            "id",
            "command",
            "caseId",
            "object",
            "scope",
        ],
        "bind_object" => &["schemaVersion", "id", "command", "caseId", "objectId"],
        "probe" | "close_case" => &["schemaVersion", "id", "command", "caseId"],
        "stats" | "shutdown" => &["schemaVersion", "id", "command"],
        "arm_ack_gate" => &[
            "schemaVersion",
            "id",
            "command",
            "caseId",
            "gateId",
            "method",
            "path",
            "mode",
        ],
        "wait_gate" => &[
            "schemaVersion",
            "id",
            "command",
            "caseId",
            "gateId",
            "timeoutMs",
        ],
        "release_gate" | "lose_ack" => &["schemaVersion", "id", "command", "caseId", "gateId"],
        "arm_read_corruption" => &[
            "schemaVersion",
            "id",
            "command",
            "caseId",
            "corruptionId",
            "method",
            "path",
            "session",
            "mode",
            "expectedRevision",
        ],
        "wait_read_corruption" => &[
            "schemaVersion",
            "id",
            "command",
            "caseId",
            "corruptionId",
            "timeoutMs",
        ],
        "cancel_read_corruption" => &["schemaVersion", "id", "command", "caseId", "corruptionId"],
        "auth_control" => &["schemaVersion", "id", "command", "caseId", "action"],
        "audit_fault" => &["schemaVersion", "id", "command", "caseId", "enabled"],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    closed_fields(message, fields)?;
    if !["stats", "shutdown"].contains(&command) && state.collection_error.lock().await.is_some() {
        return Err("owned_evidence_collection_failed".to_owned());
    }
    match command {
        "prepare" => prepare(state, message).await,
        "bind_object" => bind(state, message).await,
        "probe" => {
            observe::probe(
                &state.observer,
                &case(state, text(message, "caseId")?, false).await?,
            )
            .await
        }
        "stats" => stats(state).await,
        "arm_ack_gate" => gates::arm(state, message).await,
        "wait_gate" => gates::wait(state, message).await,
        "release_gate" => gates::release(state, message, false).await,
        "lose_ack" => gates::release(state, message, true).await,
        "arm_read_corruption" => read_fault::arm(state, message).await,
        "wait_read_corruption" => read_fault::wait(state, message).await,
        "cancel_read_corruption" => read_fault::cancel(state, message).await,
        "auth_control" => auth_control(state, message).await,
        "audit_fault" => audit_fault(state, message).await,
        "close_case" => {
            let id = text(message, "caseId")?;
            let current = case(state, id, false).await?;
            if current.fault_enabled
                || gates::case_open_count(state, id).await != 0
                || read_fault::case_open_count(state, id).await != 0
            {
                return Err("case_has_live_gate_or_fault".to_owned());
            }
            state
                .cases
                .lock()
                .await
                .get_mut(id)
                .ok_or("case_missing")?
                .closed = true;
            Ok(json!({"caseId":id,"closed":true}))
        }
        "shutdown" => Ok(json!({"closing":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
}

async fn stats(state: &State) -> Result<Value, String> {
    // Snapshot each lock separately; producer tasks may be concurrently returning real responses.
    let (requests, api_ingress_count) = {
        let records = state.requests.lock().await;
        (
            records.clone(),
            state
                .api_ingress_count
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    };
    let changes = state.controls.lock().await.clone();
    let collection_error = *state.collection_error.lock().await;
    let active_cases = state
        .cases
        .lock()
        .await
        .values()
        .filter(|c| !c.closed)
        .count();
    let gates = gates::records(state).await;
    let reads = read_fault::records(state).await;
    Ok(
        json!({"requests":requests,"apiIngressCount":api_ingress_count,
        "openGates":gates::open_count(state).await,"gates":gates,
        "openReadControls":read_fault::open_count(state).await,"readControls":reads,
        "transportControlFailures":gates::failed_count(state).await+read_fault::failed_count(state).await,
        "collectionFailed":collection_error.is_some(),"collectionError":collection_error,
        "remoteCalls":state.remote_calls.load(std::sync::atomic::Ordering::Relaxed),
        "activeCases":active_cases,"controlChanges":changes}),
    )
}

async fn prepare(state: &State, message: &Value) -> Result<Value, String> {
    let id = text(message, "caseId")?;
    if id.len() > 23
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        || !id.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err("invalid_case_id".to_owned());
    }
    let object = text(message, "object")?;
    if !["models", "sandbox", "skills", "preferences"].contains(&object) {
        return Err("invalid_object".to_owned());
    }
    let scope = text(message, "scope")?;
    if scope != "personal" && !(scope == "global" && object == "skills") {
        return Err("invalid_scope".to_owned());
    }
    let actor = format!("r415-owner-{}", Uuid::new_v4());
    let foreign_actor = format!("r415-foreign-{}", Uuid::new_v4());
    let tokens: Vec<String> = (0..3)
        .map(|_| format!("R415_PRIVATE_SESSION_{}", Uuid::new_v4()))
        .collect();
    let sessions: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
    let slug = if object == "skills" {
        format!("owned-case-skill-{id}")
    } else {
        format!("owned_case_{}", id.replace('-', "_"))
    };
    let current = Case {
        id: id.to_owned(),
        object: object.to_owned(),
        scope: scope.to_owned(),
        actor: actor.clone(),
        session_a: sessions[0].clone(),
        token_a: tokens[0].clone(),
        token_b: tokens[1].clone(),
        slug: slug.clone(),
        object_id: None,
        bound: false,
        closed: false,
        fault_enabled: false,
    };
    {
        let mut cases = state.cases.lock().await;
        if cases.contains_key(id) {
            return Err("case_id_reused".to_owned());
        }
        if cases.values().any(|c| !c.closed) || cases.len() >= 256 {
            return Err("case_active_or_limit".to_owned());
        }
        // Reserve before SQL. Even failed preparation does not permit identity reuse.
        cases.insert(id.to_owned(), current.clone());
    }
    let mut connection = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|_| "prepare_begin")?;
    for user in [&actor, &foreign_actor] {
        let email = format!("{user}@owned-r415.test");
        transaction
            .execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,7)",
                &[user, &email],
            )
            .await
            .map_err(|_| "prepare_user")?;
        let role = if user == &actor && (object == "sandbox" || scope == "global") {
            "admin"
        } else {
            "user"
        };
        transaction
            .execute(
                "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::public.role)",
                &[user, &role],
            )
            .await
            .map_err(|_| "prepare_role")?;
    }
    let now = OffsetDateTime::now_utc();
    for n in 0..3 {
        let user = if n == 2 { &foreign_actor } else { &actor };
        let hash = SessionTokenHash::compute(
            SessionToken::new(tokens[n].as_bytes()),
            SessionHashKey::new(super::SESSION_KEY),
        )
        .to_column_value();
        transaction.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$6,7)",
            &[&sessions[n],user,&hash,&(now+Duration::hours(1)),&(now-Duration::minutes(1)),&now])
            .await.map_err(|_|"prepare_session")?;
    }
    transaction.commit().await.map_err(|_| "prepare_commit")?;
    let private_key = format!("R415_PRIVATE_MODEL_{}", Uuid::new_v4());
    let (method, path, status, body, selector, read_path) = match object {
        "models" => (
            "POST",
            "/api/me/model-connections",
            201,
            json!({"name":format!("Owned R415 {id}"),
            "protocol":"openai_chat_completions","endpoint":"https://r415-model.example.test/v1/chat/completions",
            "model":"synthetic-model","enabled":false,"apiKey":private_key}),
            format!("Owned R415 {id}"),
            "/api/me/model-connections",
        ),
        "sandbox" => (
            "POST",
            "/api/sandboxed",
            200,
            json!({"slug":slug,"title":format!("Owned R415 {id}"),
            "description":"bounded owned fixture","html":"<p>owned seed</p>","css":"","jsFunctions":"",
            "argumentSchema":{"type":"object"},"sampleArguments":{},"expectedRevision":null}),
            format!("custom_{slug}"),
            "/api/sandboxed",
        ),
        "skills" => (
            "POST",
            "/api/plugins/skills",
            200,
            json!({"slug":slug,"title":format!("Owned R415 {id}"),
            "summary":"bounded owned fixture","instructions":"Synthetic instructions; no permission grant.",
            "global":scope=="global","expectedRevision":null}),
            slug.clone(),
            "/api/plugins",
        ),
        "preferences" => (
            "GET",
            "/api/me/preferences",
            200,
            Value::Null,
            actor.clone(),
            "/api/me/preferences",
        ),
        _ => return Err("invalid_object".to_owned()),
    };
    let baseline = observe::probe(&state.observer, &current).await?;
    Ok(json!({"caseId":id,"object":object,"scope":scope,
        "sessions":{"a":{"token":tokens[0],"userId":actor},"b":{"token":tokens[1],"userId":actor},
            "c":{"token":tokens[2],"userId":foreign_actor}},
        "seed":{"method":method,"path":path,"body":body,"expectedStatus":status,"selector":selector},
        "readPath":read_path,"updatePath":if object=="models" {Value::Null} else {json!(path)},"baseline":baseline}))
}

async fn bind(state: &State, message: &Value) -> Result<Value, String> {
    let id = text(message, "caseId")?;
    let mut current = case(state, id, false).await?;
    if current.bound {
        return Err("case_already_bound".to_owned());
    }
    current.object_id = Some(match current.object.as_str() {
        "preferences" => {
            if message.get("objectId").is_some() {
                return Err("preferences_object_id_not_allowed".to_owned());
            }
            current.actor.clone()
        }
        "sandbox" => {
            let actual = text(message, "objectId")?;
            if actual != format!("custom_{}", current.slug) {
                return Err("sandbox_identity_mismatch".to_owned());
            }
            actual.to_owned()
        }
        _ => text(message, "objectId")?.to_owned(),
    });
    let probe = observe::probe(&state.observer, &current).await?;
    if current.object != "preferences" && probe["row"].is_null() {
        return Err("binding_missing_committed_object".to_owned());
    }
    if current.object == "skills" && probe["row"]["slug"] != current.slug {
        return Err("skill_slug_mismatch".to_owned());
    }
    if current.object == "models" && probe["row"]["name"] != format!("Owned R415 {}", current.id) {
        return Err("model_name_mismatch".to_owned());
    }
    current.bound = true;
    state
        .cases
        .lock()
        .await
        .insert(id.to_owned(), current.clone());
    let read_path = match current.object.as_str() {
        "models" => current.update_path()?,
        "sandbox" => "/api/sandboxed".to_owned(),
        "skills" => "/api/plugins".to_owned(),
        "preferences" => "/api/me/preferences".to_owned(),
        _ => return Err("invalid_object".to_owned()),
    };
    Ok(
        json!({"caseId":id,"objectId":current.object_id,"updatePath":current.update_path()?,"readPath":read_path,"probe":probe}),
    )
}

async fn auth_control(state: &State, message: &Value) -> Result<Value, String> {
    let current = case(state, text(message, "caseId")?, false).await?;
    if gates::case_open_count(state, &current.id).await != 0
        || read_fault::case_open_count(state, &current.id).await != 0
    {
        return Err("auth_control_with_live_transport_control".to_owned());
    }
    let action = text(message, "action")?;
    let connection = state
        .observer
        .get()
        .await
        .map_err(|_| "auth_control_connection")?;
    let changed = match action {
        "generation" => {
            connection
                .execute(
                    "UPDATE public.users SET auth_generation=auth_generation+1 WHERE id=$1",
                    &[&current.actor],
                )
                .await
        }
        "revoke-a" => {
            connection
                .execute(
                    "DELETE FROM public.sessions WHERE id=$1 AND user_id=$2",
                    &[&current.session_a, &current.actor],
                )
                .await
        }
        "remove-admin" => {
            connection
                .execute(
                    "DELETE FROM public.user_roles WHERE user_id=$1 AND role='admin'",
                    &[&current.actor],
                )
                .await
        }
        _ => return Err("invalid_auth_control".to_owned()),
    }
    .map_err(|_| "auth_control_sql")?;
    state
        .record_control(
            json!({"caseId":current.id,"kind":"auth","action":action,"changed":changed}),
        )
        .await?;
    Ok(
        json!({"action":action,"changed":changed,"baseline":observe::probe(&state.observer,&current).await?}),
    )
}

async fn audit_fault(state: &State, message: &Value) -> Result<Value, String> {
    let mut current = case(state, text(message, "caseId")?, true).await?;
    let enabled = message
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or("invalid_fault_enabled")?;
    if current.fault_enabled == enabled
        || gates::case_open_count(state, &current.id).await != 0
        || read_fault::case_open_count(state, &current.id).await != 0
    {
        return Err("fault_state_or_live_control".to_owned());
    }
    let connection = state.observer.get().await.map_err(|_| "fault_connection")?;
    if enabled {
        let (kind, target) = match current.object.as_str() {
            "models" => (
                "model_connection",
                current.object_id.as_deref().ok_or("unbound")?,
            ),
            "sandbox" => ("component", current.object_id.as_deref().ok_or("unbound")?),
            "skills" => ("skill", current.slug.as_str()),
            "preferences" => ("ui_preferences", current.actor.as_str()),
            _ => return Err("invalid_object".to_owned()),
        };
        // Only generated/validated synthetic identities enter this owned DDL literal.
        if !target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("unsafe_fault_target".to_owned());
        }
        connection.batch_execute(&format!("CREATE SEQUENCE public.r415_fault_hits; CREATE FUNCTION public.r415_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.target_type='{kind}' AND NEW.target_id='{target}' AND NEW.actor_user_id='{}' THEN PERFORM nextval('public.r415_fault_hits'); RAISE EXCEPTION 'owned synthetic audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER r415_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.r415_audit_fault()",current.actor))
            .await.map_err(|_|"fault_install")?;
    } else {
        connection.batch_execute("DROP TRIGGER r415_audit_fault ON public.audit_events; DROP FUNCTION public.r415_audit_fault(); DROP SEQUENCE public.r415_fault_hits")
            .await.map_err(|_|"fault_remove")?;
    }
    current.fault_enabled = enabled;
    state
        .cases
        .lock()
        .await
        .insert(current.id.clone(), current.clone());
    state
        .record_control(json!({"caseId":current.id,"kind":"audit-fault","enabled":enabled}))
        .await?;
    Ok(json!({"enabled":enabled,"baseline":observe::probe(&state.observer,&current).await?}))
}
