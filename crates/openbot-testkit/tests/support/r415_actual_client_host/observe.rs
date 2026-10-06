use openbot_contracts::revision::RevisionSnapshot;
use openbot_infra::db::pool::DatabasePool as Pool;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::Case;

// The relation list is finite and fixed. Sessions/auth controls are intentionally separate.
const SNAPSHOT: &str = "SELECT jsonb_build_object(
 'model_connections',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]') FROM public.model_connections m),
 'model_connection_secrets',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'encrypted_value') || jsonb_build_object('encrypted_value_sql_md5',md5(encrypted_value)) ORDER BY id),'[]') FROM public.model_connection_secrets s),
 'sandboxed_components',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY name),'[]') FROM public.sandboxed_components s),
 'components',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY name),'[]') FROM public.components c),
 'sandboxed_component_retired_names',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY name),'[]') FROM public.sandboxed_component_retired_names r),
 'skills',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.skills s),
 'plugin_grants',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY kind,ref,agent_id),'[]') FROM public.plugin_grants g),
 'skill_retired_slugs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY slug),'[]') FROM public.skill_retired_slugs r),
 'user_ui_preferences',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY deployment_id,tenant_id,actor_user_id),'[]') FROM public.user_ui_preferences p),
 'audit_events',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a),
 'audit_checkpoints',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'signature') || jsonb_build_object('signature_sql_md5',md5(signature)) ORDER BY sequence),'[]') FROM public.audit_checkpoints c))";

fn fingerprint(value: &Value) -> Result<Value, String> {
    let snapshot = RevisionSnapshot::from_public(1, OffsetDateTime::UNIX_EPOCH, value)
        .map_err(|_| "observer_public_snapshot_encode")?;
    let wire = serde_json::to_value(snapshot).map_err(|_| "observer_fingerprint_encode")?;
    Ok(json!({"count":value.as_array().map_or(0,Vec::len),"sha256":wire["currentSha256"]}))
}

fn sandbox_governance(full: &Value, case: &Case, row: &Value) -> Result<Value, String> {
    if case.object != "sandbox" {
        return Ok(Value::Null);
    }
    let Some(id) = case.object_id.as_deref() else {
        // prepare observes a genuine absent baseline before the HTTP seed and identity binding.
        return if row.is_null() {
            Ok(Value::Null)
        } else {
            Err("observer_unbound_sandbox_row".to_owned())
        };
    };
    let components = full["components"]
        .as_array()
        .ok_or("observer_sandbox_components_shape")?;
    let sources = full["sandboxed_components"]
        .as_array()
        .ok_or("observer_sandbox_sources_shape")?;
    let is_selected = |value: &&Value| value.get("name").and_then(Value::as_str) == Some(id);
    let mut selected = components.iter().filter(is_selected);
    let selected = selected
        .next()
        .filter(|_| selected.next().is_none())
        .ok_or("observer_sandbox_governance_identity")?;
    let safe_columns = [
        "name",
        "title",
        "kind",
        "draft_description",
        "published_description",
        "published",
        "published_at",
        "updated_by",
        "created_at",
        "updated_at",
    ];
    let selected_object = selected
        .as_object()
        .filter(|value| {
            value.len() == safe_columns.len()
                && safe_columns
                    .iter()
                    .all(|column| value.contains_key(*column))
        })
        .ok_or("observer_sandbox_governance_shape")?;
    if selected_object["kind"].as_str() != Some("sandboxed")
        || row.get("name").and_then(Value::as_str) != Some(id)
        || sources.iter().filter(is_selected).count() != 1
    {
        return Err("observer_sandbox_governance_identity".to_owned());
    }
    // Keep the original whole-relation fingerprints. These finite projections distinguish
    // the selected draft metadata update from publication or changes to another object.
    let other_rows = components
        .iter()
        .filter(|value| !is_selected(value))
        .cloned()
        .collect();
    let other_sources = sources
        .iter()
        .filter(|value| !is_selected(value))
        .cloned()
        .collect();
    Ok(json!({"selected":selected,
        "otherRows":fingerprint(&Value::Array(other_rows))?,
        "otherSourceRows":fingerprint(&Value::Array(other_sources))?}))
}

pub(super) async fn probe(pool: &Pool, case: &Case) -> Result<Value, String> {
    let mut connection = pool.get().await.map_err(|_| "observer_connection")?;
    let transaction = connection
        .build_transaction()
        .isolation_level(deadpool_postgres::tokio_postgres::IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .await
        .map_err(|_| "observer_begin")?;
    let pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|_| "observer_pid")?
        .get(0);
    let sql = match case.object.as_str() {
        "models" => {
            "SELECT to_jsonb(m)-'current_secret_id' FROM public.model_connections m WHERE id::text=$1 AND owner_user_id=$2 AND deleted_at IS NULL"
        }
        "sandbox" => "SELECT to_jsonb(s) FROM public.sandboxed_components s WHERE name=$1",
        "skills" if case.scope == "global" => {
            "SELECT to_jsonb(s) FROM public.skills s WHERE id=$1 AND owner_user_id IS NULL"
        }
        "skills" => "SELECT to_jsonb(s) FROM public.skills s WHERE id=$1 AND owner_user_id=$2",
        "preferences" => {
            "SELECT to_jsonb(p) FROM public.user_ui_preferences p WHERE actor_user_id=$1 AND deployment_id=$2 AND tenant_id=$3"
        }
        _ => return Err("observer_invalid_object".to_owned()),
    };
    let id = case.object_id.as_deref().unwrap_or("");
    let row = match case.object.as_str() {
        "sandbox" | "skills" if case.scope == "global" || case.object == "sandbox" => {
            transaction.query_opt(sql, &[&id]).await
        }
        "preferences" => {
            transaction
                .query_opt(sql, &[&case.actor, &super::DEPLOYMENT, &super::TENANT])
                .await
        }
        _ => transaction.query_opt(sql, &[&id, &case.actor]).await,
    }
    .map_err(|_| "observer_selected_row")?
    .map_or(Value::Null, |r| r.get::<_, Value>(0));
    let full: Value = transaction
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "observer_finite_snapshot")?
        .get(0);
    let sandbox_governance = sandbox_governance(&full, case, &row)?;
    let fault_exists: bool = transaction
        .query_one(
            "SELECT to_regclass('public.r415_fault_hits') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|_| "observer_fault_exists")?
        .get(0);
    let fault_hits = if fault_exists {
        transaction
            .query_one(
                "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM public.r415_fault_hits",
                &[],
            )
            .await
            .map_err(|_| "observer_fault_hits")?
            .get::<_, i64>(0)
    } else {
        0
    };
    transaction.commit().await.map_err(|_| "observer_end")?;
    let mut business = serde_json::Map::new();
    let mut audit = serde_json::Map::new();
    for (name, value) in full.as_object().ok_or("observer_snapshot_shape")? {
        let destination = if name.starts_with("audit_") {
            &mut audit
        } else {
            &mut business
        };
        destination.insert(name.clone(), fingerprint(value)?);
    }
    let revision = if case.object == "sandbox" {
        row.get("editing_revision")
    } else {
        row.get("revision")
    }
    .cloned()
    .unwrap_or(Value::Null);
    Ok(
        json!({"caseId":case.id,"object":case.object,"objectId":case.object_id,
        "row":row,"revision":revision,"business":business,"audit":audit,"faultHits":fault_hits,
        "sandboxGovernance":sandbox_governance,
        "observer":{"backendPid":pid,"isolation":"read committed","readOnly":true},
        "privateColumnBoundary":"encrypted_value/signature represented only by SQL MD5 before canonical public SHA256; no plaintext/ciphertext output"}),
    )
}
