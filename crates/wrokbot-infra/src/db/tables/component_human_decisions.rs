//! `public.component_human_decisions` durable surface/HITL answers (native 0023).

crate::db::tables::define_table! {
    table = "component_human_decisions";
    decision_id: String = ("decision_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    run_id: String = ("run_id", "text", true),
    actor_id: String = ("actor_id", "text", true),
    bot_id: String = ("bot_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    provider_call_id: String = ("provider_call_id", "text", true),
    component_name: String = ("component_name", "text", true),
    arguments: serde_json::Value = ("arguments", "jsonb", true),
    arguments_hash: String = ("arguments_hash", "text", true),
    state: String = ("state", "text", true),
    answer: Option<serde_json::Value> = ("answer", "jsonb", false),
    requested_at: time::OffsetDateTime = ("requested_at", "timestamp with time zone", true),
    expires_at: time::OffsetDateTime = ("expires_at", "timestamp with time zone", true),
    resolved_at: Option<time::OffsetDateTime> = ("resolved_at", "timestamp with time zone", false),
    resolved_by: Option<String> = ("resolved_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_arguments_answer_and_hash_are_not_debuggable() {
        let row = Row {
            decision_id: "decision-1".to_owned(),
            deployment_id: "deployment".to_owned(),
            tenant_id: "tenant".to_owned(),
            thread_id: "thread".to_owned(),
            run_id: "run".to_owned(),
            actor_id: "actor".to_owned(),
            bot_id: "bot".to_owned(),
            auth_generation: 0,
            provider_call_id: "provider-call".to_owned(),
            component_name: "askApproval".to_owned(),
            arguments: serde_json::json!({"summary":"SENTINEL-ARGUMENT"}),
            arguments_hash: "SENTINEL-HASH".to_owned(),
            state: "answered".to_owned(),
            answer: Some(serde_json::json!({"decision":"approved","note":"SENTINEL-ANSWER"})),
            requested_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
            resolved_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            resolved_by: Some("actor".to_owned()),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(rendered.contains("askApproval"));
        assert!(!rendered.contains("SENTINEL-ARGUMENT"));
        assert!(!rendered.contains("SENTINEL-ANSWER"));
        assert!(!rendered.contains("SENTINEL-HASH"));
        assert!(rendered.matches("<redacted>").count() >= 3);
    }
}
