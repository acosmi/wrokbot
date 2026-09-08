//! `public.tool_approvals` durable human proof-of-intent rows (native 0020, v3 §8.5).

crate::db::tables::define_table! {
    table = "tool_approvals";
    approval_id: String = ("approval_id", "text", true),
    tool_call_id: String = ("tool_call_id", "text", true),
    deployment_id: String = ("deployment_id", "text", true),
    tenant_id: String = ("tenant_id", "text", true),
    thread_id: String = ("thread_id", "text", true),
    run_id: String = ("run_id", "text", true),
    actor_id: String = ("actor_id", "text", true),
    bot_id: String = ("bot_id", "text", true),
    auth_generation: i64 = ("auth_generation", "bigint", true),
    tool_name: String = ("tool_name", "text", true),
    args_hash: String = ("args_hash", "text", true),
    target_kind: String = ("target_kind", "text", true),
    target_id: String = ("target_id", "text", true),
    effect: String = ("effect", "text", true),
    approval_class: String = ("approval_class", "text", true),
    computer_generation: i64 = ("computer_generation", "bigint", true),
    catalog_generation: i64 = ("catalog_generation", "bigint", true),
    document_generation: Option<i64> = ("document_generation", "bigint", false),
    policy_version: String = ("policy_version", "text", true),
    arguments_summary: Option<serde_json::Value> = ("arguments_summary", "jsonb", false),
    change_summary: Option<serde_json::Value> = ("change_summary", "jsonb", false),
    state: String = ("state", "text", true),
    requested_at: time::OffsetDateTime = ("requested_at", "timestamp with time zone", true),
    expires_at: time::OffsetDateTime = ("expires_at", "timestamp with time zone", true),
    decided_at: Option<time::OffsetDateTime> = ("decided_at", "timestamp with time zone", false),
    decided_by: Option<String> = ("decided_by", "text", false),
    created_at: time::OffsetDateTime = ("created_at", "timestamp with time zone", true),
    updated_at: time::OffsetDateTime = ("updated_at", "timestamp with time zone", true),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_argument_presentation_and_hash_are_not_debuggable() {
        let row = Row {
            approval_id: "approval-1".to_owned(),
            tool_call_id: "call-1".to_owned(),
            deployment_id: "dep".to_owned(),
            tenant_id: "tenant".to_owned(),
            thread_id: "thread".to_owned(),
            run_id: "run".to_owned(),
            actor_id: "actor".to_owned(),
            bot_id: "bot".to_owned(),
            auth_generation: 1,
            tool_name: "MARKER-VISIBLE".to_owned(),
            args_hash: "SENTINEL-ARGS-HASH".to_owned(),
            target_kind: "mcp_tool".to_owned(),
            target_id: "server/tool".to_owned(),
            effect: "write".to_owned(),
            approval_class: "every_call".to_owned(),
            computer_generation: 0,
            catalog_generation: 1,
            document_generation: None,
            policy_version: "a".repeat(64),
            arguments_summary: Some(serde_json::json!({"value":"SENTINEL-ARGUMENT"})),
            change_summary: None,
            state: "pending".to_owned(),
            requested_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
            decided_at: None,
            decided_by: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let rendered = format!("{row:?}");
        assert!(rendered.contains("MARKER-VISIBLE"));
        assert!(!rendered.contains("SENTINEL-ARGS-HASH"));
        assert!(!rendered.contains("SENTINEL-ARGUMENT"));
        assert!(rendered.matches("<redacted>").count() >= 2);
    }
}
